# SPDX-License-Identifier: GPL-2.0-only
"""Crash-safe administrator writes for disabled T2 user mappings.

This layer never enables a mapping and performs no T2 operation. New mappings
and account-generation replacements are published disabled; a later live
Apple/AKS/Catacomb reconciliation must own any enable transition.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import os
import stat
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

import t2_linux_account
import t2_user_mapping


DEFAULT_MAPPING_PATH = Path("/var/lib/t2-touchid/users.json")
ROOT_UID = 0
MAX_KEYBAG_SIZE = 16 * 1024 * 1024
RENAME_NOREPLACE = 1


class UserMappingAdminError(RuntimeError):
    pass


AccountCollector = Callable[[int], t2_linux_account.AccountEvidence]
KeybagReader = Callable[[Path], str]


@dataclass(frozen=True, repr=False)
class AdminResult:
    operation: str
    state: str
    mapping_count: int
    enabled_mapping_count: int
    account_generation_current: bool | None
    mapping_disabled: bool | None

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "operation": self.operation,
            "state": self.state,
            "mapping_count": self.mapping_count,
            "enabled_mapping_count": self.enabled_mapping_count,
            "account_generation_current": self.account_generation_current,
            "mapping_disabled": self.mapping_disabled,
            "identifiers_redacted": True,
        }


def _require_root() -> None:
    if os.geteuid() != ROOT_UID:
        raise UserMappingAdminError("mapping administration requires root")


def _open_parent(path: Path) -> tuple[int, str]:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or t2_user_mapping.SAFE_BASENAME.fullmatch(path.name) is None
        or path.name in {".", ".."}
    ):
        raise UserMappingAdminError("mapping path is invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path.parent, flags)
        info = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise UserMappingAdminError("mapping directory is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_mode & 0o022
    ):
        os.close(descriptor)
        raise UserMappingAdminError("mapping directory ownership is unsafe")
    return descriptor, path.name


def _open_lock(directory: int, mapping_name: str) -> int:
    name = f".{mapping_name}.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        info = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise UserMappingAdminError("mapping lock is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        os.close(descriptor)
        raise UserMappingAdminError("mapping lock ownership is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError as error:
        os.close(descriptor)
        raise UserMappingAdminError("mapping lock cannot be acquired") from error
    return descriptor


def _mapping_exists(directory: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise UserMappingAdminError("mapping location cannot be inspected") from error


def _load_optional(
    directory: int, name: str
) -> t2_user_mapping.UserMappingSet | None:
    if not _mapping_exists(directory, name):
        return None
    try:
        return t2_user_mapping.load_at(directory, name)
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError("existing mapping authority is invalid") from error


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(descriptor, data[offset:])
        except OSError as error:
            raise UserMappingAdminError("mapping write failed") from error
        if written <= 0:
            raise UserMappingAdminError("mapping write was incomplete")
        offset += written


def _rename_noreplace(directory: int, source: str, target: str) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (OSError, AttributeError) as error:
        raise UserMappingAdminError(
            "atomic no-replace mapping publish is unavailable"
        ) from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory,
        source.encode("ascii"),
        directory,
        target.encode("ascii"),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise UserMappingAdminError("mapping appeared during initial publish")
        raise UserMappingAdminError("atomic no-replace mapping publish failed")


def _sync_directory(directory: int) -> None:
    try:
        os.fsync(directory)
    except OSError as error:
        raise UserMappingAdminError("mapping directory sync failed") from error


def _publish(
    directory: int,
    name: str,
    mappings: tuple[t2_user_mapping.UserMapping, ...],
    expected_generation: str | None,
) -> t2_user_mapping.UserMappingSet:
    try:
        data = t2_user_mapping.serialize(mappings)
        expected = t2_user_mapping.parse(data)
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError("new mapping authority is invalid") from error
    temporary = f".{name}.{uuid.uuid4()}.tmp"
    descriptor = -1
    published = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        if expected_generation is None:
            if _mapping_exists(directory, name):
                raise UserMappingAdminError("mapping already exists")
            _rename_noreplace(directory, temporary, name)
        else:
            current = _load_optional(directory, name)
            if current is None or current.generation != expected_generation:
                raise UserMappingAdminError(
                    "mapping authority changed before atomic publish"
                )
            os.rename(
                temporary,
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        published = True
        _sync_directory(directory)
        final = _load_optional(directory, name)
        if final is None or final.generation != expected.generation:
            raise UserMappingAdminError("published mapping failed exact read-back")
        return final
    except OSError as error:
        raise UserMappingAdminError("mapping publish failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError:
                pass


def _keybag_digest(path: Path) -> str:
    descriptor = -1
    digest = hashlib.sha256()
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != ROOT_UID
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= MAX_KEYBAG_SIZE
        ):
            raise UserMappingAdminError("keybag file is not private and root-owned")
        size = 0
        buffer = bytearray(65536)
        view = memoryview(buffer)
        try:
            while size <= MAX_KEYBAG_SIZE:
                wanted = min(len(buffer), MAX_KEYBAG_SIZE + 1 - size)
                read = os.readv(descriptor, [view[:wanted]])
                if read == 0:
                    break
                digest.update(view[:read])
                size += read
                view[:read] = b"\0" * read
        finally:
            view[:] = b"\0" * len(view)
            view.release()
        after = os.fstat(descriptor)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if size != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in fields
        ):
            raise UserMappingAdminError("keybag file changed while hashing")
        return digest.hexdigest()
    except OSError as error:
        raise UserMappingAdminError("keybag file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _collect_account(
    uid: int, collector: AccountCollector
) -> t2_linux_account.AccountEvidence:
    try:
        evidence = collector(uid)
    except t2_linux_account.LinuxAccountError as error:
        raise UserMappingAdminError("live Linux account assertion failed") from error
    if (
        not isinstance(evidence, t2_linux_account.AccountEvidence)
        or evidence.linux_uid != uid
        or evidence.source != "local-files-v2"
        or evidence.protected_password_record is not True
        or evidence.home_object_bound is not True
    ):
        raise UserMappingAdminError("live Linux account assertion is invalid")
    try:
        t2_user_mapping._sha256(evidence.generation, "account generation")
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError("live Linux account assertion is invalid") from error
    return evidence


def _result(
    operation: str,
    state: str,
    mapping_set: t2_user_mapping.UserMappingSet,
    *,
    account_current: bool | None,
    mapping_disabled: bool | None,
) -> AdminResult:
    return AdminResult(
        operation,
        state,
        len(mapping_set.mappings),
        sum(item.enabled for item in mapping_set.mappings),
        account_current,
        mapping_disabled,
    )


def bind_disabled(
    *,
    linux_uid: int,
    apple_uid: int,
    account_uuid: str,
    bag_uuid: str,
    unlock_mode: str,
    capabilities: tuple[str, ...],
    acknowledge_apple_authority_is_already_provisioned: bool,
    path: Path = DEFAULT_MAPPING_PATH,
    account_collector: AccountCollector = t2_linux_account.collect,
    keybag_reader: KeybagReader = _keybag_digest,
) -> AdminResult:
    """Add one disabled mapping; no Apple or biometric state is mutated."""

    _require_root()
    if acknowledge_apple_authority_is_already_provisioned is not True:
        raise UserMappingAdminError("disabled binding acknowledgement is required")
    if (
        not isinstance(capabilities, tuple)
        or not capabilities
        or any(not isinstance(item, str) for item in capabilities)
        or len(capabilities) != len(set(capabilities))
    ):
        raise UserMappingAdminError("at least one explicit capability is required")
    try:
        linux_uid = t2_user_mapping._unsigned(
            linux_uid, "Linux UID", minimum=1
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError(str(error)) from error
    directory, name = _open_parent(path)
    lock = -1
    try:
        lock = _open_lock(directory, name)
        current = _load_optional(directory, name)
        existing = () if current is None else current.mappings
        if any(item.linux_uid == linux_uid for item in existing):
            raise UserMappingAdminError("Linux UID already has a protected mapping")
        first_account = _collect_account(linux_uid, account_collector)
        keybag_path = Path(t2_user_mapping.KEYBAG_ROOT / str(linux_uid) / "user.kb")
        keybag_digest = keybag_reader(keybag_path)
        try:
            t2_user_mapping._sha256(keybag_digest, "keybag digest")
            candidate = t2_user_mapping.UserMapping(
                linux_uid,
                first_account.generation,
                apple_uid,
                account_uuid,
                bag_uuid,
                str(keybag_path),
                keybag_digest,
                unlock_mode,
                frozenset(capabilities),
                False,
            )
            # Serialization validates every supplied field and cross-record
            # uniqueness before any filesystem mutation.
            t2_user_mapping.serialize(existing + (candidate,))
        except t2_user_mapping.UserMappingError as error:
            raise UserMappingAdminError("disabled mapping input is invalid") from error
        if keybag_reader(keybag_path) != keybag_digest:
            raise UserMappingAdminError("keybag changed during binding")
        second_account = _collect_account(linux_uid, account_collector)
        if second_account != first_account:
            raise UserMappingAdminError("Linux account changed during binding")
        final = _publish(
            directory,
            name,
            existing + (candidate,),
            None if current is None else current.generation,
        )
        return _result(
            "bind",
            "mapping-bound-disabled",
            final,
            account_current=True,
            mapping_disabled=True,
        )
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def rebind_disabled(
    *,
    linux_uid: int,
    acknowledge_account_generation_replacement: bool,
    path: Path = DEFAULT_MAPPING_PATH,
    account_collector: AccountCollector = t2_linux_account.collect,
    keybag_reader: KeybagReader = _keybag_digest,
) -> AdminResult:
    """Replace only one account generation and force the mapping disabled."""

    _require_root()
    if acknowledge_account_generation_replacement is not True:
        raise UserMappingAdminError("account replacement acknowledgement is required")
    try:
        linux_uid = t2_user_mapping._unsigned(
            linux_uid, "Linux UID", minimum=1
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError(str(error)) from error
    directory, name = _open_parent(path)
    lock = -1
    try:
        lock = _open_lock(directory, name)
        current = _load_optional(directory, name)
        if current is None:
            raise UserMappingAdminError("protected mapping does not exist")
        matches = [item for item in current.mappings if item.linux_uid == linux_uid]
        if len(matches) != 1:
            raise UserMappingAdminError("Linux UID has no unique protected mapping")
        selected = matches[0]
        keybag_path = Path(selected.keybag_path)
        if keybag_reader(keybag_path) != selected.keybag_sha256:
            raise UserMappingAdminError("protected keybag digest changed")
        first_account = _collect_account(linux_uid, account_collector)
        if first_account.generation == selected.linux_account_generation:
            raise UserMappingAdminError("account generation is already current")
        replacement = replace(
            selected,
            linux_account_generation=first_account.generation,
            enabled=False,
        )
        updated = tuple(
            replacement if item == selected else item for item in current.mappings
        )
        if keybag_reader(keybag_path) != selected.keybag_sha256:
            raise UserMappingAdminError("keybag changed during rebinding")
        second_account = _collect_account(linux_uid, account_collector)
        if second_account != first_account:
            raise UserMappingAdminError("Linux account changed during rebinding")
        final = _publish(
            directory,
            name,
            updated,
            current.generation,
        )
        return _result(
            "rebind",
            "account-rebound-disabled",
            final,
            account_current=True,
            mapping_disabled=True,
        )
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def disable(
    *,
    linux_uid: int,
    acknowledge_immediate_mapping_revocation: bool,
    path: Path = DEFAULT_MAPPING_PATH,
) -> AdminResult:
    """Atomically revoke one enabled mapping without requiring live hardware."""

    _require_root()
    if acknowledge_immediate_mapping_revocation is not True:
        raise UserMappingAdminError("mapping revocation acknowledgement is required")
    try:
        linux_uid = t2_user_mapping._unsigned(
            linux_uid, "Linux UID", minimum=1
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserMappingAdminError(str(error)) from error
    directory, name = _open_parent(path)
    lock = -1
    try:
        lock = _open_lock(directory, name)
        current = _load_optional(directory, name)
        if current is None:
            raise UserMappingAdminError("protected mapping does not exist")
        matches = [item for item in current.mappings if item.linux_uid == linux_uid]
        if len(matches) != 1:
            raise UserMappingAdminError("Linux UID has no unique protected mapping")
        selected = matches[0]
        if not selected.enabled:
            raise UserMappingAdminError("protected mapping is already disabled")
        replacement = replace(selected, enabled=False)
        updated = tuple(
            replacement if item == selected else item for item in current.mappings
        )
        final = _publish(directory, name, updated, current.generation)
        return _result(
            "disable",
            "mapping-disabled",
            final,
            account_current=None,
            mapping_disabled=True,
        )
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(directory)


def status(
    *,
    linux_uid: int | None = None,
    path: Path = DEFAULT_MAPPING_PATH,
    account_collector: AccountCollector = t2_linux_account.collect,
) -> AdminResult:
    """Return a redacted mapping summary and optional live account comparison."""

    _require_root()
    directory, name = _open_parent(path)
    try:
        current = _load_optional(directory, name)
        if current is None:
            raise UserMappingAdminError("protected mapping does not exist")
        if linux_uid is None:
            return _result(
                "status",
                "mapping-valid",
                current,
                account_current=None,
                mapping_disabled=None,
            )
        try:
            linux_uid = t2_user_mapping._unsigned(
                linux_uid, "Linux UID", minimum=1
            )
        except t2_user_mapping.UserMappingError as error:
            raise UserMappingAdminError(str(error)) from error
        matches = [item for item in current.mappings if item.linux_uid == linux_uid]
        if len(matches) != 1:
            raise UserMappingAdminError("Linux UID has no unique protected mapping")
        evidence = _collect_account(linux_uid, account_collector)
        repeated = _load_optional(directory, name)
        if repeated is None or repeated.generation != current.generation:
            raise UserMappingAdminError("mapping changed during status collection")
        selected = matches[0]
        matches_generation = (
            evidence.generation == selected.linux_account_generation
        )
        return _result(
            "status",
            (
                "account-generation-current"
                if matches_generation
                else "account-generation-changed"
            ),
            current,
            account_current=matches_generation,
            mapping_disabled=not selected.enabled,
        )
    finally:
        os.close(directory)
