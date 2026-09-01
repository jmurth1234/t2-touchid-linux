# SPDX-License-Identifier: GPL-2.0-only
"""Concrete read-only live session for protected user mapping reconciliation."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from contextlib import ExitStack
from pathlib import Path
from types import TracebackType

import t2_aks_observer
import t2_bridge_connection
import t2_bridge_inventory
import t2_catacomb_codec
import t2_catacomb_store
import t2_identity_inventory
import t2_user_mapping
import t2_user_readiness


CONFIG = Path("/etc/t2-touchid.conf")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STORE_ROOT = Path("/var/lib/t2-touchid/catacomb")
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
MAX_CONFIG_SIZE = 1024 * 1024
ROOT_UID = 0


class LiveUserReconciliationError(RuntimeError):
    pass


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
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
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_private(path: Path, maximum: int = MAX_CONFIG_SIZE) -> bytes:
    descriptor = -1
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
            or not 0 < before.st_size <= maximum
        ):
            raise LiveUserReconciliationError(
                f"{path.name} is not private and root-owned"
            )
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_file(before, after):
            raise LiveUserReconciliationError(f"{path.name} changed during read")
        return bytes(data)
    except OSError as error:
        raise LiveUserReconciliationError(f"{path.name} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _connection_configuration() -> tuple[str, str, int]:
    try:
        text = _read_private(CONFIG).decode("utf-8")
        port_text = _read_private(PORT_CACHE, 32).decode("ascii").strip()
    except UnicodeError as error:
        raise LiveUserReconciliationError(
            "runtime connection configuration has invalid encoding"
        ) from error
    values: dict[str, list[str]] = {
        "T2_TOUCHID_HOST": [],
        "T2_TOUCHID_INTERFACE": [],
    }
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(found) != 1 for found in values.values()):
        raise LiveUserReconciliationError(
            "runtime connection configuration is missing or duplicated"
        )
    host = values["T2_TOUCHID_HOST"][0]
    interface = values["T2_TOUCHID_INTERFACE"][0]
    if (
        not host
        or len(host.encode("utf-8")) > 255
        or not interface
        or len(interface.encode("utf-8")) > 64
        or not port_text.isascii()
        or not port_text.isdecimal()
        or port_text != str(int(port_text, 10))
        or not 49152 <= int(port_text, 10) <= 65535
    ):
        raise LiveUserReconciliationError(
            "runtime connection configuration is invalid"
        )
    return host, interface, int(port_text, 10)


def _open_operation_lock() -> int:
    descriptor = -1
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(OPERATION_LOCK, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise LiveUserReconciliationError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise LiveUserReconciliationError(
                "another Touch ID operation is active"
            ) from error
        return descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise LiveUserReconciliationError("operation lock is unavailable") from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _require_clean_catacomb(live: dict[str, object], apple_uid: int) -> None:
    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or not isinstance(states, list)
        or not isinstance(catacomb.get("hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", catacomb["hash"])
    ):
        raise LiveUserReconciliationError("live SEP Catacomb is invalid")
    try:
        catacomb_uuid = catacomb.get("uuid")
        if str(uuid.UUID(catacomb_uuid)) != catacomb_uuid:
            raise LiveUserReconciliationError("live SEP Catacomb UUID is invalid")
    except (AttributeError, TypeError, ValueError) as error:
        raise LiveUserReconciliationError(
            "live SEP Catacomb UUID is invalid"
        ) from error
    selected = [
        item
        for item in states
        if isinstance(item, dict)
        and item.get("kind") == "user"
        and item.get("user_id") == apple_uid
    ]
    masters = [
        item
        for item in states
        if isinstance(item, dict) and item.get("kind") == "master"
    ]
    for item in selected + masters:
        if (
            set(item) != {"kind", "user_id", "state", "needs_save"}
            or type(item.get("state")) is not int
            or not 0 <= item["state"] <= 0xFFFFFFFF
            or item.get("needs_save") is not False
        ):
            raise LiveUserReconciliationError("live SEP Catacomb is not clean")
    if len(selected) != 1 or len(masters) != 1:
        raise LiveUserReconciliationError(
            "live SEP Catacomb binding is ambiguous"
        )


def _snapshot_digest(
    components: dict[str, bytes],
    live: dict[str, object],
    apple_uid: int,
    generation: str,
) -> str:
    try:
        digest = hashlib.sha256()
        digest.update(b"t2-user-reconciliation-snapshot-v1\0")
        digest.update(str(apple_uid).encode("ascii") + b"\0")
        digest.update(generation.encode("ascii") + b"\0")
        for name in sorted(components):
            data = components[name]
            if not isinstance(name, str) or not isinstance(data, bytes):
                raise LiveUserReconciliationError(
                    "local Catacomb snapshot has the wrong type"
                )
            digest.update(name.encode("ascii") + b"\0")
            digest.update(hashlib.sha256(data).digest())
        encoded_live = json.dumps(
            live,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        digest.update(hashlib.sha256(encoded_live).digest())
        return digest.hexdigest()
    except (UnicodeError, TypeError, ValueError) as error:
        raise LiveUserReconciliationError(
            "live reconciliation snapshot is not canonical"
        ) from error


class LiveUserReconciliationSession:
    """Own one operation lock and one Bridge generation across both reads."""

    def __init__(
        self,
        *,
        config: Path = CONFIG,
        port_cache: Path = PORT_CACHE,
        store_root: Path = STORE_ROOT,
        operation_lock: Path = OPERATION_LOCK,
    ) -> None:
        if (config, port_cache, store_root, operation_lock) != (
            CONFIG,
            PORT_CACHE,
            STORE_ROOT,
            OPERATION_LOCK,
        ):
            raise LiveUserReconciliationError(
                "live reconciliation paths are fixed by policy"
            )
        self._stack: ExitStack | None = None
        self._lease: t2_bridge_connection.BridgeConnectionLease | None = None
        self._observer: t2_aks_observer.AKSAliasObserver | None = None
        self._generation: str | None = None
        self._first_snapshot_digest: str | None = None

    @property
    def runtime_generation(self) -> str:
        if self._stack is None or self._generation is None:
            raise LiveUserReconciliationError(
                "live reconciliation session is not active"
            )
        return self._generation

    def __enter__(self) -> LiveUserReconciliationSession:
        if os.geteuid() != ROOT_UID or self._stack is not None:
            raise LiveUserReconciliationError(
                "live reconciliation session cannot be entered"
            )
        host, interface, port = _connection_configuration()
        stack = ExitStack()
        try:
            lock = _open_operation_lock()
            stack.callback(os.close, lock)
            lease = stack.enter_context(
                t2_bridge_connection.BridgeConnectionLease.connect(
                    host, interface, port, timeout=10
                )
            )
            try:
                generation = str(uuid.UUID(lease.connection_generation))
            except (AttributeError, TypeError, ValueError) as error:
                raise LiveUserReconciliationError(
                    "Bridge generation is invalid"
                ) from error
            if generation != lease.connection_generation:
                raise LiveUserReconciliationError(
                    "Bridge generation is not canonical"
                )
            self._observer = t2_aks_observer.AKSAliasObserver(
                runtime_generation=generation,
                expected_owner_uid=ROOT_UID,
            )
            self._lease = lease
            self._generation = generation
            self._first_snapshot_digest = None
            self._stack = stack
            return self
        except BaseException:
            stack.close()
            self._observer = None
            self._lease = None
            self._generation = None
            self._first_snapshot_digest = None
            raise

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        stack = self._stack
        self._stack = None
        self._observer = None
        self._lease = None
        self._generation = None
        self._first_snapshot_digest = None
        if stack is not None:
            stack.close()
        return False

    def collect(
        self,
        selected: t2_user_mapping.UserMapping,
        linux_account_generation: str,
        keybag_sha256: str,
    ) -> tuple[
        t2_user_readiness.PersistentEvidence,
        t2_user_readiness.AliasEvidence,
    ]:
        if (
            self._stack is None
            or self._lease is None
            or self._observer is None
            or self._generation is None
        ):
            raise LiveUserReconciliationError(
                "live reconciliation session is not active"
            )
        if not isinstance(selected, t2_user_mapping.UserMapping):
            raise LiveUserReconciliationError("selected mapping has the wrong type")
        try:
            t2_user_mapping._sha256(
                linux_account_generation, "Linux account generation"
            )
            t2_user_mapping._sha256(keybag_sha256, "keybag digest")
        except t2_user_mapping.UserMappingError as error:
            raise LiveUserReconciliationError(
                "host binding evidence is invalid"
            ) from error
        if self._lease.connection_generation != self._generation:
            raise LiveUserReconciliationError(
                "Bridge generation changed before reconciliation"
            )

        store = t2_catacomb_store.CatacombStore(STORE_ROOT, selected.apple_uid)
        before = store.read_committed_components()
        user_name = f"user_{selected.apple_uid:08x}.cat"
        try:
            local = t2_catacomb_codec.decode_user_catacomb(
                before[user_name], selected.apple_uid
            )
            live = t2_bridge_inventory.collect_stable_private_inventory(
                self._lease, selected.apple_uid
            )
            t2_identity_inventory.summarize(local, live)
            _require_clean_catacomb(live, selected.apple_uid)
            alias = self._observer.observe_alias(selected.special_bag_alias)
            after = store.read_committed_components()
        except (
            KeyError,
            t2_aks_observer.AKSAliasObservationError,
            t2_bridge_inventory.BridgeInventoryError,
            t2_catacomb_codec.CatacombCodecError,
            t2_catacomb_store.CatacombStoreError,
            t2_identity_inventory.IdentityInventoryError,
        ) as error:
            raise LiveUserReconciliationError(
                "live Apple, AKS, and Catacomb collection failed"
            ) from error
        if self._lease.connection_generation != self._generation:
            raise LiveUserReconciliationError(
                "Bridge generation changed during reconciliation"
            )
        if after != before:
            raise LiveUserReconciliationError(
                "local Catacomb changed during reconciliation"
            )
        snapshot = _snapshot_digest(
            before,
            live,
            selected.apple_uid,
            self._generation,
        )
        if self._first_snapshot_digest is None:
            self._first_snapshot_digest = snapshot
        elif self._first_snapshot_digest != snapshot:
            raise LiveUserReconciliationError(
                "complete live snapshot changed during reconciliation"
            )
        return (
            t2_user_readiness.PersistentEvidence(
                linux_account_generation,
                keybag_sha256,
                selected.apple_uid,
                local.account_uuid,
                local.keybag_uuid,
                True,
            ),
            alias,
        )
