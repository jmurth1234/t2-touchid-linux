# SPDX-License-Identifier: GPL-2.0-only
"""Materialize an immutable pre-mutation backup from the local Catacomb store."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import t2_baseline
import t2_catacomb_store


MAX_ARCHIVE_SIZE = 16 * 1024 * 1024


class RecoveryAnchorError(RuntimeError):
    """Raised when a durable local recovery anchor cannot be proven."""


@dataclass(frozen=True, repr=False)
class RecoveryAnchor:
    path: Path = field(repr=False)
    reference: str
    sha256: str
    host_inventory: dict[str, object] = field(repr=False)

    def __repr__(self) -> str:
        return (
            "RecoveryAnchor(reference="
            f"{self.reference!r}, sha256={self.sha256!r}, private=True)"
        )


def _require_operation_id(value: object) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise RecoveryAnchorError("recovery anchor operation ID is invalid") from error
    canonical = str(parsed)
    if value != canonical or parsed.int == 0:
        raise RecoveryAnchorError("recovery anchor operation ID is invalid")
    return canonical


def _require_private_directory(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise RecoveryAnchorError("recovery anchor directory is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise RecoveryAnchorError(
            "recovery anchor directory is not private and caller-owned"
        )


def _require_private_archive(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise RecoveryAnchorError("recovery anchor is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 0 < info.st_size <= MAX_ARCHIVE_SIZE
    ):
        raise RecoveryAnchorError(
            "recovery anchor is not a private caller-owned regular file"
        )


def _source_metadata(components: dict[str, bytes]) -> bytes:
    return b"".join(
        (
            f"-rw------- root:wheel {len(components[name])} 0 "
            f"/var/lib/t2-touchid/catacomb/{name}\n"
        ).encode("ascii")
        for name in sorted(components)
    )


def _write_tar(stream: io.BufferedWriter, components: dict[str, bytes]) -> None:
    members = {**components, "source-stat.txt": _source_metadata(components)}
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(members):
            data = members[name]
            info = tarfile.TarInfo(f"local-catacomb/{name}")
            info.size = len(data)
            info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "wheel"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))


def _component_hashes(components: dict[str, bytes]) -> dict[str, str]:
    return {
        name: hashlib.sha256(data).hexdigest()
        for name, data in components.items()
    }


def _validate(
    path: Path,
    apple_user_id: int,
    components: dict[str, bytes],
) -> RecoveryAnchor:
    _require_private_archive(path)
    try:
        host = t2_baseline.read_host_archive(path, apple_user_id)
        archive_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, t2_baseline.BaselineError) as error:
        raise RecoveryAnchorError("recovery anchor validation failed") from error
    expected_hashes = _component_hashes(components)
    observed_hashes = {
        item["name"]: item["sha256"] for item in host["host_components"]
    }
    if (
        observed_hashes != expected_hashes
        or host.get("archive_sha256") != archive_sha256
    ):
        raise RecoveryAnchorError("recovery anchor differs from the local store")
    return RecoveryAnchor(
        path,
        f"recovery-anchors/{path.name}",
        archive_sha256,
        host,
    )


def materialize(
    store: t2_catacomb_store.CatacombStore,
    anchor_root: Path,
    operation_id: str,
) -> RecoveryAnchor:
    """Create once and verify an exact backup while the caller holds its lock."""

    if not isinstance(store, t2_catacomb_store.CatacombStore):
        raise RecoveryAnchorError("recovery anchor requires a Catacomb store")
    if not isinstance(anchor_root, Path):
        raise RecoveryAnchorError("recovery anchor root must be a typed Path")
    operation_id = _require_operation_id(operation_id)
    _require_private_directory(anchor_root)
    try:
        before = store.read_committed_components()
    except t2_catacomb_store.CatacombStoreError as error:
        raise RecoveryAnchorError("local Catacomb is not committed") from error

    destination = anchor_root / f"{operation_id}.tar"
    temporary: Path | None = None
    published = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".anchor-", suffix=".tmp", dir=anchor_root
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            _write_tar(stream, before)
            stream.flush()
            os.fsync(stream.fileno())
        if temporary.stat().st_size > MAX_ARCHIVE_SIZE:
            raise RecoveryAnchorError("recovery anchor exceeds its size limit")
        try:
            os.link(temporary, destination, follow_symlinks=False)
            published = True
        except FileExistsError:
            pass
        temporary.unlink()
        temporary = None
        directory = os.open(
            anchor_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        anchor = _validate(destination, store.apple_uid, before)
        try:
            after = store.read_committed_components()
        except t2_catacomb_store.CatacombStoreError as error:
            raise RecoveryAnchorError(
                "local Catacomb changed after recovery anchoring"
            ) from error
        if after != before:
            raise RecoveryAnchorError(
                "local Catacomb changed while recovery anchor was written"
            )
        return anchor
    except RecoveryAnchorError:
        if published:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    except (OSError, tarfile.TarError) as error:
        if published:
            try:
                destination.unlink()
            except OSError:
                pass
        raise RecoveryAnchorError("recovery anchor creation failed") from error
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
