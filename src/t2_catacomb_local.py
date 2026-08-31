# SPDX-License-Identifier: GPL-2.0-only
"""Provision and verify the private Linux-local Catacomb store from a backup."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path

import t2_baseline
import t2_catacomb_store


class LocalCatacombError(RuntimeError):
    pass


MAX_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_COMPONENT_SIZE = 1024 * 1024


def _expected_names(apple_user_id: int) -> set[str]:
    if type(apple_user_id) is not int or not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise LocalCatacombError("Apple user ID is invalid")
    return {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }


def read_backup_components(
    archive_path: Path, apple_user_id: int
) -> tuple[dict[str, object], dict[str, bytes]]:
    """Read the exact component set after the independent baseline parser."""
    if not isinstance(archive_path, Path):
        raise LocalCatacombError("backup path must be a typed Path")
    try:
        info = archive_path.stat(follow_symlinks=False)
    except OSError as error:
        raise LocalCatacombError("Catacomb backup is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or not 0 < info.st_size <= MAX_ARCHIVE_SIZE
    ):
        raise LocalCatacombError("Catacomb backup is not private and caller-owned")
    try:
        host = t2_baseline.read_host_archive(archive_path, apple_user_id)
    except t2_baseline.BaselineError as error:
        raise LocalCatacombError("Catacomb backup baseline is invalid") from error

    expected = _expected_names(apple_user_id)
    components: dict[str, bytes] = {}
    try:
        archive = tarfile.open(archive_path, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise LocalCatacombError("Catacomb backup cannot be opened") from error
    with archive:
        for member in archive.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name not in expected:
                continue
            if (
                name in components
                or not member.isfile()
                or not 0 < member.size <= MAX_COMPONENT_SIZE
            ):
                raise LocalCatacombError("Catacomb backup component is unsafe")
            stream = archive.extractfile(member)
            if stream is None:
                raise LocalCatacombError("Catacomb backup component cannot be read")
            data = stream.read(MAX_COMPONENT_SIZE + 1)
            if len(data) != member.size:
                raise LocalCatacombError("Catacomb backup component changed length")
            components[name] = data
    if set(components) != expected:
        raise LocalCatacombError("Catacomb backup component set is incomplete")
    expected_hashes = {
        record["name"]: record["sha256"] for record in host["host_components"]
    }
    if {
        name: hashlib.sha256(data).hexdigest()
        for name, data in components.items()
    } != expected_hashes:
        raise LocalCatacombError("Catacomb backup hashes changed between parsers")
    return host, components


def _require_private_parent(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise LocalCatacombError("Catacomb store parent is not private")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_component(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise LocalCatacombError("short local Catacomb write")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def provision_from_backup(
    archive_path: Path, store_root: Path, apple_user_id: int
) -> tuple[dict[str, object], t2_catacomb_store.CatacombStore]:
    """Create once, or prove an existing store is byte-equal to the backup."""
    if not isinstance(store_root, Path) or store_root.name in ("", ".", ".."):
        raise LocalCatacombError("local Catacomb path is invalid")
    host, components = read_backup_components(archive_path, apple_user_id)
    _require_private_parent(store_root.parent)
    if os.path.lexists(store_root):
        try:
            store = t2_catacomb_store.CatacombStore(store_root, apple_user_id)
            if store.read_committed_components() != components:
                raise LocalCatacombError(
                    "existing local Catacomb differs from the selected backup"
                )
        except t2_catacomb_store.CatacombStoreError as error:
            raise LocalCatacombError("existing local Catacomb is invalid") from error
        return host, store

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{store_root.name}.provision-", dir=store_root.parent)
    )
    temporary.chmod(0o700)
    promoted = False
    try:
        for name in sorted(components):
            _write_component(temporary / name, components[name])
        _sync_directory(temporary)
        try:
            store = t2_catacomb_store.CatacombStore(temporary, apple_user_id)
            if store.read_committed_components() != components:
                raise LocalCatacombError("local Catacomb verification changed content")
        except t2_catacomb_store.CatacombStoreError as error:
            raise LocalCatacombError("provisioned local Catacomb is invalid") from error
        os.rename(temporary, store_root)
        promoted = True
        _sync_directory(store_root.parent)
        return host, t2_catacomb_store.CatacombStore(store_root, apple_user_id)
    finally:
        if not promoted and temporary.parent == store_root.parent:
            shutil.rmtree(temporary)
