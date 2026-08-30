#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Crash-recoverable Linux-local Catacomb component staging.

This mirrors the recovered 24G830 host transaction direction: ``prepare/``
has not crossed the commit boundary and is discard-only; ``commit/`` has
crossed it and is roll-forward-only.  SEP reconciliation remains a separate
required milestone after host recovery.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Callable

from t2_catacomb_codec import (
    CatacombCodecError,
    decode_biolockout_catacomb,
    decode_master_catacomb,
    decode_user_catacomb,
)


class CatacombStoreError(RuntimeError):
    pass


FailureHook = Callable[[str], None]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def component_names(apple_uid: int) -> set[str]:
    if not isinstance(apple_uid, int) or isinstance(apple_uid, bool) or not 0 <= apple_uid <= 0xFFFFFFFF:
        raise CatacombStoreError("Apple UID is invalid")
    return {"master.cat", "biolockout.cat", f"user_{apple_uid:08x}.cat"}


def validate_component(name: str, data: bytes, apple_uid: int) -> None:
    if name == "master.cat":
        decode_master_catacomb(data)
    elif name == "biolockout.cat":
        decode_biolockout_catacomb(data)
    elif name == f"user_{apple_uid:08x}.cat":
        decode_user_catacomb(data, apple_uid)
    else:
        raise CatacombStoreError(f"unexpected Catacomb component name: {name}")


class CatacombStore:
    def __init__(self, root: Path, apple_uid: int) -> None:
        self.root = root
        self.apple_uid = apple_uid
        self.allowed_names = component_names(apple_uid)
        self._require_private_directory(root)

    @staticmethod
    def _require_private_directory(path: Path) -> None:
        try:
            info = path.stat(follow_symlinks=False)
        except FileNotFoundError as error:
            raise CatacombStoreError(f"Catacomb directory does not exist: {path}") from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise CatacombStoreError("Catacomb directory is not private and caller-owned")

    def _sync_directory(self, path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_exclusive(self, path: Path, data: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise CatacombStoreError("short Catacomb component write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def stage(self, components: dict[str, bytes], hook: FailureHook | None = None) -> dict[str, str]:
        if not components or not set(components) <= self.allowed_names:
            raise CatacombStoreError("staged component set is empty or invalid")
        if os.path.lexists(self.root / "prepare") or os.path.lexists(self.root / "commit"):
            raise CatacombStoreError("an incomplete Catacomb transaction already exists")
        for name, data in components.items():
            try:
                validate_component(name, data, self.apple_uid)
            except CatacombCodecError as error:
                raise CatacombStoreError(f"invalid staged {name}: {error}") from error
        prepare = self.root / "prepare"
        prepare.mkdir(mode=0o700)
        self._sync_directory(self.root)
        if hook:
            hook("prepare_created")
        for name in sorted(components):
            self._write_exclusive(prepare / name, components[name])
            if hook:
                hook(f"component_written:{name}")
        self._sync_directory(prepare)
        if hook:
            hook("prepare_synced")
        return {name: sha256(data) for name, data in components.items()}

    def _read_regular(self, path: Path) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise CatacombStoreError(
                f"unsafe Catacomb transaction file: {path.name}"
            ) from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or info.st_size > 1024 * 1024
            ):
                raise CatacombStoreError(f"unsafe Catacomb transaction file: {path.name}")
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 65536))
                if not chunk:
                    raise CatacombStoreError(f"short read from {path.name}")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def _directory_entries(self, path: Path) -> set[str]:
        self._require_private_directory(path)
        names = set()
        with os.scandir(path) as entries:
            for entry in entries:
                if not re.fullmatch(r"(?:master|biolockout|user_[0-9a-f]{8})\.cat", entry.name):
                    raise CatacombStoreError(f"unexpected transaction entry: {entry.name}")
                names.add(entry.name)
        return names

    def _validate_prepare(self, expected: dict[str, str]) -> None:
        path = self.root / "prepare"
        names = self._directory_entries(path)
        if names != set(expected) or not names <= self.allowed_names:
            raise CatacombStoreError("prepare component set does not match journal")
        for name in sorted(names):
            data = self._read_regular(path / name)
            if sha256(data) != expected[name]:
                raise CatacombStoreError(f"prepare hash mismatch for {name}")
            validate_component(name, data, self.apple_uid)

    def _validate_commit(self, expected: dict[str, str]) -> set[str]:
        path = self.root / "commit"
        remaining = self._directory_entries(path)
        if not remaining <= set(expected) or not set(expected) <= self.allowed_names:
            raise CatacombStoreError("commit component set does not match journal")
        for name in sorted(expected):
            candidate = path / name if name in remaining else self.root / name
            data = self._read_regular(candidate)
            if sha256(data) != expected[name]:
                raise CatacombStoreError(f"committed hash mismatch for {name}")
            validate_component(name, data, self.apple_uid)
        return remaining

    def cross_commit_boundary(self, expected: dict[str, str], hook: FailureHook | None = None) -> None:
        self._validate_prepare(expected)
        os.rename(self.root / "prepare", self.root / "commit")
        if hook:
            hook("prepare_renamed_to_commit")
        self._roll_forward(expected, hook)

    def _roll_forward(self, expected: dict[str, str], hook: FailureHook | None = None) -> None:
        commit = self.root / "commit"
        remaining = self._validate_commit(expected)
        for name in sorted(remaining):
            source = commit / name
            destination = self.root / name
            if os.path.lexists(destination):
                old = self._read_regular(destination)
                validate_component(name, old, self.apple_uid)
                destination.unlink()
                if hook:
                    hook(f"root_unlinked:{name}")
            os.rename(source, destination)
            if hook:
                hook(f"component_promoted:{name}")
        commit.rmdir()
        self._sync_directory(self.root)
        if hook:
            hook("root_synced")

    def recover(self, expected: dict[str, str], hook: FailureHook | None = None) -> str:
        prepare = self.root / "prepare"
        commit = self.root / "commit"
        action = "clean"
        if os.path.lexists(prepare):
            self._validate_prepare(expected)
            for name in sorted(expected):
                (prepare / name).unlink()
                if hook:
                    hook(f"prepare_unlinked:{name}")
            prepare.rmdir()
            self._sync_directory(self.root)
            action = "prepare-discarded"
        if os.path.lexists(commit):
            self._roll_forward(expected, hook)
            action = "commit-rolled-forward"
        return action
