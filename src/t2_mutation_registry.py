# SPDX-License-Identifier: GPL-2.0-only
"""Route shared private mutation journals to their typed state machines."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import t2_enrollment_journal
import t2_identity_rename_journal
import t2_mutation_journal


class MutationRegistryError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class MutationEntry:
    kind: str
    phase: str
    blocks_new_mutation: bool
    post_reboot_pending: bool

    def __repr__(self) -> str:
        return (
            "MutationEntry(kind="
            f"{self.kind!r}, phase={self.phase!r}, "
            f"blocks_new_mutation={self.blocks_new_mutation}, "
            f"post_reboot_pending={self.post_reboot_pending})"
        )


def _private_directory(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise MutationRegistryError("mutation journal directory is unsafe")


def _enrollment_entry(records) -> MutationEntry:
    try:
        history = t2_enrollment_journal.validate_history(records)
    except t2_enrollment_journal.EnrollmentJournalError as error:
        raise MutationRegistryError("enrollment journal is invalid") from error
    phase = history.phase
    post_reboot = (
        phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
        and history.terminal_identity_uuid is not None
    )
    complete = (
        phase
        in {
            t2_enrollment_journal.EnrollmentPhase.ABORTED_BEFORE_START,
            t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED,
        }
        or (
            phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
            and history.terminal_identity_uuid is None
        )
    )
    return MutationEntry("enroll", phase.value, not complete, post_reboot)


def _rename_entry(records) -> MutationEntry:
    try:
        history = t2_identity_rename_journal.validate_history(records)
    except t2_identity_rename_journal.IdentityRenameJournalError as error:
        raise MutationRegistryError("rename journal is invalid") from error
    phase = history.phase
    post_reboot = phase is t2_identity_rename_journal.IdentityRenamePhase.RECONCILED
    complete = phase in {
        t2_identity_rename_journal.IdentityRenamePhase.ABORTED,
        t2_identity_rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED,
    }
    return MutationEntry("rename", phase.value, not complete, post_reboot)


def scan(root: Path) -> tuple[MutationEntry, ...]:
    if not isinstance(root, Path):
        raise MutationRegistryError("mutation journal root is not a path")
    _private_directory(root)
    result = []
    for path in sorted(root.iterdir(), key=lambda value: value.name):
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl",
            path.name,
        ) or not t2_mutation_journal.secure_regular_file(path):
            raise MutationRegistryError("mutation journal entry is unsafe")
        try:
            records = t2_mutation_journal.read(path)
        except t2_mutation_journal.JournalError as error:
            raise MutationRegistryError("mutation journal is invalid") from error
        if not records:
            raise MutationRegistryError("mutation journal is empty")
        evidence = records[0].get("evidence")
        kind = evidence.get("operation_kind") if isinstance(evidence, dict) else None
        if kind == "enroll":
            result.append(_enrollment_entry(records))
        elif kind == "rename":
            result.append(_rename_entry(records))
        elif kind in {"delete-one", "delete-batch", "recovery"}:
            # No typed completion state exists yet, so these are conservatively
            # owned by their future broker and always block another mutation.
            result.append(MutationEntry(kind, "unrouted", True, False))
        else:
            raise MutationRegistryError("mutation journal kind is unsupported")
    return tuple(result)


def blocks_new_mutation(root: Path, *, excluding_kind: str | None = None) -> bool:
    return any(
        entry.blocks_new_mutation
        and (excluding_kind is None or entry.kind != excluding_kind)
        for entry in scan(root)
    )

