# SPDX-License-Identifier: GPL-2.0-only
"""Automatic read-only post-reboot proof for one completed mutation."""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import t2_enrollment_journal
import t2_enrollment_reconciliation
import t2_catacomb_codec
import t2_identity_delete_journal
import t2_identity_delete_reconciliation
import t2_identity_rename_journal
import t2_identity_rename_reconciliation
import t2_linux_account
import t2_mutation_journal
import t2_mutation_registry
import t2_system_credential
import t2_user_mapping
import t2_user_mapping_admin
import t2_user_readiness
import t2_user_reconciliation_live


MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")
MAPPING_PATH = t2_user_mapping_admin.DEFAULT_MAPPING_PATH
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
JOURNAL_NAME = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12}\.jsonl\Z"
)
ROOT_UID = 0


class PostRebootReconcilerError(RuntimeError):
    pass


@dataclass(frozen=True)
class PostRebootReconcilerResult:
    state: str
    journal_updated: bool

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "journal_updated": self.journal_updated,
            "fingerprint_mutation_performed": False,
            "identifiers_redacted": True,
        }


@dataclass(frozen=True, repr=False)
class PendingMutation:
    kind: str
    capability: str
    path: Path
    history: object = field(repr=False)


def _boot_id() -> str:
    try:
        first = BOOT_ID.read_text(encoding="ascii").strip()
        second = BOOT_ID.read_text(encoding="ascii").strip()
        parsed = uuid.UUID(first)
    except (OSError, UnicodeError, ValueError, AttributeError) as error:
        raise PostRebootReconcilerError(
            "Linux boot identity is unavailable"
        ) from error
    if first != second or str(parsed) != first or parsed.int == 0:
        raise PostRebootReconcilerError(
            "Linux boot identity is unstable or invalid"
        )
    return first


def _pending_candidate() -> PendingMutation | None:
    try:
        entries = t2_mutation_registry.scan(MUTATION_ROOT)
        candidates = []
        for path in sorted(MUTATION_ROOT.iterdir(), key=lambda item: item.name):
            if JOURNAL_NAME.fullmatch(path.name) is None:
                raise PostRebootReconcilerError(
                    "mutation journal directory contains an unsafe entry"
                )
            records = t2_mutation_journal.read(path)
            evidence = records[0].get("evidence") if records else None
            if not isinstance(evidence, dict):
                raise PostRebootReconcilerError(
                    "mutation journal has no typed baseline"
                )
            operation_kind = evidence.get("operation_kind")
            if operation_kind == "rename":
                history = t2_identity_rename_journal.validate_history(records)
                if (
                    history.phase
                    is t2_identity_rename_journal.IdentityRenamePhase.RECONCILED
                ):
                    candidates.append(
                        PendingMutation(
                            "rename", "identity-management", path, history
                        )
                    )
            elif operation_kind == "delete-one":
                history = t2_identity_delete_journal.validate_history(records)
                if (
                    history.phase
                    is t2_identity_delete_journal.IdentityDeletePhase.RECONCILED
                ):
                    candidates.append(
                        PendingMutation(
                            "delete-one",
                            "identity-management",
                            path,
                            history,
                        )
                    )
            elif operation_kind == "enroll":
                history = t2_enrollment_journal.validate_history(records)
                if (
                    history.phase
                    is t2_enrollment_journal.EnrollmentPhase.RECONCILED
                    and history.terminal_identity_uuid is not None
                ):
                    candidates.append(
                        PendingMutation("enroll", "enroll", path, history)
                    )
            else:
                continue
    except PostRebootReconcilerError:
        raise
    except (
        OSError,
        t2_mutation_registry.MutationRegistryError,
        t2_mutation_journal.JournalError,
        t2_enrollment_journal.EnrollmentJournalError,
        t2_identity_delete_journal.IdentityDeleteJournalError,
        t2_identity_rename_journal.IdentityRenameJournalError,
    ) as error:
        raise PostRebootReconcilerError(
            "mutation journal inventory is invalid"
        ) from error
    if len(candidates) > 1:
        raise PostRebootReconcilerError(
            "multiple mutation journals await post-reboot verification"
        )
    if candidates and sum(entry.blocks_new_mutation for entry in entries) != 1:
        raise PostRebootReconcilerError(
            "another biometric mutation is unfinished"
        )
    return candidates[0] if candidates else None


def _select_mapping(
    mapping_set: t2_user_mapping.UserMappingSet,
    candidate: PendingMutation,
) -> t2_user_mapping.UserMapping:
    history = candidate.history
    baseline = history.baseline
    linux_uid = baseline["target_linux_uid"]
    try:
        selected = mapping_set.resolve(linux_uid, candidate.capability)
    except t2_user_mapping.UserMappingError as error:
        raise PostRebootReconcilerError(
            "post-reboot mapping is absent or disabled"
        ) from error
    if (
        baseline["caller_linux_uid"] != linux_uid
        or baseline["mapping_generation"] != mapping_set.generation
        or baseline["apple_uid"] != selected.apple_uid
        or baseline["account_uuid"] != selected.account_uuid
        or baseline["bag_uuid"] != selected.bag_uuid
    ):
        raise PostRebootReconcilerError(
            "post-reboot journal belongs to another protected mapping"
        )
    return selected


def _unchanged_history(candidate: PendingMutation) -> None:
    expected = candidate.history
    try:
        readers = {
            "enroll": t2_enrollment_journal.read,
            "rename": t2_identity_rename_journal.read,
            "delete-one": t2_identity_delete_journal.read,
        }
        current = readers[candidate.kind](candidate.path)
    except (
        KeyError,
        t2_enrollment_journal.EnrollmentJournalError,
        t2_identity_delete_journal.IdentityDeleteJournalError,
        t2_identity_rename_journal.IdentityRenameJournalError,
    ) as error:
        raise PostRebootReconcilerError(
            "post-reboot journal changed or became invalid"
        ) from error
    if (
        current.operation_id != expected.operation_id
        or current.phase is not expected.phase
        or current.record_count != expected.record_count
        or current.head_hash != expected.head_hash
        or current.baseline != expected.baseline
    ):
        raise PostRebootReconcilerError(
            "post-reboot journal changed during reconciliation"
        )


def run(
    *,
    live_factory=t2_user_reconciliation_live.LiveUserReconciliationSession,
    account_collector=t2_linux_account.collect,
    keybag_reader=t2_user_mapping_admin._keybag_digest,
    runtime_state=t2_system_credential._runtime_state,
    boot_reader=_boot_id,
) -> PostRebootReconcilerResult:
    """Append only a typed proof after a fresh boot reproduces committed state."""

    if os.geteuid() != ROOT_UID:
        raise PostRebootReconcilerError(
            "post-reboot reconciliation requires root"
        )
    if not all(
        callable(item)
        for item in (
            live_factory,
            account_collector,
            keybag_reader,
            runtime_state,
            boot_reader,
        )
    ):
        raise PostRebootReconcilerError(
            "post-reboot reconciliation dependency is unavailable"
        )
    candidate = _pending_candidate()
    if candidate is None:
        return PostRebootReconcilerResult("no-pending-mutation", False)
    journal_path = candidate.path
    history = candidate.history

    directory = -1
    mapping_lock = -1
    try:
        directory, name = t2_user_mapping_admin._open_parent(MAPPING_PATH)
        mapping_lock = t2_user_mapping_admin._open_lock(directory, name)
        mapping_set = t2_user_mapping_admin._load_optional(directory, name)
        if mapping_set is None:
            raise PostRebootReconcilerError(
                "protected mapping does not exist"
            )
        selected = _select_mapping(mapping_set, candidate)
        account = account_collector(selected.linux_uid)
        expected_account = t2_linux_account.AccountEvidence(
            selected.linux_uid, selected.linux_account_generation
        )
        if account != expected_account:
            raise PostRebootReconcilerError(
                "Linux account changed before post-reboot reconciliation"
            )
        keybag_sha256 = keybag_reader(Path(selected.keybag_path))
        if keybag_sha256 != selected.keybag_sha256:
            raise PostRebootReconcilerError(
                "keybag changed before post-reboot reconciliation"
            )
        runtime = runtime_state(selected.special_bag_alias)
        if (
            type(runtime) is not tuple
            or len(runtime) != 2
            or runtime[0] != 1
            or type(runtime[1]) is not int
            or not 0 < runtime[1] <= (1 << 31) - 1
        ):
            raise PostRebootReconcilerError(
                "runtime keybag state is invalid"
            )
        _session, positive_handle = runtime
        boot_uuid = boot_reader()

        manager = live_factory()
        if not hasattr(manager, "__enter__") or not hasattr(
            manager, "__exit__"
        ):
            raise PostRebootReconcilerError(
                "live post-reboot session has the wrong type"
            )
        with manager as live:
            first = live.collect(
                selected, account.generation, keybag_sha256
            )
            second = live.collect(
                selected, account.generation, keybag_sha256
            )
            if first != second:
                raise PostRebootReconcilerError(
                    "live post-reboot evidence is unstable"
                )
            try:
                readiness = t2_user_readiness.assess(
                    selected, candidate.capability, *first
                )
            except t2_user_readiness.UserReadinessError as error:
                raise PostRebootReconcilerError(
                    "post-reboot readiness evidence is invalid"
                ) from error
            if (
                readiness.state != "ready"
                or readiness.operation_permitted is not True
                or readiness.match_ready is not True
                or readiness.quarantine is not False
            ):
                raise PostRebootReconcilerError(
                    "mapped keybag is not ready for post-reboot verification"
                )
            if live.revalidate_runtime_keybag(
                selected, positive_handle
            ) is not True:
                raise PostRebootReconcilerError(
                    "runtime keybag was not revalidated"
                )
            material = live.prepare_post_reboot_material(
                selected, history.baseline
            )
            if (
                not isinstance(
                    material,
                    t2_user_reconciliation_live.PostRebootMaterial,
                )
                or material.apple_uid != selected.apple_uid
                or material.connection_generation != live.runtime_generation
                or not isinstance(
                    material.local, t2_catacomb_codec.UserCatacomb
                )
                or material.local.expected_user_id != selected.apple_uid
            ):
                raise PostRebootReconcilerError(
                    "post-reboot material is inconsistent"
                )
            _unchanged_history(candidate)
            current_mapping = t2_user_mapping_admin._load_optional(
                directory, name
            )
            if current_mapping != mapping_set:
                raise PostRebootReconcilerError(
                    "protected mapping changed during reconciliation"
                )
            if account_collector(selected.linux_uid) != account:
                raise PostRebootReconcilerError(
                    "Linux account changed during reconciliation"
                )
            if keybag_reader(Path(selected.keybag_path)) != keybag_sha256:
                raise PostRebootReconcilerError(
                    "keybag changed during reconciliation"
            )
            if candidate.kind == "enroll":
                verified = (
                    t2_enrollment_reconciliation.append_post_reboot_verified(
                        journal_path,
                        history.operation_id,
                        host=material.host,
                        live=material.live,
                        linux_boot_uuid=boot_uuid,
                        mapping_generation=mapping_set.generation,
                        keybag_runtime_revalidated=True,
                    )
                )
                expected_phase = (
                    t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
                )
            elif candidate.kind == "rename":
                verified = (
                    t2_identity_rename_reconciliation.append_post_reboot_verified(
                        journal_path,
                        history.operation_id,
                        local=material.local,
                        host=material.host,
                        live=material.live,
                        linux_boot_uuid=boot_uuid,
                        mapping_generation=mapping_set.generation,
                    )
                )
                expected_phase = (
                    t2_identity_rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED
                )
            elif candidate.kind == "delete-one":
                verified = (
                    t2_identity_delete_reconciliation.append_post_reboot_verified(
                        journal_path,
                        history.operation_id,
                        local=material.local,
                        host=material.host,
                        live=material.live,
                        linux_boot_uuid=boot_uuid,
                        mapping_generation=mapping_set.generation,
                    )
                )
                expected_phase = (
                    t2_identity_delete_journal.IdentityDeletePhase.POST_REBOOT_VERIFIED
                )
            else:
                raise PostRebootReconcilerError(
                    "post-reboot mutation kind is unsupported"
                )
        if verified.phase is not expected_phase:
            raise PostRebootReconcilerError(
                "post-reboot verification did not reach its terminal proof"
            )
        return PostRebootReconcilerResult(
            f"{candidate.kind}-post-reboot-verified", True
        )
    except PostRebootReconcilerError:
        raise
    except (
        OSError,
        t2_enrollment_reconciliation.EnrollmentReconciliationError,
        t2_identity_delete_reconciliation.IdentityDeleteReconciliationError,
        t2_identity_rename_reconciliation.IdentityRenameReconciliationError,
        t2_linux_account.LinuxAccountError,
        t2_system_credential.SystemCredentialError,
        t2_user_mapping_admin.UserMappingAdminError,
        t2_user_reconciliation_live.LiveUserReconciliationError,
    ) as error:
        raise PostRebootReconcilerError(
            "automatic post-reboot reconciliation stopped"
        ) from error
    except Exception as error:
        raise PostRebootReconcilerError(
            "automatic post-reboot reconciliation stopped"
        ) from error
    finally:
        if mapping_lock >= 0:
            os.close(mapping_lock)
        if directory >= 0:
            os.close(directory)
