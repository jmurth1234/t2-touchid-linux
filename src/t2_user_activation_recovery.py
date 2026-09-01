# SPDX-License-Identifier: GPL-2.0-only
"""Read-only reconciliation for one outcome-unknown user activation."""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import t2_mutation_journal
import t2_user_activation_journal as activation_journal
import t2_user_mapping
import t2_user_readiness


class UserActivationRecoveryError(RuntimeError):
    pass


class UserActivationRecoveryObserver(Protocol):
    runtime_generation: str

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence: ...


@dataclass(frozen=True)
class UserActivationRecoveryResult:
    resolution: str
    readiness_state: str
    mutation_performed: bool = False


def _mapping_matches(
    history: activation_journal.UserActivationHistory,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
) -> bool:
    baseline = history.baseline
    return (
        mapping_set.generation == baseline["mapping_generation"]
        and selected in mapping_set.mappings
        and selected.linux_uid == baseline["target_linux_uid"]
        and selected.apple_uid == baseline["apple_uid"]
        and selected.account_uuid == baseline["account_uuid"]
        and selected.bag_uuid == baseline["bag_uuid"]
        and selected.keybag_sha256 == baseline["keybag_sha256"]
        and selected.special_bag_alias == baseline["special_alias"]
        and selected.permits(baseline["capability"])
    )


def recover(
    path: Path,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    persistent: t2_user_readiness.PersistentEvidence,
    observer: UserActivationRecoveryObserver,
) -> UserActivationRecoveryResult:
    history = activation_journal.read(path)
    if (
        history.phase is not activation_journal.UserActivationPhase.OUTCOME_UNKNOWN
        or history.terminal_from_phase is None
    ):
        raise UserActivationRecoveryError(
            "activation journal is not an outcome-unknown recovery candidate"
        )
    try:
        t2_mutation_journal.require_uuid(
            observer.runtime_generation, "recovery runtime generation"
        )
    except t2_mutation_journal.JournalError as error:
        raise UserActivationRecoveryError(str(error)) from error
    if observer.runtime_generation == history.baseline["runtime_generation"]:
        raise UserActivationRecoveryError(
            "activation recovery requires a fresh runtime generation"
        )
    try:
        mapping_matches = _mapping_matches(history, mapping_set, selected)
    except t2_user_mapping.UserMappingError as error:
        raise UserActivationRecoveryError(str(error)) from error
    if not mapping_matches:
        raise UserActivationRecoveryError(
            "protected mapping changed since activation intent"
        )
    try:
        observed = observer.observe_alias(selected.special_bag_alias)
        if inspect.isawaitable(observed):
            close = getattr(observed, "close", None)
            if callable(close):
                close()
            raise UserActivationRecoveryError(
                "activation recovery observation must be synchronous"
            )
        if not isinstance(observed, t2_user_readiness.AliasEvidence):
            raise UserActivationRecoveryError(
                "activation recovery observation has the wrong type"
            )
        decision = t2_user_readiness.assess(
            selected, history.baseline["capability"], persistent, observed
        )
    except UserActivationRecoveryError:
        raise
    except BaseException as error:
        raise UserActivationRecoveryError(
            "activation recovery could not obtain trustworthy read-back"
        ) from error

    early = history.terminal_from_phase in {
        activation_journal.UserActivationPhase.LOAD_INTENT,
        activation_journal.UserActivationPhase.HANDLE_OBSERVED,
    }
    if decision.state == "alias-absent":
        resolution = "blocked"
    elif decision.state in {
        "persistent-binding-mismatch",
        "alias-binding-mismatch",
        "unknown-lock-state",
        "catacomb-corrupted",
        "capability-denied",
    }:
        resolution = "quarantine"
    elif early:
        # A load/handle-stage operation never dispatched bind.  A newly present
        # alias cannot be attributed to this operation and is not accepted.
        resolution = "quarantine"
    elif decision.state == "ready":
        resolution = "ready"
    elif decision.state in {
        "device-locked",
        "before-first-unlock",
        "keybag-lockout",
    }:
        resolution = "not-ready"
    else:
        resolution = "quarantine"

    alias_present = observed.present
    bag_uuid_matches = bool(
        observed.present and observed.bag_uuid == selected.bag_uuid
    )
    account_uuid_matches = bool(
        observed.present and observed.account_uuid == selected.account_uuid
    )
    activation_journal.append_checked(
        path,
        history.operation_id,
        "USER_ACTIVATION_RECOVERY_OBSERVED",
        {
            "runtime_generation": observer.runtime_generation,
            "resolution": resolution,
            "readiness_state": decision.state,
            "alias_present": alias_present,
            "bag_uuid_matches": bag_uuid_matches,
            "account_uuid_matches": account_uuid_matches,
            "match_ready": resolution == "ready",
            "mutation_performed": False,
        },
    )
    return UserActivationRecoveryResult(resolution, decision.state)
