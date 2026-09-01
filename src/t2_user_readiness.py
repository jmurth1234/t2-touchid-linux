# SPDX-License-Identifier: GPL-2.0-only
"""Pure per-user AKS/Catacomb readiness classifier.

The classifier consumes already-collected evidence and emits no AKS, SEP,
Catacomb, keybag, or filesystem operation.  It is the policy boundary future
runtime code must pass before selecting an Apple user for biometric work.
"""

from __future__ import annotations

from dataclasses import dataclass

import t2_user_mapping


DEVICE_LOCKED = 1 << 0
PASSCODE_LOCKOUT = 1 << 1
BIO_LOCKOUT = 1 << 2
UNLOCK_TOKEN_PRESENT = 1 << 3
BEFORE_FIRST_UNLOCK = 1 << 4
PASSCODE_VALIDATED = 1 << 5
IDENTIFICATION_LOCKOUT = 1 << 6
CATACOMB_CORRUPTED = 1 << 7
APPLE_PAY_TOKEN_PRESENT = 1 << 9
REMOTE_UNLOCKED = 1 << 10
KNOWN_LOCK_STATE_BITS = (
    DEVICE_LOCKED
    | PASSCODE_LOCKOUT
    | BIO_LOCKOUT
    | UNLOCK_TOKEN_PRESENT
    | BEFORE_FIRST_UNLOCK
    | PASSCODE_VALIDATED
    | IDENTIFICATION_LOCKOUT
    | CATACOMB_CORRUPTED
    | APPLE_PAY_TOKEN_PRESENT
    | REMOTE_UNLOCKED
)


class UserReadinessError(ValueError):
    """Raised when readiness evidence is malformed rather than merely unready."""


@dataclass(frozen=True)
class PersistentEvidence:
    linux_account_generation: str
    keybag_sha256: str
    catacomb_user_id: int
    account_uuid: str
    bag_uuid: str
    catacomb_reconciled: bool


@dataclass(frozen=True, repr=False)
class AliasEvidence:
    present: bool
    special_alias: int | None
    bag_uuid: str | None
    lock_state: int | None
    account_uuid: str | None


@dataclass(frozen=True)
class ReadinessDecision:
    state: str
    next_step: str
    operation_permitted: bool
    match_ready: bool
    quarantine: bool

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "next_step": self.next_step,
            "operation_permitted": self.operation_permitted,
            "match_ready": self.match_ready,
            "quarantine": self.quarantine,
            "identifiers_redacted": True,
        }


def _decision(
    state: str,
    next_step: str,
    *,
    permitted: bool = False,
    ready: bool = False,
    quarantine: bool = False,
) -> ReadinessDecision:
    return ReadinessDecision(state, next_step, permitted, ready, quarantine)


def _validate_evidence(
    persistent: PersistentEvidence, alias: AliasEvidence
) -> None:
    if not isinstance(persistent, PersistentEvidence) or not isinstance(
        alias, AliasEvidence
    ):
        raise UserReadinessError("readiness evidence has the wrong type")
    for value, label in (
        (persistent.linux_account_generation, "Linux account generation"),
        (persistent.keybag_sha256, "keybag digest"),
    ):
        try:
            t2_user_mapping._sha256(value, label)
        except t2_user_mapping.UserMappingError as error:
            raise UserReadinessError(str(error)) from error
    try:
        t2_user_mapping._unsigned(
            persistent.catacomb_user_id, "Catacomb Apple UID", minimum=10
        )
        t2_user_mapping._canonical_uuid(
            persistent.account_uuid, "Catacomb account UUID"
        )
        t2_user_mapping._canonical_uuid(persistent.bag_uuid, "Catacomb bag UUID")
    except t2_user_mapping.UserMappingError as error:
        raise UserReadinessError(str(error)) from error
    if type(persistent.catacomb_reconciled) is not bool:
        raise UserReadinessError("Catacomb reconciliation state must be Boolean")
    if type(alias.present) is not bool:
        raise UserReadinessError("alias presence state must be Boolean")
    if not alias.present:
        if any(
            value is not None
            for value in (
                alias.special_alias,
                alias.bag_uuid,
                alias.lock_state,
                alias.account_uuid,
            )
        ):
            raise UserReadinessError("absent alias contains contradictory evidence")
        return
    if (
        type(alias.special_alias) is not int
        or alias.special_alias >= 0
        or not isinstance(alias.bag_uuid, str)
        or not isinstance(alias.account_uuid, str)
        or type(alias.lock_state) is not int
        or not 0 <= alias.lock_state <= 0xFFFF
    ):
        raise UserReadinessError("present alias evidence is incomplete or invalid")
    try:
        t2_user_mapping._canonical_uuid(alias.bag_uuid, "live bag UUID")
        t2_user_mapping._canonical_uuid(
            alias.account_uuid, "live Apple account UUID"
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserReadinessError(str(error)) from error


def assess(
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: PersistentEvidence,
    alias: AliasEvidence,
) -> ReadinessDecision:
    if not isinstance(selected, t2_user_mapping.UserMapping):
        raise UserReadinessError("selected mapping has the wrong type")
    _validate_evidence(persistent, alias)
    try:
        permitted = selected.permits(capability)
    except t2_user_mapping.UserMappingError as error:
        raise UserReadinessError(str(error)) from error
    if not permitted:
        return _decision("capability-denied", "request-authorized-policy-change")
    if (
        persistent.linux_account_generation != selected.linux_account_generation
        or persistent.keybag_sha256 != selected.keybag_sha256
        or persistent.catacomb_user_id != selected.apple_uid
        or persistent.account_uuid != selected.account_uuid
        or persistent.bag_uuid != selected.bag_uuid
        or not persistent.catacomb_reconciled
    ):
        return _decision(
            "persistent-binding-mismatch", "quarantine", quarantine=True
        )
    if not alias.present:
        return _decision("alias-absent", "activate-and-reconcile-alias")
    if (
        alias.special_alias != selected.special_bag_alias
        or alias.bag_uuid != selected.bag_uuid
        or alias.account_uuid != selected.account_uuid
    ):
        return _decision("alias-binding-mismatch", "quarantine", quarantine=True)
    assert alias.lock_state is not None
    if alias.lock_state & ~KNOWN_LOCK_STATE_BITS:
        return _decision("unknown-lock-state", "quarantine", quarantine=True)
    if alias.lock_state & CATACOMB_CORRUPTED:
        return _decision("catacomb-corrupted", "quarantine", quarantine=True)
    if alias.lock_state & (PASSCODE_LOCKOUT | BIO_LOCKOUT | IDENTIFICATION_LOCKOUT):
        return _decision("keybag-lockout", "password-recovery-required")
    if alias.lock_state & BEFORE_FIRST_UNLOCK:
        return _decision("before-first-unlock", "password-unlock-required")
    if alias.lock_state & DEVICE_LOCKED:
        return _decision("device-locked", "password-unlock-required")
    return _decision("ready", "none", permitted=True, ready=True)
