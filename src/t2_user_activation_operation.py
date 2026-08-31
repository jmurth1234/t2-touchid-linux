# SPDX-License-Identifier: GPL-2.0-only
"""Dependency-injected runtime activation operation for one mapped Apple user.

No concrete transport or CLI is supplied.  Every possibly mutating call is
preceded by durable intent and followed by independent observation.  Reported
command status never substitutes for alias, bag UUID, or lock-state read-back.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import t2_user_activation_journal as activation_journal
import t2_user_mapping
import t2_user_policy
import t2_user_readiness


class UserActivationOperationError(RuntimeError):
    pass


class UserActivationTransport(Protocol):
    runtime_generation: str

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence: ...

    def load_keybag(self, keybag_path: str) -> int: ...

    def bag_uuid(self, handle: int) -> str: ...

    def bind_alias(self, handle: int, special_alias: int) -> int: ...

    def unlock_alias(self, special_alias: int, password: memoryview) -> int: ...


@dataclass(frozen=True)
class UserActivationOperationResult:
    outcome: str
    mutation_performed: bool
    reconciliation_required: bool


def _sync(value, label: str):
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise UserActivationOperationError(f"{label} must be synchronous")
    return value


def _status(value, label: str) -> int:
    value = _sync(value, label)
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise UserActivationOperationError(f"{label} returned an invalid status")
    return value


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> activation_journal.UserActivationHistory:
    return activation_journal.append_checked(
        path, operation_id, milestone, evidence
    )


def _terminal(
    path: Path,
    operation_id: str,
    runtime_generation: str,
    *,
    stage: str,
    reason: str,
    unknown: bool,
    cause: BaseException | None = None,
) -> None:
    milestone = (
        "USER_ACTIVATION_OUTCOME_UNKNOWN"
        if unknown
        else "USER_ACTIVATION_STOPPED"
    )
    try:
        _append(
            path,
            operation_id,
            milestone,
            {
                "runtime_generation": runtime_generation,
                "stage": stage,
                "reason": reason,
                "mutation_possible": True,
            },
        )
    except BaseException:
        pass
    qualifier = "reconciliation is required" if unknown else "operation stopped"
    error = UserActivationOperationError(
        f"user activation stopped at {stage}; {qualifier}"
    )
    if cause is None:
        raise error
    raise error from cause


def _append_after_mutation(
    path: Path,
    operation_id: str,
    runtime_generation: str,
    milestone: str,
    evidence: dict[str, object],
    *,
    stage: str,
) -> activation_journal.UserActivationHistory:
    try:
        return _append(path, operation_id, milestone, evidence)
    except BaseException as error:
        _terminal(
            path,
            operation_id,
            runtime_generation,
            stage=stage,
            reason="journal-error",
            unknown=True,
            cause=error,
        )


def _observe(
    transport: UserActivationTransport,
    special_alias: int,
) -> t2_user_readiness.AliasEvidence:
    value = _sync(transport.observe_alias(special_alias), "alias observation")
    if not isinstance(value, t2_user_readiness.AliasEvidence):
        raise UserActivationOperationError("alias observation returned the wrong type")
    return value


def _command_and_readback(command, observe):
    status: int | None = None
    raised = False
    try:
        status = _status(command(), "activation command")
    except BaseException:
        raised = True
    return status, raised, observe()


def run(
    path: Path,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: t2_user_readiness.PersistentEvidence,
    transport: UserActivationTransport,
    password: bytearray | None,
    *,
    authorization: t2_user_policy.UserPolicyDecision,
    linux_boot_uuid: str,
) -> UserActivationOperationResult:
    if password is not None and not isinstance(password, bytearray):
        raise UserActivationOperationError(
            "activation password must use wipeable storage"
        )
    try:
        activation_authorized = (
            isinstance(authorization, t2_user_policy.UserPolicyDecision)
            and authorization.state == "activation-authorized"
        )
        try:
            authorized_operation_id = t2_user_policy.require_bound_authority(
                authorization,
                mapping_set,
                selected,
                capability,
                linux_boot_uuid=linux_boot_uuid,
                activation=activation_authorized,
            )
        except t2_user_policy.UserPolicyError as error:
            raise UserActivationOperationError(
                "activation lacks exact caller and policy authority"
            ) from error
        if isinstance(password, bytearray) and not 1 <= len(password) <= 1024:
            raise UserActivationOperationError(
                "activation password storage has an invalid size"
            )
        if not isinstance(transport.runtime_generation, str):
            raise UserActivationOperationError("runtime generation is invalid")
        mutation_performed = False
        try:
            before = _observe(transport, selected.special_bag_alias)
            decision = t2_user_readiness.assess(
                selected, capability, persistent, before
            )
        except BaseException as error:
            raise UserActivationOperationError(
                "activation preflight could not establish target readiness"
            ) from error
        if decision.state == "ready":
            return UserActivationOperationResult("already-ready", False, False)
        if not activation_authorized:
            raise UserActivationOperationError(
                "target became not-ready without separate activation authority"
            )
        if not isinstance(password, bytearray):
            raise UserActivationOperationError(
                "activation requires a nonempty password in wipeable storage"
            )
        try:
            history = activation_journal.create(
                path,
                mapping_set,
                selected,
                capability,
                persistent,
                before,
                linux_boot_uuid=linux_boot_uuid,
                runtime_generation=transport.runtime_generation,
                operation_id=authorized_operation_id,
            )
        except activation_journal.UserActivationJournalError as error:
            raise UserActivationOperationError(
                "activation preflight is not safely actionable"
            ) from error
        operation_id = history.operation_id
        bind_status: int | None = None
        bind_raised = False

        if decision.state == "alias-absent":
            _append(
                path,
                operation_id,
                "USER_KEYBAG_LOAD_INTENT",
                {
                    "runtime_generation": transport.runtime_generation,
                    "keybag_sha256": selected.keybag_sha256,
                    "mutation_possible": True,
                },
            )
            mutation_performed = True
            try:
                handle = _sync(
                    transport.load_keybag(selected.keybag_path), "keybag load"
                )
                if type(handle) is not int or not 1 <= handle <= 0xFFFFFFFF:
                    raise UserActivationOperationError(
                        "keybag load returned an invalid handle"
                    )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="load",
                    reason="handle-unavailable",
                    unknown=True,
                    cause=error,
                )
            try:
                observed_bag_uuid = _sync(
                    transport.bag_uuid(handle), "loaded keybag UUID observation"
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="handle",
                    reason="bag-observation-failed",
                    unknown=True,
                    cause=error,
                )
            if observed_bag_uuid != selected.bag_uuid:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="handle",
                    reason="bag-binding-mismatch",
                    unknown=False,
                )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "handle": handle,
                    "bag_uuid_matches": True,
                },
                stage="handle",
            )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_BIND_INTENT",
                {
                    "runtime_generation": transport.runtime_generation,
                    "handle": handle,
                    "special_alias": selected.special_bag_alias,
                    "mutation_possible": True,
                },
                stage="bind",
            )
            try:
                bind_status, bind_raised, after_bind = _command_and_readback(
                    lambda: transport.bind_alias(
                        handle, selected.special_bag_alias
                    ),
                    lambda: _observe(transport, selected.special_bag_alias),
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="alias-observation-failed",
                    unknown=True,
                    cause=error,
                )
            try:
                after_bind_decision = t2_user_readiness.assess(
                    selected, capability, persistent, after_bind
                )
            except BaseException as error:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="readback",
                    reason="alias-evidence-invalid",
                    unknown=True,
                    cause=error,
                )
            if after_bind_decision.state in {
                "alias-absent",
                "alias-binding-mismatch",
                "persistent-binding-mismatch",
                "unknown-lock-state",
                "catacomb-corrupted",
            }:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="bind",
                    reason=after_bind_decision.state,
                    unknown=after_bind_decision.state == "alias-absent",
                )
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_OBSERVED",
                {
                    "runtime_generation": transport.runtime_generation,
                    "special_alias": selected.special_bag_alias,
                    "bag_uuid_matches": True,
                    "command_status": bind_status,
                    "command_raised": bind_raised,
                },
                stage="readback",
            )
            if after_bind_decision.state == "ready":
                _append_after_mutation(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    "USER_ACTIVATION_READY",
                    {
                        "runtime_generation": transport.runtime_generation,
                        "special_alias": selected.special_bag_alias,
                        "bag_uuid_matches": True,
                        "readiness_state": "ready",
                        "source": "bind-readback",
                        "command_status": bind_status,
                        "command_raised": bind_raised,
                    },
                    stage="readback",
                )
                return UserActivationOperationResult("ready", True, False)
            if after_bind_decision.state not in {
                "device-locked",
                "before-first-unlock",
            }:
                _terminal(
                    path,
                    operation_id,
                    transport.runtime_generation,
                    stage="bind",
                    reason=after_bind_decision.state,
                    unknown=False,
                )

        unlock_intent = {
            "runtime_generation": transport.runtime_generation,
            "special_alias": selected.special_bag_alias,
            "mutation_possible": True,
        }
        if mutation_performed:
            _append_after_mutation(
                path,
                operation_id,
                transport.runtime_generation,
                "USER_ALIAS_UNLOCK_INTENT",
                unlock_intent,
                stage="unlock",
            )
        else:
            _append(
                path,
                operation_id,
                "USER_ALIAS_UNLOCK_INTENT",
                unlock_intent,
            )
        mutation_performed = True
        try:
            unlock_status, unlock_raised, after_unlock = _command_and_readback(
                lambda: transport.unlock_alias(
                    selected.special_bag_alias, memoryview(password)
                ),
                lambda: _observe(transport, selected.special_bag_alias),
            )
        except BaseException as error:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason="unlock-observation-failed",
                unknown=True,
                cause=error,
            )
        try:
            final = t2_user_readiness.assess(
                selected, capability, persistent, after_unlock
            )
        except BaseException as error:
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="readback",
                reason="unlock-evidence-invalid",
                unknown=True,
                cause=error,
            )
        if final.state != "ready":
            _terminal(
                path,
                operation_id,
                transport.runtime_generation,
                stage="unlock",
                reason=final.state,
                unknown=final.state in {"alias-absent", "unknown-lock-state"},
            )
        _append_after_mutation(
            path,
            operation_id,
            transport.runtime_generation,
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": transport.runtime_generation,
                "special_alias": selected.special_bag_alias,
                "bag_uuid_matches": True,
                "readiness_state": "ready",
                "source": "unlock-readback",
                "command_status": unlock_status,
                "command_raised": unlock_raised,
            },
            stage="readback",
        )
        return UserActivationOperationResult("ready", mutation_performed, False)
    finally:
        if isinstance(password, bytearray):
            password[:] = b"\x00" * len(password)
