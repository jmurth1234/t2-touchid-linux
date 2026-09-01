# SPDX-License-Identifier: GPL-2.0-only
"""Pure caller/target authorization boundary for mapped T2 users.

The policy consumes evidence already authenticated by a privileged broker.  It
does not inspect process environment, call PolicyKit, activate a keybag, or
perform biometric work.  Raw Apple identifiers are never request parameters:
the selected Apple authority comes only from the protected Linux-UID mapping.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import t2_user_mapping
import t2_user_readiness


MAX_POLICY_LIFETIME_NS = 5 * 60 * 1_000_000_000
ACTIVATE_ACTION = "org.t2linux.touchid.activate-user"


@dataclass(frozen=True)
class OperationPolicy:
    capability: str
    action: str
    mutation: bool


OPERATION_POLICIES = {
    "verify": OperationPolicy(
        "verify", "org.t2linux.touchid.verify", False
    ),
    "inventory": OperationPolicy(
        "verify", "org.t2linux.touchid.inventory", False
    ),
    "enroll": OperationPolicy(
        "enroll", "org.t2linux.touchid.enroll", True
    ),
    "rename": OperationPolicy(
        "identity-management",
        "org.t2linux.touchid.identity-management",
        True,
    ),
    "delete-one": OperationPolicy(
        "identity-management",
        "org.t2linux.touchid.identity-management",
        True,
    ),
}


class UserPolicyError(ValueError):
    """Raised when supplied authorization evidence is structurally invalid."""


@dataclass(frozen=True, repr=False)
class CallerEvidence:
    linux_uid: int
    linux_account_generation: str
    authenticated: bool
    active_local_session: bool


@dataclass(frozen=True)
class OperationRequest:
    operation: str
    target_linux_uid: int
    operation_id: str
    linux_boot_uuid: str
    observed_monotonic_ns: int
    modification_allowed: bool


@dataclass(frozen=True, repr=False)
class PolicyGrant:
    authorization_id: str
    action: str
    caller_linux_uid: int
    linux_account_generation: str
    target_linux_uid: int
    mapping_generation: str
    operation_id: str
    linux_boot_uuid: str
    issued_monotonic_ns: int
    expires_monotonic_ns: int
    authorized: bool


@dataclass(frozen=True, repr=False)
class PolicyBinding:
    mapping_generation: str
    linux_account_generation: str
    operation_id: str
    linux_boot_uuid: str
    caller_linux_uid: int
    target_linux_uid: int
    capability: str
    operation_authorization_id: str
    activation_authorization_id: str | None


@dataclass(frozen=True, repr=False)
class UserPolicyDecision:
    state: str
    operation: str
    policy_action: str
    operation_permitted: bool
    activation_required: bool
    activation_permitted: bool
    readiness_state: str | None
    quarantine: bool
    selected_mapping: t2_user_mapping.UserMapping | None = field(
        repr=False, compare=False
    )
    binding: PolicyBinding | None = field(repr=False, compare=False)

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "operation": self.operation,
            "policy_action": self.policy_action,
            "operation_permitted": self.operation_permitted,
            "activation_required": self.activation_required,
            "activation_permitted": self.activation_permitted,
            "readiness_state": self.readiness_state,
            "quarantine": self.quarantine,
            "identifiers_redacted": True,
        }


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise UserPolicyError(f"{label} is not a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise UserPolicyError(f"{label} is not a canonical UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise UserPolicyError(f"{label} is not a canonical nonzero UUID")
    return value


def _uid(value: object, label: str) -> int:
    try:
        return t2_user_mapping._unsigned(value, label, minimum=1)
    except t2_user_mapping.UserMappingError as error:
        raise UserPolicyError(str(error)) from error


def _digest(value: object, label: str) -> str:
    try:
        return t2_user_mapping._sha256(value, label)
    except t2_user_mapping.UserMappingError as error:
        raise UserPolicyError(str(error)) from error


def _monotonic(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 63:
        raise UserPolicyError(f"{label} is outside the monotonic-time range")
    return value


def _validate_caller(caller: CallerEvidence) -> None:
    if not isinstance(caller, CallerEvidence):
        raise UserPolicyError("caller evidence has the wrong type")
    _uid(caller.linux_uid, "caller Linux UID")
    _digest(caller.linux_account_generation, "caller account generation")
    if type(caller.authenticated) is not bool or type(
        caller.active_local_session
    ) is not bool:
        raise UserPolicyError("caller authentication state must be Boolean")


def _validate_request(request: OperationRequest) -> OperationPolicy:
    if not isinstance(request, OperationRequest):
        raise UserPolicyError("operation request has the wrong type")
    if request.operation not in OPERATION_POLICIES:
        raise UserPolicyError("operation is unsupported")
    _uid(request.target_linux_uid, "target Linux UID")
    _canonical_uuid(request.operation_id, "operation ID")
    _canonical_uuid(request.linux_boot_uuid, "Linux boot UUID")
    _monotonic(request.observed_monotonic_ns, "observation time")
    if type(request.modification_allowed) is not bool:
        raise UserPolicyError("modification policy must be Boolean")
    return OPERATION_POLICIES[request.operation]


def _validate_grant(grant: PolicyGrant, request: OperationRequest) -> None:
    if not isinstance(grant, PolicyGrant):
        raise UserPolicyError("policy grant has the wrong type")
    _canonical_uuid(grant.authorization_id, "authorization ID")
    if not isinstance(grant.action, str) or not grant.action:
        raise UserPolicyError("policy action is invalid")
    _uid(grant.caller_linux_uid, "grant caller Linux UID")
    _digest(grant.linux_account_generation, "grant account generation")
    _uid(grant.target_linux_uid, "grant target Linux UID")
    _digest(grant.mapping_generation, "grant mapping generation")
    _canonical_uuid(grant.operation_id, "grant operation ID")
    _canonical_uuid(grant.linux_boot_uuid, "grant Linux boot UUID")
    issued = _monotonic(grant.issued_monotonic_ns, "grant issue time")
    expires = _monotonic(grant.expires_monotonic_ns, "grant expiry time")
    if (
        expires <= issued
        or expires - issued > MAX_POLICY_LIFETIME_NS
        or not issued <= request.observed_monotonic_ns <= expires
    ):
        raise UserPolicyError("policy grant is expired, premature, or overlong")
    if type(grant.authorized) is not bool:
        raise UserPolicyError("policy grant decision must be Boolean")


def _grant_bound(
    grant: PolicyGrant,
    *,
    action: str,
    caller: CallerEvidence,
    request: OperationRequest,
    mapping_generation: str,
) -> bool:
    return (
        grant.action == action
        and grant.caller_linux_uid == caller.linux_uid
        and grant.linux_account_generation == caller.linux_account_generation
        and grant.target_linux_uid == request.target_linux_uid
        and grant.mapping_generation == mapping_generation
        and grant.operation_id == request.operation_id
        and grant.linux_boot_uuid == request.linux_boot_uuid
    )


def _decision(
    request: OperationRequest,
    policy: OperationPolicy,
    state: str,
    *,
    selected: t2_user_mapping.UserMapping | None = None,
    readiness_state: str | None = None,
    permitted: bool = False,
    activation_required: bool = False,
    activation_permitted: bool = False,
    quarantine: bool = False,
    binding: PolicyBinding | None = None,
) -> UserPolicyDecision:
    return UserPolicyDecision(
        state,
        request.operation,
        policy.action,
        permitted,
        activation_required,
        activation_permitted,
        readiness_state,
        quarantine,
        selected,
        binding,
    )


def _binding(
    mapping_set: t2_user_mapping.UserMappingSet,
    request: OperationRequest,
    caller: CallerEvidence,
    policy: OperationPolicy,
    operation_grant: PolicyGrant,
    activation_grant: PolicyGrant | None = None,
) -> PolicyBinding:
    return PolicyBinding(
        mapping_set.generation,
        caller.linux_account_generation,
        request.operation_id,
        request.linux_boot_uuid,
        caller.linux_uid,
        request.target_linux_uid,
        policy.capability,
        operation_grant.authorization_id,
        (
            activation_grant.authorization_id
            if activation_grant is not None
            else None
        ),
    )


def authorize(
    mapping_set: t2_user_mapping.UserMappingSet,
    request: OperationRequest,
    caller: CallerEvidence,
    persistent: t2_user_readiness.PersistentEvidence,
    alias: t2_user_readiness.AliasEvidence,
    operation_grant: PolicyGrant | None,
    activation_grant: PolicyGrant | None = None,
) -> UserPolicyDecision:
    """Resolve one self-service operation against exact, fresh evidence.

    Cross-user requests are intentionally denied even if the broker runs as
    root.  A not-ready target never inherits activation authority from verify,
    enrollment, or identity-management policy; activation needs its own grant.
    """

    if not isinstance(mapping_set, t2_user_mapping.UserMappingSet):
        raise UserPolicyError("mapping set has the wrong type")
    policy = _validate_request(request)
    _validate_caller(caller)
    if caller.linux_uid != request.target_linux_uid:
        return _decision(request, policy, "delegation-disabled")
    if not caller.authenticated or not caller.active_local_session:
        return _decision(request, policy, "caller-session-denied")
    try:
        selected = mapping_set.resolve(request.target_linux_uid, policy.capability)
    except t2_user_mapping.UserMappingError:
        return _decision(request, policy, "mapping-or-capability-denied")
    if caller.linux_account_generation != selected.linux_account_generation:
        return _decision(
            request,
            policy,
            "caller-account-generation-mismatch",
            quarantine=True,
        )
    if operation_grant is None:
        return _decision(
            request, policy, "operation-authorization-required", selected=selected
        )
    _validate_grant(operation_grant, request)
    if not _grant_bound(
        operation_grant,
        action=policy.action,
        caller=caller,
        request=request,
        mapping_generation=mapping_set.generation,
    ):
        return _decision(
            request, policy, "operation-authorization-binding-mismatch"
        )
    if not operation_grant.authorized:
        return _decision(request, policy, "operation-policy-denied")
    if policy.mutation and not request.modification_allowed:
        return _decision(
            request, policy, "fingerprint-modification-disabled", selected=selected
        )
    try:
        readiness = t2_user_readiness.assess(
            selected, policy.capability, persistent, alias
        )
    except t2_user_readiness.UserReadinessError as error:
        raise UserPolicyError("target readiness evidence is invalid") from error
    if readiness.quarantine:
        return _decision(
            request,
            policy,
            "target-quarantined",
            readiness_state=readiness.state,
            quarantine=True,
        )
    if readiness.state == "ready":
        return _decision(
            request,
            policy,
            "authorized",
            selected=selected,
            readiness_state=readiness.state,
            permitted=True,
            binding=_binding(
                mapping_set, request, caller, policy, operation_grant
            ),
        )
    if readiness.state in {
        "alias-absent",
        "device-locked",
        "before-first-unlock",
    }:
        if activation_grant is None:
            return _decision(
                request,
                policy,
                "activation-authorization-required",
                selected=selected,
                readiness_state=readiness.state,
                activation_required=True,
            )
        _validate_grant(activation_grant, request)
        if not _grant_bound(
            activation_grant,
            action=ACTIVATE_ACTION,
            caller=caller,
            request=request,
            mapping_generation=mapping_set.generation,
        ):
            return _decision(
                request,
                policy,
                "activation-authorization-binding-mismatch",
                readiness_state=readiness.state,
            )
        if not activation_grant.authorized:
            return _decision(
                request,
                policy,
                "activation-policy-denied",
                readiness_state=readiness.state,
            )
        return _decision(
            request,
            policy,
            "activation-authorized",
            selected=selected,
            readiness_state=readiness.state,
            activation_required=True,
            activation_permitted=True,
            binding=_binding(
                mapping_set,
                request,
                caller,
                policy,
                operation_grant,
                activation_grant,
            ),
        )
    return _decision(
        request,
        policy,
        "target-not-ready",
        selected=selected,
        readiness_state=readiness.state,
    )


def require_bound_authority(
    decision: UserPolicyDecision,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    *,
    linux_boot_uuid: str,
    activation: bool,
) -> str:
    """Return the bound operation ID or reject a stale/reused decision."""

    if not isinstance(decision, UserPolicyDecision):
        raise UserPolicyError("policy decision has the wrong type")
    if not isinstance(mapping_set, t2_user_mapping.UserMappingSet) or not isinstance(
        selected, t2_user_mapping.UserMapping
    ):
        raise UserPolicyError("policy target has the wrong type")
    _canonical_uuid(linux_boot_uuid, "Linux boot UUID")
    binding = decision.binding
    expected_state = "activation-authorized" if activation else "authorized"
    expected_policy = OPERATION_POLICIES.get(decision.operation)
    if not isinstance(binding, PolicyBinding):
        raise UserPolicyError("policy decision has no typed binding")
    try:
        _digest(binding.mapping_generation, "binding mapping generation")
        _digest(binding.linux_account_generation, "binding account generation")
        _canonical_uuid(binding.operation_id, "binding operation ID")
        _canonical_uuid(binding.linux_boot_uuid, "binding Linux boot UUID")
        _uid(binding.caller_linux_uid, "binding caller Linux UID")
        _uid(binding.target_linux_uid, "binding target Linux UID")
        _canonical_uuid(
            binding.operation_authorization_id,
            "binding operation authorization ID",
        )
        if binding.activation_authorization_id is not None:
            _canonical_uuid(
                binding.activation_authorization_id,
                "binding activation authorization ID",
            )
    except UserPolicyError as error:
        raise UserPolicyError("policy decision binding is malformed") from error
    if (
        decision.state != expected_state
        or decision.selected_mapping != selected
        or expected_policy is None
        or decision.policy_action != expected_policy.action
        or binding.capability != expected_policy.capability
        or binding.mapping_generation != mapping_set.generation
        or binding.linux_account_generation
        != selected.linux_account_generation
        or binding.linux_boot_uuid != linux_boot_uuid
        or binding.target_linux_uid != selected.linux_uid
        or binding.caller_linux_uid != selected.linux_uid
        or binding.capability != capability
        or selected not in mapping_set.mappings
        or (
            activation
            and (
                decision.activation_permitted is not True
                or decision.operation_permitted is not False
            )
        )
        or (
            not activation
            and (
                decision.operation_permitted is not True
                or decision.activation_permitted is not False
            )
        )
        or (activation and binding.activation_authorization_id is None)
    ):
        raise UserPolicyError("policy decision is not bound to this operation")
    return binding.operation_id
