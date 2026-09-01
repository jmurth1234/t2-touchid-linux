# SPDX-License-Identifier: GPL-2.0-only
"""Pure redacted gate for staging native fprint enrollment."""

from __future__ import annotations

from dataclasses import dataclass

import t2_fprint_projection
import t2_user_broker_exposure_gate


REQUIRED_HEALTH_CHECKS = frozenset(
    {
        "sep-module",
        "aks-device",
        "t2-sep-transport.service",
        "t2-keybag-load.service",
        "t2-credential-unlock.service",
        "t2-biometric-ready.service",
        "fprintd.service",
        "dkms-module",
        "module-build",
        "configuration",
        "acm-transport",
        "keybag-runtime-state",
        "encrypted-credential",
        "port-cache",
        "bridge-network",
    }
)

ENROLLMENT_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "status_only",
        "unfinished_count",
        "unfinished_phases",
        "post_reboot_pending_count",
        "post_reboot_verification_candidate",
        "live_enrollment_blocked",
        "automatic_no_change_recovery_candidate",
        "local_transaction_pending",
        "local_transaction_recovery_candidate",
        "identifiers_redacted",
        "mutation_performed",
    }
)

MANAGEMENT_STATUS_KEYS = frozenset(
    {
        "schema_version",
        "status_only",
        "rename_pending_count",
        "rename_pending_phases",
        "delete_pending_count",
        "delete_pending_phases",
        "external_reconciliation_pending_count",
        "external_reconciliation_pending_phases",
        "post_reboot_pending_count",
        "rename_recovery_candidate",
        "delete_recovery_candidate",
        "new_mutation_blocked",
        "identifiers_redacted",
    }
)


class FprintActivationGateError(ValueError):
    pass


@dataclass(frozen=True)
class FprintActivationGateResult:
    stack_health_passed: bool
    canonical_projection_complete: bool
    canonical_identity_count: int | None
    enrollment_journals_clear: bool
    identity_management_journals_clear: bool
    protected_mapping_enabled: bool
    aks_alias_observer_valid: bool
    two_fingers_verified_this_boot: bool
    password_fallback_acknowledged: bool
    worker_negative_controls_acknowledged: bool
    installed_daemon_default_off: bool
    ready_to_stage_research_activation: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "stack_health_passed": self.stack_health_passed,
            "canonical_projection_complete": (
                self.canonical_projection_complete
            ),
            "canonical_identity_count": self.canonical_identity_count,
            "enrollment_journals_clear": self.enrollment_journals_clear,
            "identity_management_journals_clear": (
                self.identity_management_journals_clear
            ),
            "protected_mapping_enabled": self.protected_mapping_enabled,
            "aks_alias_observer_valid": self.aks_alias_observer_valid,
            "two_fingers_verified_this_boot": (
                self.two_fingers_verified_this_boot
            ),
            "password_fallback_acknowledged": (
                self.password_fallback_acknowledged
            ),
            "worker_negative_controls_acknowledged": (
                self.worker_negative_controls_acknowledged
            ),
            "installed_daemon_default_off": self.installed_daemon_default_off,
            "ready_to_stage_research_activation": (
                self.ready_to_stage_research_activation
            ),
            "service_mutation_performed": False,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _health_passed(value: object) -> bool:
    if type(value) is not dict or set(value) != REQUIRED_HEALTH_CHECKS:
        return False
    return all(status == "pass" for status in value.values())


def _enrollment_clear(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == ENROLLMENT_STATUS_KEYS
        and value.get("schema_version") == 1
        and value.get("status_only") is True
        and value.get("unfinished_count") == 0
        and value.get("unfinished_phases") == {}
        and value.get("post_reboot_pending_count") == 0
        and value.get("post_reboot_verification_candidate") is False
        and value.get("live_enrollment_blocked") is False
        and value.get("automatic_no_change_recovery_candidate") is False
        and value.get("local_transaction_pending") is False
        and value.get("local_transaction_recovery_candidate") is False
        and value.get("identifiers_redacted") is True
        and value.get("mutation_performed") is False
    )


def _management_clear(value: object) -> bool:
    return (
        type(value) is dict
        and set(value) == MANAGEMENT_STATUS_KEYS
        and value.get("schema_version") == 1
        and value.get("status_only") is True
        and value.get("rename_pending_count") == 0
        and value.get("rename_pending_phases") == {}
        and value.get("delete_pending_count") == 0
        and value.get("delete_pending_phases") == {}
        and value.get("external_reconciliation_pending_count") == 0
        and value.get("external_reconciliation_pending_phases") == {}
        and value.get("post_reboot_pending_count") == 0
        and value.get("rename_recovery_candidate") is False
        and value.get("delete_recovery_candidate") is False
        and value.get("new_mutation_blocked") is False
        and value.get("identifiers_redacted") is True
    )


def evaluate(
    *,
    health_checks: object,
    projection: object,
    enrollment_status: object,
    management_status: object,
    exposure: object,
    password_fallback_acknowledged: bool,
    worker_negative_controls_acknowledged: bool,
    installed_daemon_default_off: bool,
) -> FprintActivationGateResult:
    """Combine only validated redacted evidence; never stage a service."""

    for value, name in (
        (password_fallback_acknowledged, "password fallback acknowledgement"),
        (
            worker_negative_controls_acknowledged,
            "worker negative-control acknowledgement",
        ),
        (installed_daemon_default_off, "installed-daemon state"),
    ):
        if type(value) is not bool:
            raise FprintActivationGateError(f"{name} must be Boolean")
    stack = _health_passed(health_checks)
    if isinstance(projection, t2_fprint_projection.FprintProjection):
        projection_complete = projection.complete
        identity_count = projection.reconciled_identity_count
    else:
        projection_complete = False
        identity_count = None
    if isinstance(
        exposure, t2_user_broker_exposure_gate.ExposureGateResult
    ):
        mapping_enabled = exposure.protected_mapping_enabled
        observer_valid = exposure.aks_alias_observer_valid
        two_fingers = (
            exposure.two_identity_minimum
            and exposure.fingerprint_survivors_acknowledged_this_boot
        )
    else:
        mapping_enabled = False
        observer_valid = False
        two_fingers = False
    enrollment_clear = _enrollment_clear(enrollment_status)
    management_clear = _management_clear(management_status)
    ready = (
        stack
        and projection_complete
        and enrollment_clear
        and management_clear
        and mapping_enabled
        and observer_valid
        and two_fingers
        and password_fallback_acknowledged
        and worker_negative_controls_acknowledged
        and installed_daemon_default_off
    )
    return FprintActivationGateResult(
        stack,
        projection_complete,
        identity_count,
        enrollment_clear,
        management_clear,
        mapping_enabled,
        observer_valid,
        two_fingers,
        password_fallback_acknowledged,
        worker_negative_controls_acknowledged,
        installed_daemon_default_off,
        ready,
    )
