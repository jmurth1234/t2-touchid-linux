# SPDX-License-Identifier: GPL-2.0-only
"""Pure redacted readiness gate for staged read-only broker exposure."""

from __future__ import annotations

from dataclasses import dataclass

import t2_user_broker_inventory
import t2_user_mapping_admin
import t2_user_readiness


OBSERVER_KEYS = frozenset(
    {
        "schema_version",
        "operation_0x06_validated",
        "operation_0x19_validated",
        "stable_double_read",
        "queried_alias_matched",
        "bag_uuid_valid_and_redacted",
        "account_uuid_valid_and_redacted",
        "lock_state",
        "mutation_performed",
        "identifiers_redacted",
    }
)


class UserBrokerExposureGateError(ValueError):
    pass


@dataclass(frozen=True)
class ExposureGateResult:
    module_build_current: bool
    aks_alias_observer_valid: bool
    reconciled_identity_count: int | None
    two_identity_minimum: bool
    fingerprint_survivors_acknowledged_this_boot: bool
    protected_mapping_present: bool
    protected_mapping_enabled: bool
    ready_for_staged_negative_test: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "module_build_current": self.module_build_current,
            "aks_alias_observer_valid": self.aks_alias_observer_valid,
            "reconciled_identity_count": self.reconciled_identity_count,
            "two_identity_minimum": self.two_identity_minimum,
            "fingerprint_survivors_acknowledged_this_boot": (
                self.fingerprint_survivors_acknowledged_this_boot
            ),
            "protected_mapping_present": self.protected_mapping_present,
            "protected_mapping_enabled": self.protected_mapping_enabled,
            "ready_for_staged_negative_test": (
                self.ready_for_staged_negative_test
            ),
            "broker_socket_installed": False,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _observer_valid(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != OBSERVER_KEYS:
        return False
    lock_state = value.get("lock_state")
    return (
        type(value.get("schema_version")) is int
        and value["schema_version"] == 1
        and value.get("operation_0x06_validated") is True
        and value.get("operation_0x19_validated") is True
        and value.get("stable_double_read") is True
        and value.get("queried_alias_matched") is True
        and value.get("bag_uuid_valid_and_redacted") is True
        and value.get("account_uuid_valid_and_redacted") is True
        and type(lock_state) is int
        and 0 <= lock_state <= 0xFFFFFFFF
        and lock_state & ~t2_user_readiness.KNOWN_LOCK_STATE_BITS == 0
        and value.get("mutation_performed") is False
        and value.get("identifiers_redacted") is True
    )


def _identity_count(value: object) -> int | None:
    try:
        return t2_user_broker_inventory.parse_public_inventory(
            value
        ).identity_count
    except t2_user_broker_inventory.UserBrokerInventoryError:
        return None


def _mapping_state(value: object) -> tuple[bool, bool]:
    if not isinstance(value, t2_user_mapping_admin.AdminResult):
        return False, False
    if (
        value.operation != "status"
        or value.state != "mapping-valid"
        or type(value.mapping_count) is not int
        or type(value.enabled_mapping_count) is not int
        or not 1 <= value.mapping_count <= 1024
        or not 0 <= value.enabled_mapping_count <= value.mapping_count
        or value.account_generation_current is not None
        or value.mapping_disabled is not None
    ):
        return False, False
    return True, value.enabled_mapping_count > 0


def evaluate(
    *,
    module_build_current: bool,
    alias_observation: object,
    identity_inventory: object,
    mapping_status: object,
    fingerprint_survivors_acknowledged_this_boot: bool,
) -> ExposureGateResult:
    """Evaluate prerequisites without installing, starting, or mutating T2."""

    if type(module_build_current) is not bool:
        raise UserBrokerExposureGateError(
            "module-build evidence must be Boolean"
        )
    if type(fingerprint_survivors_acknowledged_this_boot) is not bool:
        raise UserBrokerExposureGateError(
            "fingerprint-survivor acknowledgement must be Boolean"
        )
    observer_valid = _observer_valid(alias_observation)
    count = _identity_count(identity_inventory)
    two_identity_minimum = count is not None and count >= 2
    mapping_present, mapping_enabled = _mapping_state(mapping_status)
    ready = (
        module_build_current
        and observer_valid
        and two_identity_minimum
        and fingerprint_survivors_acknowledged_this_boot
        and mapping_present
        and mapping_enabled
    )
    return ExposureGateResult(
        module_build_current,
        observer_valid,
        count,
        two_identity_minimum,
        fingerprint_survivors_acknowledged_this_boot,
        mapping_present,
        mapping_enabled,
        ready,
    )
