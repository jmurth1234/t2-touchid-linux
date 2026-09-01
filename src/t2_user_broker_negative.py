# SPDX-License-Identifier: GPL-2.0-only
"""Classify the staged read-only broker's unmapped/inactive caller result."""

from __future__ import annotations

from dataclasses import dataclass

import t2_user_broker_protocol


DENIED_STATES = frozenset(
    {"caller-session-denied", "mapping-or-capability-denied"}
)


class UserBrokerNegativeError(ValueError):
    pass


@dataclass(frozen=True)
class NegativeResult:
    outcome: str
    explicit_denial: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "outcome": self.outcome,
            "explicit_denial": self.explicit_denial,
            "inventory_received": False,
            "activation_authority_received": False,
            "broker_consumer_invoked": False,
            "negative_boundary_held": True,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def classify(
    response: object = None,
    *,
    peer_closed_without_response: bool = False,
) -> NegativeResult:
    """Accept only an exact denial or a clean close before any response."""

    if type(peer_closed_without_response) is not bool:
        raise UserBrokerNegativeError("peer-close evidence must be Boolean")
    if peer_closed_without_response:
        if response is not None:
            raise UserBrokerNegativeError(
                "negative result has conflicting response evidence"
            )
        return NegativeResult("connection-closed-without-response", False)
    if not isinstance(response, t2_user_broker_protocol.InventoryResponse):
        raise UserBrokerNegativeError(
            "negative test did not receive an inventory denial"
        )
    if (
        response.state not in DENIED_STATES
        or response.operation_permitted is not False
        or response.activation_required is not False
        or response.activation_permitted is not False
        or response.quarantine is not False
        or response.broker_consumer_invoked is not False
        or response.inventory is not None
    ):
        raise UserBrokerNegativeError(
            "negative response carries data or authority"
        )
    return NegativeResult(response.state, True)
