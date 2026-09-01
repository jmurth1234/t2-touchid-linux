# SPDX-License-Identifier: GPL-2.0-only
"""Identifier-free identity inventory consumer for the self-service broker."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

import t2_catacomb_codec
import t2_user_broker
import t2_user_policy


SUMMARY_KEYS = frozenset(
    {
        "schema_version",
        "identity_count",
        "identities",
        "local_live_reconciled",
        "selection_scope",
        "fprintd_listing_is_compatibility_alias",
        "identifiers_redacted",
    }
)
IDENTITY_KEYS = frozenset({"slot", "name", "live"})
MAX_PUBLIC_NAME_BYTES = t2_catacomb_codec.MAX_STRING_BYTES


class UserBrokerInventoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicIdentity:
    slot: int
    name: str
    live: bool = True

    def public(self) -> dict[str, object]:
        return {"slot": self.slot, "name": self.name, "live": self.live}


@dataclass(frozen=True)
class PublicIdentityInventory:
    identities: tuple[PublicIdentity, ...]
    local_live_reconciled: bool = True
    selection_scope: str = "current-reconciled-list"
    fprintd_listing_is_compatibility_alias: bool = True
    identifiers_redacted: bool = True

    @property
    def identity_count(self) -> int:
        return len(self.identities)

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "identity_count": self.identity_count,
            "identities": [identity.public() for identity in self.identities],
            "local_live_reconciled": self.local_live_reconciled,
            "selection_scope": self.selection_scope,
            "fprintd_listing_is_compatibility_alias": (
                self.fprintd_listing_is_compatibility_alias
            ),
            "identifiers_redacted": self.identifiers_redacted,
        }


@dataclass(frozen=True, repr=False)
class BrokerInventoryResult:
    decision: t2_user_policy.UserPolicyDecision = field(repr=False)
    consumer_invoked: bool
    inventory: PublicIdentityInventory | None

    def redacted(self) -> dict[str, object]:
        result = self.decision.redacted()
        result.update(
            {
                "broker_consumer_invoked": self.consumer_invoked,
                "identity_inventory_available": self.inventory is not None,
                "t2_mutation_performed": False,
                "identifiers_redacted": True,
            }
        )
        if self.inventory is not None:
            result["inventory"] = self.inventory.public()
        return result


def parse_public_inventory(value: object) -> PublicIdentityInventory:
    """Validate the exact redacted output of ``t2_identity_inventory``."""

    if not isinstance(value, dict) or set(value) != SUMMARY_KEYS:
        raise UserBrokerInventoryError("public identity inventory is malformed")
    count = value.get("identity_count")
    records = value.get("identities")
    if (
        type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or type(count) is not int
        or not 0 <= count <= t2_catacomb_codec.MAX_IDENTITIES
        or not isinstance(records, list)
        or len(records) != count
        or value.get("local_live_reconciled") is not True
        or value.get("selection_scope") != "current-reconciled-list"
        or value.get("fprintd_listing_is_compatibility_alias") is not True
        or value.get("identifiers_redacted") is not True
    ):
        raise UserBrokerInventoryError("public identity inventory is invalid")
    identities: list[PublicIdentity] = []
    for expected_slot, record in enumerate(records, 1):
        if not isinstance(record, dict) or set(record) != IDENTITY_KEYS:
            raise UserBrokerInventoryError("public identity record is malformed")
        name = record.get("name")
        try:
            name_length = len(name.encode("utf-8")) if isinstance(name, str) else 0
        except UnicodeError as error:
            raise UserBrokerInventoryError(
                "public identity name is invalid"
            ) from error
        if (
            type(record.get("slot")) is not int
            or record["slot"] != expected_slot
            or not isinstance(name, str)
            or not name
            or "\0" in name
            or not 1 <= name_length <= MAX_PUBLIC_NAME_BYTES
            or record.get("live") is not True
        ):
            raise UserBrokerInventoryError("public identity record is invalid")
        identities.append(PublicIdentity(expected_slot, name))
    inventory = PublicIdentityInventory(tuple(identities))
    if inventory.public() != value:
        raise UserBrokerInventoryError("public identity inventory is not canonical")
    return inventory


def _consumer(
    authority: t2_user_broker.BrokerAuthority,
    live: t2_user_broker.BrokerLiveSession,
) -> PublicIdentityInventory:
    expected = t2_user_policy.OPERATION_POLICIES["inventory"]
    if (
        not isinstance(authority, t2_user_broker.BrokerAuthority)
        or authority.stage != "operate"
        or authority.decision.operation != "inventory"
        or authority.decision.policy_action != expected.action
        or authority.decision.state != "authorized"
        or authority.decision.operation_permitted is not True
        or authority.decision.readiness_state != "ready"
        or live.runtime_generation != authority.runtime_generation
    ):
        raise UserBrokerInventoryError("inventory handoff is inconsistent")
    collector = getattr(live, "public_identity_inventory", None)
    if not callable(collector):
        raise UserBrokerInventoryError("live identity inventory is unavailable")
    try:
        value = collector(authority.selected)
    except Exception as error:
        raise UserBrokerInventoryError(
            "live identity inventory collection failed"
        ) from error
    return parse_public_inventory(value)


def run(
    connection: socket.socket,
    *,
    allow_user_interaction: bool,
    broker_runner=t2_user_broker.run_self_service,
) -> BrokerInventoryResult:
    """Authorize and return one current inventory without activation or mutation."""

    if type(allow_user_interaction) is not bool:
        raise UserBrokerInventoryError("interaction policy must be Boolean")
    try:
        result = broker_runner(
            connection,
            operation="inventory",
            modification_allowed=False,
            consumer=_consumer,
            allow_user_interaction=allow_user_interaction,
            collect_activation_authority=False,
        )
    except Exception as error:
        raise UserBrokerInventoryError(
            "self-service identity inventory transaction failed"
        ) from error
    if (
        not isinstance(result, t2_user_broker.BrokerResult)
        or result.decision.operation != "inventory"
    ):
        raise UserBrokerInventoryError("identity inventory result is malformed")
    if result.consumer_invoked:
        if (
            result.decision.state != "authorized"
            or not isinstance(result.value, PublicIdentityInventory)
        ):
            raise UserBrokerInventoryError(
                "identity inventory authority is inconsistent"
            )
        inventory = result.value
    else:
        if result.value is not None or result.decision.state == "authorized":
            raise UserBrokerInventoryError(
                "denied identity inventory returned private data"
            )
        inventory = None
    return BrokerInventoryResult(
        result.decision,
        result.consumer_invoked,
        inventory,
    )
