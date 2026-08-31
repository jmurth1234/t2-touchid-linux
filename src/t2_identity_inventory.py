# SPDX-License-Identifier: GPL-2.0-only
"""Privacy-safe join of a validated local Catacomb and stable live SEP state."""

from __future__ import annotations

import uuid
from typing import Any

import t2_catacomb_codec


class IdentityInventoryError(ValueError):
    pass


def _canonical_uuid(value: Any, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise IdentityInventoryError(f"{field} is not a UUID") from error
    if str(parsed) != value:
        raise IdentityInventoryError(f"{field} is not canonical")
    return value


def _live_pairs(records: Any, apple_user_id: int) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise IdentityInventoryError("live identity inventory is absent")
    pairs: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "user_id",
            "identity_uuid",
        }:
            raise IdentityInventoryError("live identity inventory is malformed")
        pair = (
            record["user_id"],
            _canonical_uuid(record["identity_uuid"], "live identity UUID"),
        )
        if pair[0] != apple_user_id or pair in pairs:
            raise IdentityInventoryError("live identity inventory is ambiguous")
        pairs.add(pair)
    return pairs


def _configured_global_pairs(
    records: Any, apple_user_id: int
) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise IdentityInventoryError("global identity inventory is absent")
    pairs: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "user_id",
            "identity_uuid",
            "group_type",
            "group_uuid",
        }:
            raise IdentityInventoryError("global identity inventory is malformed")
        if record["user_id"] != apple_user_id:
            continue
        if record["group_type"] not in (0, 1) or record["group_uuid"] != (
            "00000000-0000-0000-0000-000000000000"
        ):
            raise IdentityInventoryError("configured identity is not built-in")
        pair = (
            record["user_id"],
            _canonical_uuid(record["identity_uuid"], "global identity UUID"),
        )
        if pair in pairs:
            raise IdentityInventoryError("global identity inventory is ambiguous")
        pairs.add(pair)
    return pairs


def summarize(
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
) -> dict[str, Any]:
    """Require exact local/live equality and return no biometric identifiers."""
    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise IdentityInventoryError("local identity archive is not validated")
    if not isinstance(live, dict):
        raise IdentityInventoryError("live identity inventory is not a mapping")
    apple_user_id = local.expected_user_id
    if (
        live.get("double_collection_equal") is not True
        or live.get("apple_uid") != apple_user_id
        or live.get("biometric_protocol_version") != 2
        or not isinstance(live.get("catacomb"), dict)
        or live["catacomb"].get("present") is not True
    ):
        raise IdentityInventoryError("live identity inventory is stale or unstable")

    local_pairs = {(identity.user_id, identity.uuid) for identity in local.identities}
    per_user_pairs = _live_pairs(
        live.get("per_user_identity_records"), apple_user_id
    )
    global_pairs = _configured_global_pairs(
        live.get("global_identity_records"), apple_user_id
    )
    if local_pairs != per_user_pairs or per_user_pairs != global_pairs:
        raise IdentityInventoryError("local and live identity inventories disagree")

    ordered = sorted(local.identities, key=lambda identity: identity.entity)
    return {
        "schema_version": 1,
        "identity_count": len(ordered),
        "identities": [
            {
                "slot": position,
                "name": identity.name,
                "live": True,
            }
            for position, identity in enumerate(ordered, 1)
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }
