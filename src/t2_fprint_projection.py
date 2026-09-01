# SPDX-License-Identifier: GPL-2.0-only
"""Project reconciled T2 labels onto fprint's fixed finger-name vocabulary."""

from __future__ import annotations

from dataclasses import dataclass

import t2_user_broker_inventory


FINGER_NAMES = (
    "left-thumb",
    "left-index-finger",
    "left-middle-finger",
    "left-ring-finger",
    "left-little-finger",
    "right-thumb",
    "right-index-finger",
    "right-middle-finger",
    "right-ring-finger",
    "right-little-finger",
)
FINGER_NAME_SET = frozenset(FINGER_NAMES)


class FprintProjectionError(ValueError):
    pass


@dataclass(frozen=True)
class FprintProjection:
    finger_names: tuple[str, ...]
    reconciled_identity_count: int
    unassigned_identity_count: int
    duplicate_finger_name_count: int
    complete: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "finger_names": list(self.finger_names),
            "reconciled_identity_count": self.reconciled_identity_count,
            "unassigned_identity_count": self.unassigned_identity_count,
            "duplicate_finger_name_count": self.duplicate_finger_name_count,
            "complete": self.complete,
            "compatibility_alias_required": not self.complete,
            "finger_names_are_presentation_metadata": True,
            "identifiers_redacted": True,
        }


def project(value: object) -> FprintProjection:
    """Return a complete projection only when every identity maps uniquely."""

    try:
        inventory = t2_user_broker_inventory.parse_public_inventory(value)
    except t2_user_broker_inventory.UserBrokerInventoryError as error:
        raise FprintProjectionError(
            "fprint projection requires exact reconciled inventory"
        ) from error
    recognized = [
        identity.name
        for identity in inventory.identities
        if identity.name in FINGER_NAME_SET
    ]
    unassigned = inventory.identity_count - len(recognized)
    duplicates = len(recognized) - len(set(recognized))
    complete = unassigned == 0 and duplicates == 0
    ordered = (
        tuple(name for name in FINGER_NAMES if name in recognized)
        if complete
        else ()
    )
    if complete and len(ordered) != inventory.identity_count:
        raise FprintProjectionError("fprint projection is internally inconsistent")
    return FprintProjection(
        ordered,
        inventory.identity_count,
        unassigned,
        duplicates,
        complete,
    )
