# SPDX-License-Identifier: GPL-2.0-only
"""Resolve one fprint finger name to private T2 match authority."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

import t2_catacomb_codec
import t2_fprint_projection


class FprintMatchSelectionError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class SelectedMatchIdentity:
    finger_name: str
    identity_record: bytes = field(repr=False)

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "finger_name": self.finger_name,
            "single_identity_selected": True,
            "selection_scope": "fresh-reconciled-private-inventory",
            "finger_name_is_presentation_metadata": True,
            "identifiers_redacted": True,
        }


def _record(value: object, expected_user_id: int) -> tuple[str, bytes]:
    if type(value) is not bytes or len(value) != 20:
        raise FprintMatchSelectionError("T2 identity record is malformed")
    user_id = struct.unpack_from("<I", value)[0]
    try:
        identity_uuid = uuid.UUID(bytes=value[4:20])
    except (ValueError, AttributeError) as error:
        raise FprintMatchSelectionError(
            "T2 identity record UUID is malformed"
        ) from error
    if user_id != expected_user_id or identity_uuid.int == 0:
        raise FprintMatchSelectionError(
            "T2 identity record has the wrong authority"
        )
    return str(identity_uuid), value


def select(
    local: object,
    per_user_identity_records: object,
    finger_name: object,
) -> SelectedMatchIdentity:
    """Resolve only after complete local/live identity and label agreement."""

    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise FprintMatchSelectionError("local Catacomb has the wrong type")
    if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
        raise FprintMatchSelectionError("fprint finger name is invalid")
    identities = local.identities
    names = [identity.name for identity in identities]
    if (
        not identities
        or any(name not in t2_fprint_projection.FINGER_NAME_SET for name in names)
        or len(names) != len(set(names))
    ):
        raise FprintMatchSelectionError(
            "local identities do not have complete unique fprint names"
        )
    selected = [identity for identity in identities if identity.name == finger_name]
    if len(selected) != 1:
        raise FprintMatchSelectionError(
            "requested fprint identity is not uniquely enrolled"
        )
    if (
        type(per_user_identity_records) is not tuple
        or len(per_user_identity_records) != len(identities)
    ):
        raise FprintMatchSelectionError(
            "local and T2 identity inventories disagree"
        )
    parsed: dict[str, bytes] = {}
    for raw in per_user_identity_records:
        identity_uuid, record = _record(raw, local.expected_user_id)
        if identity_uuid in parsed:
            raise FprintMatchSelectionError("T2 identity inventory is duplicated")
        parsed[identity_uuid] = record
    local_uuids = {identity.uuid for identity in identities}
    if set(parsed) != local_uuids:
        raise FprintMatchSelectionError(
            "local and T2 identity inventories disagree"
        )
    return SelectedMatchIdentity(finger_name, parsed[selected[0].uuid])
