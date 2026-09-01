# SPDX-License-Identifier: GPL-2.0-only
"""Pure, non-dispatching plan for deleting one reconciled T2 identity."""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
import t2_fprint_projection
import t2_identity_inventory
import t2_mutation_journal


class IdentityDeleteError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class IdentityDeletePlan:
    apple_user_id: int
    identity_uuid: str
    entity: int
    name: str
    request: bytes
    survivor_snapshot_sha256: str
    archive: bytes

    def __repr__(self) -> str:
        return (
            "IdentityDeletePlan(apple_user_id="
            f"{self.apple_user_id}, identity_uuid=<redacted>, "
            f"entity={self.entity}, name={self.name!r}, request=<redacted>, "
            "survivor_snapshot_sha256="
            f"{self.survivor_snapshot_sha256!r}, archive=<redacted>)"
        )


def survivor_snapshot_sha256(
    identities: tuple[t2_catacomb_codec.Identity, ...],
) -> str:
    records = [
        {
            "user_id": identity.user_id,
            "identity_uuid": identity.uuid,
            "entity": identity.entity,
            "name_sha256": hashlib.sha256(
                identity.name.encode("utf-8")
            ).hexdigest(),
        }
        for identity in sorted(identities, key=lambda value: value.entity)
    ]
    return hashlib.sha256(t2_mutation_journal.canonical(records)).hexdigest()


def plan(
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
    *,
    slot: int,
) -> IdentityDeletePlan:
    """Resolve a current slot and prove a strict one-identity archive rewrite."""
    try:
        selected = t2_identity_inventory.resolve_slot(local, live, slot)
    except t2_identity_inventory.IdentityInventoryError as error:
        raise IdentityDeleteError(str(error)) from error
    return plan_target(local, selected.identity_uuid)


def plan_named(
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
    *,
    finger_name: str,
) -> IdentityDeletePlan:
    """Resolve one canonical fprint name inside a reconciled private snapshot."""
    if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
        raise IdentityDeleteError("delete finger name is not canonical")
    try:
        t2_identity_inventory.summarize(local, live)
    except t2_identity_inventory.IdentityInventoryError as error:
        raise IdentityDeleteError(str(error)) from error
    matches = [
        identity for identity in local.identities if identity.name == finger_name
    ]
    if len(matches) != 1:
        raise IdentityDeleteError(
            "delete finger name is not unique in the reconciled inventory"
        )
    return plan_target(local, matches[0].uuid)


def plan_target(
    local: t2_catacomb_codec.UserCatacomb,
    identity_uuid: str,
) -> IdentityDeletePlan:
    """Rebuild a journal-bound target plan without trusting an ephemeral slot."""
    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise IdentityDeleteError("local identity archive is not validated")
    if len(local.identities) <= 1:
        raise IdentityDeleteError(
            "single deletion would leave an unverified zero-identity component"
        )
    matches = [
        identity for identity in local.identities if identity.uuid == identity_uuid
    ]
    if len(matches) != 1:
        raise IdentityDeleteError("delete target is not unique in the local archive")
    selected = matches[0]
    try:
        archive = local.delete(selected.uuid)
        decoded = t2_catacomb_codec.decode_user_catacomb(
            archive, selected.user_id
        )
    except t2_catacomb_codec.CatacombCodecError as error:
        raise IdentityDeleteError(str(error)) from error
    before = {identity.uuid: identity for identity in local.identities}
    after = {identity.uuid: identity for identity in decoded.identities}
    if (
        selected.uuid not in before
        or selected.uuid in after
        or set(after) != set(before) - {selected.uuid}
    ):
        raise IdentityDeleteError("delete plan did not remove exactly its target")
    if any(after[identity_uuid] != before[identity_uuid] for identity_uuid in after):
        raise IdentityDeleteError("delete plan changed surviving identity metadata")
    request = uuid.UUID(selected.uuid).bytes + struct.pack(
        "<I", selected.user_id
    )
    if len(request) != 20:
        raise IdentityDeleteError("delete request is not the recovered 20-byte form")
    return IdentityDeletePlan(
        selected.user_id,
        selected.uuid,
        selected.entity,
        selected.name,
        request,
        survivor_snapshot_sha256(decoded.identities),
        archive,
    )


def recovery_plan(
    local: t2_catacomb_codec.UserCatacomb,
    *,
    identity_uuid: str,
    entity: int,
    expected_survivor_sha256: str,
) -> IdentityDeletePlan:
    """Rebind an already-committed survivor archive for forward confirmation."""
    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise IdentityDeleteError("local survivor archive is not validated")
    try:
        parsed = uuid.UUID(identity_uuid)
        t2_mutation_journal.require_sha256(
            expected_survivor_sha256, "survivor snapshot"
        )
    except (
        AttributeError,
        TypeError,
        ValueError,
        t2_mutation_journal.JournalError,
    ) as error:
        raise IdentityDeleteError("recovery delete binding is invalid") from error
    if (
        str(parsed) != identity_uuid
        or not isinstance(entity, int)
        or isinstance(entity, bool)
        or not 0 <= entity <= 0xFFFFFFFF
        or not local.identities
        or identity_uuid in {identity.uuid for identity in local.identities}
        or survivor_snapshot_sha256(local.identities)
        != expected_survivor_sha256
    ):
        raise IdentityDeleteError("recovery survivor set differs from the journal")
    request = parsed.bytes + struct.pack("<I", local.expected_user_id)
    archive = local.replace_secure_data(local.secure_data)
    verified = t2_catacomb_codec.decode_user_catacomb(
        archive, local.expected_user_id
    )
    if verified.identities != local.identities:
        raise IdentityDeleteError("recovery archive changed surviving identities")
    return IdentityDeletePlan(
        local.expected_user_id,
        identity_uuid,
        entity,
        "",
        request,
        expected_survivor_sha256,
        archive,
    )


def bind_secure_blob(
    value: IdentityDeletePlan, secure_blob: bytes | bytearray
) -> bytearray:
    """Bind only a fresh SEP user-component envelope to the survivor archive."""
    if not isinstance(value, IdentityDeletePlan):
        raise IdentityDeleteError("delete plan is invalid")
    try:
        decoded = t2_catacomb_codec.decode_user_catacomb(
            value.archive, value.apple_user_id
        )
        output = decoded.replace_secure_data(bytes(secure_blob))
        verified = t2_catacomb_codec.decode_user_catacomb(
            output, value.apple_user_id
        )
    except (TypeError, t2_catacomb_codec.CatacombCodecError) as error:
        raise IdentityDeleteError("fresh secure envelope is invalid") from error
    if (
        value.identity_uuid in {identity.uuid for identity in verified.identities}
        or survivor_snapshot_sha256(verified.identities)
        != value.survivor_snapshot_sha256
    ):
        raise IdentityDeleteError(
            "secure-envelope binding changed the deletion survivor set"
        )
    return bytearray(output)
