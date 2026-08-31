# SPDX-License-Identifier: GPL-2.0-only
"""Pure, non-dispatching plan for deleting one reconciled T2 identity."""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
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


def _survivor_snapshot(
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
    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise IdentityDeleteError("local identity archive is not validated")
    if len(local.identities) <= 1:
        raise IdentityDeleteError(
            "single deletion would leave an unverified zero-identity component"
        )
    try:
        selected = t2_identity_inventory.resolve_slot(local, live, slot)
        archive = local.delete(selected.identity_uuid)
        decoded = t2_catacomb_codec.decode_user_catacomb(
            archive, selected.apple_user_id
        )
    except (
        t2_identity_inventory.IdentityInventoryError,
        t2_catacomb_codec.CatacombCodecError,
    ) as error:
        raise IdentityDeleteError(str(error)) from error
    before = {identity.uuid: identity for identity in local.identities}
    after = {identity.uuid: identity for identity in decoded.identities}
    if (
        selected.identity_uuid not in before
        or selected.identity_uuid in after
        or set(after) != set(before) - {selected.identity_uuid}
    ):
        raise IdentityDeleteError("delete plan did not remove exactly its target")
    if any(after[identity_uuid] != before[identity_uuid] for identity_uuid in after):
        raise IdentityDeleteError("delete plan changed surviving identity metadata")
    request = uuid.UUID(selected.identity_uuid).bytes + struct.pack(
        "<I", selected.apple_user_id
    )
    if len(request) != 20:
        raise IdentityDeleteError("delete request is not the recovered 20-byte form")
    return IdentityDeletePlan(
        selected.apple_user_id,
        selected.identity_uuid,
        selected.entity,
        selected.name,
        request,
        _survivor_snapshot(decoded.identities),
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
        or _survivor_snapshot(verified.identities)
        != value.survivor_snapshot_sha256
    ):
        raise IdentityDeleteError(
            "secure-envelope binding changed the deletion survivor set"
        )
    return bytearray(output)
