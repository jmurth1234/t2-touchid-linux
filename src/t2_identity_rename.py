# SPDX-License-Identifier: GPL-2.0-only
"""Pure, non-dispatching plan for one reconciled identity-label update."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
import t2_identity_inventory


class IdentityRenameError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class IdentityRenamePlan:
    apple_user_id: int
    identity_uuid: str
    entity: int
    previous_name: str
    new_name: str
    archive: bytes

    def __repr__(self) -> str:
        return (
            "IdentityRenamePlan(apple_user_id="
            f"{self.apple_user_id}, identity_uuid=<redacted>, "
            f"entity={self.entity}, previous_name={self.previous_name!r}, "
            f"new_name={self.new_name!r}, archive=<redacted>)"
        )


def plan(
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
    *,
    slot: int,
    new_name: str,
) -> IdentityRenamePlan:
    """Resolve an ephemeral slot and build a strictly decoded renamed archive."""
    if (
        not isinstance(new_name, str)
        or not new_name
        or "\x00" in new_name
        or len(new_name.encode("utf-8")) > t2_catacomb_codec.MAX_STRING_BYTES
    ):
        raise IdentityRenameError("new identity name is invalid")
    try:
        selected = t2_identity_inventory.resolve_slot(local, live, slot)
    except t2_identity_inventory.IdentityInventoryError as error:
        raise IdentityRenameError(str(error)) from error
    if new_name == selected.name:
        raise IdentityRenameError("new identity name is unchanged")
    if any(
        identity.uuid != selected.identity_uuid and identity.name == new_name
        for identity in local.identities
    ):
        raise IdentityRenameError("new identity name is already assigned")
    try:
        archive = local.rename(selected.identity_uuid, new_name)
        decoded = t2_catacomb_codec.decode_user_catacomb(
            archive, selected.apple_user_id
        )
    except t2_catacomb_codec.CatacombCodecError as error:
        raise IdentityRenameError("renamed archive did not pass strict decoding") from error
    before = {identity.uuid: identity for identity in local.identities}
    after = {identity.uuid: identity for identity in decoded.identities}
    if set(before) != set(after):
        raise IdentityRenameError("rename changed the identity set")
    for identity_uuid, old in before.items():
        new = after[identity_uuid]
        expected_name = new_name if identity_uuid == selected.identity_uuid else old.name
        if new != old.__class__(
            uuid=old.uuid,
            user_id=old.user_id,
            entity=old.entity,
            name=expected_name,
            identity_type=old.identity_type,
            flags=old.flags,
            attribute=old.attribute,
            match_count=old.match_count,
            continuous_match_count=old.continuous_match_count,
            update_count=old.update_count,
            creation_time=old.creation_time,
        ):
            raise IdentityRenameError("rename changed non-label identity metadata")
    return IdentityRenamePlan(
        selected.apple_user_id,
        selected.identity_uuid,
        selected.entity,
        selected.name,
        new_name,
        archive,
    )


def bind_secure_blob(
    value: IdentityRenamePlan, secure_blob: bytes | bytearray
) -> bytearray:
    """Replace only the operation-fresh SEP secure envelope and revalidate."""
    if not isinstance(value, IdentityRenamePlan):
        raise IdentityRenameError("rename plan is invalid")
    try:
        decoded = t2_catacomb_codec.decode_user_catacomb(
            value.archive, value.apple_user_id
        )
        output = decoded.replace_secure_data(bytes(secure_blob))
        verified = t2_catacomb_codec.decode_user_catacomb(
            output, value.apple_user_id
        )
    except (TypeError, t2_catacomb_codec.CatacombCodecError) as error:
        raise IdentityRenameError("fresh secure envelope is invalid") from error
    target = [
        identity
        for identity in verified.identities
        if identity.uuid == value.identity_uuid
    ]
    if len(target) != 1 or target[0].name != value.new_name:
        raise IdentityRenameError("secure-envelope binding changed the rename target")
    return bytearray(output)
