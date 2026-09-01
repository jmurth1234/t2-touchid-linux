# SPDX-License-Identifier: GPL-2.0-only
"""Strict runtime policy for compatibility and truthful fprint identities."""

from __future__ import annotations

from dataclasses import dataclass

import t2_fprint_projection


class FprintRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeProjection:
    finger_names: tuple[str, ...]
    reconciled_identity_count: int
    complete: bool
    compatibility_alias: str

    @property
    def listed_fingers(self) -> tuple[str, ...]:
        if self.complete:
            return self.finger_names
        if self.reconciled_identity_count:
            return (self.compatibility_alias,)
        return ()


@dataclass(frozen=True)
class MatchRequest:
    requested_finger: str
    target_finger: str | None
    match_all: bool
    compatibility_alias_used: bool


def _integer(value: object, field: str) -> int:
    if (
        type(value) is not int
        or not 0 <= value <= len(t2_fprint_projection.FINGER_NAMES)
    ):
        raise FprintRuntimeError(f"{field} is invalid")
    return value


def parse_projection(value: object, compatibility_alias: object) -> RuntimeProjection:
    """Parse only the exact redacted projection emitted by our collector."""

    expected_keys = {
        "schema_version",
        "finger_names",
        "reconciled_identity_count",
        "unassigned_identity_count",
        "duplicate_finger_name_count",
        "complete",
        "compatibility_alias_required",
        "finger_names_are_presentation_metadata",
        "identifiers_redacted",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise FprintRuntimeError("fprint projection has an invalid schema")
    if compatibility_alias not in t2_fprint_projection.FINGER_NAME_SET:
        raise FprintRuntimeError("compatibility alias is invalid")
    names_value = value["finger_names"]
    if type(names_value) is not list or any(
        type(name) is not str or name not in t2_fprint_projection.FINGER_NAME_SET
        for name in names_value
    ):
        raise FprintRuntimeError("fprint projection names are invalid")
    names = tuple(names_value)
    identity_count = _integer(
        value["reconciled_identity_count"], "reconciled identity count"
    )
    unassigned = _integer(
        value["unassigned_identity_count"], "unassigned identity count"
    )
    duplicates = _integer(
        value["duplicate_finger_name_count"], "duplicate finger count"
    )
    complete = value["complete"]
    alias_required = value["compatibility_alias_required"]
    if (
        value["schema_version"] != 1
        or type(complete) is not bool
        or type(alias_required) is not bool
        or value["finger_names_are_presentation_metadata"] is not True
        or value["identifiers_redacted"] is not True
        or alias_required is complete
    ):
        raise FprintRuntimeError("fprint projection flags are invalid")
    canonical_order = tuple(
        name for name in t2_fprint_projection.FINGER_NAMES if name in names
    )
    if complete:
        if (
            names != canonical_order
            or len(names) != len(set(names))
            or len(names) != identity_count
            or unassigned != 0
            or duplicates != 0
        ):
            raise FprintRuntimeError("complete fprint projection is inconsistent")
    elif (
        names
        or unassigned > identity_count
        or duplicates > identity_count - unassigned
        or (unassigned == 0 and duplicates == 0)
    ):
        # Incomplete projections deliberately expose no partial name list.
        raise FprintRuntimeError("incomplete fprint projection is inconsistent")
    return RuntimeProjection(
        names,
        identity_count,
        complete,
        compatibility_alias,
    )


def resolve_match(view: object, requested_finger: object) -> MatchRequest:
    """Resolve presentation only; the probe must re-resolve private authority."""

    if not isinstance(view, RuntimeProjection):
        raise FprintRuntimeError("runtime projection has the wrong type")
    if type(requested_finger) is not str:
        raise FprintRuntimeError("requested finger has the wrong type")
    if requested_finger == "any":
        if not view.reconciled_identity_count:
            raise FprintRuntimeError("no fingerprints are enrolled")
        return MatchRequest("any", None, True, False)
    if view.complete:
        if requested_finger not in view.finger_names:
            raise FprintRuntimeError("requested finger is not enrolled")
        return MatchRequest(requested_finger, requested_finger, False, False)
    if requested_finger != view.compatibility_alias or not view.reconciled_identity_count:
        raise FprintRuntimeError("requested compatibility finger is unavailable")
    return MatchRequest(requested_finger, None, True, True)
