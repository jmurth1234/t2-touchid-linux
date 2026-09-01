# SPDX-License-Identifier: GPL-2.0-only
"""Strict decoder for the proven operation-0x19 keybag state dictionary."""

from __future__ import annotations

import uuid
from dataclasses import dataclass


MAX_DER_BYTES = 16_300
INT32_MIN = -(1 << 31)
INT32_MAX = (1 << 31) - 1
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1


class AKSStateError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class KeybagState:
    handle: int
    maximum_unlock_attempts: int
    backoff: int
    failed_attempts: int
    generation_state: int
    lock_state: int
    more_state: int
    recovery_countdown: int
    state: int
    user_uuid: str

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "maximum_unlock_attempts": self.maximum_unlock_attempts,
            "backoff": self.backoff,
            "failed_attempts": self.failed_attempts,
            "generation_state": self.generation_state,
            "lock_state": self.lock_state,
            "more_state": self.more_state,
            "recovery_countdown": self.recovery_countdown,
            "state": self.state,
            "identifiers_redacted": True,
        }


def _length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise AKSStateError("DER length is truncated")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise AKSStateError("indefinite DER length is forbidden")
    if count > 2 or offset + count > len(data):
        raise AKSStateError("DER length is invalid")
    encoded = data[offset : offset + count]
    if encoded[0] == 0:
        raise AKSStateError("DER length is not minimally encoded")
    value = int.from_bytes(encoded, "big")
    if value < 0x80:
        raise AKSStateError("DER long-form length is not minimal")
    return value, offset + count


def _tlv(data: bytes, offset: int, expected_tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != expected_tag:
        raise AKSStateError("DER tag is unexpected")
    length, content_offset = _length(data, offset + 1)
    end = content_offset + length
    if end > len(data):
        raise AKSStateError("DER value is truncated")
    return data[content_offset:end], end


def _integer(content: bytes, *, signed: bool, field: str) -> int:
    if not content:
        raise AKSStateError(f"{field} integer is empty")
    if len(content) > 1:
        if content[0] == 0 and content[1] < 0x80:
            raise AKSStateError(f"{field} integer has redundant positive padding")
        if content[0] == 0xFF and content[1] >= 0x80:
            raise AKSStateError(f"{field} integer has redundant negative padding")
    if not signed and content[0] & 0x80:
        raise AKSStateError(f"{field} integer is negative")
    value = int.from_bytes(content, "big", signed=signed)
    if signed:
        if not INT32_MIN <= value <= INT32_MAX or value == 0:
            raise AKSStateError(f"{field} is outside the signed handle range")
    elif not 0 <= value <= UINT64_MAX:
        raise AKSStateError(f"{field} is outside the unsigned state range")
    return value


def decode(data: bytes) -> KeybagState:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_DER_BYTES:
        raise AKSStateError("keybag state size is invalid")
    root, end = _tlv(data, 0, 0x31)
    if end != len(data):
        raise AKSStateError("keybag state has trailing data")

    values: dict[str, int | bytes] = {}
    offset = 0
    field_order: list[str] = []
    while offset < len(root):
        sequence, offset = _tlv(root, offset, 0x30)

        key_content, sequence_offset = _tlv(sequence, 0, 0x0C)
        try:
            key = key_content.decode("ascii")
        except UnicodeDecodeError as error:
            raise AKSStateError("keybag state key is not ASCII") from error
        if key in values:
            raise AKSStateError("keybag state contains a duplicate key")
        field_order.append(key)
        if sequence_offset >= len(sequence):
            raise AKSStateError("keybag state value is missing")
        tag = sequence[sequence_offset]
        content, value_end = _tlv(sequence, sequence_offset, tag)
        if value_end != len(sequence):
            raise AKSStateError("keybag state sequence has extra values")
        if tag == 0x02:
            values[key] = _integer(content, signed=key == "bh", field=key)
        elif tag == 0x04:
            values[key] = content
        else:
            raise AKSStateError("keybag state value type is unsupported")

    expected = {
        "bh",
        "mua",
        "sb",
        "sfa",
        "sgs",
        "sls",
        "sms",
        "srcd",
        "ss",
        "uuuid",
    }
    if set(values) != expected:
        raise AKSStateError("keybag state fields are incomplete or unsupported")
    # Apple's DER dictionary encoder orders entries by their UTF-8 key.  It
    # does not apply DER SET OF's bytewise ordering to the complete encoded
    # SEQUENCE values (which would place the shorter `sb` entry first).  Keep
    # this exact live-wire ordering fail-closed instead of accepting arbitrary
    # SET order or imposing the wrong generic DER rule.
    if field_order != sorted(expected):
        raise AKSStateError("keybag state fields are not in Apple key order")
    if not all(type(values[key]) is int for key in expected - {"uuuid"}):
        raise AKSStateError("keybag state integer field has the wrong type")
    raw_uuid = values["uuuid"]
    if not isinstance(raw_uuid, bytes) or len(raw_uuid) != 16:
        raise AKSStateError("keybag user UUID is not exactly 16 bytes")
    parsed_uuid = uuid.UUID(bytes=raw_uuid)
    if parsed_uuid.int == 0:
        raise AKSStateError("keybag user UUID is zero")

    handle = values["bh"]
    maximum_unlock_attempts = values["mua"]
    backoff = values["sb"]
    failed_attempts = values["sfa"]
    generation_state = values["sgs"]
    lock_state = values["sls"]
    more_state = values["sms"]
    recovery_countdown = values["srcd"]
    state = values["ss"]
    assert all(
        type(value) is int
        for value in (
            handle,
            maximum_unlock_attempts,
            backoff,
            failed_attempts,
            generation_state,
            lock_state,
            more_state,
            recovery_countdown,
            state,
        )
    )
    if maximum_unlock_attempts > UINT32_MAX:
        raise AKSStateError("maximum unlock attempts is outside uint32")
    if backoff > UINT32_MAX or failed_attempts > UINT32_MAX:
        raise AKSStateError("keybag retry state is outside uint32")
    if generation_state > UINT32_MAX or more_state > UINT32_MAX:
        raise AKSStateError("keybag generation state is outside uint32")
    if recovery_countdown > UINT32_MAX or state > UINT32_MAX:
        raise AKSStateError("keybag state word is outside uint32")
    if lock_state > 0xFFFF:
        raise AKSStateError("keybag lock state is outside uint16")
    return KeybagState(
        handle,
        maximum_unlock_attempts,
        backoff,
        failed_attempts,
        generation_state,
        lock_state,
        more_state,
        recovery_countdown,
        state,
        str(parsed_uuid),
    )
