# SPDX-License-Identifier: GPL-2.0-only
"""Strict wire contract for exporting SEP's biometric lockout record."""

from __future__ import annotations

import struct
from dataclasses import dataclass


class BioLockoutProtocolError(ValueError):
    """Raised when command 0x4a cannot be interpreted without guessing."""


SAVE_COMMAND = 0x4A
COMMAND_VERSION = 1
# BiometricSupport on the preserved full macOS 14.4 system allocates exactly
# 0x1000 bytes before calling performSaveBioLockoutRecordCommand:.  The 15.7.9
# daemon independently proves that command 0x4a treats the caller's initial
# NSMutableData length as the output capacity and truncates it to the returned
# length.  Keep this target-build corroboration boundary explicit.
OUTPUT_CAPACITY = 0x1000
MIN_SECURE_BLOB_LENGTH = 16
SECURE_BLOB_MAGIC = b"HRLB"
# A local, domain-separated routing token for the generic persistence engine.
# It is journaled only by digest and is never sent to SEP.
PERSISTENCE_DESCRIPTOR = struct.pack(
    "<4sII12s", SECURE_BLOB_MAGIC, SAVE_COMMAND, COMMAND_VERSION, b"\x00" * 12
)


@dataclass(frozen=True)
class SaveRequest:
    command: int = SAVE_COMMAND
    version: int = COMMAND_VERSION
    value: int = 0
    data: bytes = b""
    output_capacity: int = OUTPUT_CAPACITY


def build_save_request() -> SaveRequest:
    return SaveRequest()


def parse_save_reply(status: object, output: object) -> bytearray:
    if type(status) is not int or isinstance(status, bool) or status != 0:
        raise BioLockoutProtocolError("bio-lockout save status is not successful")
    if type(output) is not bytes:
        raise BioLockoutProtocolError("bio-lockout save output is not byte data")
    if not MIN_SECURE_BLOB_LENGTH <= len(output) <= OUTPUT_CAPACITY:
        raise BioLockoutProtocolError("bio-lockout save output length is invalid")
    if not output.startswith(SECURE_BLOB_MAGIC):
        raise BioLockoutProtocolError("bio-lockout save output envelope is invalid")
    return bytearray(output)
