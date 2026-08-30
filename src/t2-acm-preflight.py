#!/usr/bin/env python3
"""Read-only registration preflight for the experimental endpoint-10 broker."""

from __future__ import annotations

import fcntl
import json
import os
import struct
import sys
from pathlib import Path


DEVICE = Path("/dev/t2-acm")
PARAMETER = Path("/sys/module/t2_sep_transport/parameters/register_acm")
INFO_FORMAT = "=QII"
INFO_SIZE = struct.calcsize(INFO_FORMAT)


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    if not 0 <= direction < 4 or not 0 <= kind < 256 or not 0 <= number < 256:
        raise ValueError("invalid ioctl field")
    if not 0 <= size < (1 << 14):
        raise ValueError("invalid ioctl size")
    return (direction << 30) | (size << 16) | (kind << 8) | number


T2_ACM_IOC_GET_INFO = _ioc(2, 0xAC, 1, INFO_SIZE)
T2_ACM_INFO_F_POISONED = 1 << 0


def parse_info(buffer: bytes | bytearray) -> tuple[int, int]:
    if len(buffer) != INFO_SIZE:
        raise RuntimeError("endpoint-10 info size is invalid")
    generation, capacity, flags = struct.unpack(INFO_FORMAT, buffer)
    if generation == 0:
        raise RuntimeError("endpoint-10 generation is zero")
    if capacity != 16384:
        raise RuntimeError("endpoint-10 capacity is unexpected")
    if flags & ~T2_ACM_INFO_F_POISONED:
        raise RuntimeError("endpoint-10 info contains unknown flags")
    if flags & T2_ACM_INFO_F_POISONED:
        raise RuntimeError("endpoint-10 has an ambiguous late reply; reboot required")
    return generation, capacity


def collect() -> dict[str, object]:
    parameter = PARAMETER.read_text(encoding="ascii").strip()
    if parameter != "Y":
        raise RuntimeError("endpoint-10 registration is not enabled")
    fd = os.open(DEVICE, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        buffer = bytearray(INFO_SIZE)
        fcntl.ioctl(fd, T2_ACM_IOC_GET_INFO, buffer, True)
    finally:
        os.close(fd)
    generation, capacity = parse_info(buffer)
    return {
        "schema_version": 1,
        "endpoint": 10,
        "registered": True,
        "generation_nonzero": True,
        "capacity": capacity,
        "mutation_performed": False,
    }


def main() -> int:
    if os.geteuid() != 0:
        print("t2-acm-preflight must run as root", file=sys.stderr)
        return 2
    try:
        result = collect()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"t2-acm-preflight: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
