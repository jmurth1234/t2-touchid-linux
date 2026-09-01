#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Identify a scanned T2 fingerprint as an ephemeral reconciled list slot.

This bootstrap helper is read-only.  It intentionally exposes neither the
private SEP identity UUID nor a guessed anatomical name.  Re-list identities
before using the returned slot in a separately acknowledged rename operation.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
SOURCE = (
    LOCAL_SOURCE
    if (LOCAL_SOURCE / "bridge-xpc-probe.py").is_file()
    else INSTALLED_SOURCE
)
PYTHON = (
    Path(sys.executable)
    if SOURCE == LOCAL_SOURCE
    else Path("/opt/t2-touchid/.venv/bin/python")
)
PROBE = SOURCE / "bridge-xpc-probe.py"
CONFIG = Path("/etc/t2-touchid.conf")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
ROOT_UID = 0
MAX_FILE_SIZE = 1024 * 1024


class IdentifyFingerError(RuntimeError):
    pass


def _read_private(path: Path, maximum: int = MAX_FILE_SIZE) -> str:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != ROOT_UID
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= maximum
        ):
            raise IdentifyFingerError(
                f"{path.name} is not private and root-owned"
            )
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(
                descriptor, min(65536, maximum + 1 - len(data))
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            len(data) != before.st_size
            or any(
                getattr(before, field) != getattr(after, field)
                for field in stable_fields
            )
        ):
            raise IdentifyFingerError(f"{path.name} changed during read")
        return data.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise IdentifyFingerError(f"{path.name} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _configuration() -> tuple[str, str, int, int]:
    values: dict[str, list[str]] = {
        "T2_TOUCHID_HOST": [],
        "T2_TOUCHID_INTERFACE": [],
        "T2_TOUCHID_MACOS_USER_ID": [],
    }
    for line in _read_private(CONFIG).splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(found) != 1 for found in values.values()):
        raise IdentifyFingerError(
            "runtime configuration is missing or duplicated"
        )
    host = values["T2_TOUCHID_HOST"][0]
    interface = values["T2_TOUCHID_INTERFACE"][0]
    user_text = values["T2_TOUCHID_MACOS_USER_ID"][0]
    port_text = _read_private(PORT_CACHE, 32).strip()
    if (
        not host
        or len(host.encode("utf-8")) > 255
        or not interface
        or len(interface.encode("utf-8")) > 64
        or not user_text.isascii()
        or not user_text.isdecimal()
        or user_text != str(int(user_text, 10))
        or not 0 <= int(user_text, 10) <= 0xFFFFFFFF
        or not port_text.isascii()
        or not port_text.isdecimal()
        or port_text != str(int(port_text, 10))
        or not 49152 <= int(port_text, 10) <= 65535
    ):
        raise IdentifyFingerError("runtime connection configuration is invalid")
    return host, interface, int(user_text, 10), int(port_text, 10)


@contextmanager
def _operation_lock() -> Iterator[None]:
    descriptor = -1
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(OPERATION_LOCK, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise IdentifyFingerError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IdentifyFingerError(
                "another Touch ID operation is active"
            ) from error
        yield
    except OSError as error:
        raise IdentifyFingerError("operation lock is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def parse_probe_result(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise IdentifyFingerError("finger identification result is malformed")
    gate = value.get("resolved_slot_match_gate")
    post = value.get("resolved_slot_match_post_attestation")
    expected_gate = {
        "schema_version",
        "identity_count",
        "all_identities_selected",
        "same_connection_inventory_stable",
        "local_live_reconciled",
        "slot_scope",
        "identifiers_redacted",
    }
    expected_post = {
        "schema_version",
        "identity_state_unchanged",
        "local_components_unchanged",
        "per_user_inventory_unchanged",
        "global_inventory_unchanged",
        "identifiers_redacted",
    }
    if (
        not isinstance(gate, dict)
        or set(gate) != expected_gate
        or gate.get("schema_version") != 1
        or type(gate.get("identity_count")) is not int
        or not 1 <= gate["identity_count"] <= 10
        or gate.get("all_identities_selected") is not True
        or gate.get("same_connection_inventory_stable") is not True
        or gate.get("local_live_reconciled") is not True
        or gate.get("slot_scope") != "current-reconciled-list"
        or gate.get("identifiers_redacted") is not True
        or not isinstance(post, dict)
        or set(post) != expected_post
        or post.get("schema_version") != 1
        or post.get("identity_state_unchanged") is not True
        or post.get("local_components_unchanged") is not True
        or post.get("per_user_inventory_unchanged") is not True
        or post.get("global_inventory_unchanged") is not True
        or post.get("identifiers_redacted") is not True
    ):
        raise IdentifyFingerError(
            "finger identification attestation is incomplete"
        )
    events = value.get("match_events")
    if not isinstance(events, list):
        raise IdentifyFingerError("finger identification events are malformed")
    results = [
        event
        for event in events
        if isinstance(event, dict) and event.get("event_kind") == "match_result"
    ]
    if len(results) != 1 or type(results[0].get("matched")) is not bool:
        raise IdentifyFingerError(
            "finger identification has no unique match verdict"
        )
    result = results[0]
    if result["matched"]:
        slot = result.get("matched_identity_slot")
        if (
            result.get("matches_enrolled_identity") is not True
            or result.get("matched_identity_slot_present") is not True
            or type(slot) is not int
            or not 1 <= slot <= gate["identity_count"]
        ):
            raise IdentifyFingerError(
                "positive finger identification has no bound slot"
            )
        return {
            "schema_version": 1,
            "matched": True,
            "slot": slot,
            "identity_count": gate["identity_count"],
            "slot_scope": "current-reconciled-list",
            "mutation_performed": False,
            "identifiers_redacted": True,
        }
    if (
        result.get("matches_enrolled_identity") is not False
        or result.get("matched_identity_slot_present") is not False
        or "matched_identity_slot" in result
    ):
        raise IdentifyFingerError("negative finger identification is ambiguous")
    return {
        "schema_version": 1,
        "matched": False,
        "identity_count": gate["identity_count"],
        "slot_scope": "current-reconciled-list",
        "mutation_performed": False,
        "identifiers_redacted": True,
    }


def identify(match_seconds: float) -> dict[str, object]:
    if os.geteuid() != ROOT_UID:
        raise IdentifyFingerError("run through sudo")
    if (
        not isinstance(match_seconds, (int, float))
        or isinstance(match_seconds, bool)
        or not 1 <= match_seconds <= 60
    ):
        raise IdentifyFingerError("match duration is outside 1..60 seconds")
    host, interface, apple_user_id, port = _configuration()
    with _operation_lock():
        command = [
            str(PYTHON),
            str(PROBE),
            "--host",
            host,
            "--interface",
            interface,
            "--port",
            str(port),
            "--timeout",
            "10",
            "--initialize",
            "--reset-sensor",
            "--cancel-operation",
            "--load-calibration",
            "--identity-list",
            "--macos-user-id",
            str(apple_user_id),
            "--match-seconds",
            str(match_seconds),
            "--stop-on-match-result",
            "--resolve-any-identity-slot",
        ]
        print("Touch the Touch ID sensor now.", file=sys.stderr, flush=True)
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=match_seconds + 30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise IdentifyFingerError("finger identification probe failed") from error
    if completed.returncode != 0 or not completed.stdout:
        raise IdentifyFingerError("finger identification probe failed")
    try:
        report = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise IdentifyFingerError(
            "finger identification probe returned malformed data"
        ) from error
    return parse_probe_result(report)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--match-seconds",
        type=float,
        default=30.0,
        help="bounded scan window (default: 30 seconds)",
    )
    args = parser.parse_args()
    try:
        result = identify(args.match_seconds)
    except IdentifyFingerError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
