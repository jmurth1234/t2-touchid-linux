#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only BridgeXPC transport probe for the Intel T2 biometric service.

The default action performs only the protocol HELO exchange.  It never sends
a BridgeXPC application message (frame type 2).
"""

import argparse
import hashlib
import json
import os
import plistlib
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import time
import uuid

LOCAL_SOURCE = os.path.dirname(os.path.abspath(__file__))
if LOCAL_SOURCE not in sys.path:
    sys.path.insert(0, LOCAL_SOURCE)

from t2_bridge_wire import (
    BIOMETRIC_COMMAND_HEADER,
    BIOMETRIC_COMMAND_MAGIC,
    HEADER,
    MAGIC,
    PROTOCOL_VERSION,
    TYPE_HELO,
    TYPE_MESSAGE,
    biometric_command,
    describe,
    is_biometric_nil_output,
    receive_envelope,
    receive_exact,
    receive_frame,
    request,
    request_with_events,
    send_helo,
    send_message,
)
from t2_enrollment_protocol import parse_service_event


def summarize_event(
    payload: object,
    enrolled_identity_records: tuple[bytes, ...] = (),
    *,
    expected_user_id: int | None = None,
) -> dict:
    if isinstance(payload, list) and len(payload) == 5 and payload[0] == 9:
        data = payload[2]
        summary = {
            "method": "serviceStatus",
            "bridge_status": payload[1],
            "data_length": len(data) if isinstance(data, bytes) else None,
        }
        if isinstance(data, bytes) and len(data) >= 24:
            try:
                parsed_common_event = parse_service_event(data)
            except (TypeError, ValueError):
                parsed_common_event = None
            summary["common_record_valid"] = parsed_common_event is not None
            reserved, embedded_type, version, event_timestamp = struct.unpack_from(
                "<QIIQ", data
            )
            summary.update(
                reserved_zero=reserved == 0,
                embedded_type=f"0x{embedded_type:08x}",
                version=version,
                event_timestamp_present=event_timestamp > 0,
            )
            event_data = data[24:]
            if embedded_type == 0xE3FF8001:
                summary["event_kind"] = "status"
                if len(event_data) >= 4:
                    status_code = struct.unpack_from(
                        "<I", event_data
                    )[0]
                    summary["status_code"] = status_code
                    summary["ordinal"] = status_code
                    summary["parsed_ordinal_matches"] = (
                        parsed_common_event is not None
                        and parsed_common_event.ordinal == status_code
                    )
                if len(event_data) >= 16:
                    summary["status_data_length"] = struct.unpack_from(
                        "<Q", event_data, 8
                    )[0]
            elif embedded_type == 0xE3FF8002:
                summary["event_kind"] = "match_result"
                # Apple validates at least 0xc70 bytes before parsing this
                # structure.  Protocol v2 does not identify a successful
                # template in its first signed word: controlled scans showed
                # that word remains -1 for both outcomes.  Instead, a success
                # contains the selected identity UUID, while a negative scan
                # does not.  Never emit the UUID, image metrics, or biometric
                # payload itself.
                if len(event_data) >= 0xC70:
                    # identity_record_v1_t is a four-byte user ID followed by
                    # a 16-byte UUID.  Match-result layouts vary by protocol
                    # version, so compare only the opaque UUID inside this
                    # already authenticated event and expose a boolean—not
                    # the identifier or biometric payload.
                    enrolled_uuids = tuple(
                        record[4:20]
                        for record in enrolled_identity_records
                        if len(record) == 20
                    )
                    summary["contains_enrolled_identity_uuid"] = any(
                        identity_uuid in event_data
                        for identity_uuid in enrolled_uuids
                    )
                    summary["matched"] = summary[
                        "contains_enrolled_identity_uuid"
                    ]
                    summary["matches_enrolled_identity"] = summary[
                        "contains_enrolled_identity_uuid"
                    ]
            elif embedded_type == 0xE3FF8004:
                summary["event_kind"] = "statistics"
            elif embedded_type == 0xE3FF800A:
                # Keep live protocol diagnostics useful without emitting the
                # Apple user ID, SKS state, or opaque trailing bytes.
                summary["event_kind"] = "sks_lock_state"
                summary["event_data_length"] = len(event_data)
                if expected_user_id is not None and len(event_data) >= 4:
                    summary["user_id_matches_configured"] = (
                        struct.unpack_from("<I", event_data)[0] == expected_user_id
                    )
            else:
                summary["event_kind"] = "other"
        return summary
    return {"method": "unknown", "value_type": type(payload).__name__}


def summarize_command_reply(reply: object) -> dict:
    """Return JSON-safe details without assuming a successful command reply."""
    if not isinstance(reply, list) or not reply:
        return {"valid": False, "raw_type": type(reply).__name__}
    status = reply[0]
    summary = {"valid": isinstance(status, int), "status": status}
    if isinstance(status, int):
        summary["status_hex"] = f"0x{status & 0xffffffff:08x}"
    if len(reply) > 1:
        output = reply[1]
        summary["output_length"] = len(output) if isinstance(output, bytes) else None
        if is_biometric_nil_output(output):
            summary["output_kind"] = "nil-placeholder"
    return summary


def write_private_json(path: str, value: object) -> None:
    """Exclusively write root-only private inventory; never overwrite state."""
    if os.geteuid() != 0:
        raise PermissionError("private inventory output requires root")
    destination = os.path.abspath(path)
    parent = os.path.dirname(destination)
    parent_info = os.stat(parent, follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_mode & 0o077
    ):
        raise PermissionError("private inventory parent must be root-owned mode 0700")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        destination_info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(destination_info.st_mode)
            or destination_info.st_uid != 0
            or destination_info.st_nlink != 1
        ):
            raise PermissionError("private inventory output is not a root-owned regular file")
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        payload += b"\n"
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        os.close(descriptor)


def reply_bytes(reply: object) -> bytes | None:
    if (
        isinstance(reply, list)
        and len(reply) > 1
        and reply[0] == 0
        and isinstance(reply[1], bytes)
    ):
        return reply[1]
    return None


def collect_full_inventory(sock: socket.socket, macos_user_id: int) -> dict:
    uid_data = struct.pack("<I", macos_user_id)
    commands = {
        "protocol": (1, b"", 4),
        "global_identities": (0x51, b"", 40 * 10),
        "maximum_capacity": (0x0F, b"", 4),
        "per_user_identities": (0x42, uid_data, 20 * 10),
        "free_capacity": (0x41, uid_data, 4),
        "catacomb_uuid": (0x38, uid_data, 16),
        "catacomb_hash": (0x3A, uid_data, 33),
        "catacomb_state": (0x3C, b"", 4096),
        "sks_lock_state": (0x27, uid_data, 4),
    }
    replies = {}
    events = {}
    for name, (command, data, capacity) in commands.items():
        replies[name], events[name] = biometric_command(
            sock, command, data=data, output_capacity=capacity
        )
        # A freshly opened BiometricKit session can acknowledge the first
        # protocol query without returning its four-byte payload.  The query
        # is read-only and idempotent, so retry only this missing reply.  All
        # other inventory fields remain single-read per snapshot.
        if name == "protocol":
            for _attempt in range(2):
                protocol_payload = reply_bytes(replies[name])
                if isinstance(protocol_payload, bytes) and len(protocol_payload) == 4:
                    break
                retry_reply, retry_events = biometric_command(
                    sock, command, data=data, output_capacity=capacity
                )
                replies[name] = retry_reply
                events[name].extend(retry_events)
    return {"replies": replies, "events": events}


def summarize_full_inventory(
    first: dict, second: dict, macos_user_id: int, connection_generation: str, helo: dict
) -> tuple[dict, dict]:
    a = first["replies"]
    b = second["replies"]
    equality = {name: a[name] == b[name] for name in a}
    protocol = reply_bytes(a["protocol"])
    global_output = reply_bytes(a["global_identities"])
    maximum_output = reply_bytes(a["maximum_capacity"])
    per_user_output = reply_bytes(a["per_user_identities"])
    free_output = reply_bytes(a["free_capacity"])
    uuid_output = reply_bytes(a["catacomb_uuid"])
    hash_output = reply_bytes(a["catacomb_hash"])
    state_output = reply_bytes(a["catacomb_state"])
    sks_output = reply_bytes(a["sks_lock_state"])

    per_user_valid = isinstance(per_user_output, bytes) and len(per_user_output) % 20 == 0
    global_valid = isinstance(global_output, bytes) and len(global_output) % 40 == 0
    per_user_records = (
        tuple(per_user_output[offset : offset + 20] for offset in range(0, len(per_user_output), 20))
        if per_user_valid
        else ()
    )
    global_records = (
        tuple(global_output[offset : offset + 40] for offset in range(0, len(global_output), 40))
        if global_valid
        else ()
    )
    configured_global = {
        record[:20]
        for record in global_records
        if struct.unpack_from("<I", record)[0] == macos_user_id
    }
    reconciled = per_user_valid and global_valid and configured_global == set(per_user_records)
    explicit_protocol_v2 = (
        isinstance(protocol, bytes)
        and len(protocol) == 4
        and struct.unpack("<I", protocol)[0] == 2
    )
    # Global identity command 0x51 exists only in protocol v2.  A successful,
    # structurally valid reply therefore attests v2 even on firmware sessions
    # that reject the standalone command-1 query with kIOReturnBadArgument.
    protocol_v2_attested = explicit_protocol_v2 or global_valid

    public = {
        "biometric_protocol_reply": summarize_command_reply(a["protocol"]),
        "identity_list_reply": summarize_command_reply(a["per_user_identities"]),
        "identity_record_bytes_valid": per_user_valid,
        "identity_record_count": len(per_user_records) if per_user_valid else None,
        "identity_user_field": (
            "prefix"
            if per_user_records
            and all(struct.unpack_from("<I", record)[0] == macos_user_id for record in per_user_records)
            else None
        ),
        "global_identity_list_reply": summarize_command_reply(a["global_identities"]),
        "global_identity_record_bytes_valid": global_valid,
        "global_identity_record_count": len(global_records) if global_valid else None,
        "configured_identity_records_reconciled": reconciled,
        "biometric_protocol_v2_attested": protocol_v2_attested,
        "biometric_protocol_attestation": (
            "command-1" if explicit_protocol_v2 else "v2-global-identity-command"
        ) if protocol_v2_attested else None,
        "identity_capacity_reply": summarize_command_reply(a["maximum_capacity"]),
        "identity_free_count_reply": summarize_command_reply(a["free_capacity"]),
        "catacomb_uuid_reply": summarize_command_reply(a["catacomb_uuid"]),
        "catacomb_hash_reply": summarize_command_reply(a["catacomb_hash"]),
        "catacomb_uuid_length_valid": isinstance(uuid_output, bytes) and len(uuid_output) == 16,
        "catacomb_hash_length_valid": isinstance(hash_output, bytes) and len(hash_output) == 33,
        "catacomb_state_reply": summarize_command_reply(a["catacomb_state"]),
        "sks_lock_state_reply": summarize_command_reply(a["sks_lock_state"]),
        "identity_inventory_repeat_equal": equality["per_user_identities"],
        "global_identity_inventory_repeat_equal": equality["global_identities"],
        "identity_capacity_repeat_equal": equality["maximum_capacity"] and equality["free_capacity"],
        "catacomb_component_repeat_equal": equality["catacomb_uuid"] and equality["catacomb_hash"],
        "catacomb_state_repeat_equal": equality["catacomb_state"],
        "sks_lock_state_repeat_equal": equality["sks_lock_state"],
        "full_snapshot_repeat_equal": all(equality.values()),
    }
    if isinstance(protocol, bytes) and len(protocol) == 4:
        public["biometric_protocol_version"] = struct.unpack("<I", protocol)[0]
    if isinstance(maximum_output, bytes) and len(maximum_output) == 4:
        public["identity_maximum_capacity"] = struct.unpack("<I", maximum_output)[0]
    if isinstance(free_output, bytes) and len(free_output) == 4:
        public["identity_free_count"] = struct.unpack("<I", free_output)[0]
    if isinstance(hash_output, bytes) and len(hash_output) == 33:
        public["catacomb_component_present"] = bool(hash_output[0])
    if isinstance(state_output, bytes) and len(state_output) in (8, 16):
        public["catacomb_state_words"] = list(
            struct.unpack("<" + "I" * (len(state_output) // 4), state_output)
        )
    if isinstance(sks_output, bytes) and len(sks_output) == 4:
        public["sks_lock_state"] = struct.unpack("<I", sks_output)[0]

    private_gate = {
        "snapshot_stable": all(equality.values()),
        "identity_lists_reconciled": reconciled,
        "protocol_v2_attested": protocol_v2_attested,
        "maximum_capacity_length": isinstance(maximum_output, bytes) and len(maximum_output) == 4,
        "free_capacity_length": isinstance(free_output, bytes) and len(free_output) == 4,
        "catacomb_uuid_length": isinstance(uuid_output, bytes) and len(uuid_output) == 16,
        "catacomb_hash_length": isinstance(hash_output, bytes) and len(hash_output) == 33,
        "catacomb_state_present": isinstance(state_output, bytes),
        "sks_lock_state_length": isinstance(sks_output, bytes) and len(sks_output) == 4,
    }
    failures = [name for name, passed in private_gate.items() if not passed]
    public["private_inventory_complete"] = not failures
    public["private_inventory_gate_failures"] = failures
    if failures:
        return public, {}
    bridge_boot_uuid = helo.get("BootSessionUUID")
    try:
        bridge_boot_uuid = str(uuid.UUID(bridge_boot_uuid))
    except (AttributeError, TypeError, ValueError):
        bridge_boot_uuid = None
    private = {
        "schema_version": 1,
        "connection_generation": connection_generation,
        "bridge_boot_uuid": bridge_boot_uuid,
        "biometric_protocol_version": 2,
        "apple_uid": macos_user_id,
        "per_user_identity_records": [
            {
                "user_id": struct.unpack_from("<I", record)[0],
                "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
            }
            for record in per_user_records
        ],
        "global_identity_records": [
            {
                "user_id": struct.unpack_from("<I", record)[0],
                "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                "group_type": struct.unpack_from("<I", record, 20)[0],
                "group_uuid": str(uuid.UUID(bytes=record[24:40])),
            }
            for record in global_records
        ],
        "maximum_capacity": struct.unpack("<I", maximum_output)[0],
        "configured_user_free_capacity": struct.unpack("<I", free_output)[0],
        "catacomb": {
            "uuid": str(uuid.UUID(bytes=uuid_output)),
            "present": bool(hash_output[0]),
            "hash": hash_output[1:].hex(),
            "global_state": state_output.hex(),
        },
        "sks_lock_state_raw": struct.unpack("<I", sks_output)[0],
        "double_collection_equal": True,
    }
    return public, private


def read_catacomb_payloads(
    archive_path: str, macos_user_id: int = 501
) -> list[tuple[str, int, bytes]]:
    """Validate a macOS v3 catacomb archive and return opaque load payloads."""
    user_name = f"user_{macos_user_id:08x}.cat"
    expected = {"master.cat": -1, user_name: macos_user_id}
    found = {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name not in expected:
                continue
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError(f"unsafe catacomb archive member: {member.name}")
            if name in found:
                raise ValueError(f"duplicate catacomb archive member: {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"could not read catacomb archive member: {name}")
            found[name] = plistlib.loads(stream.read())

    if set(found) != set(expected):
        missing = sorted(set(expected) - set(found))
        raise ValueError(f"catacomb archive is missing: {', '.join(missing)}")

    payloads = []
    for name in ("master.cat", user_name):
        root = found[name]
        if not isinstance(root, dict):
            raise ValueError(f"{name} is not a keyed archive")
        top = root.get("$top")
        objects = root.get("$objects")
        if not isinstance(top, dict) or not isinstance(objects, list):
            raise ValueError(f"{name} has an invalid keyed-archive structure")
        if top.get("CatacombVersion") != 0x30000:
            raise ValueError(f"{name} is not a version-3 catacomb")
        if top.get("CatacombUserID") != expected[name]:
            raise ValueError(f"{name} has an unexpected user ID")
        data_uid = top.get("CatacombSecureData")
        if not isinstance(data_uid, plistlib.UID) or data_uid.data >= len(objects):
            raise ValueError(f"{name} has no secure-data object")
        data_object = objects[data_uid.data]
        data = data_object.get("NS.data") if isinstance(data_object, dict) else None
        if not isinstance(data, bytes) or len(data) < 16:
            raise ValueError(f"{name} has invalid secure data")
        if struct.unpack_from("<I", data)[0] != 0x4346544C:  # "LTFC"
            raise ValueError(f"{name} has an invalid secure-data header")
        payloads.append((name, expected[name], data))
    return payloads


def read_biolockout_payload(archive_path: str) -> bytes:
    """Validate and return macOS's opaque encrypted bio-lockout record."""
    with tarfile.open(archive_path, "r:gz") as archive:
        members = [
            member
            for member in archive.getmembers()
            if member.name.rsplit("/", 1)[-1] == "biolockout.cat"
        ]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 65536:
            raise ValueError("archive must contain one regular biolockout.cat")
        stream = archive.extractfile(members[0])
        if stream is None:
            raise ValueError("could not read biolockout.cat")
        root = plistlib.loads(stream.read())
    top = root.get("$top") if isinstance(root, dict) else None
    objects = root.get("$objects") if isinstance(root, dict) else None
    if not isinstance(top, dict) or not isinstance(objects, list):
        raise ValueError("biolockout.cat has an invalid keyed archive")
    if top.get("BioLockoutRecordVersion") != 0x10000:
        raise ValueError("biolockout.cat has an unexpected version")
    data_uid = top.get("BioLockoutRecordSecureData")
    if not isinstance(data_uid, plistlib.UID) or data_uid.data >= len(objects):
        raise ValueError("biolockout.cat has no secure-data object")
    data_object = objects[data_uid.data]
    data = data_object.get("NS.data") if isinstance(data_object, dict) else None
    if not isinstance(data, bytes) or len(data) < 16 or data[:4] != b"HRLB":
        raise ValueError("biolockout.cat has invalid secure data")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--macos-user-id",
        type=int,
        default=int(os.environ.get("T2_TOUCHID_MACOS_USER_ID", "501")),
        help="numeric macOS user identity to scope biometric operations",
    )
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument(
        "--port",
        type=int,
        default=(
            int(os.environ["T2_TOUCHID_PORT"])
            if "T2_TOUCHID_PORT" in os.environ
            else None
        ),
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument(
        "--service-open",
        action="store_true",
        help="send Apple's read-only getServiceOpened request after HELO",
    )
    parser.add_argument(
        "--bridge-version",
        action="store_true",
        help="send Apple's read-only getBridgeVersion request after HELO",
    )
    parser.add_argument(
        "--initialize",
        action="store_true",
        help="negotiate the BiometricKit bridge API version",
    )
    parser.add_argument(
        "--match-seconds",
        type=float,
        metavar="SECONDS",
        help="start a match operation, report status events, then cancel",
    )
    parser.add_argument(
        "--match-processed-flags",
        type=lambda value: int(value, 0),
        default=0,
        help="processed match flags (default: 0; use 1 for an unlock match)",
    )
    parser.add_argument(
        "--identity-blob-format",
        choices=("counted", "raw"),
        default="counted",
        help="selected identity blob representation (default: counted)",
    )
    parser.add_argument(
        "--stop-on-match-result",
        action="store_true",
        help="end the timed match as soon as SEP emits a match verdict",
    )
    parser.add_argument(
        "--audible-match-alert",
        action="store_true",
        help="play the desktop alert immediately before starting a match",
    )
    parser.add_argument(
        "--biometric-protocol",
        action="store_true",
        help="read the sensor command protocol version (biometric command 1)",
    )
    parser.add_argument(
        "--reset-sensor",
        action="store_true",
        help="run Apple's sensor reset command before other biometric commands",
    )
    parser.add_argument(
        "--cancel-operation",
        action="store_true",
        help="cancel any outstanding sensor operation (biometric command 12)",
    )
    parser.add_argument(
        "--sensor-readiness",
        action="store_true",
        help="read the one-byte sensor-ready state (biometric command 0x53)",
    )
    parser.add_argument(
        "--sensor-info",
        action="store_true",
        help="read the 12-byte sensor information record (command 0x35)",
    )
    parser.add_argument(
        "--calibration-info",
        action="store_true",
        help="read calibration blob metadata from bridgeOS without saving it",
    )
    parser.add_argument(
        "--load-calibration",
        action="store_true",
        help="load bridgeOS FDR calibration into the sensor (Apple command 0x20)",
    )
    parser.add_argument(
        "--identity-list",
        action="store_true",
        help="query the SEP identity-record count for the configured macOS user",
    )
    parser.add_argument(
        "--global-identity-list",
        action="store_true",
        help="query protocol-v2 global SEP identity records (command 0x51)",
    )
    parser.add_argument(
        "--identity-capacity",
        action="store_true",
        help="query maximum and configured-user free identity capacity",
    )
    parser.add_argument(
        "--catacomb-component-state",
        action="store_true",
        help="query configured-user SEP Catacomb UUID/presence/hash metadata",
    )
    parser.add_argument(
        "--stability-check",
        action="store_true",
        help="repeat requested inventory queries and report exact private equality",
    )
    parser.add_argument(
        "--full-inventory",
        action="store_true",
        help="collect complete inventory snapshots A and B on one connection",
    )
    parser.add_argument(
        "--private-inventory-output",
        metavar="PATH",
        help="write raw root-only inventory to a new file (never stdout)",
    )
    parser.add_argument(
        "--catacomb-state",
        action="store_true",
        help="query SEP catacomb state metadata without returning its contents",
    )
    parser.add_argument(
        "--sks-lock-state",
        action="store_true",
        help="query the secure-key-store lock state for the configured macOS user",
    )
    parser.add_argument(
        "--load-catacomb-archive",
        metavar="PATH",
        help="validate and load encrypted macOS v3 catacomb components (command 0x40)",
    )
    parser.add_argument(
        "--load-biolockout-archive",
        metavar="PATH",
        help="restore the encrypted macOS bio-lockout record (command 0x4b)",
    )
    parser.add_argument(
        "--catacomb-component",
        choices=("all", "master", "user"),
        default="all",
        help="select which validated catacomb component to load (default: all)",
    )
    parser.add_argument(
        "--strip-catacomb-file-header",
        action="store_true",
        help="strip the validated 32-byte LTFC file wrapper before command 0x40",
    )
    args = parser.parse_args()
    if not 0 <= args.macos_user_id <= 0xFFFFFFFF:
        parser.error("--macos-user-id must fit an unsigned 32-bit integer")
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if args.port is None:
        parser.error("set --port or T2_TOUCHID_PORT")

    scope_id = socket.if_nametoindex(args.interface)
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        sock.settimeout(args.timeout)
        sock.connect((args.host, args.port, 0, scope_id))
        frame_type, body = receive_frame(sock)
        if frame_type != TYPE_HELO:
            raise ValueError(f"expected HELO frame, received type {frame_type}")
        helo = describe(frame_type, body)
        send_helo(sock, int(helo.get("BridgeXPCVersion", 39)))
        result = {"peer_helo": helo, "sent": "HELO only"}
        operations = []
        connection_generation = str(uuid.uuid4())
        enrolled_identity_records: tuple[bytes, ...] = ()
        global_identity_records: tuple[bytes, ...] = ()
        maximum_output = None
        free_output = None
        uuid_output = None
        hash_output = None
        catacomb_state_output = None
        private_inventory = None
        if args.initialize:
            version_reply = request(sock, [0])
            if (
                not isinstance(version_reply, list)
                or len(version_reply) != 2
                or version_reply[0] != 0
            ):
                raise ValueError(f"getBridgeVersion failed: {version_reply!r}")
            api_version = version_reply[1]
            result["bridge_version_reply"] = version_reply
            # Apple's matching daemon deliberately negotiates API v2 even
            # when bkremoted advertises v3; v3 only gates transaction sync.
            client_version = min(api_version, 2)
            result["set_client_version_reply"] = request(
                sock, [10, client_version]
            )
            result["bridge_client_version"] = client_version
            operations.append("version negotiation")
        if args.full_inventory:
            if not args.initialize:
                raise ValueError("--full-inventory requires --initialize")
            first_inventory = collect_full_inventory(sock, args.macos_user_id)
            second_inventory = collect_full_inventory(sock, args.macos_user_id)
            public_inventory, private_inventory = summarize_full_inventory(
                first_inventory,
                second_inventory,
                args.macos_user_id,
                connection_generation,
                helo,
            )
            result.update(public_inventory)
            operations.append("full inventory snapshots A/B")
        if args.bridge_version:
            result["bridge_version_reply"] = request(sock, [0])
            operations.append("getBridgeVersion")
        if args.service_open:
            result["service_reply"] = request(sock, [1])
            operations.append("getServiceOpened")
        if args.reset_sensor:
            if not args.initialize:
                raise ValueError("--reset-sensor requires --initialize")
            reset_reply, reset_events = biometric_command(sock, 2, value=2)
            result["reset_sensor_reply"] = summarize_command_reply(reset_reply)
            result["reset_sensor_events"] = [
                summarize_event(event) for event in reset_events
            ]
            operations.append("reset sensor")
        if args.cancel_operation:
            if not args.initialize:
                raise ValueError("--cancel-operation requires --initialize")
            cancel_reply, cancel_events = biometric_command(sock, 12)
            result["cancel_operation_reply"] = summarize_command_reply(
                cancel_reply
            )
            result["cancel_operation_events"] = [
                summarize_event(event) for event in cancel_events
            ]
            operations.append("cancel operation")
        if args.biometric_protocol:
            protocol_reply, protocol_events = biometric_command(
                sock, 1, output_capacity=4
            )
            result["biometric_protocol_reply"] = summarize_command_reply(
                protocol_reply
            )
            if (
                isinstance(protocol_reply, list)
                and len(protocol_reply) > 1
                and isinstance(protocol_reply[1], bytes)
                and len(protocol_reply[1]) == 4
            ):
                result["biometric_protocol_version"] = struct.unpack(
                    "<I", protocol_reply[1]
                )[0]
            result["biometric_protocol_events"] = [
                summarize_event(event) for event in protocol_events
            ]
            operations.append("get biometric protocol")
        if args.sensor_readiness:
            readiness_reply, readiness_events = biometric_command(
                sock, 0x53, output_capacity=1
            )
            result["sensor_readiness_reply"] = summarize_command_reply(
                readiness_reply
            )
            if (
                isinstance(readiness_reply, list)
                and len(readiness_reply) > 1
                and isinstance(readiness_reply[1], bytes)
                and len(readiness_reply[1]) == 1
            ):
                result["sensor_ready"] = bool(readiness_reply[1][0])
            result["sensor_readiness_events"] = [
                summarize_event(event) for event in readiness_events
            ]
            operations.append("get sensor readiness")
        if args.sensor_info:
            sensor_info_reply, sensor_info_events = biometric_command(
                sock, 0x35, output_capacity=12
            )
            result["sensor_info_reply"] = summarize_command_reply(
                sensor_info_reply
            )
            if (
                isinstance(sensor_info_reply, list)
                and len(sensor_info_reply) > 1
                and isinstance(sensor_info_reply[1], bytes)
                and len(sensor_info_reply[1]) == 12
            ):
                result["sensor_info_words"] = list(
                    struct.unpack("<III", sensor_info_reply[1])
                )
            result["sensor_info_events"] = [
                summarize_event(event) for event in sensor_info_events
            ]
            operations.append("get sensor info")
        if args.calibration_info:
            calibration = {}
            for label, method in (("eeprom", 5), ("fdr", 11)):
                reply, events = request_with_events(sock, [method])
                entry = {"reply_type": type(reply).__name__}
                if isinstance(reply, list) and len(reply) == 1:
                    blob = reply[0]
                    if isinstance(blob, bytes):
                        entry.update(
                            length=len(blob), sha256=hashlib.sha256(blob).hexdigest()
                        )
                    elif blob is None:
                        entry["available"] = False
                entry["events"] = [summarize_event(event) for event in events]
                calibration[label] = entry
            result["calibration"] = calibration
            operations.append("read calibration metadata")
        if args.load_calibration:
            if not args.initialize:
                raise ValueError("--load-calibration requires --initialize")
            fdr_reply, fdr_events = request_with_events(sock, [11])
            if (
                not isinstance(fdr_reply, list)
                or len(fdr_reply) != 1
                or not isinstance(fdr_reply[0], bytes)
                or not fdr_reply[0]
            ):
                raise ValueError("bridgeOS returned no usable FDR calibration data")
            # Source 3 is remote/bridgeOS FDR. Source 5 is only for the local
            # macOS filesystem calibration file.
            calibration_reply, calibration_events = biometric_command(
                sock, 0x20, value=3, data=fdr_reply[0]
            )
            result["load_calibration_reply"] = summarize_command_reply(
                calibration_reply
            )
            result["load_calibration_source"] = "bridgeOS FDR"
            result["load_calibration_length"] = len(fdr_reply[0])
            result["load_calibration_events"] = [
                summarize_event(event)
                for event in fdr_events + calibration_events
            ]
            operations.append("load FDR calibration")
        if args.identity_list:
            identities_reply, identities_events = biometric_command(
                sock, 0x42, data=struct.pack("<I", args.macos_user_id), output_capacity=20 * 10
            )
            result["identity_list_reply"] = summarize_command_reply(
                identities_reply
            )
            if (
                isinstance(identities_reply, list)
                and len(identities_reply) > 1
                and isinstance(identities_reply[1], bytes)
            ):
                result["identity_record_count"] = len(identities_reply[1]) // 20
                result["identity_record_bytes_valid"] = (
                    len(identities_reply[1]) % 20 == 0
                )
                if result["identity_record_bytes_valid"]:
                    enrolled_identity_records = tuple(
                        identities_reply[1][offset : offset + 20]
                        for offset in range(0, len(identities_reply[1]), 20)
                    )
                    result["identity_user_field"] = (
                        "prefix"
                        if all(
                            struct.unpack_from("<I", record)[0] == args.macos_user_id
                            for record in enrolled_identity_records
                        )
                        else "suffix"
                        if all(
                            struct.unpack_from("<I", record, 16)[0] == args.macos_user_id
                            for record in enrolled_identity_records
                        )
                        else "unknown"
                    )
            result["identity_list_events"] = [
                summarize_event(event) for event in identities_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock,
                    0x42,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=20 * 10,
                )
                result["identity_inventory_repeat_equal"] = (
                    repeated_reply == identities_reply
                )
                result["identity_list_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["identity_list_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get identity count")
        if args.global_identity_list:
            global_reply, global_events = biometric_command(
                sock, 0x51, output_capacity=40 * 10
            )
            result["global_identity_list_reply"] = summarize_command_reply(
                global_reply
            )
            global_output = (
                global_reply[1]
                if isinstance(global_reply, list)
                and len(global_reply) > 1
                and isinstance(global_reply[1], bytes)
                else None
            )
            result["global_identity_record_bytes_valid"] = (
                isinstance(global_output, bytes) and len(global_output) % 40 == 0
            )
            if result["global_identity_record_bytes_valid"]:
                global_identity_records = tuple(
                    global_output[offset : offset + 40]
                    for offset in range(0, len(global_output), 40)
                )
                result["global_identity_record_count"] = len(
                    global_identity_records
                )
                configured_records = {
                    record[:20]
                    for record in global_identity_records
                    if struct.unpack_from("<I", record)[0] == args.macos_user_id
                }
                result["configured_identity_records_reconciled"] = (
                    bool(enrolled_identity_records)
                    and configured_records == set(enrolled_identity_records)
                ) or (not configured_records and not enrolled_identity_records)
            result["global_identity_list_events"] = [
                summarize_event(event) for event in global_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock, 0x51, output_capacity=40 * 10
                )
                result["global_identity_inventory_repeat_equal"] = (
                    repeated_reply == global_reply
                )
                result["global_identity_list_repeat_reply"] = (
                    summarize_command_reply(repeated_reply)
                )
                result["global_identity_list_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get global identity inventory")
        if args.identity_capacity:
            maximum_reply, maximum_events = biometric_command(
                sock, 0x0F, output_capacity=4
            )
            free_reply, free_events = biometric_command(
                sock,
                0x41,
                data=struct.pack("<I", args.macos_user_id),
                output_capacity=4,
            )
            result["identity_capacity_reply"] = summarize_command_reply(
                maximum_reply
            )
            result["identity_free_count_reply"] = summarize_command_reply(free_reply)
            maximum_output = (
                maximum_reply[1]
                if isinstance(maximum_reply, list)
                and len(maximum_reply) > 1
                and isinstance(maximum_reply[1], bytes)
                else None
            )
            free_output = (
                free_reply[1]
                if isinstance(free_reply, list)
                and len(free_reply) > 1
                and isinstance(free_reply[1], bytes)
                else None
            )
            if isinstance(maximum_output, bytes) and len(maximum_output) == 4:
                result["identity_maximum_capacity"] = struct.unpack(
                    "<I", maximum_output
                )[0]
            if isinstance(free_output, bytes) and len(free_output) == 4:
                result["identity_free_count"] = struct.unpack("<I", free_output)[0]
            result["identity_capacity_events"] = [
                summarize_event(event) for event in maximum_events + free_events
            ]
            if args.stability_check:
                repeated_maximum, repeated_maximum_events = biometric_command(
                    sock, 0x0F, output_capacity=4
                )
                repeated_free, repeated_free_events = biometric_command(
                    sock,
                    0x41,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=4,
                )
                result["identity_capacity_repeat_equal"] = (
                    repeated_maximum == maximum_reply and repeated_free == free_reply
                )
                result["identity_capacity_repeat_events"] = [
                    summarize_event(event)
                    for event in repeated_maximum_events + repeated_free_events
                ]
            operations.append("get identity capacity")
        if args.catacomb_component_state:
            uid_data = struct.pack("<I", args.macos_user_id)
            uuid_reply, uuid_events = biometric_command(
                sock, 0x38, data=uid_data, output_capacity=16
            )
            hash_reply, hash_events = biometric_command(
                sock, 0x3A, data=uid_data, output_capacity=33
            )
            result["catacomb_uuid_reply"] = summarize_command_reply(uuid_reply)
            result["catacomb_hash_reply"] = summarize_command_reply(hash_reply)
            uuid_output = (
                uuid_reply[1]
                if isinstance(uuid_reply, list)
                and len(uuid_reply) > 1
                and isinstance(uuid_reply[1], bytes)
                else None
            )
            hash_output = (
                hash_reply[1]
                if isinstance(hash_reply, list)
                and len(hash_reply) > 1
                and isinstance(hash_reply[1], bytes)
                else None
            )
            result["catacomb_uuid_length_valid"] = (
                isinstance(uuid_output, bytes) and len(uuid_output) == 16
            )
            result["catacomb_hash_length_valid"] = (
                isinstance(hash_output, bytes) and len(hash_output) == 33
            )
            if result["catacomb_hash_length_valid"]:
                result["catacomb_component_present"] = bool(hash_output[0])
            result["catacomb_component_events"] = [
                summarize_event(event) for event in uuid_events + hash_events
            ]
            if args.stability_check:
                repeated_uuid, repeated_uuid_events = biometric_command(
                    sock, 0x38, data=uid_data, output_capacity=16
                )
                repeated_hash, repeated_hash_events = biometric_command(
                    sock, 0x3A, data=uid_data, output_capacity=33
                )
                result["catacomb_component_repeat_equal"] = (
                    repeated_uuid == uuid_reply and repeated_hash == hash_reply
                )
                result["catacomb_component_repeat_events"] = [
                    summarize_event(event)
                    for event in repeated_uuid_events + repeated_hash_events
                ]
            operations.append("get Catacomb component metadata")
        if args.catacomb_state:
            catacomb_reply, catacomb_events = biometric_command(
                sock, 0x3C, output_capacity=4096
            )
            result["catacomb_state_reply"] = summarize_command_reply(
                catacomb_reply
            )
            if (
                isinstance(catacomb_reply, list)
                and len(catacomb_reply) > 1
                and isinstance(catacomb_reply[1], bytes)
                and len(catacomb_reply[1]) in (8, 16)
            ):
                catacomb_state_output = catacomb_reply[1]
                result["catacomb_state_words"] = list(
                    struct.unpack(
                        "<" + "I" * (len(catacomb_reply[1]) // 4),
                        catacomb_reply[1],
                    )
                )
            result["catacomb_state_events"] = [
                summarize_event(event) for event in catacomb_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock, 0x3C, output_capacity=4096
                )
                result["catacomb_state_repeat_equal"] = (
                    repeated_reply == catacomb_reply
                )
                result["catacomb_state_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["catacomb_state_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get catacomb state")
        if args.sks_lock_state:
            sks_reply, sks_events = biometric_command(
                sock, 0x27, data=struct.pack("<I", args.macos_user_id), output_capacity=4
            )
            result["sks_lock_state_reply"] = summarize_command_reply(sks_reply)
            if (
                isinstance(sks_reply, list)
                and len(sks_reply) > 1
                and isinstance(sks_reply[1], bytes)
                and len(sks_reply[1]) == 4
            ):
                result["sks_lock_state"] = struct.unpack("<I", sks_reply[1])[0]
            result["sks_lock_state_events"] = [
                summarize_event(event) for event in sks_events
            ]
            if args.stability_check:
                repeated_reply, repeated_events = biometric_command(
                    sock,
                    0x27,
                    data=struct.pack("<I", args.macos_user_id),
                    output_capacity=4,
                )
                result["sks_lock_state_repeat_equal"] = repeated_reply == sks_reply
                result["sks_lock_state_repeat_reply"] = summarize_command_reply(
                    repeated_reply
                )
                result["sks_lock_state_repeat_events"] = [
                    summarize_event(event) for event in repeated_events
                ]
            operations.append("get SKS lock state")
        if args.load_catacomb_archive:
            if not args.initialize:
                raise ValueError("--load-catacomb-archive requires --initialize")
            entries = []
            payloads = read_catacomb_payloads(
                args.load_catacomb_archive, args.macos_user_id
            )
            if args.catacomb_component != "all":
                selected_name = (
                    "master.cat"
                    if args.catacomb_component == "master"
                    else f"user_{args.macos_user_id:08x}.cat"
                )
                payloads = [
                    payload for payload in payloads if payload[0] == selected_name
                ]
            for name, user_id, secure_data in payloads:
                command_data = secure_data
                if args.strip_catacomb_file_header:
                    if len(command_data) < 33:
                        raise ValueError(f"{name} is too short for an LTFC wrapper")
                    magic, file_version, file_user_id = struct.unpack_from(
                        "<IIi", command_data
                    )
                    if (
                        magic != 0x4346544C
                        or file_version != 10
                        or file_user_id != user_id
                        or any(command_data[12:32])
                    ):
                        raise ValueError(f"{name} has an unexpected LTFC wrapper")
                    command_data = command_data[32:]
                load_reply, load_events = biometric_command(
                    sock, 0x40, version=1, data=command_data
                )
                entries.append(
                    {
                        "component": name,
                        "user_id": user_id,
                        "secure_data_length": len(secure_data),
                        "command_data_length": len(command_data),
                        "reply": summarize_command_reply(load_reply),
                        "events": [summarize_event(event) for event in load_events],
                    }
                )
                if not isinstance(load_reply, list) or not load_reply or load_reply[0] != 0:
                    break
            result["load_catacomb"] = entries
            operations.append("load encrypted catacomb")
        if args.load_biolockout_archive:
            if not args.initialize:
                raise ValueError("--load-biolockout-archive requires --initialize")
            biolockout_data = read_biolockout_payload(args.load_biolockout_archive)
            biolockout_reply, biolockout_events = biometric_command(
                sock, 0x4B, data=biolockout_data
            )
            result["load_biolockout"] = {
                "secure_data_length": len(biolockout_data),
                "reply": summarize_command_reply(biolockout_reply),
                "events": [
                    summarize_event(event) for event in biolockout_events
                ],
            }
            operations.append("load encrypted bio-lockout record")
        if args.match_seconds is not None:
            if not args.initialize:
                raise ValueError("--match-seconds requires --initialize")
            if not enrolled_identity_records:
                raise ValueError(
                    "--match-seconds requires a non-empty --identity-list result"
                )
            # match_init_data_v1: processed flags, macOS user ID, and 60 bytes
            # reserved for authenticated/special matching modes.
            # Apple's performMatchCommand: appends selectedIdentitiesBlob to
            # the fixed 68-byte match-options structure. The blob starts with
            # a uint32 record count, followed by the opaque 20-byte
            # identity_record_v1_t records returned by command 0x42.
            selected_identities = b"".join(enrolled_identity_records)
            if args.identity_blob_format == "counted":
                selected_identities = struct.pack(
                    "<I", len(enrolled_identity_records)
                ) + selected_identities
            match_data = struct.pack(
                "<II60x", args.match_processed_flags, args.macos_user_id
            ) + selected_identities
            if args.audible_match_alert:
                subprocess.run(
                    [
                        "canberra-gtk-play",
                        "--id=message-new-instant",
                        "--description=Touch ID finger requested",
                    ],
                    check=False,
                )
            match_reply, events = biometric_command(sock, 4, data=match_data)
            result["match_start_reply"] = summarize_command_reply(match_reply)
            match_started = (
                isinstance(match_reply, list)
                and bool(match_reply)
                and match_reply[0] == 0
            )
            if match_started:
                deadline = time.monotonic() + args.match_seconds
                while time.monotonic() < deadline:
                    sock.settimeout(max(0.1, deadline - time.monotonic()))
                    try:
                        envelope = receive_envelope(sock)
                    except TimeoutError:
                        break
                    if envelope[1] is False:
                        events.append(envelope[3])
                        send_message(sock, [1, True, envelope[2], [0]])
                        if (
                            args.stop_on_match_result
                            and summarize_event(
                                envelope[3],
                                enrolled_identity_records,
                                expected_user_id=args.macos_user_id,
                            ).get("event_kind")
                            == "match_result"
                        ):
                            break
                sock.settimeout(args.timeout)
                cancel_reply, cancel_events = request_with_events(
                    sock, [3, 0, BIOMETRIC_COMMAND_HEADER.pack(
                        BIOMETRIC_COMMAND_MAGIC, 12, 1, 0
                    ), 0]
                )
                events.extend(cancel_events)
                result["cancel_reply"] = summarize_command_reply(cancel_reply)
            else:
                result["match_rejected"] = True
            result["match_events"] = [
                summarize_event(
                    event,
                    enrolled_identity_records,
                    expected_user_id=args.macos_user_id,
                )
                for event in events
            ]
            operations.append("timed match" + (" + cancel" if match_started else " (rejected)"))
        if operations:
            result["sent"] = "HELO + read-only " + ", ".join(operations)
        if args.private_inventory_output:
            if args.full_inventory:
                if not private_inventory:
                    failures = result.get("private_inventory_gate_failures", ["unknown"])
                    raise ValueError(
                        "refusing to write incomplete private inventory: "
                        + ", ".join(failures)
                    )
                write_private_json(args.private_inventory_output, private_inventory)
                result["private_inventory_written"] = True
                print(json.dumps(result, indent=2))
                return
            required = (
                args.initialize,
                args.biometric_protocol,
                args.identity_list,
                args.global_identity_list,
                args.identity_capacity,
                args.catacomb_component_state,
                args.catacomb_state,
                args.sks_lock_state,
                args.stability_check,
            )
            if not all(required):
                raise ValueError(
                    "private inventory requires all inventory queries and --stability-check"
                )
            equality_fields = (
                "identity_inventory_repeat_equal",
                "global_identity_inventory_repeat_equal",
                "identity_capacity_repeat_equal",
                "catacomb_component_repeat_equal",
                "catacomb_state_repeat_equal",
                "sks_lock_state_repeat_equal",
            )
            if not all(result.get(field) is True for field in equality_fields):
                raise ValueError("refusing to write unstable private inventory")
            if not (
                isinstance(maximum_output, bytes)
                and len(maximum_output) == 4
                and isinstance(free_output, bytes)
                and len(free_output) == 4
                and isinstance(uuid_output, bytes)
                and len(uuid_output) == 16
                and isinstance(hash_output, bytes)
                and len(hash_output) == 33
                and isinstance(catacomb_state_output, bytes)
            ):
                raise ValueError("refusing to write incomplete private inventory")
            bridge_boot_uuid = helo.get("BootSessionUUID")
            try:
                bridge_boot_uuid = str(uuid.UUID(bridge_boot_uuid))
            except (AttributeError, TypeError, ValueError):
                bridge_boot_uuid = None
            private = {
                "schema_version": 1,
                "connection_generation": connection_generation,
                "bridge_boot_uuid": bridge_boot_uuid,
                "biometric_protocol_version": result.get(
                    "biometric_protocol_version"
                ),
                "apple_uid": args.macos_user_id,
                "per_user_identity_records": [
                    {
                        "user_id": struct.unpack_from("<I", record)[0],
                        "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                    }
                    for record in enrolled_identity_records
                ],
                "global_identity_records": [
                    {
                        "user_id": struct.unpack_from("<I", record)[0],
                        "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                        "group_type": struct.unpack_from("<I", record, 20)[0],
                        "group_uuid": str(uuid.UUID(bytes=record[24:40])),
                    }
                    for record in global_identity_records
                ],
                "maximum_capacity": struct.unpack("<I", maximum_output)[0],
                "configured_user_free_capacity": struct.unpack("<I", free_output)[0],
                "catacomb": {
                    "uuid": str(uuid.UUID(bytes=uuid_output)),
                    "present": bool(hash_output[0]),
                    "hash": hash_output[1:].hex(),
                    "global_state": catacomb_state_output.hex(),
                },
                "sks_lock_state_raw": result.get("sks_lock_state"),
                "double_collection_equal": True,
            }
            write_private_json(args.private_inventory_output, private)
            result["private_inventory_written"] = True
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
