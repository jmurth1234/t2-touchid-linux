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
import struct
import subprocess
import sys
import tarfile
import time
import uuid


MAGIC = 0xB892
PROTOCOL_VERSION = 1
TYPE_HELO = 1
TYPE_MESSAGE = 2
HEADER = struct.Struct("<HHIQ")
BIOMETRIC_COMMAND_HEADER = struct.Struct("<HHHH")
BIOMETRIC_COMMAND_MAGIC = 0x4D42  # "BM" in little-endian memory order


def receive_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise EOFError(f"peer closed after {len(chunks)}/{length} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_frame(sock: socket.socket) -> tuple[int, bytes]:
    raw_header = receive_exact(sock, HEADER.size)
    magic, version, frame_type, body_length = HEADER.unpack(raw_header)
    if magic != MAGIC:
        raise ValueError(f"invalid BridgeXPC magic 0x{magic:04x}")
    if version != PROTOCOL_VERSION:
        raise ValueError(f"unsupported BridgeXPC protocol version {version}")
    if body_length > 16 * 1024 * 1024:
        raise ValueError(f"refusing implausible {body_length}-byte frame")
    return frame_type, receive_exact(sock, body_length)


def send_helo(sock: socket.socket, bridge_xpc_version: int) -> None:
    body = json.dumps(
        {
            "MaxSupportedProtocolVersion": PROTOCOL_VERSION,
            "OSBuild": "Linux",
            "BridgeXPCVersion": bridge_xpc_version,
            "ProcessName": "t2-touchid-probe",
        },
        separators=(",", ":"),
    ).encode()
    sock.sendall(HEADER.pack(MAGIC, PROTOCOL_VERSION, TYPE_HELO, len(body)) + body)


def send_message(sock: socket.socket, value: object) -> None:
    body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    sock.sendall(
        HEADER.pack(MAGIC, PROTOCOL_VERSION, TYPE_MESSAGE, len(body)) + body
    )


def describe(frame_type: int, body: bytes) -> object:
    if frame_type == TYPE_HELO:
        return json.loads(body)
    if frame_type == TYPE_MESSAGE:
        return plistlib.loads(body)
    return {"unknown_frame_type": frame_type, "body_hex": body.hex()}


def receive_envelope(sock: socket.socket) -> list:
    frame_type, frame_body = receive_frame(sock)
    envelope = describe(frame_type, frame_body)
    if frame_type != TYPE_MESSAGE:
        raise ValueError(f"expected message frame, received type {frame_type}")
    if not isinstance(envelope, list) or len(envelope) != 4:
        raise ValueError("malformed BiometricKit bridge envelope")
    return envelope


def request_with_events(sock: socket.socket, payload: object) -> tuple[object, list]:
    reply_id = str(uuid.uuid4()).upper()
    send_message(sock, [1, False, reply_id, payload])
    events = []
    while True:
        envelope = receive_envelope(sock)
        if envelope[0] != 1:
            raise ValueError("unsupported BiometricKit envelope version")
        if envelope[1] is True:
            if envelope[2] != reply_id:
                raise ValueError("reply envelope does not match request")
            return envelope[3], events
        # Bridge-side status callbacks are synchronous.  Acknowledge them just
        # as BiometricKitBridgeConnection does, then continue waiting for the
        # reply to our original request.
        events.append(envelope[3])
        send_message(sock, [1, True, envelope[2], [0]])


def request(sock: socket.socket, payload: object) -> object:
    reply, _events = request_with_events(sock, payload)
    return reply


def biometric_command(
    sock: socket.socket,
    command: int,
    *,
    version: int = 1,
    value: int = 0,
    data: bytes = b"",
    output_capacity: int = 0,
) -> tuple[object, list]:
    """Send the inner AppleBiometricServices command through bkremoted.

    BiometricKitXPCServerMesa wraps every command in an eight-byte ``BM``
    header and submits it as bridge-level command zero.
    """
    inner = BIOMETRIC_COMMAND_HEADER.pack(
        BIOMETRIC_COMMAND_MAGIC, command, version, value
    ) + data
    return request_with_events(sock, [3, 0, inner, output_capacity])


def summarize_event(
    payload: object, enrolled_identity_records: tuple[bytes, ...] = ()
) -> dict:
    if isinstance(payload, list) and len(payload) == 5 and payload[0] == 9:
        data = payload[2]
        summary = {
            "method": "serviceStatus",
            "bridge_status": payload[1],
            "data_length": len(data) if isinstance(data, bytes) else None,
        }
        if isinstance(data, bytes) and len(data) >= 24:
            sequence, embedded_type, version, ordinal = struct.unpack_from(
                "<QIIQ", data
            )
            summary.update(
                sequence=sequence,
                embedded_type=f"0x{embedded_type:08x}",
                version=version,
                ordinal=ordinal,
            )
            event_data = data[24:]
            if embedded_type == 0xE3FF8001:
                summary["event_kind"] = "status"
                if len(event_data) >= 4:
                    summary["status_code"] = struct.unpack_from(
                        "<I", event_data
                    )[0]
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
    return summary


def read_catacomb_payloads(archive_path: str) -> list[tuple[str, int, bytes]]:
    """Validate a macOS v3 catacomb archive and return opaque load payloads."""
    expected = {"master.cat": -1, "user_000001f5.cat": 501}
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
    for name in ("master.cat", "user_000001f5.cat"):
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
        help="query the SEP identity-record count for macOS user 501",
    )
    parser.add_argument(
        "--catacomb-state",
        action="store_true",
        help="query SEP catacomb state metadata without returning its contents",
    )
    parser.add_argument(
        "--sks-lock-state",
        action="store_true",
        help="query the four-byte secure-key-store lock state for user 501",
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
        enrolled_identity_records: tuple[bytes, ...] = ()
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
                sock, 0x42, data=struct.pack("<I", 501), output_capacity=20 * 10
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
                            struct.unpack_from("<I", record)[0] == 501
                            for record in enrolled_identity_records
                        )
                        else "suffix"
                        if all(
                            struct.unpack_from("<I", record, 16)[0] == 501
                            for record in enrolled_identity_records
                        )
                        else "unknown"
                    )
            result["identity_list_events"] = [
                summarize_event(event) for event in identities_events
            ]
            operations.append("get identity count")
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
                result["catacomb_state_words"] = list(
                    struct.unpack(
                        "<" + "I" * (len(catacomb_reply[1]) // 4),
                        catacomb_reply[1],
                    )
                )
            result["catacomb_state_events"] = [
                summarize_event(event) for event in catacomb_events
            ]
            operations.append("get catacomb state")
        if args.sks_lock_state:
            sks_reply, sks_events = biometric_command(
                sock, 0x27, data=struct.pack("<I", 501), output_capacity=4
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
            operations.append("get SKS lock state")
        if args.load_catacomb_archive:
            if not args.initialize:
                raise ValueError("--load-catacomb-archive requires --initialize")
            entries = []
            payloads = read_catacomb_payloads(args.load_catacomb_archive)
            if args.catacomb_component != "all":
                selected_name = (
                    "master.cat"
                    if args.catacomb_component == "master"
                    else "user_000001f5.cat"
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
                "<II60x", args.match_processed_flags, 501
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
                                envelope[3], enrolled_identity_records
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
                summarize_event(event, enrolled_identity_records)
                for event in events
            ]
            operations.append("timed match" + (" + cancel" if match_started else " (rejected)"))
        if operations:
            result["sent"] = "HELO + read-only " + ", ".join(operations)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
