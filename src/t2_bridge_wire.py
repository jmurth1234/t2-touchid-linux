# SPDX-License-Identifier: GPL-2.0-only
"""Minimal BridgeXPC wire primitives shared by probes and owned leases."""

from __future__ import annotations

import json
import plistlib
import socket
import struct
import uuid


MAGIC = 0xB892
PROTOCOL_VERSION = 1
TYPE_HELO = 1
TYPE_MESSAGE = 2
HEADER = struct.Struct("<HHIQ")
BIOMETRIC_COMMAND_HEADER = struct.Struct("<HHHH")
BIOMETRIC_COMMAND_MAGIC = 0x4D42
MAX_FRAME_BODY = 16 * 1024 * 1024


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
    if body_length > MAX_FRAME_BODY:
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


def receive_envelope(sock: socket.socket) -> list[object]:
    frame_type, frame_body = receive_frame(sock)
    envelope = describe(frame_type, frame_body)
    if frame_type != TYPE_MESSAGE:
        raise ValueError(f"expected message frame, received type {frame_type}")
    if type(envelope) is not list or len(envelope) != 4:
        raise ValueError("malformed BiometricKit bridge envelope")
    return envelope


def request_with_events(
    sock: socket.socket, payload: object
) -> tuple[object, list[object]]:
    reply_id = str(uuid.uuid4()).upper()
    send_message(sock, [1, False, reply_id, payload])
    events: list[object] = []
    while True:
        envelope = receive_envelope(sock)
        if envelope[0] != 1:
            raise ValueError("unsupported BiometricKit envelope version")
        if envelope[1] is True:
            if envelope[2] != reply_id:
                raise ValueError("reply envelope does not match request")
            return envelope[3], events
        if envelope[1] is not False or not isinstance(envelope[2], str):
            raise ValueError("malformed BiometricKit service callback")
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
    data: bytes | memoryview = b"",
    output_capacity: int = 0,
) -> tuple[object, list[object]]:
    """Send one inner AppleBiometricServices command through bkremoted."""
    inner = bytearray(
        BIOMETRIC_COMMAND_HEADER.pack(
            BIOMETRIC_COMMAND_MAGIC, command, version, value
        )
    )
    inner.extend(data)
    try:
        return request_with_events(sock, [3, 0, bytes(inner), output_capacity])
    finally:
        inner[:] = b"\x00" * len(inner)
