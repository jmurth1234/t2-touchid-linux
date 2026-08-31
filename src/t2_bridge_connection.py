# SPDX-License-Identifier: GPL-2.0-only
"""Exclusive owner for one initialized BridgeXPC biometric connection."""

from __future__ import annotations

import select
import socket
import threading
import uuid
from enum import Enum

import t2_bridge_wire as wire


class BridgeConnectionError(RuntimeError):
    """Raised when a Bridge connection can no longer prove its state."""


class BridgeConnectionState(Enum):
    ACTIVE = "active"
    POISONED = "poisoned"
    CLOSED = "closed"


class BridgeConnectionLease:
    """One initialized, non-reentrant Bridge connection and generation."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        connection_generation: str | None = None,
    ) -> None:
        if not isinstance(sock, socket.socket):
            raise BridgeConnectionError("Bridge socket is invalid")
        generation = connection_generation or str(uuid.uuid4())
        try:
            parsed = uuid.UUID(generation)
        except (AttributeError, TypeError, ValueError) as error:
            raise BridgeConnectionError("connection generation must be a UUID") from error
        if str(parsed) != generation:
            raise BridgeConnectionError("connection generation is not canonical")
        self._socket = sock
        self._generation = generation
        self._state = BridgeConnectionState.ACTIVE
        self._lock = threading.Lock()
        self._peer_helo: dict[str, object] = {}
        self._client_version = 0
        try:
            self._initialize()
        except BaseException as error:
            self._poison()
            raise BridgeConnectionError("Bridge initialization failed") from error

    @classmethod
    def connect(
        cls,
        host: str,
        interface: str,
        port: int,
        *,
        timeout: float = 10.0,
    ) -> BridgeConnectionLease:
        if not isinstance(host, str) or not host:
            raise BridgeConnectionError("Bridge host is required")
        if not isinstance(interface, str) or not interface:
            raise BridgeConnectionError("Bridge interface is required")
        if type(port) is not int or not 1 <= port <= 65535:
            raise BridgeConnectionError("Bridge port is invalid")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 60:
            raise BridgeConnectionError("Bridge timeout is invalid")
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            sock.settimeout(float(timeout))
            scope_id = socket.if_nametoindex(interface)
            sock.connect((host, port, 0, scope_id))
            return cls(sock)
        except BaseException:
            sock.close()
            raise

    @property
    def connection_generation(self) -> str:
        if self._state is not BridgeConnectionState.ACTIVE:
            raise BridgeConnectionError("Bridge connection is not active")
        return self._generation

    @property
    def state(self) -> BridgeConnectionState:
        return self._state

    @property
    def client_version(self) -> int:
        return self._client_version

    @property
    def peer_boot_uuid(self) -> str | None:
        value = self._peer_helo.get("BootSessionUUID")
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError):
            return None
        return str(parsed)

    def __repr__(self) -> str:
        return (
            "BridgeConnectionLease(connection_generation="
            f"{self._generation!r}, state={self._state.value!r}, "
            f"client_version={self._client_version})"
        )

    def _initialize(self) -> None:
        frame_type, body = wire.receive_frame(self._socket)
        if frame_type != wire.TYPE_HELO:
            raise BridgeConnectionError("Bridge peer did not send HELO")
        helo = wire.describe(frame_type, body)
        if type(helo) is not dict:
            raise BridgeConnectionError("Bridge HELO is malformed")
        bridge_version = helo.get("BridgeXPCVersion")
        if type(bridge_version) is not int or not 1 <= bridge_version <= 0xFFFF:
            raise BridgeConnectionError("BridgeXPC version is invalid")
        wire.send_helo(self._socket, bridge_version)
        version_reply = wire.request(self._socket, [0])
        if (
            type(version_reply) is not list
            or len(version_reply) != 2
            or version_reply[0] != 0
            or type(version_reply[1]) is not int
            or not 1 <= version_reply[1] <= 0xFFFF
        ):
            raise BridgeConnectionError("getBridgeVersion failed")
        client_version = min(version_reply[1], 2)
        set_reply = wire.request(self._socket, [10, client_version])
        if type(set_reply) is not list or set_reply != [0]:
            raise BridgeConnectionError("setClientVersion failed")
        self._peer_helo = helo
        self._client_version = client_version

    def _poison(self) -> None:
        self._state = BridgeConnectionState.POISONED
        try:
            self._socket.close()
        except OSError:
            pass

    def _enter(self) -> None:
        if self._state is not BridgeConnectionState.ACTIVE:
            raise BridgeConnectionError("Bridge connection is not active")
        if not self._lock.acquire(blocking=False):
            raise BridgeConnectionError("Bridge connection is already in use")

    def _leave(self) -> None:
        self._lock.release()

    @staticmethod
    def _validate_command(
        command: int,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> None:
        for field, name in ((command, "command"), (version, "version"), (value, "value")):
            if type(field) is not int or not 0 <= field <= 0xFFFF:
                raise BridgeConnectionError(f"Bridge {name} is outside uint16 range")
        if type(data) not in (bytes, memoryview) or len(data) > 1024 * 1024:
            raise BridgeConnectionError("Bridge command data is invalid or unbounded")
        if type(output_capacity) is not int or not 0 <= output_capacity <= 16 * 1024 * 1024:
            raise BridgeConnectionError("Bridge output capacity is invalid")

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]:
        self._validate_command(command, version, value, data, output_capacity)
        self._enter()
        try:
            return wire.biometric_command(
                self._socket,
                command,
                version=version,
                value=value,
                data=data,
                output_capacity=output_capacity,
            )
        except BaseException as error:
            self._poison()
            raise BridgeConnectionError(
                "Bridge command failed; connection generation is poisoned"
            ) from error
        finally:
            self._leave()

    def next_service_event(self) -> object:
        self._enter()
        try:
            envelope = wire.receive_envelope(self._socket)
            if (
                envelope[0] != 1
                or envelope[1] is not False
                or not isinstance(envelope[2], str)
                or not envelope[2]
            ):
                raise BridgeConnectionError("unexpected asynchronous Bridge envelope")
            wire.send_message(self._socket, [1, True, envelope[2], [0]])
            return envelope[3]
        except BaseException as error:
            self._poison()
            if isinstance(error, BridgeConnectionError):
                raise
            raise BridgeConnectionError(
                "Bridge event receive failed; connection generation is poisoned"
            ) from error
        finally:
            self._leave()

    def wait_service_event(self, timeout: float) -> object | None:
        """Receive one event only after a bounded, non-consuming idle wait.

        Readiness is checked before reading the frame header.  An idle timeout
        therefore consumes no wire bytes and does not make the connection
        ambiguous.  Once a frame begins, the socket's ordinary I/O timeout and
        fail-closed poisoning rules still apply.
        """
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 5
        ):
            raise BridgeConnectionError("Bridge event poll timeout is invalid")
        self._enter()
        try:
            readable, _writable, _exceptional = select.select(
                [self._socket], [], [], float(timeout)
            )
            if not readable:
                return None
            envelope = wire.receive_envelope(self._socket)
            if (
                envelope[0] != 1
                or envelope[1] is not False
                or not isinstance(envelope[2], str)
                or not envelope[2]
            ):
                raise BridgeConnectionError("unexpected asynchronous Bridge envelope")
            wire.send_message(self._socket, [1, True, envelope[2], [0]])
            return envelope[3]
        except BaseException as error:
            self._poison()
            if isinstance(error, BridgeConnectionError):
                raise
            raise BridgeConnectionError(
                "Bridge event receive failed; connection generation is poisoned"
            ) from error
        finally:
            self._leave()

    def close(self) -> None:
        if self._state is BridgeConnectionState.CLOSED:
            return
        try:
            self._socket.close()
        finally:
            self._state = BridgeConnectionState.CLOSED

    def invalidate(self) -> None:
        """Permanently discard a generation after higher-layer ambiguity."""
        if self._state is BridgeConnectionState.ACTIVE:
            self._poison()

    def __enter__(self) -> BridgeConnectionLease:
        if self._state is not BridgeConnectionState.ACTIVE:
            raise BridgeConnectionError("Bridge connection is not active")
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.close()
