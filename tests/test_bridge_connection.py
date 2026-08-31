import json
import plistlib
import socket
import sys
import threading
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridge_connection as connection
import t2_bridge_wire as wire


GENERATION = str(uuid.UUID(int=31))


def send_frame(sock: socket.socket, frame_type: int, value: object) -> None:
    if frame_type == wire.TYPE_HELO:
        body = json.dumps(value).encode()
    else:
        body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    sock.sendall(wire.HEADER.pack(wire.MAGIC, 1, frame_type, len(body)) + body)


def receive_message(sock: socket.socket) -> list[object]:
    frame_type, body = wire.receive_frame(sock)
    if frame_type != wire.TYPE_MESSAGE:
        raise AssertionError("expected message")
    value = plistlib.loads(body)
    if type(value) is not list:
        raise AssertionError("expected list")
    return value


def reply_to(sock: socket.socket, request: list[object], value: object) -> None:
    send_frame(sock, wire.TYPE_MESSAGE, [1, True, request[2], value])


class ScriptedPeer:
    def __init__(self, script) -> None:
        self.client, self.peer = socket.socketpair()
        self.error: BaseException | None = None

        def run() -> None:
            try:
                send_frame(
                    self.peer,
                    wire.TYPE_HELO,
                    {
                        "BridgeXPCVersion": 39,
                        "BootSessionUUID": str(uuid.UUID(int=32)),
                    },
                )
                frame_type, _body = wire.receive_frame(self.peer)
                if frame_type != wire.TYPE_HELO:
                    raise AssertionError("client did not send HELO")
                version = receive_message(self.peer)
                reply_to(self.peer, version, [0, 3])
                set_version = receive_message(self.peer)
                if set_version[3] != [10, 2]:
                    raise AssertionError("client selected the wrong API version")
                reply_to(self.peer, set_version, [0])
                script(self.peer)
            except BaseException as error:
                self.error = error
            finally:
                self.peer.close()

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def finish(self) -> None:
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("scripted peer did not finish")
        if self.error is not None:
            raise self.error


class BridgeConnectionTests(unittest.TestCase):
    def test_initialization_command_and_async_event_share_one_socket(self):
        raw_event = b"event-data"

        def script(peer: socket.socket) -> None:
            command = receive_message(peer)
            inner = command[3][2]
            self.assertEqual(command[3][0:2], [3, 0])
            self.assertEqual(
                wire.BIOMETRIC_COMMAND_HEADER.unpack_from(inner),
                (wire.BIOMETRIC_COMMAND_MAGIC, 0x51, 2, 0),
            )
            self.assertEqual(inner[8:], b"input")
            reply_to(peer, command, [0, b"output"])
            send_frame(peer, wire.TYPE_MESSAGE, [1, False, "EVENT-1", raw_event])
            acknowledgement = receive_message(peer)
            self.assertEqual(acknowledgement, [1, True, "EVENT-1", [0]])

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        self.assertEqual(lease.client_version, 2)
        self.assertEqual(lease.peer_boot_uuid, str(uuid.UUID(int=32)))
        self.assertEqual(
            lease.biometric_command(
                0x51,
                version=2,
                value=0,
                data=b"input",
                output_capacity=40,
            ),
            ([0, b"output"], []),
        )
        self.assertEqual(lease.next_service_event(), raw_event)
        lease.close()
        peer.finish()

    def test_interleaved_command_event_is_acknowledged_and_returned(self):
        event = [9, 0, b"service-event", None, None]

        def script(peer: socket.socket) -> None:
            command = receive_message(peer)
            send_frame(peer, wire.TYPE_MESSAGE, [1, False, "CALLBACK", event])
            self.assertEqual(
                receive_message(peer), [1, True, "CALLBACK", [0]]
            )
            reply_to(peer, command, [0, None])

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        reply, events = lease.biometric_command(
            3, version=2, value=0, data=memoryview(bytes(68)), output_capacity=0
        )
        self.assertEqual(reply, [0, None])
        self.assertEqual(events, [event])
        lease.close()
        peer.finish()

    def test_disconnect_poisons_and_generation_becomes_unavailable(self):
        def script(peer: socket.socket) -> None:
            receive_message(peer)

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        with self.assertRaisesRegex(connection.BridgeConnectionError, "poisoned"):
            lease.biometric_command(
                1, version=2, value=0, data=b"", output_capacity=4
            )
        self.assertEqual(lease.state, connection.BridgeConnectionState.POISONED)
        with self.assertRaises(connection.BridgeConnectionError):
            _generation = lease.connection_generation
        peer.finish()

    def test_invalid_command_is_rejected_before_socket_use(self):
        def script(_peer: socket.socket) -> None:
            return

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        with self.assertRaises(connection.BridgeConnectionError):
            lease.biometric_command(
                -1, version=2, value=0, data=b"", output_capacity=0
            )
        self.assertEqual(lease.state, connection.BridgeConnectionState.ACTIVE)
        lease.close()
        peer.finish()

    def test_constructor_rejects_noncanonical_generation(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(connection.BridgeConnectionError):
                connection.BridgeConnectionLease(
                    left, connection_generation=GENERATION.upper()
                )
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
