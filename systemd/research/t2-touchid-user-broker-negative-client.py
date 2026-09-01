#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fixed client for the staged unmapped/inactive broker denial test."""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parents[2] / "src"
SOURCE = (
    LOCAL_SOURCE
    if (LOCAL_SOURCE / "t2_user_broker_negative.py").is_file()
    else INSTALLED_SOURCE
)
sys.path.insert(0, str(SOURCE))

import t2_user_broker_client
import t2_user_broker_negative
import t2_user_broker_protocol


SOCKET_PATH = "/run/t2-touchid/user-broker.sock"


class NegativeClientError(RuntimeError):
    pass


def run() -> t2_user_broker_negative.NegativeResult:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.connect(SOCKET_PATH)
        request = t2_user_broker_protocol.BrokerRequest(
            t2_user_broker_protocol.IDENTITIES_COMMAND,
            "inventory",
        )
        try:
            response = t2_user_broker_client.exchange(connection, request)
        except t2_user_broker_client.UserBrokerClientPeerClosed:
            return t2_user_broker_negative.classify(
                peer_closed_without_response=True
            )
        return t2_user_broker_negative.classify(response)
    except t2_user_broker_negative.UserBrokerNegativeError:
        raise
    except OSError as error:
        raise NegativeClientError("candidate broker is unavailable") from error
    finally:
        connection.close()


def main() -> int:
    if len(sys.argv) != 1:
        print(
            "t2-touchid-user-broker-negative-client: no arguments permitted",
            file=sys.stderr,
        )
        return 2
    try:
        result = run()
    except (
        NegativeClientError,
        t2_user_broker_client.UserBrokerClientError,
        t2_user_broker_negative.UserBrokerNegativeError,
    ):
        print(
            "t2-touchid-user-broker-negative-client: negative test failed",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result.public(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
