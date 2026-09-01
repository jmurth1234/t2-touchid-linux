# SPDX-License-Identifier: GPL-2.0-only
"""One-exchange client core for the non-exposed read-only user broker."""

from __future__ import annotations

import socket

import t2_user_broker_protocol


class UserBrokerClientError(RuntimeError):
    pass


class UserBrokerClientPeerClosed(UserBrokerClientError):
    pass


def exchange(
    connection: socket.socket,
    request: t2_user_broker_protocol.BrokerRequest,
) -> (
    t2_user_broker_protocol.PreflightResponse
    | t2_user_broker_protocol.InventoryResponse
):
    """Send one request and require the exact corresponding response shape."""

    try:
        t2_user_broker_protocol.send_request(connection, request)
        response = t2_user_broker_protocol.receive_response(connection)
    except t2_user_broker_protocol.UserBrokerPeerClosed as error:
        raise UserBrokerClientPeerClosed(
            "broker closed without returning authority"
        ) from error
    except t2_user_broker_protocol.UserBrokerProtocolError as error:
        raise UserBrokerClientError("broker exchange failed") from error
    if request.command == t2_user_broker_protocol.PREFLIGHT_COMMAND:
        if (
            not isinstance(
                response, t2_user_broker_protocol.PreflightResponse
            )
            or response.operation != request.operation
        ):
            raise UserBrokerClientError(
                "preflight response does not match the request"
            )
    elif request == t2_user_broker_protocol.BrokerRequest(
        t2_user_broker_protocol.IDENTITIES_COMMAND,
        "inventory",
    ):
        if not isinstance(response, t2_user_broker_protocol.InventoryResponse):
            raise UserBrokerClientError(
                "identity response does not match the request"
            )
    else:
        raise UserBrokerClientError("broker request is unsupported")
    return response
