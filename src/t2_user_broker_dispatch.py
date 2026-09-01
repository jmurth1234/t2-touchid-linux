# SPDX-License-Identifier: GPL-2.0-only
"""Single-request dispatcher for the non-exposed read-only user broker."""

from __future__ import annotations

import socket

import t2_user_broker_inventory
import t2_user_broker_preflight
import t2_user_broker_protocol


class UserBrokerDispatchError(RuntimeError):
    pass


def serve_once(
    connection: socket.socket,
    *,
    modification_allowed: bool,
    allow_user_interaction: bool,
    preflight_runner=t2_user_broker_preflight.run,
    inventory_runner=t2_user_broker_inventory.run,
) -> (
    t2_user_broker_protocol.PreflightResponse
    | t2_user_broker_protocol.InventoryResponse
):
    """Receive, execute, and answer exactly one identifier-free request."""

    if type(modification_allowed) is not bool:
        raise UserBrokerDispatchError("modification policy must be Boolean")
    if type(allow_user_interaction) is not bool:
        raise UserBrokerDispatchError("interaction policy must be Boolean")
    try:
        request = t2_user_broker_protocol.receive_request(connection)
        if request.command == t2_user_broker_protocol.PREFLIGHT_COMMAND:
            response = preflight_runner(
                connection,
                request,
                modification_allowed=modification_allowed,
                allow_user_interaction=allow_user_interaction,
            )
            if not isinstance(
                response, t2_user_broker_protocol.PreflightResponse
            ):
                raise UserBrokerDispatchError(
                    "preflight dispatcher result is malformed"
                )
        elif request == t2_user_broker_protocol.BrokerRequest(
            t2_user_broker_protocol.IDENTITIES_COMMAND,
            "inventory",
        ):
            result = inventory_runner(
                connection,
                allow_user_interaction=allow_user_interaction,
            )
            response = t2_user_broker_protocol.response_from_inventory_result(
                request, result
            )
        else:
            raise UserBrokerDispatchError("broker command is unsupported")
        t2_user_broker_protocol.send_response(connection, response)
        return response
    except UserBrokerDispatchError:
        raise
    except (
        t2_user_broker_inventory.UserBrokerInventoryError,
        t2_user_broker_preflight.UserBrokerPreflightError,
        t2_user_broker_protocol.UserBrokerProtocolError,
    ) as error:
        raise UserBrokerDispatchError("read-only broker request failed") from error
    except Exception as error:
        raise UserBrokerDispatchError("read-only broker request failed") from error
