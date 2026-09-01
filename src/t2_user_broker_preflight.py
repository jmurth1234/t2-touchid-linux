# SPDX-License-Identifier: GPL-2.0-only
"""Read-only consumer for the joined self-service broker transaction."""

from __future__ import annotations

import socket
from dataclasses import dataclass

import t2_user_broker
import t2_user_broker_protocol


class UserBrokerPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightProof:
    stage: str
    runtime_lease_held: bool
    t2_mutation_performed: bool = False


def _consumer(
    authority: t2_user_broker.BrokerAuthority,
    live: t2_user_broker.BrokerLiveSession,
) -> PreflightProof:
    if (
        not isinstance(authority, t2_user_broker.BrokerAuthority)
        or authority.stage != "operate"
        or authority.decision.state != "authorized"
        or authority.decision.operation_permitted is not True
        or live.runtime_generation != authority.runtime_generation
    ):
        raise UserBrokerPreflightError("preflight handoff is inconsistent")
    return PreflightProof("operate", True, False)


def run(
    connection: socket.socket,
    request: t2_user_broker_protocol.BrokerRequest,
    *,
    modification_allowed: bool,
    allow_user_interaction: bool,
    broker_runner=t2_user_broker.run_self_service,
) -> t2_user_broker_protocol.PreflightResponse:
    """Run a policy/live readiness preflight without activation or mutation."""

    try:
        # Re-encoding is the in-process structural gate for callers that did not
        # arrive through ``receive_request``.
        t2_user_broker_protocol.encode_request(request)
    except t2_user_broker_protocol.UserBrokerProtocolError as error:
        raise UserBrokerPreflightError("preflight request is invalid") from error
    if type(modification_allowed) is not bool:
        raise UserBrokerPreflightError("modification policy must be Boolean")
    if type(allow_user_interaction) is not bool:
        raise UserBrokerPreflightError("interaction policy must be Boolean")
    try:
        result = broker_runner(
            connection,
            operation=request.operation,
            modification_allowed=modification_allowed,
            consumer=_consumer,
            allow_user_interaction=allow_user_interaction,
            collect_activation_authority=False,
        )
    except t2_user_broker.UserBrokerError as error:
        raise UserBrokerPreflightError(
            "self-service preflight transaction failed"
        ) from error
    except Exception as error:
        raise UserBrokerPreflightError(
            "self-service preflight transaction failed"
        ) from error
    if not isinstance(result, t2_user_broker.BrokerResult):
        raise UserBrokerPreflightError("preflight broker result is malformed")
    if result.consumer_invoked:
        if (
            not isinstance(result.value, PreflightProof)
            or result.value.stage != "operate"
            or result.value.runtime_lease_held is not True
            or result.value.t2_mutation_performed is not False
        ):
            raise UserBrokerPreflightError("preflight proof is malformed")
    elif result.value is not None:
        raise UserBrokerPreflightError("denied preflight returned private data")
    try:
        return t2_user_broker_protocol.response_from_result(request, result)
    except t2_user_broker_protocol.UserBrokerProtocolError as error:
        raise UserBrokerPreflightError("preflight response is invalid") from error


def serve_once(
    connection: socket.socket,
    *,
    modification_allowed: bool,
    allow_user_interaction: bool,
    broker_runner=t2_user_broker.run_self_service,
) -> t2_user_broker_protocol.PreflightResponse:
    """Receive, execute, and answer exactly one read-only preflight packet."""

    try:
        request = t2_user_broker_protocol.receive_request(connection)
        response = run(
            connection,
            request,
            modification_allowed=modification_allowed,
            allow_user_interaction=allow_user_interaction,
            broker_runner=broker_runner,
        )
        t2_user_broker_protocol.send_response(connection, response)
        return response
    except t2_user_broker_protocol.UserBrokerProtocolError as error:
        raise UserBrokerPreflightError("preflight protocol failed") from error
