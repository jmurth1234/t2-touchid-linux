# SPDX-License-Identifier: GPL-2.0-only
"""Canonical identifier-free local protocol for the future user broker."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass

import t2_user_broker
import t2_user_broker_inventory
import t2_user_policy


MAX_REQUEST_BYTES = 512
MAX_RESPONSE_BYTES = 128 * 1024
PREFLIGHT_COMMAND = "preflight"
IDENTITIES_COMMAND = "identities"
COMMAND = PREFLIGHT_COMMAND
COMMANDS = frozenset({PREFLIGHT_COMMAND, IDENTITIES_COMMAND})
REQUEST_KEYS = frozenset({"schema_version", "command", "operation"})
PREFLIGHT_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "command",
        "operation",
        "state",
        "policy_action",
        "operation_permitted",
        "activation_required",
        "activation_permitted",
        "readiness_state",
        "quarantine",
        "ready_handoff_proved",
        "t2_mutation_performed",
        "identifiers_redacted",
    }
)
INVENTORY_RESPONSE_KEYS = frozenset(
    {
        "schema_version",
        "command",
        "operation",
        "state",
        "policy_action",
        "operation_permitted",
        "activation_required",
        "activation_permitted",
        "readiness_state",
        "quarantine",
        "broker_consumer_invoked",
        "identity_inventory_available",
        "inventory",
        "t2_mutation_performed",
        "identifiers_redacted",
    }
)
POLICY_STATES = frozenset(
    {
        "delegation-disabled",
        "caller-session-denied",
        "mapping-or-capability-denied",
        "caller-account-generation-mismatch",
        "operation-authorization-required",
        "operation-authorization-binding-mismatch",
        "operation-policy-denied",
        "fingerprint-modification-disabled",
        "target-quarantined",
        "authorized",
        "activation-authorization-required",
        "activation-authorization-binding-mismatch",
        "activation-policy-denied",
        "activation-authorized",
        "target-not-ready",
    }
)
READINESS_STATES = frozenset(
    {
        "capability-denied",
        "persistent-binding-mismatch",
        "alias-absent",
        "alias-binding-mismatch",
        "unknown-lock-state",
        "catacomb-corrupted",
        "keybag-lockout",
        "before-first-unlock",
        "device-locked",
        "ready",
    }
)


class UserBrokerProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class BrokerRequest:
    command: str
    operation: str

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "command": self.command,
            "operation": self.operation,
        }


@dataclass(frozen=True)
class PreflightResponse:
    operation: str
    state: str
    policy_action: str
    operation_permitted: bool
    activation_required: bool
    activation_permitted: bool
    readiness_state: str | None
    quarantine: bool
    ready_handoff_proved: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "command": PREFLIGHT_COMMAND,
            "operation": self.operation,
            "state": self.state,
            "policy_action": self.policy_action,
            "operation_permitted": self.operation_permitted,
            "activation_required": self.activation_required,
            "activation_permitted": self.activation_permitted,
            "readiness_state": self.readiness_state,
            "quarantine": self.quarantine,
            "ready_handoff_proved": self.ready_handoff_proved,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


@dataclass(frozen=True)
class InventoryResponse:
    state: str
    policy_action: str
    operation_permitted: bool
    activation_required: bool
    activation_permitted: bool
    readiness_state: str | None
    quarantine: bool
    broker_consumer_invoked: bool
    inventory: t2_user_broker_inventory.PublicIdentityInventory | None

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "command": IDENTITIES_COMMAND,
            "operation": "inventory",
            "state": self.state,
            "policy_action": self.policy_action,
            "operation_permitted": self.operation_permitted,
            "activation_required": self.activation_required,
            "activation_permitted": self.activation_permitted,
            "readiness_state": self.readiness_state,
            "quarantine": self.quarantine,
            "broker_consumer_invoked": self.broker_consumer_invoked,
            "identity_inventory_available": self.inventory is not None,
            "inventory": (
                self.inventory.public() if self.inventory is not None else None
            ),
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _duplicate_safe_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise UserBrokerProtocolError("protocol object has a duplicate key")
        value[key] = item
    return value


def _decode(data: bytes, maximum: int, label: str) -> dict[str, object]:
    if type(data) is not bytes or not 1 <= len(data) <= maximum or b"\0" in data:
        raise UserBrokerProtocolError(f"{label} packet size is invalid")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                UserBrokerProtocolError("non-finite JSON is forbidden")
            ),
        )
    except UserBrokerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise UserBrokerProtocolError(f"{label} packet is not strict JSON") from error
    if not isinstance(value, dict):
        raise UserBrokerProtocolError(f"{label} packet is not an object")
    return value


def _encode(value: dict[str, object], maximum: int, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise UserBrokerProtocolError(f"{label} cannot be encoded") from error
    if not 1 <= len(encoded) <= maximum:
        raise UserBrokerProtocolError(f"{label} packet size is invalid")
    return encoded


def encode_request(request: BrokerRequest) -> bytes:
    if (
        not isinstance(request, BrokerRequest)
        or request.command not in COMMANDS
        or not isinstance(request.operation, str)
        or request.operation not in t2_user_policy.OPERATION_POLICIES
        or (
            request.command == IDENTITIES_COMMAND
            and request.operation != "inventory"
        )
    ):
        raise UserBrokerProtocolError("broker request is invalid")
    return _encode(request.public(), MAX_REQUEST_BYTES, "request")


def decode_request(data: bytes) -> BrokerRequest:
    value = _decode(data, MAX_REQUEST_BYTES, "request")
    if (
        set(value) != REQUEST_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("command") not in COMMANDS
        or not isinstance(value.get("operation"), str)
        or value.get("operation") not in t2_user_policy.OPERATION_POLICIES
        or (
            value.get("command") == IDENTITIES_COMMAND
            and value.get("operation") != "inventory"
        )
    ):
        raise UserBrokerProtocolError("broker request schema is invalid")
    request = BrokerRequest(value["command"], value["operation"])
    if encode_request(request) != data:
        raise UserBrokerProtocolError("broker request is not canonical")
    return request


def _validate_response(response: PreflightResponse) -> None:
    if not isinstance(response, PreflightResponse):
        raise UserBrokerProtocolError("preflight response has the wrong type")
    expected = (
        t2_user_policy.OPERATION_POLICIES.get(response.operation)
        if isinstance(response.operation, str)
        else None
    )
    if (
        not isinstance(response.operation, str)
        or not isinstance(response.state, str)
        or not isinstance(response.policy_action, str)
        or expected is None
        or response.state not in POLICY_STATES
        or response.policy_action != expected.action
        or type(response.operation_permitted) is not bool
        or type(response.activation_required) is not bool
        or type(response.activation_permitted) is not bool
        or (
            response.readiness_state is not None
            and response.readiness_state not in READINESS_STATES
        )
        or type(response.quarantine) is not bool
        or type(response.ready_handoff_proved) is not bool
    ):
        raise UserBrokerProtocolError("preflight response schema is invalid")
    authorized_shape = (
        response.state == "authorized"
        and response.operation_permitted is True
        and response.activation_required is False
        and response.activation_permitted is False
        and response.readiness_state == "ready"
        and response.quarantine is False
        and response.ready_handoff_proved is True
    )
    if (response.state == "authorized") != authorized_shape:
        raise UserBrokerProtocolError("preflight handoff claim is inconsistent")
    if response.state != "authorized" and (
        response.operation_permitted
        or response.activation_permitted
        or response.ready_handoff_proved
    ):
        raise UserBrokerProtocolError("denied preflight carries authority")
    if response.activation_required != (
        response.state == "activation-authorization-required"
    ):
        raise UserBrokerProtocolError(
            "preflight activation requirement is inconsistent"
        )
    if response.quarantine != (
        response.state
        in {"caller-account-generation-mismatch", "target-quarantined"}
    ):
        raise UserBrokerProtocolError("preflight quarantine state is inconsistent")
    if response.state == "activation-authorized":
        raise UserBrokerProtocolError(
            "read-only preflight cannot carry activation authority"
        )


def response_from_result(
    request: BrokerRequest,
    result: t2_user_broker.BrokerResult,
) -> PreflightResponse:
    if (
        not isinstance(request, BrokerRequest)
        or request.command != PREFLIGHT_COMMAND
        or not isinstance(result, t2_user_broker.BrokerResult)
    ):
        raise UserBrokerProtocolError("preflight result has the wrong type")
    decision = result.decision
    if decision.operation != request.operation:
        raise UserBrokerProtocolError("preflight result operation changed")
    response = PreflightResponse(
        decision.operation,
        decision.state,
        decision.policy_action,
        decision.operation_permitted,
        decision.activation_required,
        decision.activation_permitted,
        decision.readiness_state,
        decision.quarantine,
        result.consumer_invoked,
    )
    _validate_response(response)
    return response


def _validate_inventory_response(response: InventoryResponse) -> None:
    if not isinstance(response, InventoryResponse):
        raise UserBrokerProtocolError("inventory response has the wrong type")
    _validate_response(
        PreflightResponse(
            "inventory",
            response.state,
            response.policy_action,
            response.operation_permitted,
            response.activation_required,
            response.activation_permitted,
            response.readiness_state,
            response.quarantine,
            response.broker_consumer_invoked,
        )
    )
    if response.broker_consumer_invoked != (response.inventory is not None):
        raise UserBrokerProtocolError("inventory handoff claim is inconsistent")
    if response.inventory is not None:
        try:
            parsed = t2_user_broker_inventory.parse_public_inventory(
                response.inventory.public()
            )
        except t2_user_broker_inventory.UserBrokerInventoryError as error:
            raise UserBrokerProtocolError("inventory response is invalid") from error
        if parsed != response.inventory:
            raise UserBrokerProtocolError("inventory response changed during validation")


def response_from_inventory_result(
    request: BrokerRequest,
    result: t2_user_broker_inventory.BrokerInventoryResult,
) -> InventoryResponse:
    if (
        not isinstance(request, BrokerRequest)
        or request != BrokerRequest(IDENTITIES_COMMAND, "inventory")
        or not isinstance(
            result, t2_user_broker_inventory.BrokerInventoryResult
        )
        or result.decision.operation != "inventory"
    ):
        raise UserBrokerProtocolError("inventory result has the wrong type")
    decision = result.decision
    response = InventoryResponse(
        decision.state,
        decision.policy_action,
        decision.operation_permitted,
        decision.activation_required,
        decision.activation_permitted,
        decision.readiness_state,
        decision.quarantine,
        result.consumer_invoked,
        result.inventory,
    )
    _validate_inventory_response(response)
    return response


def encode_response(response: PreflightResponse | InventoryResponse) -> bytes:
    if isinstance(response, PreflightResponse):
        _validate_response(response)
    elif isinstance(response, InventoryResponse):
        _validate_inventory_response(response)
    else:
        raise UserBrokerProtocolError("broker response has the wrong type")
    return _encode(response.public(), MAX_RESPONSE_BYTES, "response")


def decode_response(data: bytes) -> PreflightResponse | InventoryResponse:
    value = _decode(data, MAX_RESPONSE_BYTES, "response")
    command = value.get("command")
    if command == IDENTITIES_COMMAND:
        return _decode_inventory_response(value, data)
    if (
        set(value) != PREFLIGHT_RESPONSE_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or command != PREFLIGHT_COMMAND
        or value.get("t2_mutation_performed") is not False
        or value.get("identifiers_redacted") is not True
    ):
        raise UserBrokerProtocolError("preflight response schema is invalid")
    response = PreflightResponse(
        value.get("operation"),
        value.get("state"),
        value.get("policy_action"),
        value.get("operation_permitted"),
        value.get("activation_required"),
        value.get("activation_permitted"),
        value.get("readiness_state"),
        value.get("quarantine"),
        value.get("ready_handoff_proved"),
    )
    _validate_response(response)
    if encode_response(response) != data:
        raise UserBrokerProtocolError("preflight response is not canonical")
    return response


def _decode_inventory_response(
    value: dict[str, object], data: bytes
) -> InventoryResponse:
    if (
        set(value) != INVENTORY_RESPONSE_KEYS
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
        or value.get("command") != IDENTITIES_COMMAND
        or value.get("operation") != "inventory"
        or value.get("t2_mutation_performed") is not False
        or value.get("identifiers_redacted") is not True
        or type(value.get("broker_consumer_invoked")) is not bool
        or type(value.get("identity_inventory_available")) is not bool
        or value["identity_inventory_available"]
        != value["broker_consumer_invoked"]
    ):
        raise UserBrokerProtocolError("inventory response schema is invalid")
    raw_inventory = value.get("inventory")
    if value["identity_inventory_available"]:
        try:
            inventory = t2_user_broker_inventory.parse_public_inventory(
                raw_inventory
            )
        except t2_user_broker_inventory.UserBrokerInventoryError as error:
            raise UserBrokerProtocolError(
                "inventory response payload is invalid"
            ) from error
    else:
        if raw_inventory is not None:
            raise UserBrokerProtocolError(
                "denied inventory response contains data"
            )
        inventory = None
    response = InventoryResponse(
        value.get("state"),
        value.get("policy_action"),
        value.get("operation_permitted"),
        value.get("activation_required"),
        value.get("activation_permitted"),
        value.get("readiness_state"),
        value.get("quarantine"),
        value["broker_consumer_invoked"],
        inventory,
    )
    _validate_inventory_response(response)
    if encode_response(response) != data:
        raise UserBrokerProtocolError("inventory response is not canonical")
    return response


def _require_seqpacket(connection: socket.socket) -> None:
    if not isinstance(connection, socket.socket):
        raise UserBrokerProtocolError("broker connection has the wrong type")
    try:
        domain = connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        kind = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    except OSError as error:
        raise UserBrokerProtocolError("broker socket metadata is unavailable") from error
    if domain != socket.AF_UNIX or kind != socket.SOCK_SEQPACKET:
        raise UserBrokerProtocolError(
            "broker connection must be a Unix seqpacket socket"
        )


def receive_request(connection: socket.socket) -> BrokerRequest:
    _require_seqpacket(connection)
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_REQUEST_BYTES,
            0,
        )
    except OSError as error:
        raise UserBrokerProtocolError("broker request receive failed") from error
    forbidden_flags = socket.MSG_TRUNC | socket.MSG_CTRUNC
    if ancillary or flags & forbidden_flags:
        raise UserBrokerProtocolError(
            "broker request is truncated or contains ancillary data"
        )
    return decode_request(data)


def send_response(
    connection: socket.socket,
    response: PreflightResponse | InventoryResponse,
) -> None:
    _require_seqpacket(connection)
    encoded = encode_response(response)
    try:
        sent = connection.send(encoded)
    except OSError as error:
        raise UserBrokerProtocolError("broker response send failed") from error
    if sent != len(encoded):
        raise UserBrokerProtocolError("broker response send was incomplete")
