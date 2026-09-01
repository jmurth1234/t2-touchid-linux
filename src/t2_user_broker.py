# SPDX-License-Identifier: GPL-2.0-only
"""Joined self-service authorization transaction for one mapped T2 user.

The transaction keeps one kernel-pinned IPC peer, protected mapping lock,
machine-wide biometric lock, and Bridge generation alive through policy
collection and the authorized consumer handoff.  It does not expose a public
socket or choose a biometric operation implementation.
"""

from __future__ import annotations

import inspect
import os
import socket
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, TypeVar

import t2_ipc_session
import t2_user_mapping
import t2_user_mapping_admin
import t2_user_policy
import t2_user_readiness
import t2_user_reconciliation_live


BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
ResultValue = TypeVar("ResultValue")


class UserBrokerError(RuntimeError):
    pass


class BrokerLiveSession(Protocol):
    @property
    def runtime_generation(self) -> str: ...

    def collect(
        self,
        selected: t2_user_mapping.UserMapping,
        linux_account_generation: str,
        keybag_sha256: str,
    ) -> tuple[
        t2_user_readiness.PersistentEvidence,
        t2_user_readiness.AliasEvidence,
    ]: ...

    def public_identity_inventory(
        self, selected: t2_user_mapping.UserMapping
    ) -> dict[str, object]: ...


class BrokerAuthorizationSession(Protocol):
    caller: t2_user_policy.CallerEvidence

    @property
    def account(self): ...

    @property
    def session(self): ...

    def collect(self, **arguments) -> t2_ipc_session.AuthorizationEvidence: ...

    def revalidate(self) -> None: ...


AuthorizationFactory = Callable[[socket.socket], object]
LiveFactory = Callable[[], object]
Clock = Callable[[], int]
BootReader = Callable[[], str]
Consumer = Callable[["BrokerAuthority", BrokerLiveSession], ResultValue]


@dataclass(frozen=True, repr=False)
class BrokerAuthority:
    mapping_set: t2_user_mapping.UserMappingSet = field(repr=False)
    selected: t2_user_mapping.UserMapping = field(repr=False)
    persistent: t2_user_readiness.PersistentEvidence = field(repr=False)
    alias: t2_user_readiness.AliasEvidence = field(repr=False)
    decision: t2_user_policy.UserPolicyDecision = field(repr=False)
    operation_id: str
    linux_boot_uuid: str
    runtime_generation: str
    stage: str


@dataclass(frozen=True, repr=False)
class BrokerResult:
    decision: t2_user_policy.UserPolicyDecision = field(repr=False)
    consumer_invoked: bool
    value: object = field(repr=False)

    def redacted(self) -> dict[str, object]:
        result = self.decision.redacted()
        result.update(
            {
                "broker_consumer_invoked": self.consumer_invoked,
                "identifiers_redacted": True,
            }
        )
        return result


def _authorization_factory(connection: socket.socket):
    return t2_ipc_session.AuthorizationSession.from_socket(connection)


def _live_factory():
    return t2_user_reconciliation_live.LiveUserReconciliationSession()


def _boot_id() -> str:
    try:
        first = BOOT_ID.read_text(encoding="ascii").strip()
        second = BOOT_ID.read_text(encoding="ascii").strip()
        parsed = uuid.UUID(first)
    except (OSError, UnicodeError, ValueError, AttributeError) as error:
        raise UserBrokerError("Linux boot identity is unavailable") from error
    if first != second or str(parsed) != first or parsed.int == 0:
        raise UserBrokerError("Linux boot identity is unstable or invalid")
    return first


def _monotonic(clock: Clock) -> int:
    try:
        value = clock()
        return t2_user_policy._monotonic(value, "broker monotonic time")
    except t2_user_policy.UserPolicyError as error:
        raise UserBrokerError("broker monotonic time is invalid") from error
    except Exception as error:
        raise UserBrokerError("broker monotonic time is unavailable") from error


def _live_collect(
    session: BrokerLiveSession,
    selected: t2_user_mapping.UserMapping,
    account_generation: str,
    keybag_sha256: str,
) -> tuple[
    t2_user_readiness.PersistentEvidence,
    t2_user_readiness.AliasEvidence,
]:
    try:
        value = session.collect(
            selected,
            account_generation,
            keybag_sha256,
        )
    except Exception as error:
        raise UserBrokerError("live target evidence collection failed") from error
    if (
        type(value) is not tuple
        or len(value) != 2
        or not isinstance(value[0], t2_user_readiness.PersistentEvidence)
        or not isinstance(value[1], t2_user_readiness.AliasEvidence)
    ):
        raise UserBrokerError("live target evidence is malformed")
    return value


def _authorization_collect(
    authorization: BrokerAuthorizationSession,
    **arguments,
) -> t2_ipc_session.AuthorizationEvidence:
    try:
        value = authorization.collect(**arguments)
    except Exception as error:
        raise UserBrokerError("caller policy collection failed") from error
    if (
        not isinstance(value, t2_ipc_session.AuthorizationEvidence)
        or value.caller != authorization.caller
        or value.account != authorization.account
        or value.session != authorization.session
    ):
        raise UserBrokerError("caller policy evidence is inconsistent")
    return value


def _stable_mapping(
    directory: int,
    name: str,
    expected: t2_user_mapping.UserMappingSet,
) -> None:
    current = t2_user_mapping_admin._load_optional(directory, name)
    if current is None or current != expected:
        raise UserBrokerError("protected mapping changed during authorization")


def _keybag(
    selected: t2_user_mapping.UserMapping,
    reader: t2_user_mapping_admin.KeybagReader,
) -> str:
    try:
        digest = reader(Path(selected.keybag_path))
        t2_user_mapping._sha256(digest, "keybag digest")
    except Exception as error:
        raise UserBrokerError("protected keybag assertion failed") from error
    if digest != selected.keybag_sha256:
        raise UserBrokerError("protected keybag digest changed")
    return digest


def run_self_service(
    connection: socket.socket,
    *,
    operation: str,
    modification_allowed: bool,
    consumer: Consumer[ResultValue],
    mapping_path: Path = t2_user_mapping_admin.DEFAULT_MAPPING_PATH,
    authorization_factory: AuthorizationFactory = _authorization_factory,
    live_factory: LiveFactory = _live_factory,
    keybag_reader: t2_user_mapping_admin.KeybagReader = (
        t2_user_mapping_admin._keybag_digest
    ),
    boot_reader: BootReader = _boot_id,
    clock: Clock = time.monotonic_ns,
    allow_user_interaction: bool = True,
    collect_activation_authority: bool = True,
    grant_lifetime_ns: int = 60 * 1_000_000_000,
) -> BrokerResult:
    """Authorize and invoke one internal consumer while all leases remain held."""

    try:
        t2_user_mapping_admin._require_root()
    except t2_user_mapping_admin.UserMappingAdminError as error:
        raise UserBrokerError("self-service broker requires root") from error
    if operation not in t2_user_policy.OPERATION_POLICIES:
        raise UserBrokerError("broker operation is unsupported")
    if type(modification_allowed) is not bool:
        raise UserBrokerError("modification policy must be Boolean")
    if type(allow_user_interaction) is not bool:
        raise UserBrokerError("interaction policy must be Boolean")
    if type(collect_activation_authority) is not bool:
        raise UserBrokerError("activation collection policy must be Boolean")
    if not callable(consumer):
        raise UserBrokerError("broker consumer is unavailable")
    try:
        operation_id = str(uuid.uuid4())
        linux_boot_uuid = boot_reader()
        t2_user_policy._canonical_uuid(linux_boot_uuid, "Linux boot UUID")
    except UserBrokerError:
        raise
    except Exception as error:
        raise UserBrokerError("broker identities are unavailable") from error

    directory = -1
    mapping_lock = -1
    try:
        authorization_manager = authorization_factory(connection)
        if not hasattr(authorization_manager, "__enter__") or not hasattr(
            authorization_manager, "__exit__"
        ):
            raise UserBrokerError("authorization session has the wrong type")
        with authorization_manager as authorization:
            if not isinstance(
                authorization.caller, t2_user_policy.CallerEvidence
            ):
                raise UserBrokerError("authorization caller is malformed")
            target_uid = authorization.caller.linux_uid
            directory, name = t2_user_mapping_admin._open_parent(mapping_path)
            mapping_lock = t2_user_mapping_admin._open_lock(directory, name)
            mapping_set = t2_user_mapping_admin._load_optional(directory, name)
            if mapping_set is None:
                raise UserBrokerError("protected mapping does not exist")
            policy = t2_user_policy.OPERATION_POLICIES[operation]
            try:
                selected = mapping_set.resolve(target_uid, policy.capability)
            except t2_user_mapping.UserMappingError as error:
                raise UserBrokerError(
                    "caller has no enabled mapping for this operation"
                ) from error
            if authorization.account.generation != selected.linux_account_generation:
                raise UserBrokerError("caller account generation is not mapped")
            keybag_sha256 = _keybag(selected, keybag_reader)

            live_manager = live_factory()
            if not hasattr(live_manager, "__enter__") or not hasattr(
                live_manager, "__exit__"
            ):
                raise UserBrokerError("live broker session has the wrong type")
            with live_manager as live:
                runtime_generation = live.runtime_generation
                try:
                    t2_user_policy._canonical_uuid(
                        runtime_generation, "runtime generation"
                    )
                except t2_user_policy.UserPolicyError as error:
                    raise UserBrokerError(
                        "live broker generation is invalid"
                    ) from error
                first = _live_collect(
                    live,
                    selected,
                    authorization.account.generation,
                    keybag_sha256,
                )
                try:
                    readiness = t2_user_readiness.assess(
                        selected, policy.capability, *first
                    )
                except t2_user_readiness.UserReadinessError as error:
                    raise UserBrokerError(
                        "live target readiness is malformed"
                    ) from error

                operation_evidence = _authorization_collect(
                    authorization,
                    target_linux_uid=target_uid,
                    action=policy.action,
                    mapping_generation=mapping_set.generation,
                    operation_id=operation_id,
                    linux_boot_uuid=linux_boot_uuid,
                    runtime_generation=runtime_generation,
                    allow_user_interaction=allow_user_interaction,
                    clock=clock,
                    grant_lifetime_ns=grant_lifetime_ns,
                )
                activation_evidence = None
                if (
                    collect_activation_authority
                    and operation_evidence.policy.grant.authorized
                    and readiness.state
                    in {
                        "alias-absent",
                        "device-locked",
                        "before-first-unlock",
                    }
                ):
                    activation_evidence = _authorization_collect(
                        authorization,
                        target_linux_uid=target_uid,
                        action=t2_user_policy.ACTIVATE_ACTION,
                        mapping_generation=mapping_set.generation,
                        operation_id=operation_id,
                        linux_boot_uuid=linux_boot_uuid,
                        runtime_generation=runtime_generation,
                        allow_user_interaction=allow_user_interaction,
                        clock=clock,
                        grant_lifetime_ns=grant_lifetime_ns,
                    )

                authorization.revalidate()
                _stable_mapping(directory, name, mapping_set)
                if authorization.account.generation != selected.linux_account_generation:
                    raise UserBrokerError(
                        "caller account changed during authorization"
                    )
                if _keybag(selected, keybag_reader) != keybag_sha256:
                    raise UserBrokerError(
                        "protected keybag changed during authorization"
                    )
                second = _live_collect(
                    live,
                    selected,
                    authorization.account.generation,
                    keybag_sha256,
                )
                if second != first:
                    raise UserBrokerError(
                        "live target changed during authorization"
                    )
                observed = _monotonic(clock)
                request = t2_user_policy.OperationRequest(
                    operation,
                    target_uid,
                    operation_id,
                    linux_boot_uuid,
                    runtime_generation,
                    observed,
                    modification_allowed,
                )
                decision = t2_user_policy.authorize(
                    mapping_set,
                    request,
                    operation_evidence.caller,
                    first[0],
                    first[1],
                    operation_evidence.policy.grant,
                    (
                        activation_evidence.policy.grant
                        if activation_evidence is not None
                        else None
                    ),
                )
                if decision.state not in {"authorized", "activation-authorized"}:
                    return BrokerResult(decision, False, None)

                authorization.revalidate()
                _stable_mapping(directory, name, mapping_set)
                _keybag(selected, keybag_reader)
                third = _live_collect(
                    live,
                    selected,
                    authorization.account.generation,
                    keybag_sha256,
                )
                if third != first:
                    raise UserBrokerError(
                        "live target changed before operation handoff"
                    )
                authorization.revalidate()
                _stable_mapping(directory, name, mapping_set)
                _keybag(selected, keybag_reader)
                activation = decision.state == "activation-authorized"
                try:
                    authorized_operation_id = (
                        t2_user_policy.require_bound_authority(
                            decision,
                            mapping_set,
                            selected,
                            policy.capability,
                            linux_boot_uuid=linux_boot_uuid,
                            runtime_generation=runtime_generation,
                            observed_monotonic_ns=_monotonic(clock),
                            activation=activation,
                        )
                    )
                except t2_user_policy.UserPolicyError as error:
                    raise UserBrokerError(
                        "broker authority expired or changed before handoff"
                    ) from error
                authority = BrokerAuthority(
                    mapping_set,
                    selected,
                    first[0],
                    first[1],
                    decision,
                    authorized_operation_id,
                    linux_boot_uuid,
                    runtime_generation,
                    "activate" if activation else "operate",
                )
                try:
                    value = consumer(authority, live)
                except Exception as error:
                    raise UserBrokerError(
                        "authorized broker consumer failed; inspect its journal"
                    ) from error
                if inspect.isawaitable(value):
                    close = getattr(value, "close", None)
                    if callable(close):
                        close()
                    raise UserBrokerError(
                        "authorized broker consumer must be synchronous"
                    )
                return BrokerResult(decision, True, value)
    except UserBrokerError:
        raise
    except (
        t2_ipc_session.IPCSessionError,
        t2_user_mapping_admin.UserMappingAdminError,
        t2_user_policy.UserPolicyError,
        t2_user_reconciliation_live.LiveUserReconciliationError,
    ) as error:
        raise UserBrokerError("self-service broker transaction failed") from error
    except Exception as error:
        raise UserBrokerError("self-service broker transaction failed") from error
    finally:
        if mapping_lock >= 0:
            os.close(mapping_lock)
        if directory >= 0:
            os.close(directory)
