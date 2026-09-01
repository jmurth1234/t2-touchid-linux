# SPDX-License-Identifier: GPL-2.0-only
"""Stable local-account and login-session evidence for an fprint claim."""

from __future__ import annotations

import pwd
from collections.abc import Callable
from dataclasses import dataclass, field

import t2_dbus_identity
import t2_ipc_session
import t2_linux_account


class FprintClaimError(RuntimeError):
    pass


NameResolver = Callable[[str], object]
AccountCollector = Callable[[int], t2_linux_account.AccountEvidence]


def _resolve_uid(username: object, resolver: NameResolver) -> int:
    if type(username) is not str:
        raise FprintClaimError("claimed Linux username is invalid")
    try:
        encoded = username.encode("ascii")
    except UnicodeEncodeError as error:
        raise FprintClaimError("claimed Linux username is invalid") from error
    if t2_linux_account.ACCOUNT_NAME.fullmatch(encoded) is None:
        raise FprintClaimError("claimed Linux username is invalid")
    try:
        record = resolver(username)
        record_name = record.pw_name
        uid = record.pw_uid
    except (KeyError, OSError, AttributeError) as error:
        raise FprintClaimError("claimed Linux account is unavailable") from error
    if (
        type(record_name) is not str
        or record_name != username
        or type(uid) is not int
        or not 1 <= uid < t2_linux_account.UINT32_MAX
    ):
        raise FprintClaimError("claimed Linux account is invalid")
    return uid


def _account(
    collector: AccountCollector, uid: int
) -> t2_linux_account.AccountEvidence:
    try:
        value = collector(uid)
    except t2_linux_account.LinuxAccountError as error:
        raise FprintClaimError("Linux account assertion failed") from error
    try:
        return t2_ipc_session.validate_account(value, uid)
    except t2_ipc_session.IPCSessionError as error:
        raise FprintClaimError("Linux account assertion failed") from error


def _session(
    caller: t2_dbus_identity.PinnedDBusCaller,
    backend: t2_ipc_session.SessionBackend,
    uid: int,
) -> t2_ipc_session.SessionEvidence:
    try:
        with caller.duplicate_peer() as peer:
            return t2_ipc_session.collect_session(
                peer, backend, expected_uid=uid
            )
    except (
        t2_dbus_identity.DBusIdentityError,
        t2_ipc_session.IPCSessionError,
    ) as error:
        raise FprintClaimError("active local login assertion failed") from error


@dataclass(frozen=True, repr=False)
class ClaimEvidence:
    username: str = field(repr=False)
    linux_uid: int = field(repr=False)
    account: t2_linux_account.AccountEvidence = field(repr=False)
    session: t2_ipc_session.SessionEvidence = field(repr=False)
    backend: t2_ipc_session.SessionBackend = field(repr=False, compare=False)
    resolver: NameResolver = field(repr=False, compare=False)
    account_collector: AccountCollector = field(repr=False, compare=False)

    def revalidate(
        self,
        caller: t2_dbus_identity.PinnedDBusCaller,
    ) -> None:
        if not isinstance(caller, t2_dbus_identity.PinnedDBusCaller):
            raise FprintClaimError("pinned D-Bus caller is invalid")
        try:
            caller.verify()
        except t2_dbus_identity.DBusIdentityError as error:
            raise FprintClaimError("D-Bus caller changed") from error
        if _resolve_uid(self.username, self.resolver) != self.linux_uid:
            raise FprintClaimError("claimed Linux account changed")
        if _session(caller, self.backend, self.linux_uid) != self.session:
            raise FprintClaimError("claimed login session changed")
        if _account(self.account_collector, self.linux_uid) != self.account:
            raise FprintClaimError("claimed Linux account changed")
        try:
            caller.verify()
        except t2_dbus_identity.DBusIdentityError as error:
            raise FprintClaimError("D-Bus caller changed") from error

    def authorization_session(
        self,
        caller: t2_dbus_identity.PinnedDBusCaller,
    ) -> t2_ipc_session.AuthorizationSession:
        """Create self-service authority only for a same-UID non-root caller."""
        self.revalidate(caller)
        if caller.subject.uid != self.linux_uid:
            raise FprintClaimError(
                "root or cross-user fprint claims cannot authorize mutation"
            )
        authorization = None
        try:
            peer = caller.duplicate_peer()
            authorization = t2_ipc_session.AuthorizationSession.from_peer(
                peer,
                expected_uid=self.linux_uid,
                expected_session=self.session,
                expected_account=self.account,
                backend=self.backend,
                account_collector=self.account_collector,
            )
            caller.verify()
            return authorization
        except (
            t2_dbus_identity.DBusIdentityError,
            t2_ipc_session.IPCSessionError,
        ) as error:
            if authorization is not None:
                authorization.close()
            raise FprintClaimError(
                "fprint mutation authority could not be derived"
            ) from error

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "account": self.account.redacted(),
            "session": self.session.redacted(),
            "identifiers_redacted": True,
        }


def collect(
    caller: t2_dbus_identity.PinnedDBusCaller,
    username: object,
    *,
    backend: t2_ipc_session.SessionBackend | None = None,
    resolver: NameResolver = pwd.getpwnam,
    account_collector: AccountCollector = t2_linux_account.collect,
) -> ClaimEvidence:
    """Join one pidfd-bound caller to one stable local account/session."""

    if not isinstance(caller, t2_dbus_identity.PinnedDBusCaller):
        raise FprintClaimError("pinned D-Bus caller is invalid")
    selected_backend = backend or t2_ipc_session.LibsystemdSessionBackend()
    try:
        caller.verify()
    except t2_dbus_identity.DBusIdentityError as error:
        raise FprintClaimError("D-Bus caller changed") from error
    uid = _resolve_uid(username, resolver)
    first_session = _session(caller, selected_backend, uid)
    account = _account(account_collector, uid)
    if _resolve_uid(username, resolver) != uid:
        raise FprintClaimError("claimed Linux account changed")
    if _session(caller, selected_backend, uid) != first_session:
        raise FprintClaimError("claimed login session changed")
    try:
        caller.verify()
    except t2_dbus_identity.DBusIdentityError as error:
        raise FprintClaimError("D-Bus caller changed") from error
    return ClaimEvidence(
        username,
        uid,
        account,
        first_session,
        selected_backend,
        resolver,
        account_collector,
    )
