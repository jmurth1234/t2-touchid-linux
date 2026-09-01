# SPDX-License-Identifier: GPL-2.0-only
"""Pinned Unix-peer and active local logind-session evidence.

Linux exposes the connected peer as both immutable SO_PEERCRED credentials and
an SO_PEERPIDFD reference.  The pidfd remains open across session and PolicyKit
collection, and libsystemd's pidfd API resolves the exact process rather than a
recyclable numeric PID.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import os
import re
import signal
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import t2_linux_account
import t2_polkit_grant
import t2_user_policy


SO_PEERPIDFD = 77
PEERCRED = struct.Struct("3i")
ALLOWED_SOCKET_TYPES = frozenset({socket.SOCK_STREAM, socket.SOCK_SEQPACKET})
ALLOWED_SESSION_TYPES = frozenset({"wayland", "x11", "tty"})
ALLOWED_SESSION_CLASSES = frozenset(
    {"user", "user-early", "user-light", "user-early-light"}
)
SESSION_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class IPCSessionError(RuntimeError):
    pass


class SessionUnavailable(IPCSessionError):
    pass


@dataclass(frozen=True)
class SessionDescription:
    uid: int
    active: bool
    remote: bool
    session_type: str
    session_class: str
    seat: str | None
    start_time_usec: int = 1


@dataclass(frozen=True, repr=False)
class SessionEvidence:
    binding: str
    session_id: str
    session_type: str
    session_class: str
    seat_attached: bool
    session_start_time_usec: int
    active_local_session: bool = True

    def caller(self, account_generation: str, uid: int) -> t2_user_policy.CallerEvidence:
        try:
            t2_user_policy._digest(
                account_generation, "caller account generation"
            )
        except t2_user_policy.UserPolicyError as error:
            raise IPCSessionError(str(error)) from error
        if (
            self.active_local_session is not True
            or type(uid) is not int
            or not 1 <= uid < (1 << 32) - 1
        ):
            raise IPCSessionError("caller UID is invalid")
        return t2_user_policy.CallerEvidence(
            uid, account_generation, True, self.active_local_session
        )

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "binding": self.binding,
            "session_type": self.session_type,
            "session_class": self.session_class,
            "seat_attached": self.seat_attached,
            "active_local_session": self.active_local_session,
            "identifiers_redacted": True,
        }


@dataclass(frozen=True, repr=False)
class AuthorizationEvidence:
    caller: t2_user_policy.CallerEvidence
    account: t2_linux_account.AccountEvidence
    session: SessionEvidence
    policy: t2_polkit_grant.PolkitGrantResult

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "account": self.account.redacted(),
            "session": self.session.redacted(),
            "policy": self.policy.redacted(),
            "identifiers_redacted": True,
        }


class SessionBackend(Protocol):
    def session_for_pidfd(self, pidfd: int) -> str | None: ...

    def active_sessions(self, uid: int) -> tuple[str, ...]: ...

    def describe(self, session: str) -> SessionDescription: ...


AccountCollector = Callable[[int], t2_linux_account.AccountEvidence]


def validate_account(
    value: object, uid: int
) -> t2_linux_account.AccountEvidence:
    if (
        not isinstance(value, t2_linux_account.AccountEvidence)
        or value.linux_uid != uid
        or value.source != "local-files-v1"
        or value.protected_password_record is not True
        or value.home_object_bound is not True
    ):
        raise IPCSessionError("Linux account collector returned invalid evidence")
    try:
        t2_user_policy._digest(value.generation, "caller account generation")
    except t2_user_policy.UserPolicyError as error:
        raise IPCSessionError(
            "Linux account collector returned invalid evidence"
        ) from error
    return value


class LibsystemdSessionBackend:
    def __init__(self, library: str = "libsystemd.so.0") -> None:
        try:
            self._systemd = ctypes.CDLL(library)
            self._libc = ctypes.CDLL(None)
        except OSError as error:
            raise IPCSessionError("libsystemd session API is unavailable") from error
        self._libc.free.argtypes = [ctypes.c_void_p]
        self._libc.free.restype = None
        self._configure()

    def _configure(self) -> None:
        string_output = ctypes.POINTER(ctypes.c_void_p)
        self._systemd.sd_pidfd_get_session.argtypes = [
            ctypes.c_int,
            string_output,
        ]
        self._systemd.sd_pidfd_get_session.restype = ctypes.c_int
        self._systemd.sd_uid_get_sessions.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            string_output,
        ]
        self._systemd.sd_uid_get_sessions.restype = ctypes.c_int
        self._systemd.sd_session_get_uid.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint),
        ]
        self._systemd.sd_session_get_uid.restype = ctypes.c_int
        self._systemd.sd_session_get_start_time.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint64),
        ]
        self._systemd.sd_session_get_start_time.restype = ctypes.c_int
        for name in ("sd_session_is_active", "sd_session_is_remote"):
            function = getattr(self._systemd, name)
            function.argtypes = [ctypes.c_char_p]
            function.restype = ctypes.c_int
        for name in (
            "sd_session_get_type",
            "sd_session_get_class",
            "sd_session_get_seat",
        ):
            function = getattr(self._systemd, name)
            function.argtypes = [ctypes.c_char_p, string_output]
            function.restype = ctypes.c_int

    @staticmethod
    def _session_bytes(session: str) -> bytes:
        if not isinstance(session, str) or SESSION_ID.fullmatch(session) is None:
            raise IPCSessionError("logind session identifier is invalid")
        return session.encode("ascii")

    def _owned_string(self, function, *arguments, absent: bool = False) -> str | None:
        output = ctypes.c_void_p()
        result = function(*arguments, ctypes.byref(output))
        if result < 0:
            if absent and result in {-errno.ENODATA, -errno.ENXIO, -errno.ESRCH}:
                return None
            if result in {-errno.ENODATA, -errno.ENXIO, -errno.ESRCH}:
                raise SessionUnavailable("logind session disappeared")
            raise IPCSessionError("libsystemd session string query failed")
        if not output.value:
            raise IPCSessionError("libsystemd returned an empty session string")
        try:
            raw = ctypes.string_at(output.value)
            value = raw.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise IPCSessionError("libsystemd returned an invalid string") from error
        finally:
            self._libc.free(output)
        if not value or len(value) > 256 or "\0" in value:
            raise IPCSessionError("libsystemd returned an unsafe string")
        return value

    def session_for_pidfd(self, pidfd: int) -> str | None:
        value = self._owned_string(
            self._systemd.sd_pidfd_get_session, pidfd, absent=True
        )
        if value is not None and SESSION_ID.fullmatch(value) is None:
            raise IPCSessionError("libsystemd returned an invalid session ID")
        return value

    def active_sessions(self, uid: int) -> tuple[str, ...]:
        output = ctypes.c_void_p()
        count = self._systemd.sd_uid_get_sessions(
            ctypes.c_uint(uid), 1, ctypes.byref(output)
        )
        if count < 0:
            if count in {-errno.ENODATA, -errno.ENXIO}:
                return ()
            raise IPCSessionError("libsystemd active-session query failed")
        if count == 0:
            if output.value:
                self._libc.free(output)
            return ()
        if not output.value or count > 128:
            if output.value:
                self._libc.free(output)
            raise IPCSessionError("libsystemd returned an invalid session list")
        pointers = ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))
        values: list[str] = []
        try:
            for index in range(count):
                pointer = pointers[index]
                if not pointer:
                    raise IPCSessionError(
                        "libsystemd session list contains an empty item"
                    )
                try:
                    value = ctypes.string_at(pointer).decode("ascii")
                except (UnicodeDecodeError, ValueError) as error:
                    raise IPCSessionError(
                        "libsystemd session list is malformed"
                    ) from error
                if SESSION_ID.fullmatch(value) is None or value in values:
                    raise IPCSessionError(
                        "libsystemd session list is ambiguous"
                    )
                values.append(value)
        finally:
            for index in range(count):
                pointer = pointers[index]
                if pointer:
                    self._libc.free(pointer)
            self._libc.free(output)
        return tuple(values)

    def describe(self, session: str) -> SessionDescription:
        encoded = self._session_bytes(session)
        uid = ctypes.c_uint()
        uid_result = self._systemd.sd_session_get_uid(encoded, ctypes.byref(uid))
        if uid_result in {-errno.ENODATA, -errno.ENXIO, -errno.ESRCH}:
            raise SessionUnavailable("logind session disappeared")
        if uid_result < 0:
            raise IPCSessionError("logind session UID query failed")
        active = self._systemd.sd_session_is_active(encoded)
        remote = self._systemd.sd_session_is_remote(encoded)
        if active in {-errno.ENODATA, -errno.ENXIO, -errno.ESRCH} or remote in {
            -errno.ENODATA,
            -errno.ENXIO,
            -errno.ESRCH,
        }:
            raise SessionUnavailable("logind session disappeared")
        if active < 0 or remote < 0:
            raise IPCSessionError("logind session state query failed")
        session_type = self._owned_string(
            self._systemd.sd_session_get_type, encoded
        )
        session_class = self._owned_string(
            self._systemd.sd_session_get_class, encoded
        )
        seat = self._owned_string(
            self._systemd.sd_session_get_seat, encoded, absent=True
        )
        start_time = ctypes.c_uint64()
        start_result = self._systemd.sd_session_get_start_time(
            encoded, ctypes.byref(start_time)
        )
        if start_result in {-errno.ENODATA, -errno.ENXIO, -errno.ESRCH}:
            raise SessionUnavailable("logind session disappeared")
        if start_result < 0 or not 0 < start_time.value < 1 << 64:
            raise IPCSessionError("logind session start-time query failed")
        assert session_type is not None and session_class is not None
        return SessionDescription(
            uid.value,
            active > 0,
            remote > 0,
            session_type,
            session_class,
            seat,
            start_time.value,
        )


class PinnedPeer:
    def __init__(
        self,
        pidfd: int,
        subject: t2_polkit_grant.ProcessSubject,
        *,
        proc_root: Path,
        allow_root: bool = False,
    ) -> None:
        self.pidfd = pidfd
        self.subject = subject
        self.proc_root = proc_root
        self.allow_root = allow_root
        self._closed = False

    @classmethod
    def from_process_fd(
        cls,
        pidfd: int,
        pid: int,
        uid: int,
        *,
        proc_root: Path = t2_polkit_grant.PROC_ROOT,
        allow_root: bool = False,
    ) -> "PinnedPeer":
        """Take ownership of a D-Bus/SO_PEERPIDFD process descriptor."""
        if (
            type(pidfd) is not int
            or pidfd < 0
            or type(pid) is not int
            or not 1 <= pid <= t2_polkit_grant.MAX_PID
            or type(uid) is not int
            or type(allow_root) is not bool
            or not (0 if allow_root else 1) <= uid < (1 << 32) - 1
            or not isinstance(proc_root, Path)
            or not proc_root.is_absolute()
        ):
            if type(pidfd) is int and pidfd >= 0:
                try:
                    os.close(pidfd)
                except OSError:
                    pass
            raise IPCSessionError("pinned process credentials are invalid")
        try:
            fcntl.fcntl(pidfd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            if (
                os.readlink(Path("/proc/self/fd") / str(pidfd))
                != "anon_inode:[pidfd]"
            ):
                raise IPCSessionError("process descriptor is not a pidfd")
            fdinfo = t2_polkit_grant._read_bounded(
                Path("/proc/self/fdinfo") / str(pidfd)
            ).decode("ascii")
            pid_rows = [
                line[4:].strip()
                for line in fdinfo.splitlines()
                if line.startswith("Pid:")
            ]
            if (
                len(pid_rows) != 1
                or not pid_rows[0].isdecimal()
                or int(pid_rows[0], 10) != pid
            ):
                raise IPCSessionError("pidfd does not match the credential PID")
            subject = t2_polkit_grant.read_process_subject(
                pid, uid, proc_root=proc_root, allow_root=allow_root
            )
            peer = cls(
                pidfd, subject, proc_root=proc_root, allow_root=allow_root
            )
            peer.verify()
            return peer
        except BaseException:
            try:
                os.close(pidfd)
            except OSError:
                pass
            raise

    @classmethod
    def from_socket(
        cls,
        connection: socket.socket,
        *,
        proc_root: Path = t2_polkit_grant.PROC_ROOT,
    ) -> "PinnedPeer":
        if not isinstance(connection, socket.socket):
            raise IPCSessionError("IPC connection has the wrong type")
        try:
            domain = connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
            socket_type = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_TYPE
            )
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size
            )
        except OSError as error:
            raise IPCSessionError("IPC peer credentials are unavailable") from error
        if domain != socket.AF_UNIX or socket_type not in ALLOWED_SOCKET_TYPES:
            raise IPCSessionError("IPC connection is not a supported Unix socket")
        if len(credentials) != PEERCRED.size:
            raise IPCSessionError("IPC peer credentials have the wrong size")
        pid, uid, gid = PEERCRED.unpack(credentials)
        if (
            not 1 <= pid <= t2_polkit_grant.MAX_PID
            or not 1 <= uid < (1 << 32) - 1
            or not 0 <= gid < (1 << 32) - 1
        ):
            raise IPCSessionError("IPC peer credentials are invalid")
        try:
            pidfd = connection.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
            if type(pidfd) is not int or pidfd < 0:
                raise OSError(errno.EBADF, "invalid peer pidfd")
            fcntl.fcntl(pidfd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        except OSError as error:
            raise IPCSessionError("kernel peer pidfd is unavailable") from error
        return cls.from_process_fd(
            pidfd, pid, uid, proc_root=proc_root
        )

    def verify(self) -> t2_polkit_grant.ProcessSubject:
        if self._closed:
            raise IPCSessionError("IPC peer pidfd is closed")
        try:
            signal.pidfd_send_signal(self.pidfd, 0)
        except OSError as error:
            raise IPCSessionError("IPC peer process is no longer alive") from error
        current = t2_polkit_grant.read_process_subject(
            self.subject.pid,
            self.subject.uid,
            proc_root=self.proc_root,
            allow_root=self.allow_root,
        )
        if current != self.subject:
            raise IPCSessionError("IPC peer process identity changed")
        return current

    def close(self) -> None:
        if not self._closed:
            os.close(self.pidfd)
            self._closed = True

    def __enter__(self) -> "PinnedPeer":
        if self._closed:
            raise IPCSessionError("IPC peer pidfd is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


def _acceptable(description: SessionDescription, uid: int) -> bool:
    return (
        isinstance(description, SessionDescription)
        and description.uid == uid
        and description.active is True
        and description.remote is False
        and description.session_type in ALLOWED_SESSION_TYPES
        and description.session_class in ALLOWED_SESSION_CLASSES
        and isinstance(description.seat, str)
        and 0 < len(description.seat) <= 64
        and type(description.start_time_usec) is int
        and 0 < description.start_time_usec < 1 << 64
    )


def collect_session(
    peer: PinnedPeer,
    backend: SessionBackend | None = None,
    *,
    expected_uid: int | None = None,
) -> SessionEvidence:
    if not isinstance(peer, PinnedPeer):
        raise IPCSessionError("pinned IPC peer has the wrong type")
    backend = backend or LibsystemdSessionBackend()
    peer.verify()
    selected_uid = peer.subject.uid if expected_uid is None else expected_uid
    if (
        type(selected_uid) is not int
        or not 1 <= selected_uid < (1 << 32) - 1
        or (
            peer.subject.uid != selected_uid
            and peer.subject.uid != t2_linux_account.ROOT_UID
        )
    ):
        raise IPCSessionError("claimed Linux UID is not bound to the peer")
    direct = backend.session_for_pidfd(peer.pidfd)
    binding = "pidfd-session"
    selected: tuple[str, ...]
    if direct is not None:
        selected = (direct,)
    else:
        if peer.subject.uid == t2_linux_account.ROOT_UID:
            raise IPCSessionError(
                "root caller has no directly bound login session"
            )
        binding = "uid-active-session"
        selected = backend.active_sessions(selected_uid)
    acceptable: list[tuple[str, SessionDescription]] = []
    for session in selected:
        try:
            description = backend.describe(session)
        except SessionUnavailable:
            if direct is not None:
                raise
            continue
        if _acceptable(description, selected_uid):
            acceptable.append((session, description))
    if len(acceptable) != 1:
        raise IPCSessionError(
            "caller has no unique active local physical login session"
        )
    peer.verify()
    chosen_id, chosen = acceptable[0]
    return SessionEvidence(
        binding,
        chosen_id,
        chosen.session_type,
        chosen.session_class,
        True,
        chosen.start_time_usec,
    )


def collect_authorization(
    connection: socket.socket,
    *,
    target_linux_uid: int,
    action: str,
    mapping_generation: str,
    operation_id: str,
    linux_boot_uuid: str,
    runtime_generation: str,
    allow_user_interaction: bool,
    backend: SessionBackend | None = None,
    proc_root: Path = t2_polkit_grant.PROC_ROOT,
    pkcheck: Path = t2_polkit_grant.PKCHECK,
    runner: t2_polkit_grant.Runner = t2_polkit_grant._default_runner,
    clock: t2_polkit_grant.Clock = time.monotonic_ns,
    grant_lifetime_ns: int = t2_polkit_grant.DEFAULT_GRANT_LIFETIME_NS,
    timeout_seconds: int = 120,
    account_collector: AccountCollector = t2_linux_account.collect,
) -> AuthorizationEvidence:
    """Join a pinned peer, local account/session, and PolicyKit result."""

    with AuthorizationSession.from_socket(
        connection,
        backend=backend,
        proc_root=proc_root,
        account_collector=account_collector,
    ) as session:
        return session.collect(
            target_linux_uid=target_linux_uid,
            action=action,
            mapping_generation=mapping_generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=runtime_generation,
            allow_user_interaction=allow_user_interaction,
            pkcheck=pkcheck,
            runner=runner,
            clock=clock,
            grant_lifetime_ns=grant_lifetime_ns,
            timeout_seconds=timeout_seconds,
        )


class AuthorizationSession:
    """Hold one kernel-pinned peer and login/account assertion across grants."""

    def __init__(
        self,
        peer: PinnedPeer,
        backend: SessionBackend,
        session: SessionEvidence,
        account: t2_linux_account.AccountEvidence,
        account_collector: AccountCollector,
    ) -> None:
        self._peer = peer
        self._backend = backend
        self._session = session
        self._account = account
        self._account_collector = account_collector
        self._closed = False
        self.caller = session.caller(account.generation, peer.subject.uid)

    @classmethod
    def from_socket(
        cls,
        connection: socket.socket,
        *,
        backend: SessionBackend | None = None,
        proc_root: Path = t2_polkit_grant.PROC_ROOT,
        account_collector: AccountCollector = t2_linux_account.collect,
    ) -> "AuthorizationSession":
        peer = PinnedPeer.from_socket(connection, proc_root=proc_root)
        try:
            selected_backend = backend or LibsystemdSessionBackend()
            session = collect_session(peer, selected_backend)
            try:
                account = validate_account(
                    account_collector(peer.subject.uid), peer.subject.uid
                )
            except t2_linux_account.LinuxAccountError as error:
                raise IPCSessionError("Linux account assertion failed") from error
            return cls(
                peer,
                selected_backend,
                session,
                account,
                account_collector,
            )
        except BaseException:
            peer.close()
            raise

    @property
    def account(self) -> t2_linux_account.AccountEvidence:
        return self._account

    @property
    def session(self) -> SessionEvidence:
        return self._session

    def revalidate(self) -> None:
        if self._closed:
            raise IPCSessionError("authorization session is closed")
        self._peer.verify()
        current_session = collect_session(self._peer, self._backend)
        if current_session != self._session:
            raise IPCSessionError(
                "caller login session changed during authorization"
            )
        try:
            current_account = validate_account(
                self._account_collector(self._peer.subject.uid),
                self._peer.subject.uid,
            )
        except t2_linux_account.LinuxAccountError as error:
            raise IPCSessionError("Linux account revalidation failed") from error
        if current_account != self._account:
            raise IPCSessionError("Linux account changed during authorization")

    def collect(
        self,
        *,
        target_linux_uid: int,
        action: str,
        mapping_generation: str,
        operation_id: str,
        linux_boot_uuid: str,
        runtime_generation: str,
        allow_user_interaction: bool,
        pkcheck: Path = t2_polkit_grant.PKCHECK,
        runner: t2_polkit_grant.Runner = t2_polkit_grant._default_runner,
        clock: t2_polkit_grant.Clock = time.monotonic_ns,
        grant_lifetime_ns: int = t2_polkit_grant.DEFAULT_GRANT_LIFETIME_NS,
        timeout_seconds: int = 120,
    ) -> AuthorizationEvidence:
        if self._closed:
            raise IPCSessionError("authorization session is closed")
        self._peer.verify()
        result = t2_polkit_grant.collect(
            caller_pid=self._peer.subject.pid,
            peer_uid=self._peer.subject.uid,
            account_generation=self._account.generation,
            target_linux_uid=target_linux_uid,
            action=action,
            mapping_generation=mapping_generation,
            operation_id=operation_id,
            linux_boot_uuid=linux_boot_uuid,
            runtime_generation=runtime_generation,
            allow_user_interaction=allow_user_interaction,
            proc_root=self._peer.proc_root,
            pkcheck=pkcheck,
            runner=runner,
            clock=clock,
            grant_lifetime_ns=grant_lifetime_ns,
            timeout_seconds=timeout_seconds,
        )
        self.revalidate()
        if (
            result.grant.caller_linux_uid != self._peer.subject.uid
            or result.grant.target_linux_uid != target_linux_uid
        ):
            raise IPCSessionError("PolicyKit grant is not bound to the IPC peer")
        return AuthorizationEvidence(
            self.caller,
            self._account,
            self._session,
            result,
        )

    def close(self) -> None:
        if not self._closed:
            self._peer.close()
            self._closed = True

    def __enter__(self) -> "AuthorizationSession":
        if self._closed:
            raise IPCSessionError("authorization session is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
