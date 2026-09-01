# SPDX-License-Identifier: GPL-2.0-only
"""Kernel-pinned process identity for one system-bus unique sender."""

from __future__ import annotations

import fcntl
import os
import signal
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from dbus_next import Message, MessageType, Variant

import t2_dbus_sender
import t2_ipc_session
import t2_polkit_grant


DBUS_DESTINATION = "org.freedesktop.DBus"
DBUS_PATH = "/org/freedesktop/DBus"
DBUS_INTERFACE = "org.freedesktop.DBus"
PROC_ROOT = Path("/proc")


class DBusIdentityError(RuntimeError):
    pass


class BusCaller(Protocol):
    async def call(self, message: Message) -> Message: ...


def _close_all(descriptors: object) -> None:
    if not isinstance(descriptors, list):
        return
    for descriptor in descriptors:
        if type(descriptor) is int and descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _pidfd_matches(pidfd: int, pid: int) -> None:
    try:
        fcntl.fcntl(pidfd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        if (
            os.readlink(Path("/proc/self/fd") / str(pidfd))
            != "anon_inode:[pidfd]"
        ):
            raise DBusIdentityError("D-Bus ProcessFD is not a pidfd")
        fdinfo = t2_polkit_grant._read_bounded(
            Path("/proc/self/fdinfo") / str(pidfd)
        ).decode("ascii")
    except DBusIdentityError:
        raise
    except (OSError, UnicodeError, t2_polkit_grant.PolkitGrantError) as error:
        raise DBusIdentityError("D-Bus ProcessFD is invalid") from error
    rows = [
        line[4:].strip()
        for line in fdinfo.splitlines()
        if line.startswith("Pid:")
    ]
    if len(rows) != 1 or not rows[0].isdecimal() or int(rows[0], 10) != pid:
        raise DBusIdentityError("D-Bus ProcessFD does not match ProcessID")


@dataclass(repr=False)
class PinnedDBusCaller:
    sender: str
    subject: t2_polkit_grant.ProcessSubject = field(repr=False)
    pidfd: int = field(repr=False)
    proc_root: Path = field(repr=False, default=PROC_ROOT)
    _closed: bool = field(init=False, repr=False, default=False)

    def verify(self) -> t2_polkit_grant.ProcessSubject:
        if self._closed:
            raise DBusIdentityError("D-Bus caller pidfd is closed")
        try:
            signal.pidfd_send_signal(self.pidfd, 0)
            current = t2_polkit_grant.read_process_subject(
                self.subject.pid,
                self.subject.uid,
                proc_root=self.proc_root,
                allow_root=True,
            )
        except (OSError, t2_polkit_grant.PolkitGrantError) as error:
            raise DBusIdentityError("D-Bus caller process disappeared") from error
        if current != self.subject:
            raise DBusIdentityError("D-Bus caller process identity changed")
        return current

    def close(self) -> None:
        if not self._closed:
            os.close(self.pidfd)
            self._closed = True

    def duplicate_peer(self) -> t2_ipc_session.PinnedPeer:
        """Return an independently owned pidfd for session collection."""
        self.verify()
        try:
            descriptor = fcntl.fcntl(
                self.pidfd, fcntl.F_DUPFD_CLOEXEC, 3
            )
        except OSError as error:
            raise DBusIdentityError("D-Bus caller pidfd cannot be duplicated") from error
        try:
            peer = t2_ipc_session.PinnedPeer.from_process_fd(
                descriptor,
                self.subject.pid,
                self.subject.uid,
                proc_root=self.proc_root,
                allow_root=True,
            )
            self.verify()
            return peer
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "system_bus_unique_sender": True,
            "process_fd_pinned": True,
            "process_fd_open": not self._closed,
            "identifiers_redacted": True,
        }


def _unsigned_variant(value: object, name: str) -> int:
    if (
        not isinstance(value, Variant)
        or value.signature != "u"
        or type(value.value) is not int
        or not 0 <= value.value < 1 << 32
    ):
        raise DBusIdentityError(f"D-Bus {name} credential is invalid")
    return value.value


async def collect(
    bus: BusCaller,
    sender: object,
    *,
    proc_root: Path = PROC_ROOT,
) -> PinnedDBusCaller:
    """Collect ProcessFD, UID, and PID for one exact unique bus sender."""

    try:
        unique_sender = t2_dbus_sender.validate_sender(sender)
    except t2_dbus_sender.DBusSenderError as error:
        raise DBusIdentityError("D-Bus unique sender is invalid") from error
    if not isinstance(proc_root, Path) or not proc_root.is_absolute():
        raise DBusIdentityError("process root is invalid")
    try:
        reply = await bus.call(
            Message(
                destination=DBUS_DESTINATION,
                path=DBUS_PATH,
                interface=DBUS_INTERFACE,
                member="GetConnectionCredentials",
                signature="s",
                body=[unique_sender],
            )
        )
    except Exception as error:
        raise DBusIdentityError("D-Bus credentials query failed") from error
    descriptors = getattr(reply, "unix_fds", None)
    duplicate = -1
    try:
        if (
            not isinstance(reply, Message)
            or reply.message_type is not MessageType.METHOD_RETURN
            or reply.signature != "a{sv}"
            or type(reply.body) is not list
            or len(reply.body) != 1
            or type(reply.body[0]) is not dict
        ):
            raise DBusIdentityError("D-Bus credentials reply is malformed")
        credentials = reply.body[0]
        if not {"UnixUserID", "ProcessID", "ProcessFD"} <= set(credentials):
            raise DBusIdentityError("D-Bus credentials are incomplete")
        uid = _unsigned_variant(credentials["UnixUserID"], "UnixUserID")
        pid = _unsigned_variant(credentials["ProcessID"], "ProcessID")
        process_fd = credentials["ProcessFD"]
        if (
            not isinstance(process_fd, Variant)
            or process_fd.signature != "h"
            or type(process_fd.value) is not int
            or process_fd.value != 0
            or type(descriptors) is not list
            or len(descriptors) != 1
            or type(descriptors[0]) is not int
            or descriptors[0] < 0
        ):
            raise DBusIdentityError("D-Bus ProcessFD credential is invalid")
        duplicate = fcntl.fcntl(descriptors[0], fcntl.F_DUPFD_CLOEXEC, 3)
        _pidfd_matches(duplicate, pid)
        try:
            subject = t2_polkit_grant.read_process_subject(
                pid,
                uid,
                proc_root=proc_root,
                allow_root=True,
            )
        except t2_polkit_grant.PolkitGrantError as error:
            raise DBusIdentityError("D-Bus process identity is invalid") from error
        caller = PinnedDBusCaller(
            unique_sender, subject, duplicate, proc_root
        )
        caller.verify()
        duplicate = -1
        return caller
    finally:
        _close_all(descriptors)
        if duplicate >= 0:
            try:
                os.close(duplicate)
            except OSError:
                pass
