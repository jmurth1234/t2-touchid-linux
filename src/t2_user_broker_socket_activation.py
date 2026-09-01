# SPDX-License-Identifier: GPL-2.0-only
"""Systemd Accept=yes boundary for one non-exposed broker connection."""

from __future__ import annotations

import ctypes
import os
import socket
from typing import Protocol

import t2_user_broker_dispatch
import t2_user_broker_protocol


SD_LISTEN_FDS_START = 3
EXPECTED_DESCRIPTOR_NAME = "connection"
ROOT_UID = 0


class UserBrokerSocketActivationError(RuntimeError):
    pass


class ActivationBackend(Protocol):
    def descriptors(self) -> tuple[tuple[int, str], ...]: ...


class LibsystemdActivationBackend:
    """Consume systemd activation descriptors and unset their environment."""

    def __init__(self, library: str = "libsystemd.so.0") -> None:
        try:
            self._systemd = ctypes.CDLL(library)
            self._libc = ctypes.CDLL(None)
        except OSError as error:
            raise UserBrokerSocketActivationError(
                "systemd socket-activation API is unavailable"
            ) from error
        self._systemd.sd_listen_fds_with_names.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
        ]
        self._systemd.sd_listen_fds_with_names.restype = ctypes.c_int
        self._libc.free.argtypes = [ctypes.c_void_p]
        self._libc.free.restype = None

    def descriptors(self) -> tuple[tuple[int, str], ...]:
        names = ctypes.POINTER(ctypes.c_void_p)()
        count = self._systemd.sd_listen_fds_with_names(
            1,
            ctypes.byref(names),
        )
        if count < 0:
            if names:
                self._libc.free(ctypes.cast(names, ctypes.c_void_p))
            raise UserBrokerSocketActivationError(
                "systemd rejected the activation environment"
            )
        decoded: list[str] = []
        try:
            for index in range(count):
                pointer = names[index]
                if not pointer:
                    raise UserBrokerSocketActivationError(
                        "systemd descriptor name is missing"
                    )
                try:
                    value = ctypes.string_at(pointer).decode("ascii")
                except UnicodeError as error:
                    raise UserBrokerSocketActivationError(
                        "systemd descriptor name is invalid"
                    ) from error
                if not value or len(value) > 255 or ":" in value:
                    raise UserBrokerSocketActivationError(
                        "systemd descriptor name is unsafe"
                    )
                decoded.append(value)
        finally:
            if names:
                for index in range(max(count, 0)):
                    if names[index]:
                        self._libc.free(names[index])
                self._libc.free(ctypes.cast(names, ctypes.c_void_p))
        return tuple(
            (SD_LISTEN_FDS_START + index, name)
            for index, name in enumerate(decoded)
        )


def _close_descriptors(descriptors: tuple[tuple[int, str], ...]) -> None:
    for descriptor, _name in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def acquire_connected_socket(
    *, backend: ActivationBackend | None = None
) -> socket.socket:
    """Take ownership of one systemd-passed connected seqpacket socket."""

    if os.geteuid() != ROOT_UID:
        raise UserBrokerSocketActivationError(
            "broker socket-activation boundary requires root"
        )
    source = backend if backend is not None else LibsystemdActivationBackend()
    try:
        descriptors = source.descriptors()
    except UserBrokerSocketActivationError:
        raise
    except Exception as error:
        raise UserBrokerSocketActivationError(
            "activation descriptor collection failed"
        ) from error
    if (
        type(descriptors) is not tuple
        or len(descriptors) != 1
        or type(descriptors[0]) is not tuple
        or len(descriptors[0]) != 2
        or type(descriptors[0][0]) is not int
        or descriptors[0][0] < 0
        or descriptors[0][1] != EXPECTED_DESCRIPTOR_NAME
    ):
        if isinstance(descriptors, tuple):
            _close_descriptors(
                tuple(
                    item
                    for item in descriptors
                    if type(item) is tuple
                    and len(item) == 2
                    and type(item[0]) is int
                )
            )
        raise UserBrokerSocketActivationError(
            "exactly one named activation connection is required"
        )
    descriptor = descriptors[0][0]
    connection: socket.socket | None = None
    try:
        os.set_inheritable(descriptor, False)
        connection = socket.socket(fileno=descriptor)
        domain = connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        kind = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        accepting = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_ACCEPTCONN
        )
        connection.getpeername()
        if (
            domain != socket.AF_UNIX
            or kind != socket.SOCK_SEQPACKET
            or accepting != 0
        ):
            raise UserBrokerSocketActivationError(
                "activation descriptor is not a connected Unix seqpacket socket"
            )
        return connection
    except UserBrokerSocketActivationError:
        if connection is not None:
            connection.close()
        else:
            _close_descriptors(descriptors)
        raise
    except (OSError, ValueError) as error:
        if connection is not None:
            connection.close()
        else:
            _close_descriptors(descriptors)
        raise UserBrokerSocketActivationError(
            "activation connection validation failed"
        ) from error


def run_once(
    *,
    modification_allowed: bool,
    allow_user_interaction: bool,
    backend: ActivationBackend | None = None,
    dispatcher=t2_user_broker_dispatch.serve_once,
) -> (
    t2_user_broker_protocol.PreflightResponse
    | t2_user_broker_protocol.InventoryResponse
):
    """Dispatch one accepted connection and close it on every outcome."""

    if type(modification_allowed) is not bool:
        raise UserBrokerSocketActivationError(
            "modification policy must be Boolean"
        )
    if type(allow_user_interaction) is not bool:
        raise UserBrokerSocketActivationError(
            "interaction policy must be Boolean"
        )
    try:
        with acquire_connected_socket(backend=backend) as connection:
            response = dispatcher(
                connection,
                modification_allowed=modification_allowed,
                allow_user_interaction=allow_user_interaction,
            )
            if not isinstance(
                response,
                (
                    t2_user_broker_protocol.PreflightResponse,
                    t2_user_broker_protocol.InventoryResponse,
                ),
            ):
                raise UserBrokerSocketActivationError(
                    "broker dispatcher returned an invalid response"
                )
            return response
    except UserBrokerSocketActivationError:
        raise
    except t2_user_broker_dispatch.UserBrokerDispatchError as error:
        raise UserBrokerSocketActivationError(
            "broker connection dispatch failed"
        ) from error
    except Exception as error:
        raise UserBrokerSocketActivationError(
            "broker connection handling failed"
        ) from error
