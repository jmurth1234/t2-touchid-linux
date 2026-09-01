# SPDX-License-Identifier: GPL-2.0-only
"""Launch one encrypted-credential enrollment worker behind a private socket."""

from __future__ import annotations

import ctypes
import os
import socket
import stat
import struct
import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import t2_fprint_worker


SYSTEMD_RUN = Path("/usr/bin/systemd-run")
WORKER = Path("/usr/local/sbin/t2-fprint-enrollment-worker")
ENCRYPTED_CREDENTIAL = Path(
    "/etc/credstore.encrypted/t2-touchid-password"
)
ROOT_UID = 0
PEERCRED = struct.Struct("3i")
Runner = Callable[..., object]
UnitResolver = Callable[[int], str]


class FprintWorkerLauncherError(RuntimeError):
    pass


def _require_private_root() -> None:
    try:
        info = t2_fprint_worker.WORKER_ROOT.stat(follow_symlinks=False)
    except OSError as error:
        raise FprintWorkerLauncherError(
            "worker runtime directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_mode & 0o077
    ):
        raise FprintWorkerLauncherError(
            "worker runtime directory is not private and root-owned"
        )


def _require_executable(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise FprintWorkerLauncherError(
            "worker launcher executable is unavailable"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not info.st_mode & 0o100
    ):
        raise FprintWorkerLauncherError(
            "worker launcher executable is unsafe"
        )


def _require_credential() -> None:
    try:
        info = ENCRYPTED_CREDENTIAL.stat(follow_symlinks=False)
    except OSError as error:
        raise FprintWorkerLauncherError(
            "encrypted worker credential is unavailable"
        ) from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != ROOT_UID
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not 0 < info.st_size <= 1024 * 1024
    ):
        raise FprintWorkerLauncherError(
            "encrypted worker credential is unsafe"
        )


def _systemd_unit_for_pid(pid: int) -> str:
    if type(pid) is not int or not 1 <= pid < 1 << 31:
        raise FprintWorkerLauncherError("worker peer PID is invalid")
    try:
        systemd = ctypes.CDLL("libsystemd.so.0")
        libc = ctypes.CDLL(None)
        systemd.sd_pid_get_unit.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        systemd.sd_pid_get_unit.restype = ctypes.c_int
        libc.free.argtypes = [ctypes.c_void_p]
        libc.free.restype = None
        value = ctypes.c_void_p()
        status = systemd.sd_pid_get_unit(pid, ctypes.byref(value))
        if status < 0 or not value.value:
            raise FprintWorkerLauncherError(
                "worker peer has no systemd unit"
            )
        try:
            return ctypes.string_at(value.value).decode("utf-8", errors="strict")
        finally:
            libc.free(value)
    except FprintWorkerLauncherError:
        raise
    except (OSError, UnicodeError, AttributeError) as error:
        raise FprintWorkerLauncherError(
            "worker systemd identity is unavailable"
        ) from error


def _command(unit: str, endpoint: Path) -> list[str]:
    return [
        str(SYSTEMD_RUN),
        "--system",
        "--quiet",
        "--collect",
        "--service-type=exec",
        f"--unit={unit}",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=no",
        "--property=PrivateNetwork=no",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectClock=yes",
        "--property=PrivateMounts=yes",
        "--property=RestrictNamespaces=yes",
        "--property=RestrictRealtime=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=SystemCallArchitectures=native",
        "--property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
        "--property=AmbientCapabilities=CAP_DAC_READ_SEARCH",
        "--property=MemoryDenyWriteExecute=yes",
        "--property=ProtectHostname=yes",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET6",
        "--property=DevicePolicy=closed",
        "--property=DeviceAllow=/dev/t2-aks rw",
        "--property=ReadWritePaths=/run/t2-touchid /var/lib/t2-touchid",
        "--property=SystemCallFilter=@system-service",
        "--property=TimeoutStartSec=45s",
        "--property=TimeoutStopSec=15s",
        (
            "--property=LoadCredentialEncrypted="
            f"t2-touchid-password:{ENCRYPTED_CREDENTIAL}"
        ),
        str(WORKER),
        "--endpoint",
        str(endpoint),
    ]


@dataclass(repr=False)
class WorkerConnection:
    operation_id: str
    unit: str
    endpoint: Path = field(repr=False)
    connection: socket.socket = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __repr__(self) -> str:
        return (
            "WorkerConnection(operation_id=<redacted>, unit=<transient>, "
            "endpoint=<private>, open="
            f"{not self._closed})"
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.connection.close()
        finally:
            try:
                info = self.endpoint.stat(follow_symlinks=False)
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == ROOT_UID:
                    self.endpoint.unlink()
            except FileNotFoundError:
                pass

    def __enter__(self) -> "WorkerConnection":
        if self._closed:
            raise FprintWorkerLauncherError("worker connection is closed")
        return self

    def __exit__(self, exception_type, exception, traceback) -> None:
        self.close()


def launch(
    *,
    runner: Runner = subprocess.run,
    unit_resolver: UnitResolver = _systemd_unit_for_pid,
) -> WorkerConnection:
    """Start one hardened worker and authenticate its accepted connection."""

    if os.geteuid() != ROOT_UID:
        raise FprintWorkerLauncherError("worker launcher requires root")
    if not callable(runner) or not callable(unit_resolver):
        raise FprintWorkerLauncherError("worker launcher dependency is unavailable")
    _require_private_root()
    _require_executable(SYSTEMD_RUN)
    _require_executable(WORKER)
    _require_credential()
    operation_id = str(uuid.uuid4())
    unit = f"t2-fprint-enrollment-{operation_id}.service"
    endpoint = t2_fprint_worker.WORKER_ROOT / f"{operation_id}.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    connection: socket.socket | None = None
    succeeded = False
    try:
        server.settimeout(30)
        server.bind(str(endpoint))
        os.chmod(endpoint, 0o600, follow_symlinks=False)
        server.listen(1)
        completed = runner(
            _command(unit, endpoint),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if getattr(completed, "returncode", None) != 0:
            raise FprintWorkerLauncherError(
                "transient enrollment worker failed to start"
            )
        connection, _address = server.accept()
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size
        )
        pid, uid, gid = PEERCRED.unpack(raw)
        if (
            uid != ROOT_UID
            or gid != ROOT_UID
            or unit_resolver(pid) != unit
        ):
            raise FprintWorkerLauncherError(
                "transient enrollment worker identity is invalid"
            )
        connection.settimeout(None)
        result = WorkerConnection(
            operation_id, unit, endpoint, connection
        )
        connection = None
        succeeded = True
        return result
    except FprintWorkerLauncherError:
        raise
    except Exception as error:
        raise FprintWorkerLauncherError(
            "transient enrollment worker launch failed"
        ) from error
    finally:
        server.close()
        if connection is not None:
            connection.close()
        if not succeeded:
            try:
                info = endpoint.stat(follow_symlinks=False)
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == ROOT_UID:
                    endpoint.unlink()
            except FileNotFoundError:
                pass
