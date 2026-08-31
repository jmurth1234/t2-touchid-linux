# SPDX-License-Identifier: GPL-2.0-only
"""Concrete command adapter for the journaled per-user activation core.

This module supplies no CLI, mapping resolver, password prompt, or policy
decision.  It only adapts the narrow root-only AKS tool to the typed operation
interface after a caller has acquired the machine-wide operation lease.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import PurePosixPath

import t2_aks_observer


PasswordRunner = Callable[[list[str], memoryview], subprocess.CompletedProcess[str]]
STATUS_REPLY = re.compile(r"status=(0|0x[0-9a-f]+) response_length=([1-9][0-9]*)")
LOAD_REPLY = re.compile(
    r"status=0 handle=([1-9][0-9]*) response_length=([1-9][0-9]*)"
)


class AKSActivationTransportError(RuntimeError):
    pass


def _pipe_password(
    command: list[str], password: memoryview
) -> subprocess.CompletedProcess[str]:
    read_descriptor = -1
    write_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    try:
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        process = subprocess.Popen(
            command,
            stdin=read_descriptor,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        os.close(read_descriptor)
        read_descriptor = -1
        offset = 0
        while offset < len(password):
            try:
                written = os.write(write_descriptor, password[offset:])
            except InterruptedError:
                continue
            if written <= 0:
                raise AKSActivationTransportError(
                    "AKS password pipe stopped accepting input"
                )
            offset += written
        os.close(write_descriptor)
        write_descriptor = -1
        try:
            stdout, stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.communicate()
            raise AKSActivationTransportError(
                "AKS password command timed out"
            ) from error
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout.decode("utf-8", errors="strict"),
            stderr.decode("utf-8", errors="strict"),
        )
    except AKSActivationTransportError:
        raise
    except BaseException as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        raise AKSActivationTransportError(
            "AKS password command could not be executed"
        ) from error
    finally:
        if read_descriptor >= 0:
            os.close(read_descriptor)
        if write_descriptor >= 0:
            os.close(write_descriptor)


class AKSActivationTransport:
    def __init__(
        self,
        observer: t2_aks_observer.AKSAliasObserver,
        *,
        password_runner: PasswordRunner = _pipe_password,
    ) -> None:
        if not isinstance(observer, t2_aks_observer.AKSAliasObserver):
            raise AKSActivationTransportError("AKS observer has the wrong type")
        self._observer = observer
        self._password_runner = password_runner
        self.runtime_generation = observer.runtime_generation

    def _run(self, arguments: list[str]) -> subprocess.CompletedProcess[str]:
        return self._observer._run([str(self._observer.tool), *arguments])

    @staticmethod
    def _status(completed: subprocess.CompletedProcess[str]) -> int:
        output = completed.stdout.strip()
        match = STATUS_REPLY.fullmatch(output)
        if match is None:
            raise AKSActivationTransportError("AKS command reply is malformed")
        status = int(match.group(1), 0)
        response_length = int(match.group(2), 10)
        if response_length > 16_300:
            raise AKSActivationTransportError(
                "AKS command response length is invalid"
            )
        if completed.returncode not in {0, 1}:
            raise AKSActivationTransportError("AKS command exit status is invalid")
        if (status == 0) != (completed.returncode == 0):
            raise AKSActivationTransportError(
                "AKS command status and exit status disagree"
            )
        return status

    def observe_alias(self, special_alias: int):
        return self._observer.observe_alias(special_alias)

    def load_keybag(self, keybag_path: str) -> int:
        if not isinstance(keybag_path, str):
            raise AKSActivationTransportError("keybag path is outside policy")
        path = PurePosixPath(keybag_path)
        parts = path.parts
        if (
            len(parts) != 7
            or parts[:5] != ("/", "var", "lib", "t2-touchid", "users")
            or parts[6] != "user.kb"
            or not parts[5].isascii()
            or not parts[5].isdigit()
            or not 1 <= int(parts[5], 10) <= (1 << 31) - 1
            or str(int(parts[5], 10)) != parts[5]
            or str(path) != keybag_path
        ):
            raise AKSActivationTransportError("keybag path is outside policy")
        completed = self._run(
            ["load-keybag", keybag_path, str(self._observer.session)]
        )
        match = LOAD_REPLY.fullmatch(completed.stdout.strip())
        if completed.returncode != 0 or match is None:
            raise AKSActivationTransportError("AKS keybag load outcome is ambiguous")
        handle = int(match.group(1), 10)
        response_length = int(match.group(2), 10)
        if not 1 <= handle <= (1 << 31) - 1 or response_length > 16_300:
            raise AKSActivationTransportError("AKS keybag load reply is invalid")
        return handle

    def bag_uuid(self, handle: int) -> str:
        return self._observer.observe_handle_uuid(handle)

    def bind_alias(self, handle: int, special_alias: int) -> int:
        if type(handle) is not int or not 1 <= handle <= (1 << 31) - 1:
            raise AKSActivationTransportError("runtime AKS handle is invalid")
        if (
            type(special_alias) is not int
            or special_alias > -10
            or special_alias < -(1 << 31)
        ):
            raise AKSActivationTransportError("special AKS alias is invalid")
        return self._status(
            self._run(
                [
                    "set-system-keybag",
                    str(self._observer.session),
                    str(handle),
                    str(special_alias),
                ]
            )
        )

    def unlock_alias(self, special_alias: int, password: memoryview) -> int:
        if (
            type(special_alias) is not int
            or special_alias > -10
            or special_alias < -(1 << 31)
        ):
            raise AKSActivationTransportError("special AKS alias is invalid")
        if (
            not isinstance(password, memoryview)
            or password.readonly
            or password.ndim != 1
            or password.itemsize != 1
            or not 1 <= len(password) <= 1023
        ):
            raise AKSActivationTransportError(
                "AKS password view is not bounded writable byte storage"
            )
        command = [
            str(self._observer.tool),
            "unlock-keybag-stdin",
            str(self._observer.session),
            str(special_alias),
        ]
        try:
            completed = self._password_runner(command, password)
        except AKSActivationTransportError:
            raise
        except BaseException as error:
            raise AKSActivationTransportError(
                "AKS password command could not be executed"
            ) from error
        if not isinstance(completed, subprocess.CompletedProcess):
            raise AKSActivationTransportError(
                "AKS password runner returned the wrong type"
            )
        return self._status(completed)
