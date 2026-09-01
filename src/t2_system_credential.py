# SPDX-License-Identifier: GPL-2.0-only
"""Short-lived systemd-credential password proof and ACM binding."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

import t2_acm_device


CREDENTIAL_ROOT = Path("/run/credentials")
CREDENTIAL_NAME = "t2-touchid-password"
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
AKS_TOOL = Path("/usr/local/sbin/t2-aks-tool")
MAX_STATE_SIZE = 4096
MAX_SECRET_SIZE = 129


class SystemCredentialError(RuntimeError):
    """Raised when credential provenance or an AKS password proof fails."""


Runner = Callable[..., object]


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return all(
        getattr(before, name) == getattr(after, name)
        for name in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    )


def _read_private(path: Path, maximum: int) -> bytearray:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= maximum
        ):
            raise SystemCredentialError(
                f"{path.name} is not private and worker-owned"
            )
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(4096, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_file(before, after):
            raise SystemCredentialError(f"{path.name} changed during read")
        return data
    except SystemCredentialError:
        raise
    except OSError as error:
        raise SystemCredentialError(f"{path.name} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _wipe(value: bytearray) -> None:
    value[:] = b"\0" * len(value)


def _credential_path(environment: Mapping[str, str]) -> Path:
    value = environment.get("CREDENTIALS_DIRECTORY")
    if not isinstance(value, str) or not value:
        raise SystemCredentialError(
            "systemd credential directory is unavailable"
        )
    path = Path(value)
    try:
        relative = path.relative_to(CREDENTIAL_ROOT)
        info = path.stat(follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise SystemCredentialError(
            "systemd credential directory is invalid"
        ) from error
    if (
        not path.is_absolute()
        or len(relative.parts) != 1
        or relative.parts[0] in ("", ".", "..")
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise SystemCredentialError(
            "systemd credential directory is not private and worker-owned"
        )
    return path / CREDENTIAL_NAME


def _runtime_state(expected_special_alias: int) -> tuple[int, int]:
    if (
        type(expected_special_alias) is not int
        or not -(1 << 31) <= expected_special_alias < 0
    ):
        raise SystemCredentialError("expected special keybag alias is invalid")
    data = _read_private(KEYBAG_STATE, MAX_STATE_SIZE)
    try:
        try:
            text = data.decode("ascii")
        except UnicodeError as error:
            raise SystemCredentialError(
                "runtime keybag state has invalid encoding"
            ) from error
    finally:
        _wipe(data)
    expected = {
        "T2_KEYBAG_SESSION",
        "T2_KEYBAG_HANDLE",
        "T2_KEYBAG_SPECIAL",
    }
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(-?[0-9]+)", line)
        if match is None or match.group(1) not in expected:
            raise SystemCredentialError("runtime keybag state is malformed")
        if match.group(1) in values:
            raise SystemCredentialError("runtime keybag state is duplicated")
        values[match.group(1)] = match.group(2)
    if set(values) != expected:
        raise SystemCredentialError("runtime keybag state is incomplete")
    session = int(values["T2_KEYBAG_SESSION"], 10)
    positive_handle = int(values["T2_KEYBAG_HANDLE"], 10)
    special_alias = int(values["T2_KEYBAG_SPECIAL"], 10)
    if (
        session != 1
        or not 0 < positive_handle <= (1 << 31) - 1
        or special_alias != expected_special_alias
    ):
        raise SystemCredentialError("runtime keybag state is stale")
    return session, positive_handle


def _require_tool() -> None:
    try:
        info = AKS_TOOL.stat(follow_symlinks=False)
    except OSError as error:
        raise SystemCredentialError("AKS credential tool is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or not info.st_mode & 0o100
    ):
        raise SystemCredentialError("AKS credential tool is unsafe")


class CredentialPasswordBinder:
    """Use one service-scoped credential without retaining its plaintext."""

    def __init__(
        self,
        expected_special_alias: int,
        *,
        environment: Mapping[str, str] | None = None,
        runner: Runner = subprocess.run,
    ) -> None:
        if not callable(runner):
            raise SystemCredentialError("credential runner is unavailable")
        selected_environment = os.environ if environment is None else environment
        if not isinstance(selected_environment, Mapping):
            raise SystemCredentialError("credential environment is invalid")
        self._credential = _credential_path(selected_environment)
        self._session, self._positive_handle = _runtime_state(
            expected_special_alias
        )
        self._special_alias = expected_special_alias
        self._runner = runner
        _require_tool()

    def __repr__(self) -> str:
        return (
            "CredentialPasswordBinder(credential=<systemd-scoped>, "
            "keybag=<redacted>, private=True)"
        )

    def _invoke(self, command: list[str], prefix: bytes = b"") -> None:
        secret = _read_private(self._credential, MAX_SECRET_SIZE)
        payload = bytearray(prefix)
        try:
            payload.extend(secret)
            password_length = 0
            password_valid = True
            terminator = len(secret)
            for index, character in enumerate(secret):
                if character in (10, 13):
                    terminator = index
                    break
                if character == 0:
                    password_valid = False
                    break
                password_length += 1
            line_ending_valid = (
                terminator == len(secret)
                or (
                    terminator + 1 == len(secret)
                    and secret[terminator] in (10, 13)
                )
                or (
                    terminator + 2 == len(secret)
                    and secret[terminator] == 13
                    and secret[terminator + 1] == 10
                )
            )
            if (
                not password_valid
                or not line_ending_valid
                or not 1 <= password_length <= 128
                or len(prefix) not in (0, 16)
            ):
                raise SystemCredentialError(
                    "systemd credential contents are invalid"
                )
            completed = self._runner(
                command,
                input=payload,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if getattr(completed, "returncode", None) != 0:
                raise SystemCredentialError("AKS password proof failed")
        except SystemCredentialError:
            raise
        except Exception as error:
            raise SystemCredentialError("AKS password proof failed") from error
        finally:
            _wipe(secret)
            _wipe(payload)

    def verify_password_fallback(self) -> bool:
        self._invoke(
            [
                str(AKS_TOOL),
                "verify-password-only-stdin",
                str(self._session),
                str(self._positive_handle),
            ]
        )
        return True

    def bind(self, context: bytes) -> None:
        if not isinstance(context, bytes) or len(context) != 16:
            raise t2_acm_device.ACMDeviceError(
                "ACM external form is invalid"
            )
        try:
            self._invoke(
                [
                    str(AKS_TOOL),
                    "verify-password-acm-stdin",
                    str(self._session),
                    str(self._special_alias),
                ],
                context,
            )
        except SystemCredentialError as error:
            raise t2_acm_device.ACMDeviceError(
                "AKS credential binding failed"
            ) from error
