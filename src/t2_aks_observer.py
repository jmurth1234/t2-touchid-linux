# SPDX-License-Identifier: GPL-2.0-only
"""Concrete, read-only AKS alias observer with private transient artifacts."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path

import t2_aks_state
import t2_user_readiness


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class AKSAliasObservationError(RuntimeError):
    pass


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )


class AKSAliasObserver:
    def __init__(
        self,
        *,
        tool: Path = Path("/usr/local/sbin/t2-aks-tool"),
        runtime_root: Path = Path("/run/t2-touchid"),
        session: int = 1,
        runtime_generation: str | None = None,
        runner: Runner = _default_runner,
        expected_owner_uid: int | None = None,
    ) -> None:
        if not tool.is_absolute() or not runtime_root.is_absolute():
            raise AKSAliasObservationError("AKS observer paths must be absolute")
        if session != 1:
            raise AKSAliasObservationError("only the proven AKS session is permitted")
        generation = runtime_generation or str(uuid.uuid4())
        try:
            parsed_generation = uuid.UUID(generation)
        except (ValueError, AttributeError) as error:
            raise AKSAliasObservationError(
                "AKS runtime generation must be a UUID"
            ) from error
        if str(parsed_generation) != generation:
            raise AKSAliasObservationError(
                "AKS runtime generation must be canonical"
            )
        self.tool = tool
        self.runtime_root = runtime_root
        self.session = session
        self.runtime_generation = generation
        self._runner = runner
        self._owner_uid = (
            os.geteuid() if expected_owner_uid is None else expected_owner_uid
        )

    def _run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            completed = self._runner(command)
        except BaseException as error:
            raise AKSAliasObservationError(
                "AKS observation command could not be executed"
            ) from error
        if not isinstance(completed, subprocess.CompletedProcess):
            raise AKSAliasObservationError(
                "AKS observation runner returned the wrong type"
            )
        return completed

    def _read_private(self, path: Path, *, maximum: int, exact: int | None = None) -> bytes:
        descriptor = -1
        try:
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self._owner_uid
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= maximum
                or (exact is not None and info.st_size != exact)
            ):
                raise AKSAliasObservationError(
                    "AKS observation artifact is not private and exact"
                )
            data = bytearray()
            while len(data) <= maximum:
                block = os.read(descriptor, min(4096, maximum + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) != info.st_size:
                raise AKSAliasObservationError(
                    "AKS observation artifact changed during read"
                )
            return bytes(data)
        except OSError as error:
            raise AKSAliasObservationError(
                "AKS observation artifact cannot be read safely"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _copy_bag_uuid(self, handle: int, output: Path) -> str | None:
        completed = self._run(
            [
                str(self.tool),
                "copy-keybag-uuid",
                str(self.session),
                str(handle),
                str(output),
            ]
        )
        try:
            if completed.returncode == 3:
                if output.exists():
                    raise AKSAliasObservationError(
                        "absent AKS alias unexpectedly produced an artifact"
                    )
                return None
            if completed.returncode != 0:
                raise AKSAliasObservationError("AKS bag UUID observation failed")
            raw = self._read_private(output, maximum=16, exact=16)
            parsed = uuid.UUID(bytes=raw)
            if parsed.int == 0:
                raise AKSAliasObservationError("AKS bag UUID is zero")
            return str(parsed)
        finally:
            try:
                output.unlink(missing_ok=True)
            except OSError as error:
                raise AKSAliasObservationError(
                    "private AKS UUID artifact could not be removed"
                ) from error

    def _state(self, handle: int, output: Path) -> t2_aks_state.KeybagState:
        completed = self._run(
            [
                str(self.tool),
                "get-device-state-v1",
                str(self.session),
                str(handle),
                "0",
                str(output),
            ]
        )
        try:
            if completed.returncode != 0:
                raise AKSAliasObservationError("AKS keybag state observation failed")
            raw = self._read_private(output, maximum=t2_aks_state.MAX_DER_BYTES)
            try:
                return t2_aks_state.decode(raw)
            except t2_aks_state.AKSStateError as error:
                raise AKSAliasObservationError(
                    "AKS keybag state is malformed"
                ) from error
        finally:
            try:
                output.unlink(missing_ok=True)
            except OSError as error:
                raise AKSAliasObservationError(
                    "private AKS state artifact could not be removed"
                ) from error

    def observe_alias(self, special_alias: int) -> t2_user_readiness.AliasEvidence:
        if (
            type(special_alias) is not int
            or special_alias > -10
            or special_alias < -(1 << 31)
        ):
            raise AKSAliasObservationError("special AKS alias is invalid")
        try:
            with tempfile.TemporaryDirectory(
                prefix=".aks-observe-", dir=self.runtime_root
            ) as directory:
                private = Path(directory)
                first = self._copy_bag_uuid(special_alias, private / "uuid-1")
                if first is None:
                    second = self._copy_bag_uuid(
                        special_alias, private / "uuid-2"
                    )
                    if second is not None:
                        raise AKSAliasObservationError(
                            "AKS alias changed during absence observation"
                        )
                    return t2_user_readiness.AliasEvidence(
                        False, None, None, None
                    )
                state = self._state(special_alias, private / "state")
                second = self._copy_bag_uuid(special_alias, private / "uuid-2")
                if second is None or second != first:
                    raise AKSAliasObservationError(
                        "AKS alias changed during stable observation"
                    )
                if state.handle != special_alias:
                    raise AKSAliasObservationError(
                        "AKS state belongs to a different handle"
                    )
                return t2_user_readiness.AliasEvidence(
                    True, special_alias, first, state.lock_state
                )
        except AKSAliasObservationError:
            raise
        except OSError as error:
            raise AKSAliasObservationError(
                "private AKS observation directory is unavailable"
            ) from error

    def observe_handle_uuid(self, handle: int) -> str:
        if type(handle) is not int or not 1 <= handle <= (1 << 31) - 1:
            raise AKSAliasObservationError("runtime AKS handle is invalid")
        try:
            with tempfile.TemporaryDirectory(
                prefix=".aks-handle-", dir=self.runtime_root
            ) as directory:
                private = Path(directory)
                first = self._copy_bag_uuid(handle, private / "uuid-1")
                second = self._copy_bag_uuid(handle, private / "uuid-2")
                if first is None or second is None or first != second:
                    raise AKSAliasObservationError(
                        "runtime AKS handle changed during stable observation"
                    )
                return first
        except AKSAliasObservationError:
            raise
        except OSError as error:
            raise AKSAliasObservationError(
                "private AKS observation directory is unavailable"
            ) from error
