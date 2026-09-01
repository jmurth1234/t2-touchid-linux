# SPDX-License-Identifier: GPL-2.0-only
"""Create a bounded policy grant for one kernel-pinned caller process.

The caller PID and UID must come from a trusted IPC peer-credential mechanism.
This module never derives them from argv, environment variables, usernames, or
the process itself.  It uses pkcheck's race-resistant PID,start-time,UID subject
form and verifies the kernel identity again after the authorization decision.
"""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import t2_user_policy


PKCHECK = Path("/usr/bin/pkcheck")
PROC_ROOT = Path("/proc")
MAX_PROC_RECORD = 64 * 1024
DEFAULT_GRANT_LIFETIME_NS = 60 * 1_000_000_000
MAX_PID = (1 << 31) - 1
ACTION_IDS = frozenset(
    {item.action for item in t2_user_policy.OPERATION_POLICIES.values()}
    | {t2_user_policy.ACTIVATE_ACTION}
)


Runner = Callable[[list[str], int], subprocess.CompletedProcess[bytes]]
Clock = Callable[[], int]


class PolkitGrantError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessSubject:
    pid: int
    uid: int
    start_time_ticks: int
    setuid_real_uid: int | None = None


@dataclass(frozen=True, repr=False)
class PolkitGrantResult:
    outcome: str
    grant: t2_user_policy.PolicyGrant

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "outcome": self.outcome,
            "authorized": self.grant.authorized,
            "identifiers_redacted": True,
        }


def _read_bounded(path: Path) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        data = bytearray()
        while len(data) <= MAX_PROC_RECORD:
            block = os.read(
                descriptor, min(4096, MAX_PROC_RECORD + 1 - len(data))
            )
            if not block:
                break
            data.extend(block)
        if not data or len(data) > MAX_PROC_RECORD or b"\0" in data:
            raise PolkitGrantError("caller process record is invalid")
        return bytes(data)
    except OSError as error:
        raise PolkitGrantError("caller process record is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _stat_start_time(data: bytes, expected_pid: int) -> int:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise PolkitGrantError("caller stat record is not ASCII") from error
    prefix = f"{expected_pid} ("
    closing = text.rfind(")")
    if not text.startswith(prefix) or closing < len(prefix) or not text[
        closing + 1 :
    ].startswith(" "):
        raise PolkitGrantError("caller stat record has an invalid envelope")
    fields = text[closing + 2 :].split()
    # fields[0] is proc(5) field 3 (state), so field 22 is index 19.
    if len(fields) <= 19 or len(fields[0]) != 1 or not fields[19].isdecimal():
        raise PolkitGrantError("caller stat record is incomplete")
    try:
        start_time = int(fields[19], 10)
    except ValueError as error:
        raise PolkitGrantError("caller start time is invalid") from error
    if start_time <= 0 or start_time >= 1 << 64:
        raise PolkitGrantError("caller start time is outside the kernel range")
    return start_time


def _status_uids(data: bytes) -> tuple[int, int, int, int]:
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise PolkitGrantError("caller status record is not ASCII") from error
    found = [line for line in lines if line.startswith("Uid:")]
    if len(found) != 1:
        raise PolkitGrantError("caller status UID record is missing or duplicated")
    values = found[0][4:].split()
    if len(values) != 4 or any(not value.isdecimal() for value in values):
        raise PolkitGrantError("caller status UID record is malformed")
    parsed = tuple(int(value, 10) for value in values)
    if any(value < 0 or value >= 1 << 32 for value in parsed):
        raise PolkitGrantError("caller status UID is outside uint32")
    return parsed[0], parsed[1], parsed[2], parsed[3]


def read_process_subject(
    pid: int,
    peer_uid: int,
    *,
    proc_root: Path = PROC_ROOT,
    allow_root: bool = False,
    allow_setuid_root: bool = False,
) -> ProcessSubject:
    if (
        type(pid) is not int
        or not 1 <= pid <= MAX_PID
        or type(peer_uid) is not int
        or type(allow_root) is not bool
        or type(allow_setuid_root) is not bool
        or not (0 if allow_root else 1) <= peer_uid < (1 << 32) - 1
        or not isinstance(proc_root, Path)
        or not proc_root.is_absolute()
    ):
        raise PolkitGrantError("caller process subject is invalid")
    process_root = proc_root / str(pid)
    start_time = _stat_start_time(_read_bounded(process_root / "stat"), pid)
    uids = _status_uids(_read_bounded(process_root / "status"))
    if all(value == peer_uid for value in uids):
        return ProcessSubject(pid, peer_uid, start_time)
    real_uid, effective_uid, saved_uid, filesystem_uid = uids
    if (
        allow_setuid_root
        and allow_root
        and 1 <= real_uid < (1 << 32) - 1
        and peer_uid in (0, real_uid)
        and effective_uid == saved_uid == filesystem_uid == 0
    ):
        # A system-bus peer credential reflects the effective UID. Preserve
        # the non-root real UID in the immutable subject so a setuid-root PAM
        # client cannot change its originating account while a claim is live.
        return ProcessSubject(pid, peer_uid, start_time, real_uid)
    raise PolkitGrantError(
        "caller real/effective/saved/filesystem UIDs are not the peer UID"
    )


def _default_runner(
    command: list[str], timeout: int
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )


def _checked_uuid(value: object, label: str) -> str:
    try:
        return t2_user_policy._canonical_uuid(value, label)
    except t2_user_policy.UserPolicyError as error:
        raise PolkitGrantError(str(error)) from error


def _checked_digest(value: object, label: str) -> str:
    try:
        return t2_user_policy._digest(value, label)
    except t2_user_policy.UserPolicyError as error:
        raise PolkitGrantError(str(error)) from error


def collect(
    *,
    caller_pid: int,
    peer_uid: int,
    account_generation: str,
    target_linux_uid: int,
    action: str,
    mapping_generation: str,
    operation_id: str,
    linux_boot_uuid: str,
    runtime_generation: str,
    allow_user_interaction: bool,
    proc_root: Path = PROC_ROOT,
    pkcheck: Path = PKCHECK,
    runner: Runner = _default_runner,
    clock: Clock = time.monotonic_ns,
    grant_lifetime_ns: int = DEFAULT_GRANT_LIFETIME_NS,
    timeout_seconds: int = 120,
) -> PolkitGrantResult:
    if action not in ACTION_IDS:
        raise PolkitGrantError("PolicyKit action is unsupported")
    if type(target_linux_uid) is not int or target_linux_uid != peer_uid:
        raise PolkitGrantError("cross-user PolicyKit collection is disabled")
    if type(allow_user_interaction) is not bool:
        raise PolkitGrantError("interaction policy must be Boolean")
    if (
        not isinstance(pkcheck, Path)
        or not pkcheck.is_absolute()
        or type(grant_lifetime_ns) is not int
        or not 1 <= grant_lifetime_ns <= t2_user_policy.MAX_POLICY_LIFETIME_NS
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 300
    ):
        raise PolkitGrantError("PolicyKit collector bounds are invalid")
    mapping_generation = _checked_digest(
        mapping_generation, "mapping generation"
    )
    account_generation = _checked_digest(
        account_generation, "account generation"
    )
    operation_id = _checked_uuid(operation_id, "operation ID")
    linux_boot_uuid = _checked_uuid(linux_boot_uuid, "Linux boot UUID")
    runtime_generation = _checked_uuid(
        runtime_generation, "runtime generation"
    )
    before = read_process_subject(
        caller_pid, peer_uid, proc_root=proc_root
    )
    command = [
        str(pkcheck),
        "--action-id",
        action,
        "--process",
        f"{before.pid},{before.start_time_ticks},{before.uid}",
        "--detail",
        "t2.operation-id",
        operation_id,
        "--detail",
        "t2.target-linux-uid",
        str(target_linux_uid),
        "--detail",
        "t2.mapping-generation",
        mapping_generation,
        "--detail",
        "t2.account-generation",
        account_generation,
        "--detail",
        "t2.runtime-generation",
        runtime_generation,
    ]
    if allow_user_interaction:
        command.append("--allow-user-interaction")
    try:
        completed = runner(command, timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise PolkitGrantError("PolicyKit authorization timed out") from error
    except BaseException as error:
        raise PolkitGrantError("PolicyKit authorization could not execute") from error
    if not isinstance(completed, subprocess.CompletedProcess):
        raise PolkitGrantError("PolicyKit runner returned the wrong type")
    after = read_process_subject(caller_pid, peer_uid, proc_root=proc_root)
    if after != before:
        raise PolkitGrantError("caller process identity changed during authorization")
    outcomes = {
        0: "authorized",
        1: "denied",
        2: "interaction-unavailable",
        3: "dismissed",
    }
    if type(completed.returncode) is not int or completed.returncode not in outcomes:
        raise PolkitGrantError("PolicyKit authorization failed ambiguously")
    try:
        issued = clock()
    except BaseException as error:
        raise PolkitGrantError("monotonic authorization time is unavailable") from error
    if type(issued) is not int or not 0 <= issued < 1 << 63:
        raise PolkitGrantError("monotonic authorization time is invalid")
    grant = t2_user_policy.PolicyGrant(
        str(uuid.uuid4()),
        action,
        peer_uid,
        account_generation,
        target_linux_uid,
        mapping_generation,
        operation_id,
        linux_boot_uuid,
        runtime_generation,
        issued,
        issued + grant_lifetime_ns,
        completed.returncode == 0,
    )
    if grant.expires_monotonic_ns >= 1 << 63:
        raise PolkitGrantError("PolicyKit grant expiry overflows monotonic time")
    return PolkitGrantResult(outcomes[completed.returncode], grant)
