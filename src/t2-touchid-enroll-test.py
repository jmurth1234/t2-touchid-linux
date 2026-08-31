#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Explicitly gated experimental built-in Touch ID enrollment broker."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from threading import Event
from typing import Callable, Iterator


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_enrollment_coordinator.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_baseline
import t2_bridge_connection
import t2_bridge_inventory
import t2_catacomb_local
import t2_catacomb_store
import t2_enrollment_coordinator
import t2_enrollment_finalizer
import t2_enrollment_journal
import t2_enrollment_persistence_journal
import t2_enrollment_protocol
import t2_enrollment_reconciliation
import t2_mutation_journal
from t2_acm_device import ACMDevice, ACMDeviceError


CONFIG = Path("/etc/t2-touchid.conf")
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STATE_ROOT = Path("/var/lib/t2-touchid")
BACKUP_ROOT = STATE_ROOT / "backups"
STORE_ROOT = STATE_ROOT / "catacomb"
MUTATION_ROOT = STATE_ROOT / "mutations"
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
AKS_TOOL = Path("/usr/local/sbin/t2-aks-tool")
SYSTEMD_INHIBIT = Path("/usr/bin/systemd-inhibit")
CAT = Path("/usr/bin/cat")


class EnrollmentCommandError(RuntimeError):
    pass


def _sleep_inhibitor_is_registered(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is not None:
        return False
    completed = subprocess.run(
        [str(SYSTEMD_INHIBIT), "--list", "--json=short"],
        check=False,
        capture_output=True,
        timeout=2,
    )
    if completed.returncode:
        return False
    try:
        records = json.loads(completed.stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(records, list):
        return False
    return any(
        isinstance(record, dict)
        and record.get("pid") == process.pid
        and record.get("who") == "t2-touchid-enrollment"
        and record.get("what") == "sleep"
        and record.get("mode") == "block"
        for record in records
    )


@contextmanager
def sleep_inhibitor() -> Iterator[subprocess.Popen[bytes]]:
    """Block suspend for a live mutation and drop the block on parent death."""
    process = subprocess.Popen(
        [
            str(SYSTEMD_INHIBIT),
            "--what=sleep",
            "--who=t2-touchid-enrollment",
            "--why=Touch ID enrollment is active",
            "--mode=block",
            str(CAT),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        for _attempt in range(20):
            if _sleep_inhibitor_is_registered(process):
                break
            if process.poll() is not None:
                raise EnrollmentCommandError("sleep inhibitor exited during setup")
            time.sleep(0.05)
        else:
            raise EnrollmentCommandError("sleep inhibitor could not be verified")
        yield process
    finally:
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def _private_root_owned(path: Path, *, directory: bool) -> os.stat_result:
    info = path.stat(follow_symlinks=False)
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or info.st_uid != 0 or info.st_mode & 0o077:
        raise EnrollmentCommandError(f"{path} is not private and root-owned")
    return info


def _unique_assignments(path: Path, keys: set[str]) -> dict[str, str]:
    _private_root_owned(path, directory=False)
    values = {key: [] for key in keys}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(found) != 1 for found in values.values()):
        raise EnrollmentCommandError("runtime configuration is missing or duplicated")
    return {key: found[0] for key, found in values.items()}


def runtime_configuration() -> dict[str, object]:
    values = _unique_assignments(
        CONFIG,
        {
            "T2_TOUCHID_USER",
            "T2_TOUCHID_HOST",
            "T2_TOUCHID_INTERFACE",
            "T2_TOUCHID_MACOS_USER_ID",
            "T2_TOUCHID_SPECIAL_BAG",
        },
    )
    user_name = values["T2_TOUCHID_USER"]
    try:
        linux_user_id = pwd.getpwnam(user_name).pw_uid
    except KeyError as error:
        raise EnrollmentCommandError("mapped Linux user does not exist") from error
    user_id_text = values["T2_TOUCHID_MACOS_USER_ID"]
    special_text = values["T2_TOUCHID_SPECIAL_BAG"]
    if (
        linux_user_id <= 0
        or not user_id_text.isdecimal()
        or not 0 <= int(user_id_text) <= 0xFFFFFFFF
        or not re.fullmatch(r"-[0-9]+", special_text)
        or int(special_text) != -int(user_id_text)
        or not values["T2_TOUCHID_HOST"]
        or not values["T2_TOUCHID_INTERFACE"]
    ):
        raise EnrollmentCommandError("runtime account mapping is invalid")
    sudo_uid = os.environ.get("SUDO_UID", "")
    if not sudo_uid.isdecimal() or int(sudo_uid) != linux_user_id:
        raise EnrollmentCommandError(
            "caller is not the configured mapped Linux user through sudo"
        )
    return {
        "linux_user": user_name,
        "linux_uid": linux_user_id,
        "apple_uid": int(user_id_text),
        "special_bag": int(special_text),
        "host": values["T2_TOUCHID_HOST"],
        "interface": values["T2_TOUCHID_INTERFACE"],
        "mapping_generation": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
    }


def keybag_runtime(expected_special: int) -> tuple[int, int]:
    values = _unique_assignments(
        KEYBAG_STATE,
        {"T2_KEYBAG_SESSION", "T2_KEYBAG_HANDLE", "T2_KEYBAG_SPECIAL"},
    )
    if not all(re.fullmatch(r"-?[0-9]+", value) for value in values.values()):
        raise EnrollmentCommandError("runtime keybag state is malformed")
    session = int(values["T2_KEYBAG_SESSION"])
    handle = int(values["T2_KEYBAG_HANDLE"])
    special = int(values["T2_KEYBAG_SPECIAL"])
    if session != 1 or handle <= 0 or special != expected_special:
        raise EnrollmentCommandError("runtime keybag state is stale")
    return session, handle


def select_backup() -> Path:
    _private_root_owned(BACKUP_ROOT, directory=True)
    candidates = []
    for entry in BACKUP_ROOT.iterdir():
        if re.fullmatch(r"[0-9a-f]{64}\.tar\.gz", entry.name):
            _private_root_owned(entry, directory=False)
            candidates.append(entry)
    if len(candidates) != 1:
        raise EnrollmentCommandError(
            "exactly one private baseline backup is required for the first enrollment"
        )
    candidate = candidates[0]
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate.name[:64]:
        raise EnrollmentCommandError("baseline backup filename/hash mismatch")
    return candidate


def warm_sensor() -> None:
    completed = subprocess.run(
        ["/usr/bin/systemctl", "restart", "t2-biometric-ready.service"],
        check=False,
        timeout=60,
    )
    if completed.returncode:
        raise EnrollmentCommandError("BiometricKit warm-up failed")


def notify_user(user_name: str, unit: str) -> None:
    try:
        subprocess.run(
            [
                "/usr/bin/systemctl",
                f"--machine={user_name}@.host",
                "--user",
                "start",
                "--no-block",
                unit,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        # Desktop feedback is advisory. It must never change the outcome of an
        # authorized biometric operation or its persistence transaction.
        pass


def report_enrollment_feedback(user_name: str, transition: object) -> None:
    progress = getattr(transition, "progress_percent", None)
    action = getattr(transition, "action", None)
    message = None
    audible = False
    if isinstance(progress, int):
        message = f"Touch ID enrollment progress: {progress}%"
    elif action is t2_enrollment_protocol.EnrollmentAction.REMOVE_AND_RETRY:
        message = "Lift your finger, then place it on the sensor again."
        audible = True
    elif action is t2_enrollment_protocol.EnrollmentAction.RETRY_SCAN:
        message = "Fingerprint scan was not accepted; try again."
        audible = True
    elif action is t2_enrollment_protocol.EnrollmentAction.RETRY_SMALL_COVERAGE:
        message = "Cover more of the Touch ID sensor and try again."
        audible = True
    elif action is t2_enrollment_protocol.EnrollmentAction.DIRTY_SENSOR:
        message = "Clean the Touch ID sensor and try again."
        audible = True
    if message is not None:
        try:
            print(message, flush=True)
        except (BrokenPipeError, OSError, ValueError):
            pass
    if audible:
        notify_user(user_name, "t2-touchid-alert.service")


def _port() -> int:
    _private_root_owned(PORT_CACHE, directory=False)
    value = PORT_CACHE.read_text().strip()
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise EnrollmentCommandError("cached biometric service port is invalid")
    return int(value)


def _build_preflight_baseline(
    configuration: dict[str, object],
    host_inventory: dict[str, object],
    live_inventory: dict[str, object],
    backup: Path,
) -> dict[str, object]:
    return t2_baseline.build_baseline(
        host=host_inventory,
        live=live_inventory,
        caller_linux_uid=configuration["linux_uid"],
        target_linux_uid=configuration["linux_uid"],
        linux_boot_uuid=BOOT_ID.read_text().strip(),
        mapping_generation=configuration["mapping_generation"],
        backup_reference=backup.name,
        password_fallback_verified=True,
    )


def open_current_or_provision(
    backup: Path, configuration: dict[str, object]
) -> tuple[dict[str, object], t2_catacomb_store.CatacombStore, bool]:
    """Open the authoritative local generation or provision its first copy."""
    apple_user_id = configuration["apple_uid"]
    if not os.path.lexists(STORE_ROOT):
        host, store = t2_catacomb_local.provision_from_backup(
            backup, STORE_ROOT, apple_user_id
        )
        return host, store, True

    backup_host, _backup_components = t2_catacomb_local.read_backup_components(
        backup, apple_user_id
    )
    store = t2_catacomb_store.CatacombStore(STORE_ROOT, apple_user_id)
    current = t2_enrollment_finalizer.read_local_host_snapshot(
        store,
        {
            "apple_uid": apple_user_id,
            "host_components": backup_host["host_components"],
        },
    )
    if (
        current["account_uuid"] != backup_host["account_uuid"]
        or current["bag_uuid"] != backup_host["bag_uuid"]
    ):
        raise EnrollmentCommandError(
            "local Catacomb account or keybag binding differs from its backup"
        )
    # The original archive remains the immutable recovery anchor.  Its
    # component contents are not the current baseline after a successful
    # enrollment; the independently decoded local store above is.
    current["archive_sha256"] = backup_host["archive_sha256"]
    return current, store, False


def run_preflight(
    configuration: dict[str, object], host_inventory: dict[str, object], backup: Path
) -> dict[str, object]:
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"],
        configuration["interface"],
        _port(),
        timeout=60,
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        baseline = _build_preflight_baseline(
            configuration, host_inventory, live, backup
        )
    return {
        "schema_version": 1,
        "preflight_ready": True,
        "identity_count": len(baseline["identity_records"]),
        "capacity_available": (
            baseline["capacity"]["used"] < baseline["capacity"]["maximum"]
        ),
        "same_connection_inventory": True,
        "local_store_verified": True,
        "identifiers_redacted": True,
        "mutation_performed": False,
    }


UNFINISHED_PHASES = frozenset(
    {
        t2_enrollment_journal.EnrollmentPhase.START_INTENT,
        t2_enrollment_journal.EnrollmentPhase.ACTIVE,
        t2_enrollment_journal.EnrollmentPhase.CONTINUE_INTENT,
        t2_enrollment_journal.EnrollmentPhase.CANCEL_INTENT,
        t2_enrollment_journal.EnrollmentPhase.CANCEL_REQUESTED,
        t2_enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY,
        t2_enrollment_journal.EnrollmentPhase.TERMINAL_FAILURE,
        t2_enrollment_journal.EnrollmentPhase.PERSISTING,
        t2_enrollment_journal.EnrollmentPhase.PERSISTENCE_READY,
        t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
    }
)


def enrollment_journals() -> list[
    tuple[Path, t2_enrollment_journal.EnrollmentHistory]
]:
    _private_root_owned(MUTATION_ROOT, directory=True)
    found = []
    for entry in sorted(MUTATION_ROOT.iterdir(), key=lambda value: value.name):
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl",
            entry.name,
        ):
            raise EnrollmentCommandError(
                "mutation journal directory contains an unexpected entry"
            )
        _private_root_owned(entry, directory=False)
        found.append((entry, t2_enrollment_journal.read(entry)))
    return found


def unfinished_enrollment_journals() -> list[
    tuple[Path, t2_enrollment_journal.EnrollmentHistory]
]:
    return [
        item for item in enrollment_journals() if item[1].phase in UNFINISHED_PHASES
    ]


def pending_post_reboot_journals() -> list[
    tuple[Path, t2_enrollment_journal.EnrollmentHistory]
]:
    return [
        item
        for item in enrollment_journals()
        if item[1].phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
        and item[1].terminal_identity_uuid is not None
    ]


def require_no_unfinished_enrollment() -> None:
    journals = enrollment_journals()
    unfinished = any(history.phase in UNFINISHED_PHASES for _path, history in journals)
    pending_post_reboot = any(
        history.phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
        and history.terminal_identity_uuid is not None
        for _path, history in journals
    )
    local_transaction_pending = os.path.lexists(
        STORE_ROOT / "prepare"
    ) or os.path.lexists(STORE_ROOT / "commit")
    if unfinished or pending_post_reboot or local_transaction_pending:
        raise EnrollmentCommandError(
            "an earlier enrollment is unfinished, has a pending local transaction, "
            "or awaits post-reboot verification"
        )


def enrollment_status() -> dict[str, object]:
    commit_intent = (
        t2_enrollment_persistence_journal.PersistencePhase.BATCH_COMMIT_INTENT
    )
    journals = enrollment_journals()
    unfinished = [item for item in journals if item[1].phase in UNFINISHED_PHASES]
    pending_post_reboot = [
        item
        for item in journals
        if item[1].phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
        and item[1].terminal_identity_uuid is not None
    ]
    phases: dict[str, int] = {}
    for _path, history in unfinished:
        name = history.phase.value
        phases[name] = phases.get(name, 0) + 1
    prepare_pending = os.path.lexists(STORE_ROOT / "prepare")
    commit_pending = os.path.lexists(STORE_ROOT / "commit")
    local_transaction_pending = prepare_pending or commit_pending
    recovery_available = (
        len(unfinished) == 1
        and unfinished[0][1].phase
        is t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
        and not local_transaction_pending
    )
    local_recovery_candidate = False
    if prepare_pending != commit_pending and len(unfinished) == 1:
        history = unfinished[0][1]
        recovery_stage = (
            "local-prepare-discarded"
            if prepare_pending
            else "local-commit-rolled-forward"
        )
        phase_allows_recovery = (
            history.phase is t2_enrollment_journal.EnrollmentPhase.PERSISTING
            or (
                history.phase
                is t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
                and history.outcome_unknown_stage == recovery_stage
            )
        )
        persistence = history.persistence
        batch_index = persistence.batch_index
        if (
            phase_allows_recovery
            and batch_index is not None
            and 0 <= batch_index < len(persistence.batches)
        ):
            expected_names = {
                name for name, _descriptor in persistence.batches[batch_index]
            }
            staged_names = {name for name, _digest in persistence.staged_files}
            local_recovery_candidate = (
                bool(expected_names) and staged_names <= expected_names
            )
            if commit_pending:
                local_recovery_candidate = (
                    local_recovery_candidate
                    and staged_names == expected_names
                    and persistence.phase is commit_intent
                )
    return {
        "schema_version": 1,
        "status_only": True,
        "unfinished_count": len(unfinished),
        "unfinished_phases": dict(sorted(phases.items())),
        "post_reboot_pending_count": len(pending_post_reboot),
        "post_reboot_verification_candidate": len(pending_post_reboot) == 1,
        "live_enrollment_blocked": bool(
            unfinished or pending_post_reboot or local_transaction_pending
        ),
        "automatic_no_change_recovery_candidate": recovery_available,
        "local_transaction_pending": local_transaction_pending,
        "local_transaction_recovery_candidate": local_recovery_candidate,
        "identifiers_redacted": True,
        "mutation_performed": False,
    }


def run_outcome_unknown_reconciliation(
    configuration: dict[str, object], store: t2_catacomb_store.CatacombStore
) -> dict[str, object]:
    unfinished = unfinished_enrollment_journals()
    if (
        len(unfinished) != 1
        or unfinished[0][1].phase
        is not t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
    ):
        raise EnrollmentCommandError(
            "automatic recovery requires exactly one unfinished outcome-unknown journal"
        )
    journal_path, history = unfinished[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise EnrollmentCommandError(
            "outcome-unknown journal belongs to another mapping"
        )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"],
        configuration["interface"],
        _port(),
        timeout=60,
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        host = t2_enrollment_finalizer.read_local_host_snapshot(
            store, history.baseline
        )
        reconciled = t2_enrollment_reconciliation.append_reconciled(
            journal_path,
            history.operation_id,
            host=host,
            live=live,
            mapping_generation=configuration["mapping_generation"],
        )
    if reconciled.phase is not t2_enrollment_journal.EnrollmentPhase.RECONCILED:
        raise EnrollmentCommandError("outcome-unknown journal did not reconcile")
    return {
        "schema_version": 1,
        "outcome_unknown_reconciled": True,
        "identity_count": len(live["per_user_identity_records"]),
        "persistent_identity_delta": False,
        "identifiers_redacted": True,
        "fingerprint_mutation_performed": False,
    }


def run_local_transaction_recovery(
    configuration: dict[str, object], store: t2_catacomb_store.CatacombStore
) -> dict[str, object]:
    commit_intent = (
        t2_enrollment_persistence_journal.PersistencePhase.BATCH_COMMIT_INTENT
    )
    unfinished = unfinished_enrollment_journals()
    if (
        len(unfinished) != 1
        or unfinished[0][1].phase
        not in {
            t2_enrollment_journal.EnrollmentPhase.PERSISTING,
            t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
        }
    ):
        raise EnrollmentCommandError(
            "local transaction recovery requires exactly one persisting enrollment"
        )
    journal_path, history = unfinished[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise EnrollmentCommandError(
            "persisting enrollment belongs to another protected mapping"
        )
    prepare_pending = os.path.lexists(STORE_ROOT / "prepare")
    commit_pending = os.path.lexists(STORE_ROOT / "commit")
    if prepare_pending == commit_pending:
        raise EnrollmentCommandError(
            "local recovery requires exactly one prepare or commit transaction"
        )
    persistence = history.persistence
    if (
        persistence.batch_index is None
        or not 0 <= persistence.batch_index < len(persistence.batches)
    ):
        raise EnrollmentCommandError("persisting journal has no current Catacomb batch")
    expected_names = {
        name for name, _descriptor in persistence.batches[persistence.batch_index]
    }
    expected_hashes = dict(persistence.staged_files)
    if not expected_names or not set(expected_hashes) <= expected_names:
        raise EnrollmentCommandError("persisting journal staged set is inconsistent")

    if prepare_pending:
        recovery_stage = "local-prepare-discarded"
    else:
        if (
            set(expected_hashes) != expected_names
            or persistence.phase is not commit_intent
        ):
            raise EnrollmentCommandError(
                "commit recovery lacks a complete journaled host batch"
            )
        recovery_stage = "local-commit-rolled-forward"

    if history.phase is t2_enrollment_journal.EnrollmentPhase.PERSISTING:
        recovered = t2_enrollment_journal.append_checked(
            journal_path,
            history.operation_id,
            "ENROLL_OUTCOME_UNKNOWN",
            {
                "connection_generation": history.baseline["connection_generation"],
                "stage": recovery_stage,
                "reason": "process-interrupted",
                "mutation_possible": True,
            },
        )
    else:
        if history.outcome_unknown_stage != recovery_stage:
            raise EnrollmentCommandError(
                "local transaction differs from its journaled recovery direction"
            )
        recovered = history
    if recovered.phase is not t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN:
        raise EnrollmentCommandError("local recovery did not preserve ambiguity")

    if prepare_pending:
        store.discard_prepare(expected_names, expected_hashes)
    elif store.recover(expected_hashes) != "commit-rolled-forward":
        raise EnrollmentCommandError("commit transaction did not roll forward")
    return {
        "schema_version": 1,
        "local_transaction_recovered": True,
        "recovery_action": (
            "prepare-discarded"
            if prepare_pending
            else "commit-rolled-forward"
        ),
        "outcome_unknown": True,
        "identifiers_redacted": True,
        "fingerprint_mutation_performed": False,
    }


def run_post_reboot_verification(
    configuration: dict[str, object], store: t2_catacomb_store.CatacombStore
) -> dict[str, object]:
    candidates = pending_post_reboot_journals()
    if len(candidates) != 1:
        raise EnrollmentCommandError(
            "post-reboot verification requires exactly one reconciled identity journal"
        )
    journal_path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise EnrollmentCommandError(
            "post-reboot journal belongs to another mapping"
        )
    keybag_runtime(configuration["special_bag"])
    host = t2_enrollment_finalizer.read_local_host_snapshot(
        store, history.baseline
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"],
        configuration["interface"],
        _port(),
        timeout=60,
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        verified = t2_enrollment_reconciliation.append_post_reboot_verified(
            journal_path,
            history.operation_id,
            host=host,
            live=live,
            linux_boot_uuid=BOOT_ID.read_text().strip(),
            mapping_generation=configuration["mapping_generation"],
            keybag_runtime_revalidated=True,
        )
    if (
        verified.phase
        is not t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
    ):
        raise EnrollmentCommandError("post-reboot verification did not reach E4")
    return {
        "schema_version": 1,
        "post_reboot_verified": True,
        "identity_count": len(live["per_user_identity_records"]),
        "identifiers_redacted": True,
        "fingerprint_mutation_performed": False,
        "journal_updated": True,
    }


def run_enrollment(
    configuration: dict[str, object],
    host_inventory: dict[str, object],
    backup: Path,
    identity_name: str,
    cancel_requested: Callable[[], bool],
) -> dict[str, object]:
    session, _positive_handle = keybag_runtime(configuration["special_bag"])
    operation_id = str(uuid.uuid4())
    journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"

    def bind_password(context: bytes) -> None:
        completed = subprocess.run(
            [
                str(AKS_TOOL),
                "verify-password-acm",
                str(session),
                str(configuration["special_bag"]),
            ],
            input=context,
            check=False,
        )
        if completed.returncode:
            raise ACMDeviceError("AKS password binding failed")
        notify_user(configuration["linux_user"], "t2-touchid-alert.service")

    def feedback(transition: object) -> None:
        report_enrollment_feedback(configuration["linux_user"], transition)

    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"],
        configuration["interface"],
        _port(),
        timeout=60,
    ) as lease, ACMDevice() as device:
        finalizer = t2_enrollment_finalizer.BuiltinEnrollmentFinalizer(
            lease=lease,
            apple_user_id=configuration["apple_uid"],
            connection_generation=lease.connection_generation,
            journal_path=journal_path,
            operation_id=operation_id,
            catacomb_root=STORE_ROOT,
            mapping_generation=configuration["mapping_generation"],
            identity_name=identity_name,
        )
        result = t2_enrollment_coordinator.run(
            lease=lease,
            acm_device=device,
            apple_user_id=configuration["apple_uid"],
            host_inventory=host_inventory,
            journal_path=journal_path,
            operation_id=operation_id,
            caller_linux_uid=configuration["linux_uid"],
            target_linux_uid=configuration["linux_uid"],
            linux_boot_uuid=BOOT_ID.read_text().strip(),
            mapping_generation=configuration["mapping_generation"],
            backup_reference=backup.name,
            password_fallback_verified=True,
            password_binder=bind_password,
            finalizer=finalizer,
            cancel_requested=cancel_requested,
            on_feedback=feedback,
        )
    successful = (
        result.outcome == "identity-observed"
        and result.policy_satisfied
        and result.persistence_ready
        and result.reconciliation_complete
    )
    notify_user(
        configuration["linux_user"],
        "t2-touchid-success.service" if successful else "t2-touchid-failure.service",
    )
    return {
        "schema_version": 1,
        "outcome": result.outcome,
        "policy_satisfied": result.policy_satisfied,
        "persistence_ready": result.persistence_ready,
        "reconciliation_complete": result.reconciliation_complete,
        "enrollment_succeeded": successful,
        "identifiers_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight-only", action="store_true")
    mode.add_argument("--reconcile-outcome-unknown", action="store_true")
    mode.add_argument("--status-only", action="store_true")
    mode.add_argument("--verify-post-reboot", action="store_true")
    mode.add_argument("--recover-local-transaction", action="store_true")
    parser.add_argument("--identity-name", default="Linux enrolled finger")
    parser.add_argument(
        "--acknowledge-password-fallback-tested", action="store_true"
    )
    parser.add_argument(
        "--acknowledge-live-fingerprint-enrollment", action="store_true"
    )
    parser.add_argument(
        "--acknowledge-local-catacomb-mutation", action="store_true"
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run through sudo from the mapped desktop user")
    if (
        not args.reconcile_outcome_unknown
        and not args.status_only
        and not args.verify_post_reboot
        and not args.recover_local_transaction
        and not args.acknowledge_password_fallback_tested
    ):
        parser.error("password-fallback acknowledgement is required")
    live_enrollment = (
        not args.preflight_only
        and not args.reconcile_outcome_unknown
        and not args.status_only
        and not args.verify_post_reboot
        and not args.recover_local_transaction
    )
    if live_enrollment and not (
        args.acknowledge_live_fingerprint_enrollment
        and args.acknowledge_local_catacomb_mutation
    ):
        parser.error("both live mutation acknowledgements are required")
    if live_enrollment and (
        not args.identity_name
        or "\x00" in args.identity_name
        or len(args.identity_name.encode("utf-8")) > 1024
    ):
        parser.error("identity name is invalid")

    cancellation = Event()
    configuration: dict[str, object] | None = None
    handled_signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous_handlers = {
        handled: signal.signal(
            handled, lambda _signum, _frame: cancellation.set()
        )
        for handled in handled_signals
    }
    try:
        configuration = runtime_configuration()
        _private_root_owned(STATE_ROOT, directory=True)
        _private_root_owned(MUTATION_ROOT, directory=True)
        backup: Path | None = None
        if not args.status_only and not args.recover_local_transaction:
            if not args.verify_post_reboot:
                backup = select_backup()
            # The readiness service takes OPERATION_LOCK itself, so this must
            # finish before the broker acquires its long-lived operation lock.
            warm_sensor()
        lock_flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_descriptor = os.open(OPERATION_LOCK, lock_flags, 0o600)
        try:
            lock_info = os.fstat(lock_descriptor)
            if (
                not stat.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != 0
                or lock_info.st_mode & 0o077
            ):
                raise EnrollmentCommandError("operation lock is unsafe")
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.status_only:
                result = enrollment_status()
            elif args.recover_local_transaction:
                if not os.path.lexists(STORE_ROOT):
                    raise EnrollmentCommandError(
                        "local transaction recovery requires the existing Catacomb"
                    )
                store = t2_catacomb_store.CatacombStore(
                    STORE_ROOT, configuration["apple_uid"]
                )
                result = run_local_transaction_recovery(configuration, store)
                result["local_store_provisioned"] = False
            elif args.verify_post_reboot:
                if not os.path.lexists(STORE_ROOT):
                    raise EnrollmentCommandError(
                        "post-reboot verification requires the existing local Catacomb"
                    )
                store = t2_catacomb_store.CatacombStore(
                    STORE_ROOT, configuration["apple_uid"]
                )
                result = run_post_reboot_verification(configuration, store)
                result["local_store_provisioned"] = False
            else:
                if backup is None:
                    raise EnrollmentCommandError(
                        "protected Catacomb backup selection was skipped"
                    )
                host_inventory, store, store_provisioned = open_current_or_provision(
                    backup, configuration
                )
                if args.preflight_only:
                    result = run_preflight(configuration, host_inventory, backup)
                elif args.reconcile_outcome_unknown:
                    result = run_outcome_unknown_reconciliation(configuration, store)
                else:
                    require_no_unfinished_enrollment()
                    with sleep_inhibitor() as inhibitor:
                        if cancellation.is_set():
                            raise EnrollmentCommandError(
                                "enrollment was cancelled before dispatch"
                            )
                        result = run_enrollment(
                            configuration,
                            host_inventory,
                            backup,
                            args.identity_name,
                            lambda: cancellation.is_set()
                            or inhibitor.poll() is not None,
                        )
                result["local_store_provisioned"] = store_provisioned
        finally:
            os.close(lock_descriptor)
    except (
        ACMDeviceError,
        EnrollmentCommandError,
        OSError,
        subprocess.SubprocessError,
        t2_baseline.BaselineError,
        t2_bridge_connection.BridgeConnectionError,
        t2_bridge_inventory.BridgeInventoryError,
        t2_catacomb_local.LocalCatacombError,
        t2_catacomb_store.CatacombStoreError,
        t2_enrollment_coordinator.EnrollmentCoordinatorError,
        t2_enrollment_finalizer.EnrollmentFinalizerError,
        t2_enrollment_reconciliation.EnrollmentReconciliationError,
        t2_mutation_journal.JournalError,
    ) as error:
        if live_enrollment and configuration is not None:
            notify_user(configuration["linux_user"], "t2-touchid-failure.service")
        print(f"t2-touchid-enroll-test: {error}", file=sys.stderr)
        return 1
    finally:
        for handled, previous in previous_handlers.items():
            signal.signal(handled, previous)
    print(json.dumps(result, indent=2, sort_keys=True))
    if live_enrollment and result.get("enrollment_succeeded") is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
