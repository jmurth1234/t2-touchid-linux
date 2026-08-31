#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Journaled management of reconciled built-in T2 Touch ID identities."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_identity_rename.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_baseline
import t2_bridge_connection
import t2_bridge_inventory
import t2_catacomb_bridge
import t2_catacomb_codec
import t2_catacomb_local
import t2_catacomb_store
import t2_enrollment_finalizer
import t2_enrollment_persistence_journal
import t2_identity_delete
import t2_identity_delete_bridge
import t2_identity_delete_journal
import t2_identity_delete_operation
import t2_identity_delete_persistence
import t2_identity_delete_reconciliation
import t2_identity_delete_recovery
import t2_identity_inventory
import t2_identity_rename
import t2_identity_rename_journal
import t2_identity_rename_operation
import t2_identity_rename_recovery
import t2_identity_rename_reconciliation
import t2_mutation_journal
import t2_mutation_registry


CONFIG = Path("/etc/t2-touchid.conf")
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STATE_ROOT = Path("/var/lib/t2-touchid")
BACKUP_ROOT = STATE_ROOT / "backups"
STORE_ROOT = STATE_ROOT / "catacomb"
MUTATION_ROOT = STATE_ROOT / "mutations"
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SYSTEMD_INHIBIT = Path("/usr/bin/systemd-inhibit")
CAT = Path("/usr/bin/cat")


class IdentityManagementError(RuntimeError):
    pass


def _private_root_owned(path: Path, *, directory: bool) -> os.stat_result:
    info = path.stat(follow_symlinks=False)
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or info.st_uid != 0 or info.st_mode & 0o077:
        raise IdentityManagementError(f"{path.name} is not private and root-owned")
    return info


def _unique_assignments(path: Path, keys: set[str]) -> dict[str, str]:
    _private_root_owned(path, directory=False)
    values = {key: [] for key in keys}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(found) != 1 for found in values.values()):
        raise IdentityManagementError("runtime configuration is missing or duplicated")
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
    try:
        linux_uid = pwd.getpwnam(values["T2_TOUCHID_USER"]).pw_uid
    except KeyError as error:
        raise IdentityManagementError("mapped Linux user does not exist") from error
    apple_text = values["T2_TOUCHID_MACOS_USER_ID"]
    special_text = values["T2_TOUCHID_SPECIAL_BAG"]
    sudo_uid = os.environ.get("SUDO_UID", "")
    if (
        linux_uid <= 0
        or not sudo_uid.isdecimal()
        or int(sudo_uid) != linux_uid
        or not apple_text.isdecimal()
        or not 0 <= int(apple_text) <= 0xFFFFFFFF
        or not re.fullmatch(r"-[0-9]+", special_text)
        or int(special_text) != -int(apple_text)
        or not values["T2_TOUCHID_HOST"]
        or not values["T2_TOUCHID_INTERFACE"]
    ):
        raise IdentityManagementError("runtime account mapping is invalid")
    return {
        "linux_user": values["T2_TOUCHID_USER"],
        "linux_uid": linux_uid,
        "apple_uid": int(apple_text),
        "special_bag": int(special_text),
        "host": values["T2_TOUCHID_HOST"],
        "interface": values["T2_TOUCHID_INTERFACE"],
        "mapping_generation": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
    }


def _port() -> int:
    _private_root_owned(PORT_CACHE, directory=False)
    value = PORT_CACHE.read_text(encoding="ascii").strip()
    if not value.isdecimal() or not 49152 <= int(value) <= 65535:
        raise IdentityManagementError("cached biometric service port is invalid")
    return int(value)


def keybag_runtime(expected_special: int) -> None:
    values = _unique_assignments(
        KEYBAG_STATE,
        {"T2_KEYBAG_SESSION", "T2_KEYBAG_HANDLE", "T2_KEYBAG_SPECIAL"},
    )
    if not all(re.fullmatch(r"-?[0-9]+", value) for value in values.values()):
        raise IdentityManagementError("runtime keybag state is malformed")
    if (
        int(values["T2_KEYBAG_SESSION"]) != 1
        or int(values["T2_KEYBAG_HANDLE"]) <= 0
        or int(values["T2_KEYBAG_SPECIAL"]) != expected_special
    ):
        raise IdentityManagementError("runtime keybag state is stale")


def select_backup() -> Path:
    _private_root_owned(BACKUP_ROOT, directory=True)
    candidates = []
    for entry in BACKUP_ROOT.iterdir():
        if re.fullmatch(r"[0-9a-f]{64}\.tar\.gz", entry.name):
            _private_root_owned(entry, directory=False)
            if hashlib.sha256(entry.read_bytes()).hexdigest() != entry.name[:64]:
                raise IdentityManagementError("baseline backup filename/hash mismatch")
            candidates.append(entry)
    if len(candidates) != 1:
        raise IdentityManagementError("exactly one private baseline backup is required")
    return candidates[0]


def warm_sensor() -> None:
    completed = subprocess.run(
        ["/usr/bin/systemctl", "restart", "t2-biometric-ready.service"],
        check=False,
        timeout=60,
    )
    if completed.returncode:
        raise IdentityManagementError("BiometricKit warm-up failed")


def _sleep_inhibitor_registered(process: subprocess.Popen[bytes]) -> bool:
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
    return isinstance(records, list) and any(
        isinstance(record, dict)
        and record.get("pid") == process.pid
        and record.get("who") == "t2-touchid-management"
        and record.get("what") == "sleep"
        and record.get("mode") == "block"
        for record in records
    )


@contextmanager
def operation_lock() -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(OPERATION_LOCK, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise IdentityManagementError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IdentityManagementError("another Touch ID operation is active") from error
        yield
    finally:
        os.close(descriptor)


@contextmanager
def sleep_inhibitor() -> Iterator[None]:
    process = subprocess.Popen(
        [
            str(SYSTEMD_INHIBIT),
            "--what=sleep",
            "--who=t2-touchid-management",
            "--why=Touch ID identity management is active",
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
            if _sleep_inhibitor_registered(process):
                break
            if process.poll() is not None:
                raise IdentityManagementError("sleep inhibitor exited during setup")
            time.sleep(0.05)
        else:
            raise IdentityManagementError("sleep inhibitor could not be established")
        yield
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
            process.wait(timeout=2)


def current_host_and_local(
    configuration: dict[str, object],
) -> tuple[
    t2_catacomb_store.CatacombStore,
    dict[str, object],
    t2_catacomb_codec.UserCatacomb,
    Path,
]:
    backup = select_backup()
    backup_host, _components = t2_catacomb_local.read_backup_components(
        backup, configuration["apple_uid"]
    )
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    host = t2_enrollment_finalizer.read_local_host_snapshot(
        store,
        {
            "apple_uid": configuration["apple_uid"],
            "host_components": backup_host["host_components"],
        },
    )
    if (
        host["account_uuid"] != backup_host["account_uuid"]
        or host["bag_uuid"] != backup_host["bag_uuid"]
    ):
        raise IdentityManagementError(
            "local Catacomb account or keybag differs from its recovery anchor"
        )
    host["archive_sha256"] = backup_host["archive_sha256"]
    components = store.read_committed_components()
    local = t2_catacomb_codec.decode_user_catacomb(
        components[f'user_{configuration["apple_uid"]:08x}.cat'],
        configuration["apple_uid"],
    )
    return store, host, local, backup


def rename_journals() -> list[tuple[Path, object]]:
    _private_root_owned(MUTATION_ROOT, directory=True)
    found = []
    for entry in sorted(MUTATION_ROOT.iterdir(), key=lambda value: value.name):
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl",
            entry.name,
        ) or not t2_mutation_journal.secure_regular_file(entry):
            raise IdentityManagementError("mutation journal directory is unsafe")
        records = t2_mutation_journal.read(entry)
        evidence = records[0].get("evidence") if records else None
        if isinstance(evidence, dict) and evidence.get("operation_kind") == "rename":
            found.append((entry, t2_identity_rename_journal.validate_history(records)))
    return found


def delete_journals() -> list[tuple[Path, object]]:
    _private_root_owned(MUTATION_ROOT, directory=True)
    found = []
    for entry in sorted(MUTATION_ROOT.iterdir(), key=lambda value: value.name):
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl",
            entry.name,
        ) or not t2_mutation_journal.secure_regular_file(entry):
            raise IdentityManagementError("mutation journal directory is unsafe")
        records = t2_mutation_journal.read(entry)
        evidence = records[0].get("evidence") if records else None
        if isinstance(evidence, dict) and evidence.get("operation_kind") == "delete-one":
            found.append((entry, t2_identity_delete_journal.validate_history(records)))
    return found


def status() -> dict[str, object]:
    entries = t2_mutation_registry.scan(MUTATION_ROOT)
    rename_phases: dict[str, int] = {}
    delete_phases: dict[str, int] = {}
    rename_pending = 0
    delete_pending = 0
    rename_post_reboot = 0
    delete_post_reboot = 0
    for entry in entries:
        if entry.kind == "rename" and entry.blocks_new_mutation:
            rename_phases[entry.phase] = rename_phases.get(entry.phase, 0) + 1
            rename_pending += 1
            rename_post_reboot += int(entry.post_reboot_pending)
        elif entry.kind == "delete-one" and entry.blocks_new_mutation:
            delete_phases[entry.phase] = delete_phases.get(entry.phase, 0) + 1
            delete_pending += 1
            delete_post_reboot += int(entry.post_reboot_pending)
    return {
        "schema_version": 1,
        "status_only": True,
        "rename_pending_count": rename_pending,
        "rename_pending_phases": dict(sorted(rename_phases.items())),
        "delete_pending_count": delete_pending,
        "delete_pending_phases": dict(sorted(delete_phases.items())),
        "post_reboot_pending_count": rename_post_reboot + delete_post_reboot,
        "rename_recovery_candidate": (
            rename_pending == 1
            and rename_post_reboot == 0
            and delete_pending == 0
        ),
        "delete_recovery_candidate": (
            delete_pending == 1
            and delete_post_reboot == 0
            and rename_pending == 0
        ),
        "new_mutation_blocked": any(item.blocks_new_mutation for item in entries),
        "identifiers_redacted": True,
    }


def run_rename(
    configuration: dict[str, object], *, slot: int, new_name: str
) -> dict[str, object]:
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    keybag_runtime(configuration["special_bag"])
    store, host, local, backup = current_host_and_local(configuration)
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        t2_identity_inventory.summarize(local, live)
        plan = t2_identity_rename.plan(
            local, live, slot=slot, new_name=new_name
        )
        baseline = t2_baseline.build_baseline(
            host=host,
            live=live,
            caller_linux_uid=configuration["linux_uid"],
            target_linux_uid=configuration["linux_uid"],
            linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
            mapping_generation=configuration["mapping_generation"],
            backup_reference=backup.name,
            password_fallback_verified=True,
        )
        operation_id = str(uuid.uuid4())
        journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"
        t2_mutation_journal.create(
            journal_path, "rename", baseline, operation_id=operation_id
        )
        t2_identity_rename_journal.append_checked(
            journal_path,
            operation_id,
            "RENAME_INTENT",
            {
                "connection_generation": lease.connection_generation,
                "user_id": configuration["apple_uid"],
                "identity_uuid": plan.identity_uuid,
                "entity": plan.entity,
                "previous_name_sha256": hashlib.sha256(
                    plan.previous_name.encode("utf-8")
                ).hexdigest(),
                "new_name_sha256": hashlib.sha256(
                    plan.new_name.encode("utf-8")
                ).hexdigest(),
                "mapping_generation": configuration["mapping_generation"],
            },
        )
        transport = t2_catacomb_bridge.CatacombBridgeTransport(
            lease,
            protocol_version=2,
            connection_generation=lease.connection_generation,
        )

        def readback() -> t2_identity_rename_operation.RenameReadbackAttestation:
            observed_live = t2_bridge_inventory.collect_stable_private_inventory(
                lease, configuration["apple_uid"]
            )
            observed_host = t2_enrollment_finalizer.read_local_host_snapshot(
                store, baseline
            )
            components = store.read_committed_components()
            observed_local = t2_catacomb_codec.decode_user_catacomb(
                components[f'user_{configuration["apple_uid"]:08x}.cat'],
                configuration["apple_uid"],
            )
            attestation = t2_identity_rename_reconciliation.classify(
                t2_identity_rename_journal.read(journal_path),
                plan,
                local=observed_local,
                host=observed_host,
                live=observed_live,
                mapping_generation=configuration["mapping_generation"],
            )
            return t2_identity_rename_operation.RenameReadbackAttestation(
                attestation.connection_generation,
                attestation.snapshot_sha256,
                attestation.identity_count,
                attestation.identity_set_unchanged,
                attestation.label_updated,
                attestation.local_live_equal,
            )

        final = t2_identity_rename_operation.run(
            journal_path,
            operation_id,
            plan=plan,
            transport=transport,
            store=store,
            mapping_generation=configuration["mapping_generation"],
            readback=readback,
        )
    if final.phase is not t2_identity_rename_journal.IdentityRenamePhase.RECONCILED:
        raise IdentityManagementError("rename did not reach reconciled state")
    return {
        "schema_version": 1,
        "rename_succeeded": True,
        "slot": slot,
        "name": new_name,
        "identity_count": len(baseline["identity_records"]),
        "post_reboot_verification_required": True,
        "identifiers_redacted": True,
    }


def _persist_delete(
    configuration: dict[str, object],
    *,
    lease: t2_bridge_connection.BridgeConnectionLease,
    store: t2_catacomb_store.CatacombStore,
    journal_path: Path,
    operation_id: str,
    plan: t2_identity_delete.IdentityDeletePlan,
) -> t2_identity_delete_journal.IdentityDeleteHistory:
    transport = t2_catacomb_bridge.CatacombBridgeTransport(
        lease,
        protocol_version=2,
        connection_generation=lease.connection_generation,
    )

    def readback() -> t2_identity_delete_persistence.DeleteReadbackAttestation:
        observed_live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        history = t2_identity_delete_journal.read(journal_path)
        observed_host = t2_enrollment_finalizer.read_local_host_snapshot(
            store, history.baseline
        )
        components = store.read_committed_components()
        observed_local = t2_catacomb_codec.decode_user_catacomb(
            components[f'user_{configuration["apple_uid"]:08x}.cat'],
            configuration["apple_uid"],
        )
        attestation = t2_identity_delete_reconciliation.classify(
            history,
            plan,
            local=observed_local,
            host=observed_host,
            live=observed_live,
            mapping_generation=configuration["mapping_generation"],
        )
        return t2_identity_delete_persistence.DeleteReadbackAttestation(
            attestation.connection_generation,
            attestation.snapshot_sha256,
            attestation.identity_count,
        )

    return t2_identity_delete_persistence.run(
        journal_path,
        operation_id,
        plan=plan,
        transport=transport,
        store=store,
        mapping_generation=configuration["mapping_generation"],
        readback=readback,
    )


def run_delete(
    configuration: dict[str, object], *, slot: int
) -> dict[str, object]:
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    keybag_runtime(configuration["special_bag"])
    store, host, local, backup = current_host_and_local(configuration)
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        plan = t2_identity_delete.plan(local, live, slot=slot)
        baseline = t2_baseline.build_baseline(
            host=host,
            live=live,
            caller_linux_uid=configuration["linux_uid"],
            target_linux_uid=configuration["linux_uid"],
            linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
            mapping_generation=configuration["mapping_generation"],
            backup_reference=backup.name,
            password_fallback_verified=True,
        )
        operation_id = str(uuid.uuid4())
        journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"
        t2_mutation_journal.create(
            journal_path, "delete-one", baseline, operation_id=operation_id
        )
        t2_identity_delete_journal.append_checked(
            journal_path,
            operation_id,
            "DELETE_INTENT",
            {
                "connection_generation": lease.connection_generation,
                "user_id": configuration["apple_uid"],
                "identity_uuid": plan.identity_uuid,
                "entity": plan.entity,
                "target_name_sha256": hashlib.sha256(
                    plan.name.encode("utf-8")
                ).hexdigest(),
                "request_sha256": hashlib.sha256(plan.request).hexdigest(),
                "request_length": len(plan.request),
                "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
                "survivor_count": len(local.identities) - 1,
                "mapping_generation": configuration["mapping_generation"],
            },
        )
        bridge = t2_identity_delete_bridge.IdentityDeleteBridge(
            lease, connection_generation=lease.connection_generation
        )
        result = t2_identity_delete_operation.run(
            journal_path,
            operation_id,
            plan=plan,
            local=local,
            bridge=bridge,
            collect_inventory=lambda: (
                t2_bridge_inventory.collect_stable_private_inventory(
                    lease, configuration["apple_uid"]
                )
            ),
        )
        if result.outcome == "not-deleted":
            return {
                "schema_version": 1,
                "delete_succeeded": False,
                "outcome": "not-deleted",
                "identity_count": len(local.identities),
                "post_reboot_verification_required": False,
                "identifiers_redacted": True,
            }
        final = _persist_delete(
            configuration,
            lease=lease,
            store=store,
            journal_path=journal_path,
            operation_id=operation_id,
            plan=plan,
        )
    if final.phase is not t2_identity_delete_journal.IdentityDeletePhase.RECONCILED:
        raise IdentityManagementError("identity deletion did not reconcile")
    return {
        "schema_version": 1,
        "delete_succeeded": True,
        "slot": slot,
        "identity_count": len(baseline["identity_records"]) - 1,
        "post_reboot_verification_required": True,
        "identifiers_redacted": True,
    }


def run_post_reboot_verification(
    configuration: dict[str, object]
) -> dict[str, object]:
    candidates = [
        item
        for item in rename_journals()
        if item[1].phase
        is t2_identity_rename_journal.IdentityRenamePhase.RECONCILED
    ]
    if len(candidates) != 1:
        raise IdentityManagementError(
            "post-reboot verification requires exactly one reconciled rename"
        )
    path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise IdentityManagementError("rename journal belongs to another mapping")
    keybag_runtime(configuration["special_bag"])
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    host = t2_enrollment_finalizer.read_local_host_snapshot(store, history.baseline)
    components = store.read_committed_components()
    local = t2_catacomb_codec.decode_user_catacomb(
        components[f'user_{configuration["apple_uid"]:08x}.cat'],
        configuration["apple_uid"],
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        final = t2_identity_rename_reconciliation.append_post_reboot_verified(
            path,
            history.operation_id,
            local=local,
            host=host,
            live=live,
            linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
            mapping_generation=configuration["mapping_generation"],
        )
    if final.phase is not (
        t2_identity_rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED
    ):
        raise IdentityManagementError("rename post-reboot verification did not close")
    return {
        "schema_version": 1,
        "post_reboot_verified": True,
        "identity_count": len(local.identities),
        "identifiers_redacted": True,
    }


def run_delete_post_reboot_verification(
    configuration: dict[str, object]
) -> dict[str, object]:
    candidates = [
        item
        for item in delete_journals()
        if item[1].phase
        is t2_identity_delete_journal.IdentityDeletePhase.RECONCILED
    ]
    if len(candidates) != 1:
        raise IdentityManagementError(
            "post-reboot verification requires exactly one reconciled deletion"
        )
    path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise IdentityManagementError("delete journal belongs to another mapping")
    keybag_runtime(configuration["special_bag"])
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    host = t2_enrollment_finalizer.read_local_host_snapshot(store, history.baseline)
    components = store.read_committed_components()
    local = t2_catacomb_codec.decode_user_catacomb(
        components[f'user_{configuration["apple_uid"]:08x}.cat'],
        configuration["apple_uid"],
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        final = t2_identity_delete_reconciliation.append_post_reboot_verified(
            path,
            history.operation_id,
            local=local,
            host=host,
            live=live,
            linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
            mapping_generation=configuration["mapping_generation"],
        )
    if final.phase is not (
        t2_identity_delete_journal.IdentityDeletePhase.POST_REBOOT_VERIFIED
    ):
        raise IdentityManagementError(
            "delete post-reboot verification did not close"
        )
    return {
        "schema_version": 1,
        "delete_post_reboot_verified": True,
        "identity_count": len(local.identities),
        "identifiers_redacted": True,
    }


def _recovery_component_expectations(history) -> tuple[set[str], dict[str, str]]:
    persistence = history.persistence
    batch_index = persistence.batch_index
    if (
        batch_index is None
        or not 0 <= batch_index < len(persistence.batches)
    ):
        raise IdentityManagementError(
            "interrupted mutation has no journaled Catacomb batch"
        )
    names = {name for name, _descriptor in persistence.batches[batch_index]}
    hashes = dict(persistence.staged_files)
    if not names or not set(hashes) <= names:
        raise IdentityManagementError(
            "interrupted mutation has inconsistent staged components"
        )
    return names, hashes


def run_recovery(configuration: dict[str, object]) -> dict[str, object]:
    candidates = [
        item
        for item in rename_journals()
        if item[1].phase
        in {
            t2_identity_rename_journal.IdentityRenamePhase.INTENT,
            t2_identity_rename_journal.IdentityRenamePhase.PERSISTING,
            t2_identity_rename_journal.IdentityRenamePhase.PERSISTENCE_READY,
            t2_identity_rename_journal.IdentityRenamePhase.OUTCOME_UNKNOWN,
        }
    ]
    if len(candidates) != 1:
        raise IdentityManagementError(
            "rename recovery requires exactly one interrupted rename"
        )
    path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise IdentityManagementError("rename recovery belongs to another mapping")
    keybag_runtime(configuration["special_bag"])
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    prepare_pending = os.path.lexists(STORE_ROOT / "prepare")
    commit_pending = os.path.lexists(STORE_ROOT / "commit")
    if prepare_pending and commit_pending:
        raise IdentityManagementError("both local transaction directions are present")
    observed_action = (
        "prepare-discarded"
        if prepare_pending
        else "commit-rolled-forward"
        if commit_pending
        else "no-local-transaction"
    )
    recovery_expectations = None
    if prepare_pending or commit_pending:
        recovery_expectations = _recovery_component_expectations(history)
    if commit_pending:
        expected_names, expected_hashes = recovery_expectations
        if (
            set(expected_hashes) != expected_names
            or history.persistence.phase
            is not t2_enrollment_persistence_journal.PersistencePhase.BATCH_COMMIT_INTENT
        ):
            raise IdentityManagementError(
                "commit recovery lacks a complete journaled commit boundary"
            )
    action = history.recovery_action
    if action is None:
        history = t2_identity_rename_journal.append_checked(
            path,
            history.operation_id,
            "RENAME_RECOVERY_INTENT",
            {
                "action": observed_action,
                "mapping_generation": configuration["mapping_generation"],
                "host_commit_possible": observed_action != "prepare-discarded",
                "mutation_possible": True,
            },
        )
        action = observed_action
    elif (
        observed_action != action
        and observed_action != "no-local-transaction"
    ):
        raise IdentityManagementError(
            "local transaction direction differs from its recovery journal"
        )

    if action == "prepare-discarded" and prepare_pending:
        expected_names, expected_hashes = recovery_expectations
        store.discard_prepare(expected_names, expected_hashes)
    elif action == "commit-rolled-forward" and commit_pending:
        expected_names, expected_hashes = recovery_expectations
        if store.recover(expected_hashes) != "commit-rolled-forward":
            raise IdentityManagementError("commit transaction did not roll forward")
    elif action == "no-local-transaction" and (prepare_pending or commit_pending):
        raise IdentityManagementError(
            "journal expects no local transaction but one is present"
        )

    host = t2_enrollment_finalizer.read_local_host_snapshot(
        store, history.baseline
    )
    components = store.read_committed_components()
    local = t2_catacomb_codec.decode_user_catacomb(
        components[f'user_{configuration["apple_uid"]:08x}.cat'],
        configuration["apple_uid"],
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        observed = t2_identity_rename_recovery.classify(
            t2_identity_rename_journal.read(path),
            local=local,
            host=host,
            live=live,
            mapping_generation=configuration["mapping_generation"],
        )
        final = t2_identity_rename_recovery.append_reconciled(
            path,
            history.operation_id,
            observed,
            mapping_generation=configuration["mapping_generation"],
        )
    expected_phase = (
        t2_identity_rename_journal.IdentityRenamePhase.RECONCILED
        if observed.outcome == "committed"
        else t2_identity_rename_journal.IdentityRenamePhase.ABORTED
    )
    if final.phase is not expected_phase:
        raise IdentityManagementError("rename recovery did not reach a terminal state")
    return {
        "schema_version": 1,
        "rename_recovery_succeeded": True,
        "outcome": observed.outcome,
        "identity_count": observed.identity_count,
        "post_reboot_verification_required": observed.outcome == "committed",
        "identifiers_redacted": True,
    }


def run_delete_recovery(configuration: dict[str, object]) -> dict[str, object]:
    candidates = [
        item
        for item in delete_journals()
        if item[1].phase
        in {
            t2_identity_delete_journal.IdentityDeletePhase.INTENT,
            t2_identity_delete_journal.IdentityDeletePhase.DISPATCH_INTENT,
            t2_identity_delete_journal.IdentityDeletePhase.COMMAND_OBSERVED,
            t2_identity_delete_journal.IdentityDeletePhase.SEP_DELETED,
            t2_identity_delete_journal.IdentityDeletePhase.PERSISTING,
            t2_identity_delete_journal.IdentityDeletePhase.PERSISTENCE_READY,
            t2_identity_delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
        }
    ]
    if len(candidates) != 1:
        raise IdentityManagementError(
            "delete recovery requires exactly one interrupted deletion"
        )
    path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
    ):
        raise IdentityManagementError("delete recovery belongs to another mapping")
    keybag_runtime(configuration["special_bag"])
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    prepare_pending = os.path.lexists(STORE_ROOT / "prepare")
    commit_pending = os.path.lexists(STORE_ROOT / "commit")
    if prepare_pending and commit_pending:
        raise IdentityManagementError("both local transaction directions are present")
    observed_action = (
        "prepare-discarded"
        if prepare_pending
        else "commit-rolled-forward"
        if commit_pending
        else "no-local-transaction"
    )
    recovery_expectations = None
    if prepare_pending or commit_pending:
        recovery_expectations = _recovery_component_expectations(history)
    if commit_pending:
        expected_names, expected_hashes = recovery_expectations
        if (
            set(expected_hashes) != expected_names
            or history.persistence.phase
            is not t2_enrollment_persistence_journal.PersistencePhase.BATCH_COMMIT_INTENT
        ):
            raise IdentityManagementError(
                "delete commit recovery lacks a complete journaled boundary"
            )
    action = history.recovery_action
    retrying_forward_transaction = (
        action is not None
        and history.phase
        is t2_identity_delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN
        and history.persistence_connection_generation
        != history.baseline["connection_generation"]
        and (prepare_pending or commit_pending)
    )
    if action is None or retrying_forward_transaction:
        history = t2_identity_delete_journal.append_checked(
            path,
            history.operation_id,
            "DELETE_RECOVERY_INTENT",
            {
                "action": observed_action,
                "linux_boot_uuid": BOOT_ID.read_text(encoding="ascii").strip(),
                "mapping_generation": configuration["mapping_generation"],
                "host_commit_possible": observed_action != "prepare-discarded",
                "mutation_possible": True,
            },
        )
        action = observed_action
    elif observed_action != action and observed_action != "no-local-transaction":
        raise IdentityManagementError(
            "local transaction direction differs from its recovery journal"
        )

    if action == "prepare-discarded" and prepare_pending:
        expected_names, expected_hashes = recovery_expectations
        store.discard_prepare(expected_names, expected_hashes)
    elif action == "commit-rolled-forward" and commit_pending:
        _expected_names, expected_hashes = recovery_expectations
        if store.recover(expected_hashes) != "commit-rolled-forward":
            raise IdentityManagementError("delete commit did not roll forward")
    elif action == "no-local-transaction" and (prepare_pending or commit_pending):
        raise IdentityManagementError(
            "journal expects no local transaction but one is present"
        )

    host = t2_enrollment_finalizer.read_local_host_snapshot(
        store, history.baseline
    )
    components = store.read_committed_components()
    local = t2_catacomb_codec.decode_user_catacomb(
        components[f'user_{configuration["apple_uid"]:08x}.cat'],
        configuration["apple_uid"],
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        observed = t2_identity_delete_recovery.classify(
            t2_identity_delete_journal.read(path),
            local=local,
            host=host,
            live=live,
            mapping_generation=configuration["mapping_generation"],
        )
        final = t2_identity_delete_recovery.append_observed(
            path,
            history.operation_id,
            observed,
            mapping_generation=configuration["mapping_generation"],
        )
        if observed.outcome == "forward-required":
            if observed.archive_state == "baseline":
                plan = t2_identity_delete.plan_target(
                    local, history.target_identity_uuid
                )
            elif observed.archive_state == "survivors":
                plan = t2_identity_delete.recovery_plan(
                    local,
                    identity_uuid=history.target_identity_uuid,
                    entity=history.target_entity,
                    expected_survivor_sha256=(
                        history.survivor_snapshot_sha256
                    ),
                )
            else:
                raise IdentityManagementError(
                    "delete recovery archive state is invalid"
                )
            final = _persist_delete(
                configuration,
                lease=lease,
                store=store,
                journal_path=path,
                operation_id=history.operation_id,
                plan=plan,
            )
    expected_phase = (
        t2_identity_delete_journal.IdentityDeletePhase.ABORTED
        if observed.outcome == "no-change"
        else t2_identity_delete_journal.IdentityDeletePhase.RECONCILED
    )
    if final.phase is not expected_phase:
        raise IdentityManagementError(
            "delete recovery did not reach a reconciled terminal state"
        )
    return {
        "schema_version": 1,
        "delete_recovery_succeeded": True,
        "outcome": observed.outcome,
        "identity_count": (
            observed.identity_count
            if observed.outcome != "forward-required"
            else len(history.baseline["identity_records"]) - 1
        ),
        "post_reboot_verification_required": (
            observed.outcome != "no-change"
        ),
        "identifiers_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="show redacted mutation status")
    rename = subparsers.add_parser("rename", help="rename one reconciled identity")
    rename.add_argument("--slot", type=int, required=True)
    rename.add_argument("--name", required=True)
    rename.add_argument(
        "--acknowledge-identity-label-mutation", action="store_true"
    )
    rename.add_argument(
        "--acknowledge-local-catacomb-persistence", action="store_true"
    )
    delete = subparsers.add_parser(
        "delete", help="delete one reconciled fingerprint identity"
    )
    delete.add_argument("--slot", type=int, required=True)
    delete.add_argument(
        "--acknowledge-fingerprint-deletion", action="store_true"
    )
    delete.add_argument(
        "--acknowledge-local-catacomb-persistence", action="store_true"
    )
    subparsers.add_parser(
        "verify-post-reboot", help="verify a reconciled rename after reboot"
    )
    subparsers.add_parser(
        "verify-delete-post-reboot",
        help="verify a reconciled deletion after reboot",
    )
    recover = subparsers.add_parser(
        "recover", help="reconcile one interrupted rename without replay"
    )
    recover.add_argument(
        "--acknowledge-interrupted-rename-recovery", action="store_true"
    )
    recover_delete = subparsers.add_parser(
        "recover-delete", help="reconcile one interrupted deletion without replay"
    )
    recover_delete.add_argument(
        "--acknowledge-interrupted-delete-recovery", action="store_true"
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run through sudo from the mapped desktop user")
    if args.command == "rename" and not (
        args.acknowledge_identity_label_mutation
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("both rename mutation acknowledgements are required")
    if args.command == "delete" and not (
        args.acknowledge_fingerprint_deletion
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("both deletion mutation acknowledgements are required")
    if args.command == "recover" and not (
        args.acknowledge_interrupted_rename_recovery
    ):
        parser.error("interrupted-rename recovery acknowledgement is required")
    if args.command == "recover-delete" and not (
        args.acknowledge_interrupted_delete_recovery
    ):
        parser.error("interrupted-delete recovery acknowledgement is required")
    try:
        configuration = runtime_configuration()
        _private_root_owned(STATE_ROOT, directory=True)
        _private_root_owned(MUTATION_ROOT, directory=True)
        if args.command != "status":
            warm_sensor()
        with operation_lock():
            if args.command == "status":
                result = status()
            elif args.command == "verify-post-reboot":
                result = run_post_reboot_verification(configuration)
            elif args.command == "verify-delete-post-reboot":
                result = run_delete_post_reboot_verification(configuration)
            elif args.command == "recover":
                with sleep_inhibitor():
                    result = run_recovery(configuration)
            elif args.command == "recover-delete":
                with sleep_inhibitor():
                    result = run_delete_recovery(configuration)
            elif args.command == "delete":
                with sleep_inhibitor():
                    result = run_delete(configuration, slot=args.slot)
            else:
                with sleep_inhibitor():
                    result = run_rename(
                        configuration, slot=args.slot, new_name=args.name
                    )
    except (
        IdentityManagementError,
        OSError,
        UnicodeError,
        subprocess.SubprocessError,
        t2_baseline.BaselineError,
        t2_bridge_connection.BridgeConnectionError,
        t2_bridge_inventory.BridgeInventoryError,
        t2_catacomb_bridge.CatacombBridgeError,
        t2_catacomb_codec.CatacombCodecError,
        t2_catacomb_local.LocalCatacombError,
        t2_catacomb_store.CatacombStoreError,
        t2_enrollment_finalizer.EnrollmentFinalizerError,
        t2_identity_delete.IdentityDeleteError,
        t2_identity_delete_bridge.IdentityDeleteBridgeError,
        t2_identity_delete_journal.IdentityDeleteJournalError,
        t2_identity_delete_operation.IdentityDeleteOperationError,
        t2_identity_delete_persistence.IdentityDeletePersistenceError,
        t2_identity_delete_reconciliation.IdentityDeleteReconciliationError,
        t2_identity_delete_recovery.IdentityDeleteRecoveryError,
        t2_identity_inventory.IdentityInventoryError,
        t2_identity_rename.IdentityRenameError,
        t2_identity_rename_journal.IdentityRenameJournalError,
        t2_identity_rename_operation.IdentityRenameOperationError,
        t2_identity_rename_recovery.IdentityRenameRecoveryError,
        t2_identity_rename_reconciliation.IdentityRenameReconciliationError,
        t2_mutation_journal.JournalError,
        t2_mutation_registry.MutationRegistryError,
    ) as error:
        print(f"t2-touchid-manage: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
