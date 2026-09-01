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
import t2_catacomb_protocol
import t2_catacomb_store
import t2_catacomb_sync_journal
import t2_enrollment_finalizer
import t2_enrollment_persistence_journal
import t2_external_delete_reconcile
import t2_fprint_projection
import t2_identity_delete
import t2_identity_delete_bridge
import t2_identity_delete_journal
import t2_identity_delete_operation
import t2_identity_delete_pipeline
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
import t2_user_mapping


CONFIG = Path("/etc/t2-touchid.conf")
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STATE_ROOT = Path("/var/lib/t2-touchid")
BACKUP_ROOT = STATE_ROOT / "backups"
STORE_ROOT = STATE_ROOT / "catacomb"
MUTATION_ROOT = STATE_ROOT / "mutations"
EXTERNAL_BACKUP_ROOT = STATE_ROOT / "external-reconciliation-backups"
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SYSTEMD_INHIBIT = Path("/usr/bin/systemd-inhibit")
CAT = Path("/usr/bin/cat")
MAPPING_PATH = Path("/var/lib/t2-touchid/users.json")


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
    mapping_generation = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    protected_mapping_present = MAPPING_PATH.exists()
    mapping_enabled = False
    mapping_capabilities: frozenset[str] = frozenset()
    if protected_mapping_present:
        try:
            mapping_set = t2_user_mapping.load(MAPPING_PATH)
            selected = [
                item
                for item in mapping_set.mappings
                if item.linux_uid == linux_uid
            ]
        except t2_user_mapping.UserMappingError as error:
            raise IdentityManagementError(
                "protected account mapping is invalid"
            ) from error
        if (
            len(selected) != 1
            or selected[0].apple_uid != int(apple_text)
            or selected[0].special_bag_alias != int(special_text)
        ):
            raise IdentityManagementError(
                "protected account mapping differs from runtime configuration"
            )
        mapping_generation = mapping_set.generation
        mapping_enabled = selected[0].enabled
        mapping_capabilities = selected[0].capabilities
    return {
        "linux_user": values["T2_TOUCHID_USER"],
        "linux_uid": linux_uid,
        "apple_uid": int(apple_text),
        "special_bag": int(special_text),
        "host": values["T2_TOUCHID_HOST"],
        "interface": values["T2_TOUCHID_INTERFACE"],
        "mapping_generation": mapping_generation,
        "protected_mapping_present": protected_mapping_present,
        "mapping_enabled": mapping_enabled,
        "mapping_capabilities": mapping_capabilities,
    }


def require_mapping_capability(
    configuration: dict[str, object], capability: str
) -> None:
    """Require the protected authority when called from the real CLI path."""

    if configuration.get("protected_mapping_present") is not True:
        return
    capabilities = configuration.get("mapping_capabilities")
    if (
        configuration.get("mapping_enabled") is not True
        or not isinstance(capabilities, frozenset)
        or capability not in capabilities
    ):
        raise IdentityManagementError(
            f"protected mapping does not permit {capability}"
        )


def require_declared_mapping_capability(
    configuration: dict[str, object], capability: str
) -> None:
    capabilities = configuration.get("mapping_capabilities")
    if (
        configuration.get("protected_mapping_present") is not True
        or not isinstance(capabilities, frozenset)
        or capability not in capabilities
    ):
        raise IdentityManagementError(
            f"protected mapping does not declare {capability}"
        )


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


def external_delete_journals() -> list[tuple[Path, object]]:
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
        if isinstance(evidence, dict) and evidence.get("operation_kind") == (
            "reconcile-external-delete"
        ):
            found.append(
                (
                    entry,
                    t2_external_delete_reconcile.validate_history(records),
                )
            )
    return found


def status() -> dict[str, object]:
    entries = t2_mutation_registry.scan(MUTATION_ROOT)
    rename_phases: dict[str, int] = {}
    delete_phases: dict[str, int] = {}
    sync_phases: dict[str, int] = {}
    external_phases: dict[str, int] = {}
    rename_pending = 0
    delete_pending = 0
    sync_pending = 0
    external_pending = 0
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
        elif entry.kind == "sync-user-catacomb" and entry.blocks_new_mutation:
            sync_phases[entry.phase] = sync_phases.get(entry.phase, 0) + 1
            sync_pending += 1
        elif (
            entry.kind == "reconcile-external-delete"
            and entry.blocks_new_mutation
        ):
            external_phases[entry.phase] = (
                external_phases.get(entry.phase, 0) + 1
            )
            external_pending += 1
    return {
        "schema_version": 1,
        "status_only": True,
        "rename_pending_count": rename_pending,
        "rename_pending_phases": dict(sorted(rename_phases.items())),
        "delete_pending_count": delete_pending,
        "delete_pending_phases": dict(sorted(delete_phases.items())),
        "catacomb_sync_pending_count": sync_pending,
        "catacomb_sync_pending_phases": dict(sorted(sync_phases.items())),
        "external_reconciliation_pending_count": external_pending,
        "external_reconciliation_pending_phases": dict(
            sorted(external_phases.items())
        ),
        "post_reboot_pending_count": rename_post_reboot + delete_post_reboot,
        "rename_recovery_candidate": (
            rename_pending == 1
            and rename_post_reboot == 0
            and delete_pending == 0
            and sync_pending == 0
            and external_pending == 0
        ),
        "delete_recovery_candidate": (
            delete_pending == 1
            and delete_post_reboot == 0
            and rename_pending == 0
            and sync_pending == 0
            and external_pending == 0
        ),
        "new_mutation_blocked": any(item.blocks_new_mutation for item in entries),
        "identifiers_redacted": True,
    }


def run_rename(
    configuration: dict[str, object], *, slot: int, new_name: str
) -> dict[str, object]:
    require_mapping_capability(configuration, "identity-management")
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
        renamed_local = t2_catacomb_codec.decode_user_catacomb(
            plan.archive, configuration["apple_uid"]
        )
        renamed_projection = t2_fprint_projection.project(
            t2_identity_inventory.summarize(renamed_local, live)
        )
        baseline = t2_baseline.build_baseline(
            host=host,
            live=live,
            caller_linux_uid=configuration["linux_uid"],
            target_linux_uid=configuration["linux_uid"],
            linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
            mapping_generation=configuration["mapping_generation"],
            backup_reference=backup.name,
            # Label-only rename is credential-free.  Preserve that fact in
            # the generic mutation baseline instead of manufacturing the
            # enrollment-only password attestation.
            password_fallback_verified=False,
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
        "fprint_projection_complete": renamed_projection.complete,
        "fprint_unassigned_identity_count": (
            renamed_projection.unassigned_identity_count
        ),
        "fprint_duplicate_name_count": (
            renamed_projection.duplicate_finger_name_count
        ),
        "post_reboot_verification_required": True,
        "identifiers_redacted": True,
    }


def _identity_snapshot(local: t2_catacomb_codec.UserCatacomb) -> str:
    records = [
        {
            "uuid": item.uuid,
            "user_id": item.user_id,
            "entity": item.entity,
            "name": item.name,
            "identity_type": item.identity_type,
            "flags": item.flags,
            "attribute": item.attribute,
            "match_count": item.match_count,
            "continuous_match_count": item.continuous_match_count,
            "update_count": item.update_count,
            "creation_time": item.creation_time,
        }
        for item in local.identities
    ]
    return hashlib.sha256(t2_mutation_journal.canonical(records)).hexdigest()


def _component_snapshot(
    components: dict[str, bytes], names: tuple[str, ...]
) -> str:
    value = [
        {"name": name, "sha256": hashlib.sha256(components[name]).hexdigest()}
        for name in names
    ]
    return hashlib.sha256(t2_mutation_journal.canonical(value)).hexdigest()


def _catacomb_clean_state(
    live: dict[str, object], apple_uid: int
) -> tuple[bool, bool]:
    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if not isinstance(states, list):
        raise IdentityManagementError("SEP Catacomb state is unavailable")
    selected = [
        item
        for item in states
        if isinstance(item, dict)
        and item.get("kind") == "user"
        and item.get("user_id") == apple_uid
    ]
    masters = [
        item
        for item in states
        if isinstance(item, dict) and item.get("kind") == "master"
    ]
    if (
        len(selected) != 1
        or len(masters) != 1
        or type(selected[0].get("needs_save")) is not bool
        or type(masters[0].get("needs_save")) is not bool
    ):
        raise IdentityManagementError("SEP Catacomb state is ambiguous")
    return selected[0]["needs_save"], masters[0]["needs_save"]


def pending_catacomb_sync_recovery() -> tuple[
    Path, t2_catacomb_sync_journal.CatacombSyncHistory
]:
    found = []
    for entry in MUTATION_ROOT.iterdir():
        if not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl",
            entry.name,
        ) or not t2_mutation_journal.secure_regular_file(entry):
            raise IdentityManagementError("mutation journal directory is unsafe")
        records = t2_mutation_journal.read(entry)
        evidence = records[0].get("evidence") if records else None
        if isinstance(evidence, dict) and evidence.get("operation_kind") == (
            "sync-user-catacomb"
        ):
            history = t2_catacomb_sync_journal.validate_history(records)
            if history.phase is t2_catacomb_sync_journal.CatacombSyncPhase.OUTCOME_UNKNOWN:
                found.append((entry, history))
    if len(found) != 1:
        raise IdentityManagementError(
            "exactly one ambiguous adaptive sync is required for recovery"
        )
    return found[0]


def run_user_catacomb_sync(
    configuration: dict[str, object], *, recovery: bool = False
) -> dict[str, object]:
    """Persist one existing adaptive user update without changing identities."""

    require_declared_mapping_capability(configuration, "verify")
    recovery_entry = pending_catacomb_sync_recovery() if recovery else None
    if not recovery and t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    keybag_runtime(configuration["special_bag"])
    store, host, local, backup = current_host_and_local(configuration)
    user_name = f'user_{configuration["apple_uid"]:08x}.cat'
    component_names = (user_name, "master.cat")
    descriptors = (
        t2_catacomb_protocol.CatacombComponent.user(
            configuration["apple_uid"]
        ).descriptor,
        t2_catacomb_protocol.CatacombComponent.master().descriptor,
    )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        t2_identity_inventory.summarize(local, live)
        user_dirty, master_dirty = _catacomb_clean_state(
            live, configuration["apple_uid"]
        )
        initial_components = store.read_committed_components()
        master = t2_catacomb_codec.decode_master_catacomb(
            initial_components["master.cat"]
        )
        initial_component_snapshot = _component_snapshot(
            initial_components, component_names
        )
        initial_identity_snapshot = _identity_snapshot(local)
        descriptor_snapshot = hashlib.sha256(
            t2_mutation_journal.canonical(
                [hashlib.sha256(value).hexdigest() for value in descriptors]
            )
        ).hexdigest()
        if recovery_entry is not None:
            journal_path, recovery_history = recovery_entry
            if (
                recovery_history.recovery_attempted
                or recovery_history.intent is None
                or recovery_history.host_commit is None
                or recovery_history.baseline["mapping_generation"]
                != configuration["mapping_generation"]
                or recovery_history.baseline["sep_catacomb"]["uuid"]
                != live["catacomb"]["uuid"]
                or initial_component_snapshot
                != recovery_history.host_commit[
                    "final_component_snapshot_sha256"
                ]
                or initial_identity_snapshot
                != recovery_history.intent["identity_snapshot_sha256"]
                or lease.connection_generation
                in {
                    recovery_history.baseline["connection_generation"],
                    recovery_history.intent["connection_generation"],
                }
            ):
                raise IdentityManagementError(
                    "adaptive sync recovery binding is not exact"
                )
            operation_id = recovery_history.operation_id
            baseline = recovery_history.baseline
            if not user_dirty and not master_dirty:
                t2_catacomb_sync_journal.append_checked(
                    journal_path,
                    operation_id,
                    "CATACOMB_SYNC_RECOVERED_CLEAN",
                    {
                        "connection_generation": lease.connection_generation,
                        "final_component_snapshot_sha256": initial_component_snapshot,
                        "identity_snapshot_sha256": initial_identity_snapshot,
                        "final_sep_catacomb_hash": live["catacomb"]["hash"],
                        "sep_clean": True,
                        "local_live_equal": True,
                    },
                )
                return {
                    "schema_version": 1,
                    "catacomb_sync_recovery_performed": True,
                    "catacomb_sync_performed": False,
                    "identity_count": len(local.identities),
                    "identifiers_redacted": True,
                }
            if user_dirty is not True or master_dirty is not False:
                raise IdentityManagementError(
                    "adaptive sync recovery refuses the current dirty set"
                )
            t2_catacomb_sync_journal.append_checked(
                journal_path,
                operation_id,
                "CATACOMB_SYNC_RECOVERY_INTENT",
                {
                    "connection_generation": lease.connection_generation,
                    "mapping_generation": configuration["mapping_generation"],
                    "descriptor_snapshot_sha256": descriptor_snapshot,
                    "initial_component_snapshot_sha256": initial_component_snapshot,
                    "initial_sep_catacomb_hash": live["catacomb"]["hash"],
                    "identity_snapshot_sha256": initial_identity_snapshot,
                    "prior_final_component_snapshot_sha256": initial_component_snapshot,
                },
            )
        else:
            if not user_dirty and not master_dirty:
                return {
                    "schema_version": 1,
                    "catacomb_already_clean": True,
                    "catacomb_sync_performed": False,
                    "identity_count": len(local.identities),
                    "identifiers_redacted": True,
                }
            if user_dirty is not True or master_dirty is not False:
                raise IdentityManagementError(
                    "Catacomb sync refuses an unexpected dirty component set"
                )
            baseline = t2_baseline.build_baseline(
                host=host,
                live=live,
                caller_linux_uid=configuration["linux_uid"],
                target_linux_uid=configuration["linux_uid"],
                linux_boot_uuid=BOOT_ID.read_text(encoding="ascii").strip(),
                mapping_generation=configuration["mapping_generation"],
                backup_reference=backup.name,
                password_fallback_verified=False,
            )
            operation_id = str(uuid.uuid4())
            journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"
            t2_mutation_journal.create(
                journal_path,
                "sync-user-catacomb",
                baseline,
                operation_id=operation_id,
            )
            t2_catacomb_sync_journal.append_checked(
                journal_path,
                operation_id,
                "CATACOMB_SYNC_INTENT",
                {
                    "connection_generation": lease.connection_generation,
                    "mapping_generation": configuration["mapping_generation"],
                    "descriptor_snapshot_sha256": descriptor_snapshot,
                    "initial_component_snapshot_sha256": initial_component_snapshot,
                    "initial_sep_catacomb_hash": live["catacomb"]["hash"],
                    "identity_snapshot_sha256": initial_identity_snapshot,
                },
            )
        try:
            store.begin_stage(set(component_names))
        except BaseException as error:
            t2_catacomb_sync_journal.append_checked(
                journal_path,
                operation_id,
                (
                    "CATACOMB_SYNC_OUTCOME_UNKNOWN"
                    if recovery_entry is not None
                    else "CATACOMB_SYNC_ABORTED_BEFORE_DISPATCH"
                ),
                (
                    {
                        "stage": "recovery-host-store",
                        "reason": "sync-error",
                        "mutation_possible": True,
                        "host_commit_possible": False,
                    }
                    if recovery_entry is not None
                    else {
                        "reason": "host-store-unavailable",
                        "mutation_possible": False,
                    }
                ),
            )
            raise IdentityManagementError(
                "Catacomb sync could not create a local transaction"
            ) from error
        transport = t2_catacomb_bridge.CatacombBridgeTransport(
            lease,
            protocol_version=2,
            connection_generation=lease.connection_generation,
        )
        secure_blobs: list[bytearray] = []
        encoded_values: list[bytearray] = []
        stage = "prepare"
        host_commit_possible = False
        try:
            staged: dict[str, str] = {}
            secure_hashes: list[str] = []
            for index, (name, descriptor) in enumerate(
                zip(component_names, descriptors, strict=True)
            ):
                stage = f"prepare-{name}"
                _status, expected_length = transport.prepare(descriptor)
                stage = f"complete-{name}"
                _status, secure_blob = transport.complete(descriptor)
                secure_blobs.append(secure_blob)
                if len(secure_blob) != expected_length:
                    raise IdentityManagementError(
                        "Catacomb sync export length changed"
                    )
                secure_hashes.append(hashlib.sha256(secure_blob).hexdigest())
                stage = f"encode-{name}"
                if name == user_name:
                    encoded = bytearray(
                        local.replace_secure_data(bytes(secure_blob))
                    )
                    verified = t2_catacomb_codec.decode_user_catacomb(
                        bytes(encoded), configuration["apple_uid"]
                    )
                    if (
                        verified.identities != local.identities
                        or verified.account_uuid != local.account_uuid
                        or verified.keybag_uuid != local.keybag_uuid
                    ):
                        raise IdentityManagementError(
                            "Catacomb sync changed host identity metadata"
                        )
                else:
                    encoded = bytearray(
                        master.encode(secure_data=bytes(secure_blob))
                    )
                    t2_catacomb_codec.decode_master_catacomb(bytes(encoded))
                encoded_values.append(encoded)
                stage = f"host-stage-{name}"
                staged[name] = store.stage_component(
                    name, encoded, set(component_names)
                )
                if index + 1 < len(component_names):
                    stage = f"early-confirm-{name}"
                    transport.confirm(descriptor)
            stage = "host-commit"
            host_commit_possible = True
            store.cross_commit_boundary(staged)
            final_component_snapshot = hashlib.sha256(
                t2_mutation_journal.canonical(
                    [{"name": name, "sha256": staged[name]} for name in component_names]
                )
            ).hexdigest()
            t2_catacomb_sync_journal.append_checked(
                journal_path,
                operation_id,
                "CATACOMB_SYNC_HOST_COMMITTED",
                {
                    "connection_generation": lease.connection_generation,
                    "final_component_snapshot_sha256": final_component_snapshot,
                    "secure_blob_snapshot_sha256": hashlib.sha256(
                        t2_mutation_journal.canonical(secure_hashes)
                    ).hexdigest(),
                },
            )
            stage = "final-confirm"
            transport.confirm(descriptors[-1])
            stage = "readback"
            observed_live = t2_bridge_inventory.collect_stable_private_inventory(
                lease, configuration["apple_uid"]
            )
            observed_components = store.read_committed_components()
            observed_local = t2_catacomb_codec.decode_user_catacomb(
                observed_components[user_name], configuration["apple_uid"]
            )
            observed_host = t2_enrollment_finalizer.read_local_host_snapshot(
                store, baseline
            )
            t2_identity_inventory.summarize(observed_local, observed_live)
            observed_user_dirty, observed_master_dirty = _catacomb_clean_state(
                observed_live, configuration["apple_uid"]
            )
            if (
                observed_user_dirty
                or observed_master_dirty
                or _identity_snapshot(observed_local) != initial_identity_snapshot
                or observed_local.account_uuid != local.account_uuid
                or observed_local.keybag_uuid != local.keybag_uuid
                or observed_host["account_uuid"] != host["account_uuid"]
                or observed_host["bag_uuid"] != host["bag_uuid"]
                or observed_live["catacomb"]["uuid"]
                != live["catacomb"]["uuid"]
                or _component_snapshot(observed_components, component_names)
                != final_component_snapshot
                or observed_components["biolockout.cat"]
                != initial_components["biolockout.cat"]
            ):
                raise IdentityManagementError(
                    "Catacomb sync read-back did not reconcile"
                )
            final = t2_catacomb_sync_journal.append_checked(
                journal_path,
                operation_id,
                "CATACOMB_SYNC_RECONCILED",
                {
                    "connection_generation": lease.connection_generation,
                    "final_component_snapshot_sha256": final_component_snapshot,
                    "final_sep_catacomb_hash": observed_live["catacomb"]["hash"],
                    "identity_snapshot_sha256": initial_identity_snapshot,
                    "sep_clean": True,
                    "local_live_equal": True,
                },
            )
        except BaseException as error:
            try:
                current = t2_catacomb_sync_journal.read(journal_path)
                if current.phase not in {
                    t2_catacomb_sync_journal.CatacombSyncPhase.RECONCILED,
                    t2_catacomb_sync_journal.CatacombSyncPhase.ABORTED,
                    t2_catacomb_sync_journal.CatacombSyncPhase.OUTCOME_UNKNOWN,
                }:
                    t2_catacomb_sync_journal.append_checked(
                        journal_path,
                        operation_id,
                        "CATACOMB_SYNC_OUTCOME_UNKNOWN",
                        {
                            "stage": stage,
                            "reason": "sync-error",
                            "mutation_possible": True,
                            "host_commit_possible": host_commit_possible,
                        },
                    )
            except BaseException:
                pass
            raise IdentityManagementError(
                f"Catacomb sync stopped at {stage}; reconciliation is required"
            ) from error
        finally:
            for value in encoded_values + secure_blobs:
                value[:] = b"\x00" * len(value)
    if final.phase is not t2_catacomb_sync_journal.CatacombSyncPhase.RECONCILED:
        raise IdentityManagementError("Catacomb sync did not reconcile")
    return {
        "schema_version": 1,
        "catacomb_already_clean": False,
        "catacomb_sync_performed": True,
        "catacomb_sync_recovery_performed": recovery_entry is not None,
        "identity_count": len(local.identities),
        "identifiers_redacted": True,
    }


def _external_plan_from_history(
    history: t2_external_delete_reconcile.ExternalDeleteHistory,
    archive: bytes,
) -> t2_external_delete_reconcile.ExternalDeletePlan:
    baseline = history.baseline
    return t2_external_delete_reconcile.ExternalDeletePlan(
        baseline["apple_uid"],
        baseline["stale_identity_uuid"],
        baseline["stale_entity"],
        baseline["stale_name_sha256"],
        baseline["local_identity_count"],
        baseline["live_identity_count"],
        baseline["local_snapshot_sha256"],
        baseline["live_snapshot_sha256"],
        baseline["survivor_snapshot_sha256"],
        archive,
    )


def _external_reconciliation_readback(
    configuration: dict[str, object],
    *,
    lease: t2_bridge_connection.BridgeConnectionLease,
    store: t2_catacomb_store.CatacombStore,
    history: t2_external_delete_reconcile.ExternalDeleteHistory,
) -> None:
    if history.intent is None:
        raise IdentityManagementError("external reconciliation has no host intent")
    components = store.read_committed_components()
    user_name = f'user_{configuration["apple_uid"]:08x}.cat'
    if (
        hashlib.sha256(components[user_name]).hexdigest()
        != history.intent["staged_user_sha256"]
        or _component_snapshot(
            components,
            tuple(sorted(set(components) - {user_name})),
        )
        != history.baseline["other_components_snapshot_sha256"]
    ):
        raise IdentityManagementError(
            "external reconciliation changed an unexpected local component"
        )
    local = t2_catacomb_codec.decode_user_catacomb(
        components[user_name], configuration["apple_uid"]
    )
    live = t2_bridge_inventory.collect_stable_private_inventory(
        lease, configuration["apple_uid"]
    )
    plan = _external_plan_from_history(history, components[user_name])
    t2_external_delete_reconcile.verify(plan, local, live)


def run_external_delete_reconciliation(
    configuration: dict[str, object],
) -> dict[str, object]:
    """Prune one local-only identity after an external SEP deletion."""

    require_mapping_capability(configuration, "identity-management")
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    _private_root_owned(EXTERNAL_BACKUP_ROOT, directory=True)
    keybag_runtime(configuration["special_bag"])
    store, _host, local, _backup = current_host_and_local(configuration)
    components = store.read_committed_components()
    user_name = f'user_{configuration["apple_uid"]:08x}.cat'
    operation_id = str(uuid.uuid4())
    journal_path = MUTATION_ROOT / f"{operation_id}.jsonl"
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        plan = t2_external_delete_reconcile.plan(local, live)
        backup = t2_external_delete_reconcile.create_backup(
            EXTERNAL_BACKUP_ROOT, operation_id, components
        )
        history = t2_external_delete_reconcile.create_journal(
            journal_path,
            operation_id,
            {
                "operation_kind": "reconcile-external-delete",
                "apple_uid": configuration["apple_uid"],
                "linux_boot_uuid": BOOT_ID.read_text(encoding="ascii").strip(),
                "connection_generation": lease.connection_generation,
                "mapping_generation": configuration["mapping_generation"],
                "local_identity_count": plan.local_identity_count,
                "live_identity_count": plan.live_identity_count,
                "stale_identity_uuid": plan.stale_identity_uuid,
                "stale_entity": plan.stale_entity,
                "stale_name_sha256": plan.stale_name_sha256,
                "local_snapshot_sha256": plan.local_snapshot_sha256,
                "live_snapshot_sha256": plan.live_snapshot_sha256,
                "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
                "before_user_sha256": hashlib.sha256(
                    components[user_name]
                ).hexdigest(),
                "other_components_snapshot_sha256": _component_snapshot(
                    components,
                    tuple(sorted(set(components) - {user_name})),
                ),
                "backup_reference": backup.reference,
                "backup_snapshot_sha256": backup.snapshot_sha256,
                "sep_mutation_performed": False,
            },
        )
        staged_hash = hashlib.sha256(plan.archive).hexdigest()
        history = t2_external_delete_reconcile.append_checked(
            journal_path,
            operation_id,
            "EXTERNAL_DELETE_INTENT",
            {
                "connection_generation": lease.connection_generation,
                "staged_user_sha256": staged_hash,
                "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
                "identity_count": plan.live_identity_count,
                "sep_mutation_performed": False,
            },
        )
        stage = "host-stage"
        try:
            store.begin_stage({user_name})
            observed_hash = store.stage_component(
                user_name, plan.archive, {user_name}
            )
            if observed_hash != staged_hash:
                raise IdentityManagementError(
                    "staged external reconciliation changed content"
                )
            stage = "host-commit"
            store.cross_commit_boundary({user_name: staged_hash})
        except BaseException as error:
            try:
                t2_external_delete_reconcile.append_checked(
                    journal_path,
                    operation_id,
                    "EXTERNAL_DELETE_OUTCOME_UNKNOWN",
                    {
                        "stage": stage,
                        "host_commit_possible": os.path.lexists(
                            STORE_ROOT / "commit"
                        ),
                        "sep_mutation_performed": False,
                    },
                )
            except BaseException:
                pass
            raise IdentityManagementError(
                "external reconciliation local commit needs recovery"
            ) from error
        history = t2_external_delete_reconcile.append_checked(
            journal_path,
            operation_id,
            "EXTERNAL_DELETE_HOST_COMMITTED",
            {
                "staged_user_sha256": staged_hash,
                "recovery_action": "direct",
                "sep_mutation_performed": False,
            },
        )
        try:
            _external_reconciliation_readback(
                configuration, lease=lease, store=store, history=history
            )
        except BaseException as error:
            try:
                t2_external_delete_reconcile.append_checked(
                    journal_path,
                    operation_id,
                    "EXTERNAL_DELETE_OUTCOME_UNKNOWN",
                    {
                        "stage": "readback",
                        "host_commit_possible": True,
                        "sep_mutation_performed": False,
                    },
                )
            except BaseException:
                pass
            raise IdentityManagementError(
                "external reconciliation read-back needs recovery"
            ) from error
        final = t2_external_delete_reconcile.append_checked(
            journal_path,
            operation_id,
            "EXTERNAL_DELETE_RECONCILED",
            {
                "connection_generation": lease.connection_generation,
                "staged_user_sha256": staged_hash,
                "identity_count": plan.live_identity_count,
                "local_live_equal": True,
                "target_absent": True,
                "other_components_unchanged": True,
                "sep_mutation_performed": False,
            },
        )
    if final.phase is not (
        t2_external_delete_reconcile.ExternalDeletePhase.RECONCILED
    ):
        raise IdentityManagementError("external reconciliation did not complete")
    return {
        "schema_version": 1,
        "external_deletion_reconciled": True,
        "removed_local_only_identity_count": 1,
        "identity_count": plan.live_identity_count,
        "backup_created": True,
        "local_catacomb_mutated": True,
        "sep_mutation_performed": False,
        "identifiers_redacted": True,
    }


def run_external_delete_recovery(
    configuration: dict[str, object],
) -> dict[str, object]:
    """Recover exactly one interrupted host-only reconciliation forward or back."""

    require_mapping_capability(configuration, "identity-management")
    candidates = [
        item
        for item in external_delete_journals()
        if item[1].phase
        not in {
            t2_external_delete_reconcile.ExternalDeletePhase.BASELINE,
            t2_external_delete_reconcile.ExternalDeletePhase.RECONCILED,
            t2_external_delete_reconcile.ExternalDeletePhase.ABORTED,
        }
    ]
    if len(candidates) != 1:
        raise IdentityManagementError(
            "external reconciliation recovery requires exactly one pending journal"
        )
    journal_path, history = candidates[0]
    if (
        history.baseline["apple_uid"] != configuration["apple_uid"]
        or history.baseline["mapping_generation"]
        != configuration["mapping_generation"]
        or history.intent is None
    ):
        raise IdentityManagementError(
            "external reconciliation recovery binding changed"
        )
    keybag_runtime(configuration["special_bag"])
    store = t2_catacomb_store.CatacombStore(
        STORE_ROOT, configuration["apple_uid"]
    )
    user_name = f'user_{configuration["apple_uid"]:08x}.cat'
    expected = {user_name: history.intent["staged_user_sha256"]}
    prepare_exists = os.path.lexists(STORE_ROOT / "prepare")
    commit_exists = os.path.lexists(STORE_ROOT / "commit")
    if prepare_exists and commit_exists:
        raise IdentityManagementError("both Catacomb transaction states are present")
    if prepare_exists and history.phase is (
        t2_external_delete_reconcile.ExternalDeletePhase.HOST_COMMITTED
    ):
        raise IdentityManagementError(
            "committed external reconciliation has an unexpected prepare state"
        )
    if prepare_exists:
        store.discard_prepare(set(expected), expected)
        t2_external_delete_reconcile.append_checked(
            journal_path,
            history.operation_id,
            "EXTERNAL_DELETE_ABORTED",
            {
                "reason": "prepare-discarded",
                "host_commit_possible": False,
                "sep_mutation_performed": False,
            },
        )
        return {
            "schema_version": 1,
            "external_reconciliation_recovery_performed": True,
            "recovery_action": "prepare-discarded",
            "local_catacomb_mutated": False,
            "sep_mutation_performed": False,
            "identifiers_redacted": True,
        }
    recovery_action = "direct"
    if commit_exists:
        if store.recover(expected) != "commit-rolled-forward":
            raise IdentityManagementError(
                "external reconciliation commit did not roll forward"
            )
        recovery_action = "commit-rolled-forward"
    components = store.read_committed_components()
    current_user_hash = hashlib.sha256(components[user_name]).hexdigest()
    if current_user_hash == history.baseline["before_user_sha256"]:
        if history.phase is (
            t2_external_delete_reconcile.ExternalDeletePhase.HOST_COMMITTED
        ):
            raise IdentityManagementError(
                "external reconciliation journal says committed but old host remains"
            )
        t2_external_delete_reconcile.append_checked(
            journal_path,
            history.operation_id,
            "EXTERNAL_DELETE_ABORTED",
            {
                "reason": "before-host-stage",
                "host_commit_possible": False,
                "sep_mutation_performed": False,
            },
        )
        return {
            "schema_version": 1,
            "external_reconciliation_recovery_performed": True,
            "recovery_action": "no-local-commit",
            "local_catacomb_mutated": False,
            "sep_mutation_performed": False,
            "identifiers_redacted": True,
        }
    if current_user_hash != history.intent["staged_user_sha256"]:
        raise IdentityManagementError(
            "external reconciliation host component differs from its journal"
        )
    if history.phase is not (
        t2_external_delete_reconcile.ExternalDeletePhase.HOST_COMMITTED
    ):
        history = t2_external_delete_reconcile.append_checked(
            journal_path,
            history.operation_id,
            "EXTERNAL_DELETE_HOST_COMMITTED",
            {
                "staged_user_sha256": history.intent["staged_user_sha256"],
                "recovery_action": recovery_action,
                "sep_mutation_performed": False,
            },
        )
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        _external_reconciliation_readback(
            configuration, lease=lease, store=store, history=history
        )
        final = t2_external_delete_reconcile.append_checked(
            journal_path,
            history.operation_id,
            "EXTERNAL_DELETE_RECONCILED",
            {
                "connection_generation": lease.connection_generation,
                "staged_user_sha256": history.intent["staged_user_sha256"],
                "identity_count": history.baseline["live_identity_count"],
                "local_live_equal": True,
                "target_absent": True,
                "other_components_unchanged": True,
                "sep_mutation_performed": False,
            },
        )
    return {
        "schema_version": 1,
        "external_reconciliation_recovery_performed": True,
        "external_deletion_reconciled": final.phase
        is t2_external_delete_reconcile.ExternalDeletePhase.RECONCILED,
        "recovery_action": recovery_action,
        "identity_count": history.baseline["live_identity_count"],
        "local_catacomb_mutated": True,
        "sep_mutation_performed": False,
        "identifiers_redacted": True,
    }


def require_fprint_name(name: object) -> str:
    if (
        not isinstance(name, str)
        or name not in t2_fprint_projection.FINGER_NAME_SET
    ):
        raise IdentityManagementError(
            "fprint migration requires one canonical anatomical finger name"
        )
    return name


def run_fprint_rename_preflight(
    configuration: dict[str, object], *, slot: int, new_name: str
) -> dict[str, object]:
    """Forecast one canonical label migration without persisting or dispatching."""

    require_fprint_name(new_name)
    require_mapping_capability(configuration, "identity-management")
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    keybag_runtime(configuration["special_bag"])
    _store, _host, local, _backup = current_host_and_local(configuration)
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        current = t2_fprint_projection.project(
            t2_identity_inventory.summarize(local, live)
        )
        plan = t2_identity_rename.plan(
            local, live, slot=slot, new_name=new_name
        )
        renamed_local = t2_catacomb_codec.decode_user_catacomb(
            plan.archive, configuration["apple_uid"]
        )
        projected = t2_fprint_projection.project(
            t2_identity_inventory.summarize(renamed_local, live)
        )
    return {
        "schema_version": 1,
        "fprint_rename_preflight_succeeded": True,
        "slot": slot,
        "previous_name": plan.previous_name,
        "name": new_name,
        "identity_count": projected.reconciled_identity_count,
        "current_fprint_projection_complete": current.complete,
        "projected_fprint_projection_complete": projected.complete,
        "projected_unassigned_identity_count": (
            projected.unassigned_identity_count
        ),
        "projected_duplicate_name_count": (
            projected.duplicate_finger_name_count
        ),
        "mutation_performed": False,
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
    return t2_identity_delete_pipeline.persist(
        lease=lease,
        store=store,
        journal_path=journal_path,
        operation_id=operation_id,
        plan=plan,
        apple_uid=configuration["apple_uid"],
        mapping_generation=configuration["mapping_generation"],
    )


def run_delete(
    configuration: dict[str, object], *, slot: int
) -> dict[str, object]:
    require_mapping_capability(configuration, "identity-management")
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
            # Single deletion is credential-free.  The operation is bound by
            # its mapping, target, live inventory, and journal—not by a
            # password check this process never performs.
            password_fallback_verified=False,
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


def run_delete_preflight(
    configuration: dict[str, object], *, slot: int
) -> dict[str, object]:
    require_mapping_capability(configuration, "identity-management")
    if t2_mutation_registry.blocks_new_mutation(MUTATION_ROOT):
        raise IdentityManagementError(
            "an earlier biometric mutation is unfinished or awaits verification"
        )
    if os.path.lexists(STORE_ROOT / "prepare") or os.path.lexists(
        STORE_ROOT / "commit"
    ):
        raise IdentityManagementError("a local Catacomb transaction needs recovery")
    keybag_runtime(configuration["special_bag"])
    _store, _host, local, _backup = current_host_and_local(configuration)
    with t2_bridge_connection.BridgeConnectionLease.connect(
        configuration["host"], configuration["interface"], _port(), timeout=60
    ) as lease:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, configuration["apple_uid"]
        )
        plan = t2_identity_delete.plan(local, live, slot=slot)
    return {
        "schema_version": 1,
        "delete_preflight_succeeded": True,
        "mutation_performed": False,
        "slot": slot,
        "name": plan.name,
        "identity_count_before": len(local.identities),
        "identity_count_after": len(local.identities) - 1,
        "last_identity_deletion_refused": True,
        "post_reboot_verification_required_after_delete": True,
        "selection_scope": "current-reconciled-list",
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
    plan_fprint_rename = subparsers.add_parser(
        "plan-fprint-rename",
        help="validate one canonical fprint label migration without mutation",
    )
    plan_fprint_rename.add_argument("--slot", type=int, required=True)
    plan_fprint_rename.add_argument("--name", required=True)
    rename_fprint = subparsers.add_parser(
        "rename-fprint", help="assign one canonical fprint finger name"
    )
    rename_fprint.add_argument("--slot", type=int, required=True)
    rename_fprint.add_argument("--name", required=True)
    rename_fprint.add_argument(
        "--acknowledge-identity-label-mutation", action="store_true"
    )
    rename_fprint.add_argument(
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
    plan_delete = subparsers.add_parser(
        "plan-delete", help="validate one deletion target without mutating it"
    )
    plan_delete.add_argument("--slot", type=int, required=True)
    sync_user = subparsers.add_parser(
        "sync-user-catacomb",
        help="persist one current adaptive user Catacomb update",
    )
    sync_user.add_argument(
        "--acknowledge-adaptive-template-persistence", action="store_true"
    )
    sync_user.add_argument(
        "--acknowledge-local-catacomb-persistence", action="store_true"
    )
    recover_sync = subparsers.add_parser(
        "recover-catacomb-sync",
        help="reconcile one ambiguous adaptive Catacomb sync",
    )
    recover_sync.add_argument(
        "--acknowledge-interrupted-adaptive-sync-recovery",
        action="store_true",
    )
    recover_sync.add_argument(
        "--acknowledge-adaptive-template-persistence", action="store_true"
    )
    recover_sync.add_argument(
        "--acknowledge-local-catacomb-persistence", action="store_true"
    )
    external_delete = subparsers.add_parser(
        "reconcile-external-deletion",
        help="remove one local record already absent from stable SEP inventory",
    )
    external_delete.add_argument(
        "--acknowledge-external-fingerprint-removal", action="store_true"
    )
    external_delete.add_argument(
        "--acknowledge-local-catacomb-reconciliation", action="store_true"
    )
    recover_external = subparsers.add_parser(
        "recover-external-deletion",
        help="recover one interrupted external-deletion reconciliation",
    )
    recover_external.add_argument(
        "--acknowledge-interrupted-external-reconciliation",
        action="store_true",
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
    if args.command in {"rename", "rename-fprint"} and not (
        args.acknowledge_identity_label_mutation
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("both rename mutation acknowledgements are required")
    if args.command == "delete" and not (
        args.acknowledge_fingerprint_deletion
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("both deletion mutation acknowledgements are required")
    if args.command == "sync-user-catacomb" and not (
        args.acknowledge_adaptive_template_persistence
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("both adaptive Catacomb sync acknowledgements are required")
    if args.command == "recover-catacomb-sync" and not (
        args.acknowledge_interrupted_adaptive_sync_recovery
        and args.acknowledge_adaptive_template_persistence
        and args.acknowledge_local_catacomb_persistence
    ):
        parser.error("all adaptive Catacomb recovery acknowledgements are required")
    if args.command == "reconcile-external-deletion" and not (
        args.acknowledge_external_fingerprint_removal
        and args.acknowledge_local_catacomb_reconciliation
    ):
        parser.error("both external reconciliation acknowledgements are required")
    if args.command == "recover-external-deletion" and not (
        args.acknowledge_interrupted_external_reconciliation
    ):
        parser.error("external reconciliation recovery acknowledgement is required")
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
        # Adaptive sync is dispatched only after an already-successful match
        # and its static service requires the active readiness unit. Restarting
        # readiness here would stop both fprintd and this dependent oneshot.
        if args.command not in {
            "status",
            "sync-user-catacomb",
            "recover-catacomb-sync",
        }:
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
            elif args.command == "plan-delete":
                result = run_delete_preflight(configuration, slot=args.slot)
            elif args.command == "plan-fprint-rename":
                result = run_fprint_rename_preflight(
                    configuration, slot=args.slot, new_name=args.name
                )
            elif args.command == "sync-user-catacomb":
                with sleep_inhibitor():
                    result = run_user_catacomb_sync(configuration)
            elif args.command == "recover-catacomb-sync":
                with sleep_inhibitor():
                    result = run_user_catacomb_sync(configuration, recovery=True)
            elif args.command == "reconcile-external-deletion":
                with sleep_inhibitor():
                    result = run_external_delete_reconciliation(configuration)
            elif args.command == "recover-external-deletion":
                with sleep_inhibitor():
                    result = run_external_delete_recovery(configuration)
            elif args.command == "delete":
                with sleep_inhibitor():
                    result = run_delete(configuration, slot=args.slot)
            else:
                with sleep_inhibitor():
                    if args.command == "rename-fprint":
                        require_fprint_name(args.name)
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
        t2_catacomb_sync_journal.CatacombSyncJournalError,
        t2_catacomb_codec.CatacombCodecError,
        t2_catacomb_local.LocalCatacombError,
        t2_catacomb_store.CatacombStoreError,
        t2_enrollment_finalizer.EnrollmentFinalizerError,
        t2_external_delete_reconcile.ExternalDeleteReconcileError,
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
