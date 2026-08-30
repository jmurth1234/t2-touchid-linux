#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Create a private, non-mutating enrollment-management baseline journal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
if INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_baseline
import t2_mutation_journal


CONFIG = Path("/etc/t2-touchid.conf")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STATE_ROOT = Path("/var/lib/t2-touchid")
RUN_ROOT = Path("/run/t2-touchid")


class BaselineCommandError(RuntimeError):
    pass


def assignments(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z0-9_]+", key):
            values[key] = value
    return values


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise BaselineCommandError(f"{path} is not a private root-owned directory")


def copy_verified_backup(source: Path, destination: Path, expected_hash: str) -> None:
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_hash:
            raise BaselineCommandError("existing backup hash does not match")
        info = destination.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise BaselineCommandError("existing backup is not private")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    source_flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    descriptor = None
    copied = False
    try:
        source_info = os.fstat(source_descriptor)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > 16 * 1024 * 1024:
            raise BaselineCommandError("Catacomb archive changed during backup")
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(os.dup(source_descriptor), "rb", closefd=True) as input_stream, os.fdopen(
            os.dup(descriptor), "wb", closefd=True
        ) as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
            output_stream.flush()
        os.fsync(descriptor)
        copied = True
    finally:
        os.close(source_descriptor)
        if descriptor is not None:
            os.close(descriptor)
        if descriptor is not None and not copied:
            destination.unlink(missing_ok=True)
    directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_hash:
        raise BaselineCommandError("backup verification failed")


def run_private_inventory(config: dict[str, str], output: Path) -> dict:
    host = config.get("T2_TOUCHID_HOST", "")
    interface = config.get("T2_TOUCHID_INTERFACE", "")
    uid_text = config.get("T2_TOUCHID_MACOS_USER_ID", "")
    project = Path(config.get("T2_TOUCHID_PROJECT_DIR", "/opt/t2-touchid"))
    port = PORT_CACHE.read_text().strip()
    if not uid_text.isdecimal() or not host or not interface or not port.isdecimal():
        raise BaselineCommandError("Touch ID configuration/inventory cache is incomplete")
    command = [
        "/usr/bin/flock",
        "--exclusive",
        "--timeout",
        "10",
        "--no-fork",
        str(RUN_ROOT / "operation.lock"),
        str(project / ".venv/bin/python"),
        str(project / "src/bridge-xpc-probe.py"),
        "--host", host,
        "--interface", interface,
        "--port", port,
        "--macos-user-id", uid_text,
        "--initialize",
        "--full-inventory",
        "--private-inventory-output", str(output),
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env={"PATH": "/usr/bin:/bin"},
    )
    if completed.returncode:
        detail = completed.stderr.strip().splitlines()[-1:] or ["unknown error"]
        raise BaselineCommandError(f"private inventory failed: {detail[0]}")
    try:
        public = json.loads(completed.stdout)
        private = json.loads(output.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineCommandError("private inventory output is malformed") from error
    if public.get("private_inventory_written") is not True:
        raise BaselineCommandError("probe did not attest private inventory output")
    return private


def warmed_private_inventory(config: dict[str, str], output: Path) -> dict:
    """Collect under the shared operation lock while the sensor stays warmed.

    Stopping fprintd tears down BiometricKit's required sensor state on this
    hardware (protocol command 1 returns IOKit 0xe00002c2).  The daemon itself
    does not hold a bridge session while idle; both it and this command take
    operation.lock around every bridge operation.
    """
    active = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", "fprintd.service"],
        check=False,
    ).returncode == 0
    if not active:
        raise BaselineCommandError(
            "fprintd must be active so BiometricKit remains initialized"
        )
    warmed = subprocess.run(
        [
            "/usr/bin/systemctl",
            "restart",
            "t2-biometric-ready.service",
        ],
        check=False,
    )
    if warmed.returncode:
        raise BaselineCommandError("could not warm BiometricKit before inventory")
    return run_private_inventory(config, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catacomb-archive", required=True, type=Path)
    parser.add_argument(
        "--operation-kind",
        required=True,
        choices=("enroll", "delete-one", "delete-batch", "recovery"),
    )
    parser.add_argument(
        "--acknowledge-password-fallback-tested",
        action="store_true",
        help="confirm password fallback was physically tested this boot",
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise BaselineCommandError("run through sudo")
        sudo_uid_text = os.environ.get("SUDO_UID", "")
        if not sudo_uid_text.isdecimal() or int(sudo_uid_text) == 0:
            raise BaselineCommandError("run through sudo from the mapped desktop user")
        if not args.acknowledge_password_fallback_tested:
            raise BaselineCommandError("password-fallback acknowledgement is required")
        config = assignments(CONFIG)
        linux_user = config.get("T2_TOUCHID_USER", "")
        if not linux_user or pwd.getpwnam(linux_user).pw_uid != int(sudo_uid_text):
            raise BaselineCommandError("sudo caller is not the configured Touch ID user")
        apple_uid_text = config.get("T2_TOUCHID_MACOS_USER_ID", "")
        if not apple_uid_text.isdecimal():
            raise BaselineCommandError("configured Apple UID is invalid")
        archive_info = args.catacomb_archive.stat()
        if (
            not stat.S_ISREG(archive_info.st_mode)
            or archive_info.st_uid not in (0, int(sudo_uid_text))
            or archive_info.st_mode & 0o022
            or archive_info.st_size > 16 * 1024 * 1024
        ):
            raise BaselineCommandError("Catacomb archive ownership/mode/size is unsafe")

        private_directory(STATE_ROOT)
        private_directory(STATE_ROOT / "backups")
        private_directory(STATE_ROOT / "mutations")
        private_directory(RUN_ROOT)
        host = t2_baseline.read_host_archive(args.catacomb_archive, int(apple_uid_text))
        backup = STATE_ROOT / "backups" / f'{host["archive_sha256"]}.tar.gz'
        copy_verified_backup(args.catacomb_archive, backup, host["archive_sha256"])
        temporary = RUN_ROOT / f"private-inventory-{uuid.uuid4()}.json"
        try:
            live = warmed_private_inventory(config, temporary)
        finally:
            temporary.unlink(missing_ok=True)
        boot_uuid = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        mapping_generation = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
        baseline = t2_baseline.build_baseline(
            host=host,
            live=live,
            caller_linux_uid=int(sudo_uid_text),
            target_linux_uid=int(sudo_uid_text),
            linux_boot_uuid=boot_uuid,
            mapping_generation=mapping_generation,
            backup_reference=backup.name,
            password_fallback_verified=True,
        )
        operation_id = str(uuid.uuid4())
        journal_path = STATE_ROOT / "mutations" / f"{operation_id}.jsonl"
        t2_mutation_journal.create(
            journal_path, args.operation_kind, baseline, operation_id=operation_id
        )
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "operation_id": operation_id,
                    "operation_kind": args.operation_kind,
                    "identity_count": len(baseline["identity_records"]),
                    "baseline_reconciled": True,
                    "journal_created": True,
                    "identifiers_redacted": True,
                    "mutation_performed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
    except (
        BaselineCommandError,
        t2_baseline.BaselineError,
        t2_mutation_journal.JournalError,
        KeyError,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
