#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privacy-safe health report for the T2 Touch ID stack."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


CONFIG = Path("/etc/t2-touchid.conf")
STATE = Path("/run/t2-touchid/keybag.env")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
CREDENTIAL = Path("/etc/credstore.encrypted/t2-touchid-password")
SERVICES = (
    "t2-sep-transport.service",
    "t2-keybag-load.service",
    "t2-credential-unlock.service",
    "t2-biometric-ready.service",
    "fprintd.service",
)


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def run(*command: str, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def read_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Z0-9_]+", key):
            values[key] = value
    return values


def private_regular_file(path: Path) -> bool:
    info = path.stat()
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not (info.st_mode & 0o077)
    )


def service_check(service: str) -> Check:
    result = run(
        "systemctl",
        "show",
        service,
        "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus",
        "--value",
    )
    values = result.stdout.splitlines()
    if result.returncode or len(values) < 5:
        return Check("fail", service, "unit state unavailable")
    load, active, sub, unit_result, main_status = values[:5]
    if load != "loaded":
        return Check("fail", service, "unit is not loaded")
    if active == "active" and unit_result in ("success", ""):
        return Check("pass", service, f"{active}/{sub}")
    return Check(
        "fail",
        service,
        f"{active}/{sub}; result={unit_result or 'unknown'}; status={main_status}",
    )


def network_check(config: dict[str, str], port: int) -> Check:
    host = config.get("T2_TOUCHID_HOST", "")
    interface = config.get("T2_TOUCHID_INTERFACE", "")
    if not host or not interface:
        return Check("fail", "bridge-network", "host/interface configuration missing")
    try:
        scope = socket.if_nametoindex(interface)
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            sock.connect((host, port, 0, scope))
    except (OSError, ValueError):
        return Check("fail", "bridge-network", "cached BridgeXPC endpoint unreachable")
    return Check("pass", "bridge-network", "cached BridgeXPC endpoint reachable")


def dkms_check() -> Check:
    try:
        result = run(
            "dkms",
            "status",
            "-m",
            "t2-sep-transport",
            "-v",
            "0.1.0",
        )
    except FileNotFoundError:
        return Check("warn", "dkms-module", "DKMS is not installed")
    current = platform.release()
    installed = any(
        current in line and line.rstrip().endswith(": installed")
        for line in result.stdout.splitlines()
    )
    return Check(
        "pass" if installed else "warn",
        "dkms-module",
        "installed for running kernel"
        if installed
        else "not installed for running kernel",
    )


def gnu_build_id(data: bytes) -> bytes | None:
    """Return the GNU build-id descriptor from an ELF image or sysfs note."""
    marker = b"GNU\0"
    offset = data.find(marker)
    while offset >= 12:
        header = data[offset - 12 : offset]
        namesz = int.from_bytes(header[0:4], "little")
        descsz = int.from_bytes(header[4:8], "little")
        note_type = int.from_bytes(header[8:12], "little")
        descriptor = offset + ((namesz + 3) & ~3)
        if (
            namesz == len(marker)
            and note_type == 3
            and descsz > 0
            and descriptor + descsz <= len(data)
        ):
            return data[descriptor : descriptor + descsz]
        offset = data.find(marker, offset + len(marker))
    return None


def module_build_check() -> Check:
    live_note = Path(
        "/sys/module/t2_sep_transport/notes/.note.gnu.build-id"
    )
    try:
        live_build = gnu_build_id(live_note.read_bytes())
        module_path_result = run("modinfo", "-n", "t2_sep_transport")
        module_path = Path(module_path_result.stdout.strip())
        if module_path_result.returncode or not module_path.is_file():
            raise OSError("installed module path unavailable")
        if module_path.suffix == ".zst":
            installed = subprocess.run(
                ("zstdcat", str(module_path)),
                check=False,
                capture_output=True,
                timeout=5,
            )
            if installed.returncode:
                raise OSError("installed module decompression failed")
            installed_image = installed.stdout
        else:
            installed_image = module_path.read_bytes()
        installed_build = gnu_build_id(installed_image)
        if live_build is None or installed_build is None:
            raise ValueError("GNU build ID unavailable")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return Check("warn", "module-build", "live/installed comparison unavailable")
    if live_build != installed_build:
        return Check(
            "warn",
            "module-build",
            "live module differs from installed build; reboot required",
        )
    return Check("pass", "module-build", "live module matches installed build")


def watchdog_check() -> Check:
    kernel_log = run(
        "journalctl",
        "-q",
        "-b",
        "-k",
        "--no-pager",
        "--grep=NETDEV WATCHDOG",
        timeout=10,
    )
    seen = any("NETDEV WATCHDOG" in line for line in kernel_log.stdout.splitlines())
    return Check(
        "warn" if seen else "pass",
        "suspend-health",
        "T2 network watchdog timeout seen this boot"
        if seen
        else "no network watchdog timeout this boot",
    )


def collect() -> list[Check]:
    checks: list[Check] = []

    checks.append(
        Check(
            "pass" if Path("/sys/module/t2_sep_transport").exists() else "fail",
            "sep-module",
            "loaded" if Path("/sys/module/t2_sep_transport").exists() else "not loaded",
        )
    )
    checks.append(
        Check(
            "pass" if Path("/dev/t2-aks").exists() else "fail",
            "aks-device",
            "present" if Path("/dev/t2-aks").exists() else "missing",
        )
    )
    checks.extend(service_check(service) for service in SERVICES)
    checks.append(dkms_check())
    checks.append(module_build_check())

    config: dict[str, str] = {}
    try:
        config = read_assignments(CONFIG)
        required = {
            "T2_TOUCHID_USER",
            "T2_TOUCHID_HOST",
            "T2_TOUCHID_INTERFACE",
            "T2_TOUCHID_PROJECT_DIR",
        }
        valid = required <= config.keys() and private_regular_file(CONFIG)
        checks.append(
            Check(
                "pass" if valid else "fail",
                "configuration",
                "complete and private" if valid else "missing, incomplete, or permissive",
            )
        )
    except PermissionError:
        checks.append(Check("warn", "configuration", "not readable; run as root"))
    except (OSError, UnicodeError):
        checks.append(Check("fail", "configuration", "missing or malformed"))

    try:
        state = read_assignments(STATE)
        valid_state = (
            state.get("T2_KEYBAG_SESSION", "").isdigit()
            and re.fullmatch(r"-?[0-9]+", state.get("T2_KEYBAG_HANDLE", ""))
            and re.fullmatch(r"-?[0-9]+", state.get("T2_KEYBAG_SPECIAL", ""))
            and private_regular_file(STATE)
        )
        checks.append(
            Check(
                "pass" if valid_state else "fail",
                "keybag-runtime-state",
                "valid and private" if valid_state else "invalid or permissive",
            )
        )
    except (OSError, UnicodeError):
        checks.append(Check("warn", "keybag-runtime-state", "not readable; run as root"))

    try:
        credential_ok = private_regular_file(CREDENTIAL) and CREDENTIAL.stat().st_size > 0
        checks.append(
            Check(
                "pass" if credential_ok else "fail",
                "encrypted-credential",
                "present and private" if credential_ok else "missing, empty, or permissive",
            )
        )
    except OSError:
        checks.append(Check("warn", "encrypted-credential", "not readable; run as root"))

    cached_port = 0
    try:
        cached_port = int(PORT_CACHE.read_text().strip())
        cache_ok = 49152 <= cached_port <= 65535 and private_regular_file(PORT_CACHE)
        checks.append(
            Check(
                "pass" if cache_ok else "fail",
                "port-cache",
                "valid and private" if cache_ok else "invalid or permissive",
            )
        )
    except (OSError, ValueError):
        checks.append(Check("warn", "port-cache", "not readable; run as root"))

    if config and cached_port:
        checks.append(network_check(config, cached_port))

    if os.geteuid() == 0:
        checks.append(watchdog_check())
    else:
        checks.append(Check("warn", "privileged-checks", "run with sudo for full report"))

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    checks = collect()
    if args.json:
        print(json.dumps({"checks": [asdict(check) for check in checks]}, indent=2))
    else:
        width = max(len(check.name) for check in checks)
        for check in checks:
            print(f"{check.status.upper():4}  {check.name:<{width}}  {check.detail}")
    return 1 if any(check.status == "fail" for check in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
