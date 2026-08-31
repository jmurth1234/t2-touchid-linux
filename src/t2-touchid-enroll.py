#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stable command interface for journaled T2 Touch ID enrollment."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


LOCAL_BROKER = Path(__file__).resolve().with_name("t2-touchid-enroll-test.py")
INSTALLED_BROKER = Path("/usr/local/sbin/t2-touchid-enroll-test")
LOCAL_IDENTITIES = Path(__file__).resolve().with_name("t2-touchid-identities.py")
INSTALLED_IDENTITIES = Path("/usr/local/sbin/t2-touchid-identities")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="show redacted enrollment state")
    identities = commands.add_parser(
        "list", help="list truthful reconciled identity labels"
    )
    identities.add_argument(
        "--json", action="store_true", help="emit compact JSON"
    )

    preflight = commands.add_parser(
        "preflight", help="validate readiness without enrolling"
    )
    preflight.add_argument(
        "--acknowledge-password-fallback-tested", action="store_true"
    )

    enroll = commands.add_parser("start", help="enroll one new fingerprint")
    enroll.add_argument("--name", default="Linux enrolled finger")
    enroll.add_argument(
        "--acknowledge-password-fallback-tested", action="store_true"
    )
    enroll.add_argument(
        "--acknowledge-live-fingerprint-enrollment", action="store_true"
    )
    enroll.add_argument(
        "--acknowledge-local-catacomb-mutation", action="store_true"
    )

    commands.add_parser(
        "verify-post-reboot",
        help="verify a reconciled enrollment after reboot",
    )
    commands.add_parser(
        "recover-outcome",
        help="reconcile one outcome-unknown enrollment without replay",
    )
    commands.add_parser(
        "recover-local",
        help="resolve one journal-bound local Catacomb transaction",
    )
    observed = commands.add_parser(
        "recover-observed",
        help="persist one newly observed identity after explicit review",
    )
    observed.add_argument("--name", default="Linux enrolled finger")
    observed.add_argument(
        "--acknowledge-observed-identity-recovery", action="store_true"
    )
    observed.add_argument(
        "--acknowledge-local-catacomb-mutation", action="store_true"
    )
    return value


def broker_arguments(args: argparse.Namespace) -> list[str]:
    if args.command == "status":
        return ["--status-only"]
    if args.command == "preflight":
        result = ["--preflight-only"]
        if args.acknowledge_password_fallback_tested:
            result.append("--acknowledge-password-fallback-tested")
        return result
    if args.command == "start":
        result = ["--identity-name", args.name]
        for enabled, option in (
            (
                args.acknowledge_password_fallback_tested,
                "--acknowledge-password-fallback-tested",
            ),
            (
                args.acknowledge_live_fingerprint_enrollment,
                "--acknowledge-live-fingerprint-enrollment",
            ),
            (
                args.acknowledge_local_catacomb_mutation,
                "--acknowledge-local-catacomb-mutation",
            ),
        ):
            if enabled:
                result.append(option)
        return result
    if args.command == "verify-post-reboot":
        return ["--verify-post-reboot"]
    if args.command == "recover-outcome":
        return ["--reconcile-outcome-unknown"]
    if args.command == "recover-local":
        return ["--recover-local-transaction"]
    if args.command == "recover-observed":
        result = ["--recover-observed-identity", "--identity-name", args.name]
        if args.acknowledge_observed_identity_recovery:
            result.append("--acknowledge-observed-identity-recovery")
        if args.acknowledge_local_catacomb_mutation:
            result.append("--acknowledge-local-catacomb-mutation")
        return result
    raise ValueError("unsupported enrollment command")


def command_path(local: Path, installed: Path) -> Path:
    selected = local if local.is_file() else installed
    if not selected.is_file():
        raise FileNotFoundError(f"{installed.name} is not installed")
    return selected


def command_invocation(args: argparse.Namespace) -> tuple[Path, list[str]]:
    if args.command == "list":
        arguments = ["--json"] if args.json else []
        return command_path(LOCAL_IDENTITIES, INSTALLED_IDENTITIES), arguments
    return command_path(LOCAL_BROKER, INSTALLED_BROKER), broker_arguments(args)


def main() -> int:
    args = parser().parse_args()
    try:
        selected, translated = command_invocation(args)
    except (FileNotFoundError, ValueError) as error:
        print(f"t2-touchid-enroll: {error}", file=sys.stderr)
        return 1
    os.execv(sys.executable, [sys.executable, str(selected), *translated])
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
