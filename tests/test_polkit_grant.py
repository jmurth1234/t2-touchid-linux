# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_polkit_grant as collector
import t2_user_policy as policy


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def stat_record(pid: int, start: int, name: str = "caller (worker)") -> bytes:
    fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 30
    return f"{pid} ({name}) {' '.join(fields)}\n".encode()


class FakeRunner:
    def __init__(self, returncode=0, mutate=None):
        self.returncode = returncode
        self.mutate = mutate
        self.command = None
        self.timeout = None

    def __call__(self, command, timeout):
        self.command = command
        self.timeout = timeout
        if self.mutate is not None:
            self.mutate()
        return subprocess.CompletedProcess(command, self.returncode, b"", b"")


class PolkitGrantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proc = Path(self.temp.name)
        self.pid = 1234
        self.uid = 1000
        self.process = self.proc / str(self.pid)
        self.process.mkdir()
        (self.process / "stat").write_bytes(stat_record(self.pid, 777))
        (self.process / "status").write_text(
            "Name:\tcaller\nUid:\t1000\t1000\t1000\t1000\n",
            encoding="ascii",
        )

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, runner=None, **changes):
        values = {
            "caller_pid": self.pid,
            "peer_uid": self.uid,
            "account_generation": "b" * 64,
            "target_linux_uid": self.uid,
            "action": "org.t2linux.touchid.enroll",
            "mapping_generation": "a" * 64,
            "operation_id": identifier(10),
            "linux_boot_uuid": identifier(11),
            "runtime_generation": identifier(12),
            "allow_user_interaction": True,
            "proc_root": self.proc,
            "pkcheck": Path("/test/pkcheck"),
            "runner": runner or FakeRunner(),
            "clock": lambda: 10_000,
            "grant_lifetime_ns": 5_000,
            "timeout_seconds": 30,
        }
        values.update(changes)
        return collector.collect(**values)

    def test_uses_exact_race_resistant_subject_and_bound_details(self):
        runner = FakeRunner()
        result = self.collect(runner)
        self.assertEqual(result.outcome, "authorized")
        self.assertTrue(result.grant.authorized)
        self.assertEqual(result.grant.issued_monotonic_ns, 10_000)
        self.assertEqual(result.grant.expires_monotonic_ns, 15_000)
        self.assertEqual(result.grant.runtime_generation, identifier(12))
        self.assertEqual(runner.timeout, 30)
        self.assertEqual(
            runner.command,
            [
                "/test/pkcheck",
                "--action-id",
                "org.t2linux.touchid.enroll",
                "--process",
                "1234,777,1000",
                "--detail",
                "t2.operation-id",
                identifier(10),
                "--detail",
                "t2.target-linux-uid",
                "1000",
                "--detail",
                "t2.mapping-generation",
                "a" * 64,
                "--detail",
                "t2.account-generation",
                "b" * 64,
                "--detail",
                "t2.runtime-generation",
                identifier(12),
                "--allow-user-interaction",
            ],
        )
        rendered = str(result.redacted())
        self.assertNotIn(identifier(10), rendered)
        self.assertNotIn("1000", rendered)

    def test_denial_no_agent_and_dismissal_are_typed_non_grants(self):
        for returncode, outcome in (
            (1, "denied"),
            (2, "interaction-unavailable"),
            (3, "dismissed"),
        ):
            with self.subTest(returncode=returncode):
                result = self.collect(FakeRunner(returncode))
                self.assertEqual(result.outcome, outcome)
                self.assertFalse(result.grant.authorized)

    def test_errors_and_timeouts_never_create_a_grant(self):
        for returncode in (4, 126, 127, -9):
            with self.subTest(returncode=returncode):
                with self.assertRaises(collector.PolkitGrantError):
                    self.collect(FakeRunner(returncode))

        def timeout(command, seconds):
            raise subprocess.TimeoutExpired(command, seconds)

        with self.assertRaisesRegex(collector.PolkitGrantError, "timed out"):
            self.collect(timeout)

    def test_pid_reuse_or_uid_change_during_check_fails_closed(self):
        def replace_start():
            (self.process / "stat").write_bytes(stat_record(self.pid, 778))

        with self.assertRaisesRegex(collector.PolkitGrantError, "identity changed"):
            self.collect(FakeRunner(mutate=replace_start))

        (self.process / "stat").write_bytes(stat_record(self.pid, 777))

        def replace_uid():
            (self.process / "status").write_text(
                "Uid:\t1001\t1001\t1001\t1001\n", encoding="ascii"
            )

        with self.assertRaisesRegex(collector.PolkitGrantError, "peer UID"):
            self.collect(FakeRunner(mutate=replace_uid))

    def test_setuid_process_and_malformed_proc_records_are_rejected(self):
        (self.process / "status").write_text(
            "Uid:\t1000\t0\t0\t0\n", encoding="ascii"
        )
        with self.assertRaisesRegex(collector.PolkitGrantError, "peer UID"):
            self.collect()
        (self.process / "status").write_text(
            "Uid:\t1000\t1000\t1000\t1000\n", encoding="ascii"
        )
        for malformed in (
            b"not proc stat\n",
            stat_record(self.pid + 1, 777),
            stat_record(self.pid, 0),
        ):
            with self.subTest(record=malformed[:20]):
                (self.process / "stat").write_bytes(malformed)
                with self.assertRaises(collector.PolkitGrantError):
                    self.collect()

    def test_rejects_cross_user_unknown_action_and_unbounded_inputs(self):
        cases = (
            {"target_linux_uid": 1001},
            {"action": "org.t2linux.touchid.raw-sep"},
            {"allow_user_interaction": 1},
            {"grant_lifetime_ns": policy.MAX_POLICY_LIFETIME_NS + 1},
            {"timeout_seconds": 301},
            {"operation_id": "bad"},
            {"runtime_generation": "bad"},
            {"account_generation": "bad"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(collector.PolkitGrantError):
                    self.collect(**changes)

    def test_interaction_flag_is_omitted_for_noninteractive_check(self):
        runner = FakeRunner()
        self.collect(runner, allow_user_interaction=False)
        self.assertNotIn("--allow-user-interaction", runner.command)

    def test_installed_action_manifest_matches_the_compiled_allowlist(self):
        root = ET.parse(
            SOURCE.parent / "polkit" / "org.t2linux.touchid.policy"
        ).getroot()
        actions = {item.attrib.get("id") for item in root.findall("action")}
        self.assertEqual(actions, collector.ACTION_IDS)
        for item in root.findall("action"):
            defaults = item.find("defaults")
            self.assertIsNotNone(defaults)
            self.assertEqual(defaults.findtext("allow_any"), "no")
            self.assertEqual(defaults.findtext("allow_inactive"), "no")
            self.assertIn(defaults.findtext("allow_active"), {"yes", "auth_self"})

    def test_install_and_uninstall_own_the_action_manifest(self):
        install = (SOURCE.parent / "install.sh").read_text(encoding="utf-8")
        uninstall = (SOURCE.parent / "uninstall.sh").read_text(encoding="utf-8")
        target = "/usr/share/polkit-1/actions/org.t2linux.touchid.policy"
        self.assertIn("polkit/org.t2linux.touchid.policy", install)
        self.assertIn(target, install)
        self.assertIn(target, uninstall)


if __name__ == "__main__":
    unittest.main()
