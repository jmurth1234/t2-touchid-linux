# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AKSToolTests(unittest.TestCase):
    def test_two_keybag_unlock_hardens_and_wipes_one_secret(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")

        self.assertIn("unlock-keybags-stdin", source)
        self.assertIn("setrlimit(RLIMIT_CORE", source)
        self.assertIn("prctl(PR_SET_DUMPABLE", source)
        self.assertIn("mlock(secret, size)", source)
        self.assertIn("mlock(request, exchange.request_length)", source)
        self.assertIn("explicit_bzero(secret, sizeof(secret))", source)
        self.assertIn("munlock(request, exchange.request_length)", source)
        self.assertIn("munlock(secret, sizeof(secret))", source)
        self.assertIn("static ssize_t read_secret_line", source)
        self.assertIn("if (errno == EINTR)", source)
        self.assertIn('getenv("PAM_TTY")', source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("S_ISCHR", source)

    def test_verify_password_acm_wire_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-aks-tool-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-D_FORTIFY_SOURCE=3",
                    str(ROOT / "tests/t2_aks_tool_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_verify_secret_kernel_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-aks-protocol-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tests/t2_aks_protocol_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_acm_kernel_lifecycle_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-acm-lifecycle-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tests/t2_acm_lifecycle_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
