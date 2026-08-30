# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AKSToolTests(unittest.TestCase):
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
                    str(ROOT / "tests/t2_aks_tool_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
