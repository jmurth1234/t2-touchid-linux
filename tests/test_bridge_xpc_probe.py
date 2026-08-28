#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free fail-closed parser tests for BridgeXPC replies."""

import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/bridge-xpc-probe.py"
SPEC = importlib.util.spec_from_file_location("bridge_xpc_probe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReplyTests(unittest.TestCase):
    def test_malformed_command_replies_are_invalid(self):
        for value in (None, {}, [], ["zero"], b"bytes"):
            with self.subTest(value=value):
                self.assertFalse(MODULE.summarize_command_reply(value)["valid"])

    def test_status_and_output_are_summarized_without_payload(self):
        summary = MODULE.summarize_command_reply([0, b"secret payload"])
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["output_length"], 14)
        self.assertNotIn("output", summary)


if __name__ == "__main__":
    unittest.main()
