# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from dataclasses import replace
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_deletion_runtime as runtime


class FprintDeletionRuntimeTests(unittest.TestCase):
    def test_exact_reconciled_completion_is_accepted(self):
        value = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )
        self.assertEqual(value.finger_name, "left-thumb")
        self.assertTrue(value.reconciled)

    def test_invalid_name_or_incomplete_proof_is_rejected(self):
        valid = runtime.DeletionCompletion(
            "left-thumb", True, True, True, True
        )
        candidates = (
            ("any", True, True, True, True),
            ("left-thumb", False, True, True, True),
            ("left-thumb", True, False, True, True),
            ("left-thumb", True, True, False, True),
            ("left-thumb", True, True, True, False),
            ("left-thumb", 1, True, True, True),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(
                runtime.FprintDeletionRuntimeError
            ):
                runtime.DeletionCompletion(*candidate)
        with self.assertRaises(runtime.FprintDeletionRuntimeError):
            replace(valid, post_reboot_pending=False)


if __name__ == "__main__":
    unittest.main()
