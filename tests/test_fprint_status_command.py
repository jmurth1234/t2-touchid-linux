# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))
import t2_fprint_projection as projection


SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_fprint_status_command",
    SOURCE / "t2-touchid-fprint-status.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def inventory(names=("Finger 1", "Linux enrolled finger")):
    return {
        "schema_version": 1,
        "identity_count": len(names),
        "identities": [
            {"slot": slot, "name": name, "live": True}
            for slot, name in enumerate(names, 1)
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


class FprintStatusCommandTests(unittest.TestCase):
    def test_collect_projects_only_fresh_identity_collector_output(self):
        identities = mock.Mock()
        identities.collect.return_value = inventory()
        with mock.patch.object(
            MODULE, "_load_identities", return_value=identities
        ):
            result = MODULE.collect()
        identities.collect.assert_called_once_with()
        self.assertFalse(result.complete)
        self.assertEqual(result.unassigned_identity_count, 2)

    def test_main_prints_redacted_status_and_rejects_arguments(self):
        expected = projection.project(inventory())
        output = io.StringIO()
        with (
            mock.patch.object(MODULE, "collect", return_value=expected),
            mock.patch.object(MODULE.sys, "argv", ["t2-touchid-fprint-status"]),
            redirect_stdout(output),
        ):
            self.assertEqual(MODULE.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), expected.public())

        error = io.StringIO()
        with (
            mock.patch.object(
                MODULE.sys,
                "argv",
                ["t2-touchid-fprint-status", "private"],
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 2)
        self.assertNotIn("private", error.getvalue())

    def test_collection_failure_is_generic(self):
        error = io.StringIO()
        with (
            mock.patch.object(
                MODULE,
                "collect",
                side_effect=MODULE.FprintStatusError("private"),
            ),
            mock.patch.object(MODULE.sys, "argv", ["t2-touchid-fprint-status"]),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 1)
        self.assertEqual(error.getvalue(), "t2-touchid-fprint-status: unavailable\n")

    def test_real_identity_collector_loads_with_registered_metadata(self):
        name = "t2_touchid_fprint_status_identities"
        previous = sys.modules.pop(name, None)
        try:
            loaded = MODULE._load_identities()
            self.assertIs(sys.modules[name], loaded)
        finally:
            sys.modules.pop(name, None)
            if previous is not None:
                sys.modules[name] = previous

    def test_installer_owns_status_command(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("src/t2-touchid-fprint-status.py", install)
        self.assertIn("t2-touchid-fprint-status", uninstall)


if __name__ == "__main__":
    unittest.main()
