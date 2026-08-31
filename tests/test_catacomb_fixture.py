import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_fixture as checker
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture


class CatacombFixtureTests(unittest.TestCase):
    def components(self) -> dict[str, bytes]:
        return {
            "master.cat": master_fixture(),
            "user_000001f5.cat": fixture(),
            "biolockout.cat": biolockout_fixture(),
        }

    def archive(self, directory: str, *, duplicate: bool = False) -> Path:
        path = Path(directory) / "private.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data in self.components().items():
                for occurrence in range(2 if duplicate and name == "master.cat" else 1):
                    info = tarfile.TarInfo(f"capture/{occurrence}/{name}")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        path.chmod(0o600)
        return path

    def test_realistic_archive_round_trip_is_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            result = checker.check_archive(self.archive(directory), 501)
        self.assertEqual(result["identity_count"], 1)
        self.assertTrue(result["semantic_round_trip_equal"])
        self.assertTrue(result["independent_oracle_readback"])
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("uuid", result)

    def test_component_set_is_bound_to_selected_user(self):
        with self.assertRaises(checker.FixtureCheckError):
            checker.check_components(self.components(), 502)

    def test_duplicate_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(checker.FixtureCheckError):
                checker.check_archive(self.archive(directory, duplicate=True), 501)

    def test_archive_must_be_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory)
            path.chmod(0o644)
            with self.assertRaises(checker.FixtureCheckError):
                checker.check_archive(path, 501)

    def test_parent_traversal_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for name, data in self.components().items():
                    info = tarfile.TarInfo(f"../{name}")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            path.chmod(0o600)
            with self.assertRaises(checker.FixtureCheckError):
                checker.check_archive(path, 501)


if __name__ == "__main__":
    unittest.main()
