# SPDX-License-Identifier: GPL-2.0-only
import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_local as local
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture


def write_archive(path: Path) -> None:
    components = {
        "master.cat": master_fixture(),
        "biolockout.cat": biolockout_fixture(),
        "user_000001f5.cat": fixture(),
    }
    metadata = b"".join(
        f"-rw-r--r-- root:wheel {len(data)} 1 /Library/Catacomb/TEST/{name}\n".encode()
        for name, data in components.items()
    )
    with tarfile.open(path, "w:gz") as archive:
        for name, data in {**components, "source-stat.txt": metadata}.items():
            info = tarfile.TarInfo(f"capture/{name}")
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))


class LocalCatacombTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.parent = Path(self.temp.name) / "private"
        self.parent.mkdir(mode=0o700)
        self.archive = self.parent / "backup.tar.gz"
        write_archive(self.archive)
        self.archive.chmod(0o600)
        self.root = self.parent / "catacomb"

    def tearDown(self):
        self.temp.cleanup()

    def test_provision_is_private_validated_and_idempotent(self):
        host, store = local.provision_from_backup(self.archive, self.root, 501)
        self.assertEqual(len(host["identity_records"]), 1)
        first = store.read_committed_components()
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertTrue(
            all((self.root / name).stat().st_mode & 0o777 == 0o600 for name in first)
        )
        second_host, second_store = local.provision_from_backup(
            self.archive, self.root, 501
        )
        self.assertEqual(second_host["archive_sha256"], host["archive_sha256"])
        self.assertEqual(second_store.read_committed_components(), first)

    def test_existing_store_is_never_replaced_on_mismatch(self):
        _host, store = local.provision_from_backup(self.archive, self.root, 501)
        target = self.root / "master.cat"
        original = target.read_bytes()
        target.write_bytes(original + b"x")
        target.chmod(0o600)
        with self.assertRaises(local.LocalCatacombError):
            local.provision_from_backup(self.archive, self.root, 501)
        self.assertEqual(target.read_bytes(), original + b"x")

    def test_duplicate_component_archive_is_rejected_without_store(self):
        duplicate = self.parent / "duplicate.tar.gz"
        with tarfile.open(self.archive, "r:gz") as source, tarfile.open(
            duplicate, "w:gz"
        ) as output:
            for member in source.getmembers():
                stream = source.extractfile(member) if member.isfile() else None
                data = stream.read() if stream is not None else b""
                output.addfile(member, io.BytesIO(data) if member.isfile() else None)
                if member.name.endswith("master.cat"):
                    output.addfile(member, io.BytesIO(data))
        duplicate.chmod(0o600)
        with self.assertRaises(local.LocalCatacombError):
            local.provision_from_backup(duplicate, self.root, 501)
        self.assertFalse(os.path.lexists(self.root))


if __name__ == "__main__":
    unittest.main()
