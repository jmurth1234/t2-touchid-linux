# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_linux_account as account


class LocalAccountTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.uid = os.getuid() if os.getuid() != 0 else 1000
        self.gid = os.getgid() if os.getuid() != 0 else 1000
        self.name = "testuser"
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        if os.getuid() == 0:
            os.chown(self.home, self.uid, self.gid)
        self.passwd = self.root / "passwd"
        self.shadow = self.root / "shadow"
        self._write_passwd()
        self._write_shadow()
        self.owner = mock.patch.object(account, "ROOT_UID", os.getuid())
        self.owner.start()

    def tearDown(self):
        self.owner.stop()
        self.temporary.cleanup()

    def _write_passwd(self, *, prefix="root:x:0:0:root:/root:/bin/bash\n"):
        self.passwd.write_text(
            prefix
            + f"{self.name}:x:{self.uid}:{self.gid}:Test User:"
            + f"{self.home}:/bin/bash\n",
            encoding="utf-8",
        )
        self.passwd.chmod(0o644)

    def _write_shadow(self, password="$6$salt$protected"):
        self.shadow.write_text(
            "root:*:1:0:99999:7:::\n"
            + f"{self.name}:{password}:1:0:99999:7:::\n",
            encoding="utf-8",
        )
        self.shadow.chmod(0o600)

    def _resolver(self, uid):
        if uid != self.uid:
            raise KeyError(uid)
        return SimpleNamespace(
            pw_name=self.name,
            pw_passwd="x",
            pw_uid=self.uid,
            pw_gid=self.gid,
            pw_gecos="Test User",
            pw_dir=str(self.home),
            pw_shell="/bin/bash",
        )

    def collect(self, *, resolver=None):
        return account.collect(
            self.uid,
            passwd_path=self.passwd,
            shadow_path=self.shadow,
            resolver=resolver or self._resolver,
        )

    def test_stable_generation_and_redacted_output(self):
        first = self.collect()
        second = self.collect()
        self.assertEqual(first, second)
        self.assertEqual(len(first.generation), 64)
        self.assertEqual(
            first.redacted(),
            {
                "schema_version": 1,
                "source": "local-files-v1",
                "protected_password_record": True,
                "home_object_bound": True,
                "identifiers_redacted": True,
            },
        )
        rendered = repr(first) + str(first.redacted())
        self.assertNotIn(self.name, rendered)
        self.assertNotIn("$6$salt$protected", rendered)
        self.assertNotIn(str(self.uid), rendered)

    def test_target_password_change_changes_generation(self):
        before = self.collect().generation
        self._write_shadow("$6$different$protected")
        after = self.collect().generation
        self.assertNotEqual(before, after)

    def test_any_passwd_database_replacement_changes_epoch(self):
        before = self.collect().generation
        self._write_passwd(prefix="other:x:42:42::/var/empty:/bin/false\n")
        after = self.collect().generation
        self.assertNotEqual(before, after)

    def test_replacing_home_object_changes_generation(self):
        before = self.collect().generation
        self.home.rmdir()
        self.home.mkdir(mode=0o700)
        if os.getuid() == 0:
            os.chown(self.home, self.uid, self.gid)
        after = self.collect().generation
        self.assertNotEqual(before, after)

    def test_duplicate_uid_and_nss_disagreement_fail_closed(self):
        self._write_passwd(
            prefix=(
                f"other:x:{self.uid}:{self.gid}::/var/empty:/bin/false\n"
            )
        )
        with self.assertRaisesRegex(account.LinuxAccountError, "unique"):
            self.collect()
        self._write_passwd()
        wrong = SimpleNamespace(**self._resolver(self.uid).__dict__)
        wrong.pw_dir = "/different"
        with self.assertRaisesRegex(account.LinuxAccountError, "disagree"):
            self.collect(resolver=lambda uid: wrong)

    def test_locked_or_public_shadow_record_is_rejected(self):
        self._write_shadow("!")
        with self.assertRaisesRegex(account.LinuxAccountError, "usable"):
            self.collect()
        self._write_shadow()
        self.shadow.chmod(0o644)
        with self.assertRaisesRegex(account.LinuxAccountError, "metadata"):
            self.collect()

    def test_symlinked_database_and_unsafe_home_owner_are_rejected(self):
        original = self.passwd
        link = self.root / "passwd-link"
        link.symlink_to(original)
        with self.assertRaises(account.LinuxAccountError):
            account.collect(
                self.uid,
                passwd_path=link,
                shadow_path=self.shadow,
                resolver=self._resolver,
            )
        if os.getuid() != 0:
            real_fstat = os.fstat
            with mock.patch.object(account.os, "fstat", wraps=os.fstat) as wrapped:
                # Ownership is covered by a focused unit-level replacement;
                # descriptor safety itself remains exercised above.
                def unsafe_home(descriptor):
                    info = real_fstat(descriptor)
                    if stat.S_ISDIR(info.st_mode):
                        return SimpleNamespace(
                            st_mode=info.st_mode,
                            st_uid=self.uid + 1,
                            st_gid=info.st_gid,
                            st_dev=info.st_dev,
                            st_ino=info.st_ino,
                            st_nlink=info.st_nlink,
                            st_size=info.st_size,
                            st_mtime_ns=info.st_mtime_ns,
                            st_ctime_ns=info.st_ctime_ns,
                        )
                    return info

                wrapped.side_effect = unsafe_home
                with self.assertRaisesRegex(account.LinuxAccountError, "ownership"):
                    self.collect()

    def test_mid_collection_account_change_is_rejected(self):
        calls = 0

        def changing_resolver(uid):
            nonlocal calls
            calls += 1
            result = self._resolver(uid)
            if calls == 1:
                self._write_shadow("$6$changed$during-collection")
            return result

        with self.assertRaisesRegex(account.LinuxAccountError, "changed"):
            self.collect(resolver=changing_resolver)

    def test_invalid_uid_and_missing_local_record_are_rejected(self):
        for uid in (0, True, -1, (1 << 32) - 1):
            with self.subTest(uid=uid):
                with self.assertRaises(account.LinuxAccountError):
                    account.collect(
                        uid,
                        passwd_path=self.passwd,
                        shadow_path=self.shadow,
                        resolver=self._resolver,
                    )
        self._write_passwd(prefix="")
        self.passwd.write_text("other:x:42:42::/var/empty:/bin/false\n")
        self.passwd.chmod(0o644)
        with self.assertRaisesRegex(account.LinuxAccountError, "unique"):
            self.collect()
if __name__ == "__main__":
    unittest.main()
