# SPDX-License-Identifier: GPL-2.0-only
import struct
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_identity_delete as delete
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for


class IdentityDeleteTests(unittest.TestCase):
    def setUp(self):
        one = codec.decode_user_catacomb(fixture(), 501)
        second_uuid = str(uuid.UUID(int=2))
        self.local = codec.decode_user_catacomb(
            one.add(identity_uuid=second_uuid, entity=1, name="Finger 2"), 501
        )
        self.live = live_for(self.local)

    def test_plan_removes_only_selected_identity_and_builds_exact_wire_record(self):
        value = delete.plan(self.local, self.live, slot=2)
        decoded = codec.decode_user_catacomb(value.archive, 501)
        self.assertEqual(len(decoded.identities), 1)
        self.assertEqual(decoded.identities[0], self.local.identities[0])
        self.assertEqual(value.identity_uuid, str(uuid.UUID(int=2)))
        self.assertEqual(
            value.request,
            uuid.UUID(int=2).bytes + struct.pack("<I", 501),
        )
        self.assertNotIn(value.identity_uuid, repr(value))
        self.assertNotIn(value.request.hex(), repr(value))

    def test_plan_rejects_stale_slot_or_last_identity(self):
        with self.assertRaises(delete.IdentityDeleteError):
            delete.plan(self.local, self.live, slot=3)
        one = codec.decode_user_catacomb(fixture(), 501)
        with self.assertRaisesRegex(delete.IdentityDeleteError, "zero-identity"):
            delete.plan(one, live_for(one), slot=1)

    def test_plan_target_rebuilds_the_same_journal_bound_plan(self):
        selected = delete.plan(self.local, self.live, slot=2)
        rebuilt = delete.plan_target(self.local, selected.identity_uuid)
        self.assertEqual(rebuilt, selected)

    def test_recovery_plan_rebinds_an_already_committed_survivor_archive(self):
        selected = delete.plan(self.local, self.live, slot=2)
        survivor = codec.decode_user_catacomb(selected.archive, 501)
        rebuilt = delete.recovery_plan(
            survivor,
            identity_uuid=selected.identity_uuid,
            entity=selected.entity,
            expected_survivor_sha256=selected.survivor_snapshot_sha256,
        )
        self.assertEqual(rebuilt.identity_uuid, selected.identity_uuid)
        self.assertEqual(rebuilt.entity, selected.entity)
        self.assertEqual(rebuilt.request, selected.request)
        rebound = codec.decode_user_catacomb(rebuilt.archive, 501)
        self.assertEqual(rebound.identities, survivor.identities)

    def test_secure_blob_binding_preserves_exact_survivors(self):
        value = delete.plan(self.local, self.live, slot=1)
        output = delete.bind_secure_blob(value, b"LTFC" + b"z" * 28)
        decoded = codec.decode_user_catacomb(bytes(output), 501)
        self.assertEqual(decoded.secure_data, b"LTFC" + b"z" * 28)
        self.assertEqual(decoded.identities, (self.local.identities[1],))

    def test_reconciliation_gate_rejects_live_mismatch(self):
        live = live_for(self.local)
        live["per_user_identity_records"].pop()
        with self.assertRaises(delete.IdentityDeleteError):
            delete.plan(self.local, live, slot=1)


if __name__ == "__main__":
    unittest.main()
