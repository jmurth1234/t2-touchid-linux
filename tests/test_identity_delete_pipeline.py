# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_catacomb_store
import t2_identity_delete_pipeline as pipeline
import t2_identity_delete_persistence as persistence
from tests.test_catacomb_codec import fixture
from tests.test_identity_delete import IdentityDeleteTests


class Lease:
    connection_generation = str(uuid.UUID(int=32))


class IdentityDeletePipelineTests(unittest.TestCase):
    def test_composes_transport_and_independent_readback(self):
        source = IdentityDeleteTests()
        source.setUp()
        plan = pipeline.t2_identity_delete.plan(
            source.local, source.live, slot=2
        )
        store = object.__new__(t2_catacomb_store.CatacombStore)
        store.read_committed_components = mock.Mock(
            return_value={"user_000001f5.cat": fixture()}
        )
        history = SimpleNamespace(baseline={"stable": True})
        attestation = SimpleNamespace(
            connection_generation=Lease.connection_generation,
            snapshot_sha256="a" * 64,
            identity_count=1,
        )
        final = mock.sentinel.final
        transport = mock.sentinel.transport

        def run(*_arguments, **keywords):
            observed = keywords["readback"]()
            self.assertEqual(
                observed,
                persistence.DeleteReadbackAttestation(
                    Lease.connection_generation, "a" * 64, 1
                ),
            )
            self.assertIs(keywords["transport"], transport)
            return final

        with mock.patch.object(
            pipeline.t2_catacomb_bridge,
            "CatacombBridgeTransport",
            return_value=transport,
        ), mock.patch.object(
            pipeline.t2_bridge_inventory,
            "collect_stable_private_inventory",
            return_value={"live": True},
        ), mock.patch.object(
            pipeline.delete_journal, "read", return_value=history
        ), mock.patch.object(
            pipeline.t2_enrollment_finalizer,
            "read_local_host_snapshot",
            return_value={"host": True},
        ), mock.patch.object(
            pipeline.t2_catacomb_codec,
            "decode_user_catacomb",
            return_value=source.local,
        ), mock.patch.object(
            pipeline.t2_identity_delete_reconciliation,
            "classify",
            return_value=attestation,
        ) as classify, mock.patch.object(
            pipeline.t2_identity_delete_persistence, "run", side_effect=run
        ):
            value = pipeline.persist(
                lease=Lease(),
                store=store,
                journal_path=Path("/private/delete.jsonl"),
                operation_id=str(uuid.UUID(int=30)),
                plan=plan,
                apple_uid=501,
                mapping_generation="b" * 64,
            )
        self.assertIs(value, final)
        classify.assert_called_once()

    def test_rejects_untyped_or_rebound_input_before_transport(self):
        source = IdentityDeleteTests()
        source.setUp()
        plan = pipeline.t2_identity_delete.plan(
            source.local, source.live, slot=2
        )
        for store, apple_uid in ((object(), 501), (object.__new__(t2_catacomb_store.CatacombStore), 502)):
            with self.subTest(apple_uid=apple_uid), self.assertRaises(
                pipeline.IdentityDeletePipelineError
            ):
                pipeline.persist(
                    lease=Lease(),
                    store=store,
                    journal_path=Path("/private/delete.jsonl"),
                    operation_id=str(uuid.UUID(int=30)),
                    plan=plan,
                    apple_uid=apple_uid,
                    mapping_generation="b" * 64,
                )


if __name__ == "__main__":
    unittest.main()
