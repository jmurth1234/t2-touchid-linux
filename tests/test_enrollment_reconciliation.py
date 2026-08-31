import copy
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_journal as enrollment_journal
import t2_enrollment_reconciliation as reconciliation
import t2_mutation_journal as mutation_journal
from tests.test_mutation_journal import baseline
from tests.test_enrollment_persistence_journal import append_persistence


class EnrollmentReconciliationTests(unittest.TestCase):
    def create_terminal(
        self, directory: str, *, identity: bool
    ) -> tuple[Path, str, str | None]:
        value = baseline()
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = mutation_journal.create(path, "enroll", value)
        enrollment_journal.append_checked(
            path,
            operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": 501,
                "protocol_version": 2,
                "connection_generation": value["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            },
        )
        enrollment_journal.append_checked(
            path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
        )
        identity_uuid = str(uuid.UUID(int=8)) if identity else None
        if identity:
            enrollment_journal.append_checked(
                path,
                operation_id,
                "E2_TERMINAL_IDENTITY_OBSERVED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 1,
                    "envelope_type": enrollment_journal.SERVICE_ENROLLMENT_RESULT,
                    "event_version": 2,
                    "user_id": 501,
                    "identity_uuid": identity_uuid,
                },
            )
        else:
            enrollment_journal.append_checked(
                path,
                operation_id,
                "ENROLL_TERMINAL_FAILURE_OBSERVED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 1,
                    "envelope_type": enrollment_journal.SERVICE_STATUS,
                    "status": 67,
                },
            )
        return path, operation_id, identity_uuid

    def snapshots(self, *, success: bool) -> tuple[dict, dict]:
        value = baseline()
        identities = copy.deepcopy(value["identity_records"])
        if success:
            identities.append(
                {
                    "user_id": 501,
                    "uuid": str(uuid.UUID(int=8)),
                    "entity": 1,
                }
            )
        components = copy.deepcopy(value["host_components"])
        if success:
            for component in components:
                if component["name"] == "master.cat":
                    component["sha256"] = "1" * 64
                elif component["name"] == "user_000001f5.cat":
                    component["sha256"] = "2" * 64
        host = {
            "account_uuid": value["account_uuid"],
            "bag_uuid": value["bag_uuid"],
            "identity_records": identities,
            "host_components": components,
            "master_enrollment_count": value["master_enrollment_count"]
            + int(success),
        }
        per_user = [
            {"user_id": item["user_id"], "identity_uuid": item["uuid"]}
            for item in identities
        ]
        live = {
            "double_collection_equal": True,
            "connection_generation": value["connection_generation"],
            "apple_uid": 501,
            "biometric_protocol_version": 2,
            "per_user_identity_records": per_user,
            "global_identity_records": [
                {**item, "group_type": 1, "group_uuid": str(uuid.UUID(int=0))}
                for item in per_user
            ],
            "maximum_capacity": value["capacity"]["maximum"],
            "configured_user_free_capacity": value["capacity"]["maximum"]
            - len(per_user),
            "catacomb": {
                "present": True,
                "uuid": value["sep_catacomb"]["uuid"],
                "hash": "3" * 64 if success else value["sep_catacomb"]["hash"],
            },
        }
        return host, live

    def snapshot_digest(self, host, live):
        identity_records = sorted(
            (record["user_id"], record["identity_uuid"])
            for record in live["per_user_identity_records"]
        )
        components = {
            component["name"]: component for component in host["host_components"]
        }
        model = {
            "account_uuid": host["account_uuid"],
            "bag_uuid": host["bag_uuid"],
            "identity_records": identity_records,
            "catacomb": {
                "uuid": live["catacomb"]["uuid"],
                "hash": live["catacomb"]["hash"],
            },
            "host_components": [components[name] for name in sorted(components)],
            "master_enrollment_count": host["master_enrollment_count"],
            "mapping_generation": baseline()["mapping_generation"],
        }
        return hashlib.sha256(mutation_journal.canonical(model)).hexdigest()

    def persist(self, path, operation_id, host, live):
        return append_persistence(
            path, operation_id, self.snapshot_digest(host, live)
        )

    def test_terminal_identity_reconciles_only_after_durable_state_advances(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)

    def test_e4_requires_new_boot_and_exact_e3_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, operation_id, host, live)
            reconciled = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            evidence = {
                "linux_boot_uuid": str(uuid.UUID(int=20)),
                "connection_generation": str(uuid.UUID(int=21)),
                "bridge_boot_uuid": None,
                "protocol_version": 2,
                "mapping_generation": baseline()["mapping_generation"],
                "account_uuid": baseline()["account_uuid"],
                "bag_uuid": baseline()["bag_uuid"],
                "identity_uuid": identity_uuid,
                "snapshot_sha256": reconciled.reconciled_snapshot_sha256,
                "double_collection_equal": True,
                "host_sep_identity_equal": True,
                "bindings_preserved": True,
                "keybag_runtime_revalidated": True,
            }
            with self.assertRaisesRegex(
                enrollment_journal.EnrollmentJournalError, "boot"
            ):
                enrollment_journal.append_checked(
                    path,
                    operation_id,
                    "E4_POST_REBOOT_VERIFIED",
                    {
                        **evidence,
                        "linux_boot_uuid": baseline()["linux_boot_uuid"],
                    },
                )
            with self.assertRaisesRegex(
                enrollment_journal.EnrollmentJournalError, "differs"
            ):
                enrollment_journal.append_checked(
                    path,
                    operation_id,
                    "E4_POST_REBOOT_VERIFIED",
                    {**evidence, "snapshot_sha256": "f" * 64},
                )
            result = enrollment_journal.append_checked(
                path, operation_id, "E4_POST_REBOOT_VERIFIED", evidence
            )
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )

    def test_identity_reconciliation_requires_completed_persistence_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "not ready"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_e3_readback_must_match_journaled_persistence_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            append_persistence(path, operation_id, "f" * 64)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "snapshot"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_generic_failure_reconciles_only_when_every_snapshot_is_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=False
            )
            host, live = self.snapshots(success=False)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)

    def test_failure_with_new_identity_is_promoted_before_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=False
            )
            host, live = self.snapshots(success=True)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
            )
            records = mutation_journal.read(path)
        self.assertEqual(
            result.phase, enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY
        )
        self.assertEqual(records[-1]["milestone"], "E2_IDENTITY_READBACK_OBSERVED")

    def test_host_sep_divergence_and_mapping_change_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            host["identity_records"] = host["identity_records"][:-1]
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "diverge"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )
            host, live = self.snapshots(success=True)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "mapping"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation="f" * 64,
                )

    def test_existing_identity_and_component_metadata_must_be_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            host["identity_records"][0]["entity"] = 4
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "entity"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

            host, live = self.snapshots(success=True)
            host["host_components"][0]["mode"] = 0o600
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "metadata"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

            host, live = self.snapshots(success=True)
            live["catacomb"]["uuid"] = str(uuid.UUID(int=9))
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "Catacomb UUID"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )

    def test_identity_event_without_changed_persistence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            self.persist(path, _operation_id, host, live)
            before = baseline()
            for component in host["host_components"]:
                component["sha256"] = next(
                    item["sha256"]
                    for item in before["host_components"]
                    if item["name"] == component["name"]
                )
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "durable"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                )


if __name__ == "__main__":
    unittest.main()
