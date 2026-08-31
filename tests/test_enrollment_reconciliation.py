import copy
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

    def attestation(self) -> reconciliation.PersistenceAttestation:
        return reconciliation.PersistenceAttestation(True, True, True, True)

    def test_terminal_identity_reconciles_only_after_durable_state_advances(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            result = reconciliation.append_reconciled(
                path,
                operation_id,
                host=host,
                live=live,
                mapping_generation=baseline()["mapping_generation"],
                persistence=self.attestation(),
            )
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)

    def test_identity_reconciliation_requires_complete_persistence_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "attestation"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                    persistence=reconciliation.PersistenceAttestation(
                        True, False, True, True
                    ),
                )

            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "attestation"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                    persistence=reconciliation.PersistenceAttestation(
                        1, True, True, True
                    ),
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

    def test_failure_with_new_identity_is_promoted_before_e3(self):
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
                persistence=self.attestation(),
            )
            records = mutation_journal.read(path)
        self.assertEqual(result.phase, enrollment_journal.EnrollmentPhase.RECONCILED)
        self.assertEqual(records[-2]["milestone"], "E2_IDENTITY_READBACK_OBSERVED")

    def test_host_sep_divergence_and_mapping_change_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            host["identity_records"] = host["identity_records"][:-1]
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "diverge"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                    persistence=self.attestation(),
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
                    persistence=self.attestation(),
                )

    def test_existing_identity_and_component_metadata_must_be_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
            host["identity_records"][0]["entity"] = 4
            with self.assertRaisesRegex(
                reconciliation.EnrollmentReconciliationError, "entity"
            ):
                reconciliation.classify(
                    enrollment_journal.read(path),
                    host=host,
                    live=live,
                    mapping_generation=baseline()["mapping_generation"],
                    persistence=self.attestation(),
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
                    persistence=self.attestation(),
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
                    persistence=self.attestation(),
                )

    def test_identity_event_without_changed_persistence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id, _identity_uuid = self.create_terminal(
                directory, identity=True
            )
            host, live = self.snapshots(success=True)
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
                    persistence=self.attestation(),
                )


if __name__ == "__main__":
    unittest.main()
