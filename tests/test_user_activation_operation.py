# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_activation_journal as journal
import t2_user_activation_operation as operation
import t2_user_mapping as mapping
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mapped() -> tuple[mapping.UserMappingSet, mapping.UserMapping]:
    document = {
        "schema_version": 1,
        "mappings": [
            {
                "linux_uid": 1000,
                "linux_account_generation": "a" * 64,
                "apple_uid": 501,
                "account_uuid": identifier(1),
                "bag_uuid": identifier(2),
                "keybag_path": "/var/lib/t2-touchid/users/1000/user.kb",
                "keybag_sha256": "b" * 64,
                "unlock_mode": "password-on-demand",
                "capabilities": ["enroll", "verify"],
                "enabled": True,
            }
        ],
    }
    result = mapping.parse(json.dumps(document, sort_keys=True).encode())
    return result, result.mappings[0]


def persistent() -> readiness.PersistentEvidence:
    return readiness.PersistentEvidence(
        "a" * 64,
        "b" * 64,
        501,
        identifier(1),
        identifier(2),
        True,
    )


ABSENT = readiness.AliasEvidence(False, None, None, None)
LOCKED = readiness.AliasEvidence(True, -501, identifier(2), readiness.DEVICE_LOCKED)
READY = readiness.AliasEvidence(True, -501, identifier(2), 0)
UNSET = object()


class FakeTransport:
    runtime_generation = identifier(20)

    def __init__(
        self,
        observations,
        *,
        load=7,
        loaded_bag_uuid=identifier(2),
        bind=0,
        unlock=0,
    ):
        self.observations = iter(observations)
        self.load_result = load
        self.loaded_bag_uuid = loaded_bag_uuid
        self.bind_result = bind
        self.unlock_result = unlock
        self.calls = []
        self.password_seen = None

    @staticmethod
    def _result(value):
        if isinstance(value, BaseException):
            raise value
        return value

    def observe_alias(self, special_alias):
        self.calls.append(("observe", special_alias))
        return self._result(next(self.observations))

    def load_keybag(self, path):
        self.calls.append(("load", path))
        return self._result(self.load_result)

    def bag_uuid(self, handle):
        self.calls.append(("bag-uuid", handle))
        return self._result(self.loaded_bag_uuid)

    def bind_alias(self, handle, special_alias):
        self.calls.append(("bind", handle, special_alias))
        return self._result(self.bind_result)

    def unlock_alias(self, special_alias, password):
        self.calls.append(("unlock", special_alias))
        self.password_seen = bytes(password)
        return self._result(self.unlock_result)


class UserActivationOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "activation.jsonl"
        self.mapping_set, self.selected = mapped()

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, transport, password=UNSET):
        password = bytearray(b"test-password") if password is UNSET else password
        try:
            result = operation.run(
                self.path,
                self.mapping_set,
                self.selected,
                "verify",
                persistent(),
                transport,
                password,
                linux_boot_uuid=identifier(21),
            )
            return result, password
        except BaseException as error:
            error.wiped_password = password
            raise

    def test_already_ready_performs_no_mutation_or_journal(self):
        transport = FakeTransport([READY])
        result, password = self.invoke(transport)
        self.assertEqual(result.outcome, "already-ready")
        self.assertFalse(result.mutation_performed)
        self.assertEqual(password, bytearray(len(password)))
        self.assertEqual(transport.calls, [("observe", -501)])
        self.assertFalse(self.path.exists())

    def test_already_ready_needs_no_password(self):
        transport = FakeTransport([READY])
        result, password = self.invoke(transport, password=None)
        self.assertEqual(result.outcome, "already-ready")
        self.assertIsNone(password)
        self.assertFalse(self.path.exists())

    def test_actionable_state_refuses_to_mutate_without_password(self):
        transport = FakeTransport([ABSENT])
        with self.assertRaisesRegex(
            operation.UserActivationOperationError, "requires a nonempty password"
        ):
            self.invoke(transport, password=None)
        self.assertEqual(transport.calls, [("observe", -501)])
        self.assertFalse(self.path.exists())

    def test_absent_alias_loads_binds_unlocks_and_reconciles(self):
        transport = FakeTransport([ABSENT, LOCKED, READY])
        result, password = self.invoke(transport)
        self.assertEqual(result.outcome, "ready")
        self.assertTrue(result.mutation_performed)
        self.assertFalse(result.reconciliation_required)
        self.assertEqual(transport.password_seen, b"test-password")
        self.assertEqual(password, bytearray(len(password)))
        self.assertEqual(journal.read(self.path).phase, journal.UserActivationPhase.READY)
        self.assertEqual(
            [call[0] for call in transport.calls],
            ["observe", "load", "bag-uuid", "bind", "observe", "unlock", "observe"],
        )

    def test_bind_error_with_ready_readback_is_success_without_unlock(self):
        transport = FakeTransport([ABSENT, READY], bind=OSError("lost reply"))
        result, password = self.invoke(transport)
        self.assertEqual(result.outcome, "ready")
        self.assertNotIn("unlock", [call[0] for call in transport.calls])
        self.assertEqual(password, bytearray(len(password)))
        self.assertEqual(journal.read(self.path).phase, journal.UserActivationPhase.READY)

    def test_unlock_error_with_ready_readback_is_observed_success(self):
        transport = FakeTransport([LOCKED, READY], unlock=OSError("lost reply"))
        result, password = self.invoke(transport)
        self.assertEqual(result.outcome, "ready")
        self.assertTrue(result.mutation_performed)
        self.assertEqual(password, bytearray(len(password)))
        self.assertEqual(journal.read(self.path).phase, journal.UserActivationPhase.READY)

    def test_load_error_freezes_outcome_unknown_without_retry(self):
        transport = FakeTransport([ABSENT], load=OSError("transport"))
        with self.assertRaisesRegex(operation.UserActivationOperationError, "reconciliation") as caught:
            self.invoke(transport)
        self.assertEqual(caught.exception.wiped_password, bytearray(13))
        self.assertEqual(
            journal.read(self.path).phase,
            journal.UserActivationPhase.OUTCOME_UNKNOWN,
        )
        self.assertEqual([call[0] for call in transport.calls].count("load"), 1)

    def test_loaded_wrong_bag_stops_before_bind(self):
        transport = FakeTransport([ABSENT], loaded_bag_uuid=identifier(9))
        with self.assertRaisesRegex(operation.UserActivationOperationError, "stopped") as caught:
            self.invoke(transport)
        self.assertEqual(caught.exception.wiped_password, bytearray(13))
        self.assertEqual(journal.read(self.path).phase, journal.UserActivationPhase.STOPPED)
        self.assertNotIn("bind", [call[0] for call in transport.calls])

    def test_post_load_journal_failure_freezes_before_bind(self):
        transport = FakeTransport([ABSENT])
        original = journal.append_checked

        def append(path, operation_id, milestone, evidence):
            if milestone == "USER_KEYBAG_HANDLE_OBSERVED":
                raise OSError("synthetic journal failure")
            return original(path, operation_id, milestone, evidence)

        with mock.patch.object(
            operation.activation_journal, "append_checked", side_effect=append
        ):
            with self.assertRaisesRegex(
                operation.UserActivationOperationError, "reconciliation"
            ):
                self.invoke(transport)
        self.assertEqual(
            journal.read(self.path).phase,
            journal.UserActivationPhase.OUTCOME_UNKNOWN,
        )
        self.assertNotIn("bind", [call[0] for call in transport.calls])

    def test_bind_without_alias_readback_is_outcome_unknown(self):
        transport = FakeTransport([ABSENT, ABSENT])
        with self.assertRaisesRegex(operation.UserActivationOperationError, "reconciliation"):
            self.invoke(transport)
        self.assertEqual(
            journal.read(self.path).phase,
            journal.UserActivationPhase.OUTCOME_UNKNOWN,
        )
        self.assertEqual([call[0] for call in transport.calls].count("bind"), 1)

    def test_unlock_that_remains_locked_stops_without_retry(self):
        transport = FakeTransport([LOCKED, LOCKED])
        with self.assertRaisesRegex(operation.UserActivationOperationError, "stopped"):
            self.invoke(transport)
        self.assertEqual(journal.read(self.path).phase, journal.UserActivationPhase.STOPPED)
        self.assertEqual([call[0] for call in transport.calls].count("unlock"), 1)

    def test_oversized_wipeable_password_is_erased_on_rejection(self):
        transport = FakeTransport([READY])
        password = bytearray(b"x" * 1025)
        with self.assertRaises(operation.UserActivationOperationError) as caught:
            self.invoke(transport, password=password)
        self.assertEqual(caught.exception.wiped_password, bytearray(1025))
        self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
