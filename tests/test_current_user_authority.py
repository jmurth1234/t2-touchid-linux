# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_current_user_authority as authority
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class Observer:
    def __init__(self, evidence):
        self.evidence = evidence
        self.alias = None

    def observe_alias(self, alias):
        self.alias = alias
        return self.evidence


class CurrentUserAuthorityTests(unittest.TestCase):
    def test_configuration_requires_one_matching_canonical_user_and_alias(self):
        valid = (
            b"T2_TOUCHID_MACOS_USER_ID=501\n"
            b"T2_TOUCHID_SPECIAL_BAG=-501\n"
        )
        with mock.patch.object(
            authority, "_read_private_root_file", return_value=valid
        ):
            self.assertEqual(authority._configured_user_id(), 501)

        invalid = (
            b"T2_TOUCHID_MACOS_USER_ID=0501\nT2_TOUCHID_SPECIAL_BAG=-501\n",
            b"T2_TOUCHID_MACOS_USER_ID=501\nT2_TOUCHID_SPECIAL_BAG=-502\n",
            b"T2_TOUCHID_MACOS_USER_ID=501\nT2_TOUCHID_MACOS_USER_ID=501\n"
            b"T2_TOUCHID_SPECIAL_BAG=-501\n",
            b"T2_TOUCHID_MACOS_USER_ID=501\n",
        )
        for value in invalid:
            with self.subTest(value=value), mock.patch.object(
                authority, "_read_private_root_file", return_value=value
            ), self.assertRaises(authority.CurrentUserAuthorityError):
                authority._configured_user_id()

    def test_collect_returns_private_exact_authority_under_lock(self):
        evidence = readiness.AliasEvidence(
            True, -501, identifier(2), 0, identifier(1)
        )
        observer = Observer(evidence)
        read_descriptor, write_descriptor = os.pipe()
        os.close(write_descriptor)
        try:
            with (
                mock.patch.object(authority.os, "geteuid", return_value=0),
                mock.patch.object(
                    authority, "_configured_user_id", return_value=501
                ),
                mock.patch.object(
                    authority,
                    "_open_operation_lock",
                    return_value=read_descriptor,
                ),
                mock.patch.object(
                    authority.t2_aks_observer,
                    "AKSAliasObserver",
                    return_value=observer,
                ) as factory,
            ):
                result = authority.collect()
        finally:
            try:
                os.close(read_descriptor)
            except OSError:
                pass
        factory.assert_called_once_with(expected_owner_uid=0)
        self.assertEqual(observer.alias, -501)
        self.assertEqual(result.apple_uid, 501)
        self.assertEqual(result.account_uuid, identifier(1))
        self.assertEqual(result.bag_uuid, identifier(2))
        rendered = json.dumps(result.redacted(), sort_keys=True)
        self.assertNotIn(identifier(1), rendered)
        self.assertNotIn(identifier(2), rendered)
        self.assertNotIn("501", rendered)
        self.assertFalse(result.redacted()["t2_mutation_performed"])

    def test_invalid_alias_evidence_fails_closed(self):
        cases = (
            object(),
            readiness.AliasEvidence(False, None, None, None, None),
            readiness.AliasEvidence(
                True, -502, identifier(2), 0, identifier(1)
            ),
            readiness.AliasEvidence(
                True, -501, identifier(2), 1 << 8, identifier(1)
            ),
            readiness.AliasEvidence(
                True, -501, identifier(2), 0, identifier(0)
            ),
        )
        for evidence in cases:
            with self.subTest(evidence=evidence), self.assertRaises(
                authority.CurrentUserAuthorityError
            ):
                authority._validate(501, evidence)

    def test_nonroot_fails_before_configuration_or_observation(self):
        with (
            mock.patch.object(authority.os, "geteuid", return_value=1000),
            mock.patch.object(authority, "_configured_user_id") as configured,
            self.assertRaises(authority.CurrentUserAuthorityError),
        ):
            authority.collect()
        configured.assert_not_called()


if __name__ == "__main__":
    unittest.main()
