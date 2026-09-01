# SPDX-License-Identifier: GPL-2.0-only
"""Atomic enable transaction after stable, read-only live reconciliation.

The transaction holds the protected-mapping writer lock while an injected
session owns the machine-wide biometric operation lock.  Its session interface
has only a read-only ``collect`` method: no T2 activation or biometric mutation
can be requested through this boundary.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol

import t2_linux_account
import t2_user_mapping
import t2_user_mapping_admin
import t2_user_readiness


class UserReconciliationError(RuntimeError):
    pass


class LiveReconciliationSession(Protocol):
    def collect(
        self,
        selected: t2_user_mapping.UserMapping,
        linux_account_generation: str,
        keybag_sha256: str,
    ) -> tuple[
        t2_user_readiness.PersistentEvidence,
        t2_user_readiness.AliasEvidence,
    ]: ...


LiveSessionFactory = Callable[
    [], AbstractContextManager[LiveReconciliationSession]
]
AccountCollector = Callable[[int], t2_linux_account.AccountEvidence]
KeybagReader = Callable[[Path], str]


@dataclass(frozen=True, repr=False)
class ReconciliationResult:
    state: str
    mapping_count: int
    enabled_mapping_count: int
    enabled_capability_count: int

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "state": self.state,
            "mapping_count": self.mapping_count,
            "enabled_mapping_count": self.enabled_mapping_count,
            "enabled_capability_count": self.enabled_capability_count,
            "host_mapping_mutated": True,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _collect_live(
    session: LiveReconciliationSession,
    selected: t2_user_mapping.UserMapping,
    account_generation: str,
    keybag_sha256: str,
) -> tuple[
    t2_user_readiness.PersistentEvidence,
    t2_user_readiness.AliasEvidence,
]:
    try:
        evidence = session.collect(
            selected,
            account_generation,
            keybag_sha256,
        )
    except Exception as error:
        raise UserReconciliationError(
            "live reconciliation evidence could not be collected"
        ) from error
    if (
        type(evidence) is not tuple
        or len(evidence) != 2
        or not isinstance(evidence[0], t2_user_readiness.PersistentEvidence)
        or not isinstance(evidence[1], t2_user_readiness.AliasEvidence)
        or evidence[0].linux_account_generation != account_generation
        or evidence[0].keybag_sha256 != keybag_sha256
    ):
        raise UserReconciliationError("live reconciliation evidence is invalid")
    return evidence


def _collect_account(
    linux_uid: int,
    collector: AccountCollector,
) -> t2_linux_account.AccountEvidence:
    try:
        return t2_user_mapping_admin._collect_account(linux_uid, collector)
    except Exception as error:
        raise UserReconciliationError(
            "live Linux account assertion failed"
        ) from error


def _read_keybag(path: Path, reader: KeybagReader) -> str:
    try:
        digest = reader(path)
        t2_user_mapping._sha256(digest, "keybag digest")
    except Exception as error:
        raise UserReconciliationError(
            "protected keybag could not be read safely"
        ) from error
    return digest


def _require_ready(
    selected: t2_user_mapping.UserMapping,
    persistent: t2_user_readiness.PersistentEvidence,
    alias: t2_user_readiness.AliasEvidence,
) -> t2_user_mapping.UserMapping:
    candidate = replace(selected, enabled=True)
    try:
        # Every stored capability must independently resolve through the same
        # fully enabled candidate.  This catches malformed or empty direct
        # construction before the protected mapping can be published.
        capabilities = tuple(sorted(candidate.capabilities))
        if not capabilities:
            raise UserReconciliationError("mapping has no explicit capabilities")
        for capability in capabilities:
            decision = t2_user_readiness.assess(
                candidate,
                capability,
                persistent,
                alias,
            )
            if decision.state != "ready" or not decision.match_ready:
                raise UserReconciliationError(
                    "live Apple, AKS, and Catacomb authority did not reconcile"
                )
        t2_user_mapping.serialize((candidate,))
    except t2_user_mapping.UserMappingError as error:
        raise UserReconciliationError("enabled mapping is invalid") from error
    except t2_user_readiness.UserReadinessError as error:
        raise UserReconciliationError(
            "live reconciliation evidence is invalid"
        ) from error
    return candidate


def enable_reconciled(
    *,
    linux_uid: int,
    acknowledge_live_apple_authority_and_enable: bool,
    live_session_factory: LiveSessionFactory,
    path: Path = t2_user_mapping_admin.DEFAULT_MAPPING_PATH,
    account_collector: AccountCollector = t2_linux_account.collect,
    keybag_reader: KeybagReader = t2_user_mapping_admin._keybag_digest,
) -> ReconciliationResult:
    """Enable one exact disabled record after two stable live observations."""

    try:
        t2_user_mapping_admin._require_root()
    except t2_user_mapping_admin.UserMappingAdminError as error:
        raise UserReconciliationError(
            "live mapping reconciliation requires root"
        ) from error
    if acknowledge_live_apple_authority_and_enable is not True:
        raise UserReconciliationError(
            "live reconciliation and enable acknowledgement is required"
        )
    if not callable(live_session_factory):
        raise UserReconciliationError("live reconciliation session is unavailable")
    try:
        linux_uid = t2_user_mapping._unsigned(
            linux_uid, "Linux UID", minimum=1
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserReconciliationError(str(error)) from error

    directory = -1
    mapping_lock = -1
    publish_started = False
    try:
        directory, name = t2_user_mapping_admin._open_parent(path)
        mapping_lock = t2_user_mapping_admin._open_lock(directory, name)
        current = t2_user_mapping_admin._load_optional(directory, name)
        if current is None:
            raise UserReconciliationError("protected mapping does not exist")
        matches = [item for item in current.mappings if item.linux_uid == linux_uid]
        if len(matches) != 1:
            raise UserReconciliationError(
                "Linux UID has no unique protected mapping"
            )
        selected = matches[0]
        if selected.enabled:
            raise UserReconciliationError("protected mapping is already enabled")

        first_account = _collect_account(linux_uid, account_collector)
        if first_account.generation != selected.linux_account_generation:
            raise UserReconciliationError("Linux account generation changed")
        keybag_path = Path(selected.keybag_path)
        first_keybag = _read_keybag(keybag_path, keybag_reader)
        if first_keybag != selected.keybag_sha256:
            raise UserReconciliationError("protected keybag digest changed")

        try:
            session_manager = live_session_factory()
            if not isinstance(session_manager, AbstractContextManager):
                raise UserReconciliationError(
                    "live reconciliation session has the wrong type"
                )
            with session_manager as session:
                first = _collect_live(
                    session,
                    selected,
                    first_account.generation,
                    first_keybag,
                )
                candidate = _require_ready(selected, *first)

                second_account = _collect_account(linux_uid, account_collector)
                if second_account != first_account:
                    raise UserReconciliationError(
                        "Linux account changed during reconciliation"
                    )
                second_keybag = _read_keybag(keybag_path, keybag_reader)
                if second_keybag != first_keybag:
                    raise UserReconciliationError(
                        "keybag changed during reconciliation"
                    )
                second = _collect_live(
                    session,
                    selected,
                    second_account.generation,
                    second_keybag,
                )
                if second != first:
                    raise UserReconciliationError(
                        "live authority changed during reconciliation"
                    )
                _require_ready(selected, *second)

                updated = tuple(
                    candidate if item == selected else item
                    for item in current.mappings
                )
                publish_started = True
                final = t2_user_mapping_admin._publish(
                    directory,
                    name,
                    updated,
                    current.generation,
                )
        except UserReconciliationError:
            raise
        except t2_user_mapping_admin.UserMappingAdminError as error:
            if publish_started:
                raise UserReconciliationError(
                    "mapping enable outcome is unknown; inspect status and do not retry"
                ) from error
            raise UserReconciliationError(
                "protected mapping could not be enabled atomically"
            ) from error
        except Exception as error:
            if publish_started:
                raise UserReconciliationError(
                    "mapping enable outcome is unknown; inspect status and do not retry"
                ) from error
            raise UserReconciliationError(
                "live reconciliation session failed"
            ) from error

        return ReconciliationResult(
            "mapping-enabled-after-live-reconciliation",
            len(final.mappings),
            sum(item.enabled for item in final.mappings),
            len(candidate.capabilities),
        )
    except t2_user_mapping_admin.UserMappingAdminError as error:
        raise UserReconciliationError("protected mapping is unavailable") from error
    finally:
        if mapping_lock >= 0:
            os.close(mapping_lock)
        if directory >= 0:
            os.close(directory)
