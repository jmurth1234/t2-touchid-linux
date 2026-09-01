# SPDX-License-Identifier: GPL-2.0-only
"""Async facade-side lifecycle for one detached deletion worker."""

from __future__ import annotations

import asyncio

import t2_dbus_identity
import t2_fprint_claim
import t2_fprint_delete_worker_launcher
import t2_fprint_delete_worker_protocol
import t2_fprint_deletion_runtime
import t2_fprint_projection


class FprintDeleteWorkerClientError(RuntimeError):
    pass


class DeletionWorkerClient:
    """Serialize requests and retain each worker through reconciliation."""

    def __init__(
        self,
        *,
        launcher=t2_fprint_delete_worker_launcher.launch,
    ) -> None:
        if not callable(launcher):
            raise FprintDeleteWorkerClientError(
                "delete worker launcher is unavailable"
            )
        self._launcher = launcher
        self._lock = asyncio.Lock()

    async def delete(
        self,
        finger_name: object,
        caller: t2_dbus_identity.PinnedDBusCaller,
        evidence: t2_fprint_claim.ClaimEvidence,
    ) -> t2_fprint_deletion_runtime.DeletionCompletion:
        if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintDeleteWorkerClientError(
                "worker deletion requires a canonical finger name"
            )
        if (
            not isinstance(caller, t2_dbus_identity.PinnedDBusCaller)
            or not isinstance(evidence, t2_fprint_claim.ClaimEvidence)
            or caller.subject.uid != evidence.linux_uid
            or evidence.account.linux_uid != evidence.linux_uid
        ):
            raise FprintDeleteWorkerClientError(
                "worker deletion claim is invalid or cross-user"
            )
        async with self._lock:
            operation = asyncio.create_task(
                self._run(finger_name, caller, evidence)
            )
            try:
                return await asyncio.shield(operation)
            except asyncio.CancelledError:
                # A handed-off deletion may already have reached SEP. Keep the
                # private channel alive until the worker reports reconciliation.
                return await operation

    async def _run(
        self,
        finger_name: str,
        caller: t2_dbus_identity.PinnedDBusCaller,
        evidence: t2_fprint_claim.ClaimEvidence,
    ) -> t2_fprint_deletion_runtime.DeletionCompletion:
        session = None
        try:
            await asyncio.to_thread(evidence.revalidate, caller)
            session = await asyncio.to_thread(self._launcher)
            if not isinstance(
                session,
                t2_fprint_delete_worker_launcher.DeleteWorkerConnection,
            ):
                raise FprintDeleteWorkerClientError(
                    "delete worker launcher returned no typed connection"
                )
            await asyncio.to_thread(evidence.revalidate, caller)
            request = t2_fprint_delete_worker_protocol.DeleteRequest(
                finger_name,
                caller.subject,
                evidence.account,
                evidence.session,
            )
            await asyncio.to_thread(
                t2_fprint_delete_worker_protocol.send_request,
                session.connection,
                request,
                caller.pidfd,
            )
            result = await asyncio.to_thread(
                t2_fprint_delete_worker_protocol.receive_completion,
                session.connection,
            )
            if (
                type(result)
                is not t2_fprint_deletion_runtime.DeletionCompletion
                or result.finger_name != finger_name
            ):
                raise FprintDeleteWorkerClientError(
                    "delete worker completion changed its target"
                )
            return result
        except FprintDeleteWorkerClientError:
            raise
        except Exception as error:
            raise FprintDeleteWorkerClientError(
                "delete worker did not reconcile"
            ) from error
        finally:
            if session is not None:
                session.close()
