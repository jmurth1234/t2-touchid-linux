# SPDX-License-Identifier: GPL-2.0-only
"""Internal handoff from a pinned fprint claim to the mutation broker."""

from __future__ import annotations

import t2_dbus_identity
import t2_fprint_claim
import t2_user_broker


MUTATION_OPERATIONS = frozenset({"enroll", "identity-management"})


class FprintBrokerError(RuntimeError):
    pass


def run_mutation(
    caller: t2_dbus_identity.PinnedDBusCaller,
    evidence: t2_fprint_claim.ClaimEvidence,
    *,
    operation: str,
    consumer: t2_user_broker.Consumer,
    allow_user_interaction: bool = True,
) -> t2_user_broker.BrokerResult:
    """Run one same-user mutation while retaining the fprint claim binding."""

    if not isinstance(caller, t2_dbus_identity.PinnedDBusCaller):
        raise FprintBrokerError("pinned D-Bus caller is invalid")
    if not isinstance(evidence, t2_fprint_claim.ClaimEvidence):
        raise FprintBrokerError("fprint claim evidence is invalid")
    if operation not in MUTATION_OPERATIONS:
        raise FprintBrokerError("fprint mutation operation is unsupported")
    if not callable(consumer):
        raise FprintBrokerError("fprint mutation consumer is unavailable")
    if type(allow_user_interaction) is not bool:
        raise FprintBrokerError("fprint interaction policy must be Boolean")
    try:
        authorization = evidence.authorization_session(caller)
    except t2_fprint_claim.FprintClaimError as error:
        raise FprintBrokerError(
            "fprint claim cannot authorize mutation"
        ) from error
    try:
        return t2_user_broker.run_self_service(
            None,
            operation=operation,
            modification_allowed=True,
            consumer=consumer,
            allow_user_interaction=allow_user_interaction,
            authorization_manager=authorization,
        )
    except t2_user_broker.UserBrokerError as error:
        raise FprintBrokerError("fprint mutation authorization failed") from error
    finally:
        # run_self_service normally owns the context. This idempotent close also
        # covers failures before it enters the supplied authorization session.
        authorization.close()
