# SPDX-License-Identifier: GPL-2.0-only
"""Route one enrollment persistence plan across its two SEP protocols."""

from __future__ import annotations

from enum import Enum

import t2_biolockout_bridge
import t2_biolockout_protocol
import t2_catacomb_bridge


class EnrollmentPersistenceBridgeError(RuntimeError):
    pass


class RouteState(Enum):
    IDLE = "idle"
    CATACOMB = "catacomb"
    BIOLOCKOUT_PREPARED = "biolockout-prepared"
    BIOLOCKOUT_CAPTURED = "biolockout-captured"


class EnrollmentPersistenceBridgeTransport:
    """One same-generation transport for user/master then bio-lockout."""

    def __init__(self, lease, *, protocol_version: int, connection_generation: str):
        self._catacomb = t2_catacomb_bridge.CatacombBridgeTransport(
            lease,
            protocol_version=protocol_version,
            connection_generation=connection_generation,
        )
        self._biolockout = t2_biolockout_bridge.BioLockoutBridgeTransport(
            lease, connection_generation=connection_generation
        )
        self._state = RouteState.IDLE

    @property
    def state(self) -> RouteState:
        return self._state

    @staticmethod
    def _is_biolockout(descriptor: bytes) -> bool:
        return descriptor == t2_biolockout_protocol.PERSISTENCE_DESCRIPTOR

    def prepare(self, descriptor: bytes) -> tuple[int, int]:
        if self._state is not RouteState.IDLE:
            raise EnrollmentPersistenceBridgeError(
                "enrollment persistence prepare is out of order"
            )
        if self._is_biolockout(descriptor):
            self._state = RouteState.BIOLOCKOUT_PREPARED
            return 0, t2_biolockout_protocol.OUTPUT_CAPACITY
        self._state = RouteState.CATACOMB
        try:
            return self._catacomb.prepare(descriptor)
        except BaseException:
            self._state = RouteState.IDLE
            raise

    def complete(self, descriptor: bytes) -> tuple[int, bytearray]:
        if self._is_biolockout(descriptor):
            if self._state is not RouteState.BIOLOCKOUT_PREPARED:
                raise EnrollmentPersistenceBridgeError(
                    "bio-lockout capture is out of order"
                )
            output = self._biolockout.capture()
            self._state = RouteState.BIOLOCKOUT_CAPTURED
            return 0, output
        if self._state is not RouteState.CATACOMB:
            raise EnrollmentPersistenceBridgeError(
                "Catacomb complete is out of order"
            )
        return self._catacomb.complete(descriptor)

    def confirm(self, descriptor: bytes) -> int:
        if self._is_biolockout(descriptor):
            if self._state is not RouteState.BIOLOCKOUT_CAPTURED:
                raise EnrollmentPersistenceBridgeError(
                    "bio-lockout host confirmation is out of order"
                )
            self._state = RouteState.IDLE
            return 0
        if self._state is not RouteState.CATACOMB:
            raise EnrollmentPersistenceBridgeError(
                "Catacomb confirm is out of order"
            )
        status = self._catacomb.confirm(descriptor)
        self._state = RouteState.IDLE
        return status
