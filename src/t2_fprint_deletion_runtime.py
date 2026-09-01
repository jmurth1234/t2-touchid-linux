# SPDX-License-Identifier: GPL-2.0-only
"""Typed completion boundary for one journaled fprint identity deletion."""

from __future__ import annotations

from dataclasses import dataclass

import t2_fprint_projection


class FprintDeletionRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class DeletionCompletion:
    finger_name: str
    deleted: bool
    reconciled: bool
    post_reboot_pending: bool
    mutation_performed: bool

    def __post_init__(self) -> None:
        if self.finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintDeletionRuntimeError(
                "deletion completion finger name is invalid"
            )
        if any(
            type(value) is not bool
            for value in (
                self.deleted,
                self.reconciled,
                self.post_reboot_pending,
                self.mutation_performed,
            )
        ):
            raise FprintDeletionRuntimeError(
                "deletion completion flags must be Boolean"
            )
        if not (
            self.deleted
            and self.reconciled
            and self.post_reboot_pending
            and self.mutation_performed
        ):
            raise FprintDeletionRuntimeError(
                "deletion completion does not prove reconciled mutation"
            )
