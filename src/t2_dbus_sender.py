# SPDX-License-Identifier: GPL-2.0-only
"""Preserve the exact system-bus sender across dbus-next service dispatch."""

from __future__ import annotations

import contextvars
import re

from dbus_next.aio import MessageBus


class DBusSenderError(RuntimeError):
    pass


_CURRENT_SENDER: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "t2_touchid_dbus_sender", default=None
)
_UNIQUE_NAME = re.compile(r":[0-9]+(?:\.[0-9]+)+")


def current_sender() -> str:
    value = _CURRENT_SENDER.get()
    if (
        type(value) is not str
        or len(value) > 255
        or _UNIQUE_NAME.fullmatch(value) is None
    ):
        raise DBusSenderError("D-Bus caller has no canonical unique name")
    return value


class SenderAwareMessageBus(MessageBus):
    """Pin each method task to the sender of its immutable D-Bus message."""

    def _make_method_handler(self, interface, method):
        delegated = super()._make_method_handler(interface, method)

        def handler(message, send_reply):
            token = _CURRENT_SENDER.set(message.sender)
            try:
                return delegated(message, send_reply)
            finally:
                _CURRENT_SENDER.reset(token)

        return handler
