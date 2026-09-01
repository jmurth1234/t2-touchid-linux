# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from dbus_next.aio import MessageBus


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_dbus_sender as sender


class DBusSenderTests(unittest.TestCase):
    def test_sender_is_task_local_and_strict(self):
        for value in (None, "", "org.example.Name", ":1", ":a.1", ":1.x"):
            token = sender._CURRENT_SENDER.set(value)
            try:
                with self.subTest(value=value), self.assertRaises(
                    sender.DBusSenderError
                ):
                    sender.current_sender()
            finally:
                sender._CURRENT_SENDER.reset(token)
        token = sender._CURRENT_SENDER.set(":1.42")
        try:
            self.assertEqual(sender.current_sender(), ":1.42")
        finally:
            sender._CURRENT_SENDER.reset(token)

    def test_async_task_inherits_then_isolates_sender_context(self):
        async def scenario():
            async def read_sender():
                await asyncio.sleep(0)
                return sender.current_sender()

            token = sender._CURRENT_SENDER.set(":1.7")
            try:
                task = asyncio.create_task(read_sender())
            finally:
                sender._CURRENT_SENDER.reset(token)
            self.assertEqual(await task, ":1.7")
            with self.assertRaises(sender.DBusSenderError):
                sender.current_sender()

        asyncio.run(scenario())


class SenderAwareBusTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_service_task_inherits_message_sender(self):
        observed = asyncio.get_running_loop().create_future()

        def delegated(_message, _send_reply):
            async def read_later():
                await asyncio.sleep(0)
                observed.set_result(sender.current_sender())

            asyncio.create_task(read_later())

        bus = object.__new__(sender.SenderAwareMessageBus)
        with mock.patch.object(
            MessageBus, "_make_method_handler", return_value=delegated
        ):
            handler = bus._make_method_handler(object(), object())
        handler(SimpleNamespace(sender=":1.88"), object())
        self.assertEqual(await observed, ":1.88")
        with self.assertRaises(sender.DBusSenderError):
            sender.current_sender()


if __name__ == "__main__":
    unittest.main()
