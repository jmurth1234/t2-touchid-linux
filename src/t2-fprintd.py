#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Minimal fprintd-compatible D-Bus facade for the T2 matcher.

This compatibility service deliberately supports verification only. Enrollment
and identity management use separate explicitly gated, journaled commands.
Authentication remains fail-closed and accepts only the UUID of an identity
selected from the scoped Apple-user identity list.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import sys

from dbus_next import BusType, DBusError, Message, MessageType, Variant
from dbus_next.aio import MessageBus
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method, signal


BUS_NAME = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
FPRINT_ERROR = "net.reactivated.Fprint.Error"
LINUX_USER = os.environ.get("T2_TOUCHID_USER", "")
MACOS_USER_ID = int(os.environ.get("T2_TOUCHID_MACOS_USER_ID", "501"))
ENROLLED_FINGER = os.environ.get(
    "T2_TOUCHID_ENROLLED_FINGER", "right-index-finger"
)
ALLOWED_PAM_USERS = (LINUX_USER, "root")
UNSTARTED_CLAIM_SECONDS = 5.0
COMPLETED_CLAIM_SECONDS = 0.5

if not 0 <= MACOS_USER_ID <= 0xFFFFFFFF:
    raise RuntimeError("T2_TOUCHID_MACOS_USER_ID is outside uint32 range")
if ENROLLED_FINGER not in {
    f"{hand}-{finger}"
    for hand in ("left", "right")
    for finger in (
        "thumb",
        "index-finger",
        "middle-finger",
        "ring-finger",
        "little-finger",
    )
}:
    raise RuntimeError("T2_TOUCHID_ENROLLED_FINGER is invalid")


def verdict_from_result(result: object) -> str:
    """Translate privacy-safe probe JSON into a fail-closed fprintd verdict."""
    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    events = result.get("match_events", [])
    if not isinstance(events, list):
        raise RuntimeError("malformed T2 match event list")
    for event in events:
        if not isinstance(event, dict) or event.get("event_kind") != "match_result":
            continue
        if (
            event.get("matched") is True
            and event.get("matches_enrolled_identity") is True
        ):
            return "verify-match"
        return "verify-no-match"
    if result.get("match_rejected") is True:
        raise RuntimeError("the T2 rejected match startup")
    return "verify-no-match"


class T2Backend:
    def __init__(self, project_dir: Path, match_seconds: float) -> None:
        if not LINUX_USER:
            raise RuntimeError("T2_TOUCHID_USER is not configured")
        self.project_dir = project_dir
        self.match_seconds = match_seconds
        self.process: asyncio.subprocess.Process | None = None
        self.port: int | None = None
        self.port_from_cache = False
        port_file = Path(
            os.environ.get(
                "T2_TOUCHID_PORT_FILE", "/var/lib/t2-touchid/biometric-port"
            )
        )
        try:
            cached_port = int(port_file.read_text().strip())
            if 49152 <= cached_port <= 65535:
                self.port = cached_port
                self.port_from_cache = True
        except (OSError, ValueError):
            pass

    async def discover(self) -> int:
        if self.port is not None:
            return self.port
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(self.project_dir / "src/discover-biometric-port.py"),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(stderr.decode(errors="replace").strip())
        self.port = int(stdout.decode().strip())
        if not 49152 <= self.port <= 65535:
            self.port = None
            raise RuntimeError("discovery returned an invalid port")
        self.port_from_cache = False
        return self.port

    async def _run_probe(self, port: int) -> dict:
        command = [
            "/usr/bin/flock",
            "--exclusive",
            "--timeout",
            "10",
            "--no-fork",
            "/run/t2-touchid/operation.lock",
            sys.executable,
            str(self.project_dir / "src/bridge-xpc-probe.py"),
            "--port",
            str(port),
            "--initialize",
            "--reset-sensor",
            "--cancel-operation",
            "--load-calibration",
            "--identity-list",
            "--macos-user-id",
            str(MACOS_USER_ID),
            "--match-seconds",
            str(self.match_seconds),
            "--stop-on-match-result",
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.process = process
        try:
            stdout, stderr = await process.communicate()
        finally:
            self.process = None
        if not stdout or process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "BridgeXPC probe failed")
        try:
            result = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("BridgeXPC probe returned malformed JSON") from error
        if not isinstance(result, dict):
            raise RuntimeError("BridgeXPC probe returned malformed JSON")
        return result

    async def verify(self) -> tuple[str, dict]:
        port = await self.discover()
        await self.notify_finger_requested()
        try:
            result = await self._run_probe(port)
        except RuntimeError:
            if not self.port_from_cache:
                raise
            # A cached service endpoint may disappear after bridgeOS restarts.
            # Rediscover once; never turn a valid negative match into a retry.
            self.port = None
            self.port_from_cache = False
            port = await self.discover()
            result = await self._run_probe(port)
        verdict = verdict_from_result(result)
        await self.notify_feedback(verdict)
        return verdict, result

    async def notify_feedback(self, verdict: str) -> None:
        unit = (
            "t2-touchid-success.service"
            if verdict == "verify-match"
            else "t2-touchid-failure.service"
        )
        await self.start_user_unit(unit)

    async def notify_finger_requested(self) -> None:
        """Play the user's requested audible cue without making it auth-critical."""
        if os.geteuid() == 0:
            await self.start_user_unit("t2-touchid-alert.service")
            return
        else:
            command = [
                "/usr/bin/canberra-gtk-play",
                "--id=message-new-instant",
                "--description=Touch ID finger requested",
            ]
        env = os.environ.copy()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=3
            )
            if process.returncode != 0:
                print(
                    "Touch ID alert failed:",
                    stderr.decode(errors="replace").strip(),
                    flush=True,
                )
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

    async def start_user_unit(self, unit: str) -> None:
        command = [
            "/usr/bin/systemctl",
            f"--machine={LINUX_USER}@.host",
            "--user",
            "start",
            "--no-block",
            unit,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=3
            )
            if process.returncode != 0:
                print(
                    f"Touch ID desktop unit {unit} failed:",
                    stderr.decode(errors="replace").strip(),
                    flush=True,
                )
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

    async def cancel(self) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


class FprintDevice(ServiceInterface):
    def __init__(self, backend: T2Backend) -> None:
        super().__init__("net.reactivated.Fprint.Device")
        self.backend = backend
        self.claimed_user: str | None = None
        self.verify_task: asyncio.Task | None = None
        self.claim_expiry_task: asyncio.Task | None = None

    @dbus_property(access=PropertyAccess.READ, name="name")
    def device_name(self) -> "s":
        return "Apple T2 Touch ID"

    @method()
    def Claim(self, username: "s"):
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        if self.claimed_user is not None:
            raise DBusError(f"{FPRINT_ERROR}.AlreadyInUse", "device is claimed")
        self.claimed_user = requested
        self.claim_expiry_task = asyncio.create_task(self._expire_unstarted_claim())

    @method()
    async def Release(self):
        if self.claimed_user is None:
            raise DBusError(f"{FPRINT_ERROR}.ClaimDevice", "device is not claimed")
        await self._stop_verification(require_running=False)
        self.claimed_user = None

    @method()
    def ListEnrolledFingers(self, username: "s") -> "as":
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        return [ENROLLED_FINGER]

    @method()
    def VerifyStart(self, finger_name: "s"):
        if self.claimed_user is None:
            raise DBusError(f"{FPRINT_ERROR}.ClaimDevice", "device is not claimed")
        if self.verify_task is not None:
            raise DBusError(f"{FPRINT_ERROR}.AlreadyInUse", "verification is active")
        if finger_name not in ("any", ENROLLED_FINGER):
            raise DBusError(
                f"{FPRINT_ERROR}.NoEnrolledPrints", "finger is not enrolled"
            )
        selected = ENROLLED_FINGER if finger_name == "any" else finger_name
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        self.VerifyFingerSelected(selected)
        self.verify_task = asyncio.create_task(self._run_verification())

    @method()
    async def VerifyStop(self):
        await self._stop_verification(require_running=True)

    async def _run_verification(self) -> None:
        current_task = asyncio.current_task()
        try:
            verdict, _result = await self.backend.verify()
            self.VerifyStatus(verdict, True)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.backend.notify_feedback("verify-unknown-error")
            self.VerifyStatus("verify-unknown-error", True)
        # Keep the completed task as the active transaction until the client
        # calls VerifyStop (or Release).  pam_fprintd follows that lifecycle;
        # clearing it here would make its mandatory VerifyStop fail with
        # NoActionInProgress immediately after a terminal VerifyStatus.
        self.claim_expiry_task = asyncio.create_task(
            self._expire_stale_claim(current_task)
        )

    async def _expire_stale_claim(self, completed_task: asyncio.Task) -> None:
        await asyncio.sleep(COMPLETED_CLAIM_SECONDS)
        if self.verify_task is completed_task:
            self.verify_task = None
            self.claimed_user = None
        self.claim_expiry_task = None

    async def _expire_unstarted_claim(self) -> None:
        await asyncio.sleep(UNSTARTED_CLAIM_SECONDS)
        if self.verify_task is None:
            self.claimed_user = None
        self.claim_expiry_task = None

    async def _stop_verification(self, require_running: bool) -> None:
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None
        task = self.verify_task
        if task is None:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoActionInProgress",
                    "verification is not active",
                )
            return
        await self.backend.cancel()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.verify_task = None

    @method()
    def EnrollStart(self, finger_name: "s"):
        raise DBusError(f"{FPRINT_ERROR}.Internal", "enroll in macOS")

    @method()
    def EnrollStop(self):
        raise DBusError(f"{FPRINT_ERROR}.NoActionInProgress", "enroll is disabled")

    @method()
    def DeleteEnrolledFingers(self, username: "s"):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    def DeleteEnrolledFingers2(self):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    def DeleteEnrolledFinger(self, finger_name: "s"):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @signal()
    def VerifyFingerSelected(self, finger_name: "s") -> "s":
        return finger_name

    @signal()
    def VerifyStatus(self, result: "s", done: "b") -> "sb":
        return [result, done]

    @signal()
    def EnrollStatus(self, result: "s", done: "b") -> "sb":
        return [result, done]


class FprintManager(ServiceInterface):
    def __init__(self) -> None:
        super().__init__("net.reactivated.Fprint.Manager")

    @method()
    def GetDevices(self) -> "ao":
        return [DEVICE_PATH]

    @method()
    def GetDefaultDevice(self) -> "o":
        return DEVICE_PATH


async def main_async(args: argparse.Namespace) -> None:
    project_dir = Path(
        os.environ.get(
            "T2_TOUCHID_PROJECT_DIR", Path(__file__).resolve().parent.parent
        )
    )
    backend = T2Backend(project_dir, args.match_seconds)
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    # fprintd's historical ABI contains hyphenated property names, although
    # D-Bus member-name validators (including dbus-next's) reject hyphens.
    # Intercept the compatibility property before dbus-next's property layer.
    def legacy_property_handler(message: Message):
        if (
            message.message_type != MessageType.METHOD_CALL
            or message.path != DEVICE_PATH
            or message.interface != "org.freedesktop.DBus.Properties"
        ):
            return False
        if (
            message.member == "Get"
            and message.body == ["net.reactivated.Fprint.Device", "scan-type"]
        ):
            return Message.new_method_return(
                message, signature="v", body=[Variant("s", "press")]
            )
        return False

    bus.add_message_handler(legacy_property_handler)
    bus.export(MANAGER_PATH, FprintManager())
    bus.export(DEVICE_PATH, FprintDevice(backend))
    await bus.request_name(BUS_NAME)
    await asyncio.get_running_loop().create_future()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match-seconds", type=float, default=20.0)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
