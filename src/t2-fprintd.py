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

LOCAL_SOURCE = Path(__file__).resolve().parent
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from dbus_next import BusType, DBusError, Message, MessageType, Variant
from dbus_next.constants import PropertyAccess
from dbus_next.service import ServiceInterface, dbus_property, method, signal

import t2_fprint_projection
import t2_fprint_runtime
import t2_dbus_identity
import t2_fprint_claim
from t2_dbus_sender import (
    DBusSenderError,
    SenderAwareMessageBus,
    current_sender as current_dbus_sender,
)


BUS_NAME = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
FPRINT_ERROR = "net.reactivated.Fprint.Error"
LINUX_USER = os.environ.get("T2_TOUCHID_USER", "")
MACOS_USER_ID = int(os.environ.get("T2_TOUCHID_MACOS_USER_ID", "501"))
ENROLLED_FINGER = os.environ.get(
    "T2_TOUCHID_ENROLLED_FINGER", "right-index-finger"
)
ALLOWED_PAM_USERS = (LINUX_USER,)
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


def verdict_from_result(
    result: object, target_finger: str | None = None
) -> str:
    """Translate privacy-safe probe JSON into a fail-closed fprintd verdict."""
    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    if target_finger is not None:
        gate = result.get("targeted_match_gate")
        post = result.get("targeted_match_post_attestation")
        if (
            target_finger == "any"
            or not isinstance(gate, dict)
            or gate.get("finger_name") != target_finger
            or gate.get("single_identity_selected") is not True
            or gate.get("same_connection_inventory_stable") is not True
            or gate.get("local_live_reconciled") is not True
            or gate.get("identifiers_redacted") is not True
            or not isinstance(post, dict)
            or post.get("identity_state_unchanged") is not True
            or post.get("local_components_unchanged") is not True
            or post.get("per_user_inventory_unchanged") is not True
            or post.get("global_inventory_unchanged") is not True
            or post.get("identifiers_redacted") is not True
        ):
            raise RuntimeError("named T2 match attestation is incomplete")
    events = result.get("match_events", [])
    if not isinstance(events, list):
        raise RuntimeError("malformed T2 match event list")
    for event in events:
        if not isinstance(event, dict) or event.get("event_kind") != "match_result":
            continue
        if (
            event.get("matched") is True
            and event.get("matches_enrolled_identity") is True
            and (
                target_finger is None
                or event.get("matches_selected_identity") is True
            )
        ):
            return "verify-match"
        return "verify-no-match"
    if result.get("match_rejected") is True:
        raise RuntimeError("the T2 rejected match startup")
    return "verify-no-match"


def resolved_any_finger_from_result(result: object) -> str | None:
    """Return the canonical identity selected by an attested `any` match."""
    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    gate = result.get("resolved_any_match_gate")
    post = result.get("resolved_any_match_post_attestation")
    if (
        not isinstance(gate, dict)
        or type(gate.get("identity_count")) is not int
        or not 1 <= gate["identity_count"] <= len(t2_fprint_projection.FINGER_NAMES)
        or gate.get("complete_named_inventory") is not True
        or gate.get("all_identities_selected") is not True
        or gate.get("same_connection_inventory_stable") is not True
        or gate.get("local_live_reconciled") is not True
        or gate.get("identifiers_redacted") is not True
        or not isinstance(post, dict)
        or post.get("identity_state_unchanged") is not True
        or post.get("local_components_unchanged") is not True
        or post.get("per_user_inventory_unchanged") is not True
        or post.get("global_inventory_unchanged") is not True
        or post.get("identifiers_redacted") is not True
    ):
        raise RuntimeError("resolved-any T2 match attestation is incomplete")
    events = result.get("match_events")
    if not isinstance(events, list):
        raise RuntimeError("malformed T2 match event list")
    for event in events:
        if not isinstance(event, dict) or event.get("event_kind") != "match_result":
            continue
        if event.get("matched") is not True:
            return None
        finger_name = event.get("matched_finger_name")
        if (
            event.get("matches_enrolled_identity") is not True
            or event.get("matched_finger_name_present") is not True
            or finger_name not in t2_fprint_projection.FINGER_NAME_SET
        ):
            raise RuntimeError("resolved-any T2 match result is incomplete")
        return finger_name
    if result.get("match_rejected") is True:
        raise RuntimeError("the T2 rejected match startup")
    return None


class T2Backend:
    def __init__(self, project_dir: Path, match_seconds: float) -> None:
        if not LINUX_USER:
            raise RuntimeError("T2_TOUCHID_USER is not configured")
        self.project_dir = project_dir
        self.match_seconds = match_seconds
        self.process: asyncio.subprocess.Process | None = None
        self.operation_lock = asyncio.Lock()
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

    async def runtime_projection(self) -> t2_fprint_runtime.RuntimeProjection:
        command = [
            sys.executable,
            str(self.project_dir / "src/t2-touchid-fprint-status.py"),
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
        if process.returncode != 0 or not stdout:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "fprint projection collection failed")
        try:
            value = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("fprint projection returned malformed JSON") from error
        try:
            return t2_fprint_runtime.parse_projection(value, ENROLLED_FINGER)
        except t2_fprint_runtime.FprintRuntimeError as error:
            raise RuntimeError("fprint projection failed validation") from error

    async def list_fingers(self) -> tuple[str, ...]:
        async with self.operation_lock:
            return (await self.runtime_projection()).listed_fingers

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

    async def _run_probe(
        self,
        port: int,
        target_finger: str | None = None,
        resolve_any_finger: bool = False,
    ) -> dict:
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
        if target_finger is not None:
            command.extend(["--match-finger-name", target_finger])
        if resolve_any_finger:
            command.append("--resolve-any-finger-name")
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

    async def verify(
        self,
        target_finger: str | None = None,
        resolve_any_finger: bool = False,
    ) -> tuple[str, dict]:
        if target_finger is not None and resolve_any_finger:
            raise RuntimeError("named and resolved-any matching conflict")
        port = await self.discover()
        await self.notify_finger_requested()
        try:
            result = await self._run_probe(
                port, target_finger, resolve_any_finger
            )
        except RuntimeError:
            if not self.port_from_cache:
                raise
            # A cached service endpoint may disappear after bridgeOS restarts.
            # Rediscover once; never turn a valid negative match into a retry.
            self.port = None
            self.port_from_cache = False
            port = await self.discover()
            result = await self._run_probe(
                port, target_finger, resolve_any_finger
            )
        if resolve_any_finger:
            verdict = (
                "verify-match"
                if resolved_any_finger_from_result(result) is not None
                else "verify-no-match"
            )
        else:
            verdict = verdict_from_result(result, target_finger)
        await self.notify_feedback(verdict)
        return verdict, result

    async def verify_fprint(self, requested_finger: str) -> tuple[str, dict]:
        """Resolve presentation afresh, then let the probe resolve authority."""
        async with self.operation_lock:
            view = await self.runtime_projection()
            try:
                request = t2_fprint_runtime.resolve_match(
                    view, requested_finger
                )
            except t2_fprint_runtime.FprintRuntimeError as error:
                raise RuntimeError("requested fprint identity is unavailable") from error
            return await self.verify(
                target_finger=request.target_finger,
                resolve_any_finger=(
                    request.requested_finger == "any" and view.complete
                ),
            )

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
    def __init__(
        self,
        backend: T2Backend,
        identity_bus,
        caller_collector=t2_dbus_identity.collect,
        claim_evidence_collector=t2_fprint_claim.collect,
    ) -> None:
        super().__init__("net.reactivated.Fprint.Device")
        self.backend = backend
        self.identity_bus = identity_bus
        self.caller_collector = caller_collector
        self.claim_evidence_collector = claim_evidence_collector
        self.claim_lock = asyncio.Lock()
        self.claimed_user: str | None = None
        self.claimed_sender: str | None = None
        self.claimed_caller: t2_dbus_identity.PinnedDBusCaller | None = None
        self.claimed_evidence: t2_fprint_claim.ClaimEvidence | None = None
        self.verify_task: asyncio.Task | None = None
        self.claim_expiry_task: asyncio.Task | None = None
        self.enrolled_fingers: tuple[str, ...] = (ENROLLED_FINGER,)
        self.finger_present = False
        self.finger_needed = False

    @dbus_property(access=PropertyAccess.READ, name="name")
    def device_name(self) -> "s":
        return "Apple T2 Touch ID"

    @method()
    async def Claim(self, username: "s"):
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        try:
            sender = current_dbus_sender()
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        async with self.claim_lock:
            if self.claimed_user is not None:
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse", "device is claimed"
                )
            caller = None
            try:
                caller = await self.caller_collector(
                    self.identity_bus, sender
                )
                if current_dbus_sender() != sender or caller.sender != sender:
                    raise t2_dbus_identity.DBusIdentityError(
                        "D-Bus caller changed during claim"
                    )
                caller.verify()
                evidence = await asyncio.to_thread(
                    self.claim_evidence_collector, caller, requested
                )
                if not isinstance(evidence, t2_fprint_claim.ClaimEvidence):
                    raise t2_fprint_claim.FprintClaimError(
                        "claim evidence collector returned an invalid result"
                    )
                if current_dbus_sender() != sender or caller.sender != sender:
                    raise t2_dbus_identity.DBusIdentityError(
                        "D-Bus caller changed during claim evidence collection"
                    )
                caller.verify()
            except (
                DBusSenderError,
                t2_dbus_identity.DBusIdentityError,
                t2_fprint_claim.FprintClaimError,
            ) as error:
                if caller is not None:
                    caller.close()
                raise DBusError(
                    f"{FPRINT_ERROR}.PermissionDenied",
                    "caller process identity unavailable",
                ) from error
            self.claimed_user = requested
            self.claimed_sender = sender
            self.claimed_caller = caller
            self.claimed_evidence = evidence
            self.claim_expiry_task = asyncio.create_task(
                self._expire_unstarted_claim()
            )

    def _clear_claim(self) -> None:
        caller = self.claimed_caller
        self.claimed_user = None
        self.claimed_sender = None
        self.claimed_caller = None
        self.claimed_evidence = None
        if caller is not None:
            caller.close()

    def _require_claim_owner(self) -> None:
        if (
            self.claimed_user is None
            or self.claimed_sender is None
            or self.claimed_caller is None
            or self.claimed_evidence is None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.ClaimDevice", "device is not claimed"
            )
        try:
            sender = current_dbus_sender()
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        if sender != self.claimed_sender:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "device is claimed by another D-Bus connection",
            )
        try:
            if self.claimed_caller.sender != sender:
                raise t2_dbus_identity.DBusIdentityError(
                    "pinned sender does not match the claim"
                )
            self.claimed_caller.verify()
            self.claimed_evidence.revalidate(self.claimed_caller)
        except (
            t2_dbus_identity.DBusIdentityError,
            t2_fprint_claim.FprintClaimError,
        ) as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "caller process identity is no longer valid",
            ) from error

    @method()
    async def Release(self):
        self._require_claim_owner()
        await self._stop_verification(require_running=False)
        self._clear_claim()

    @method()
    async def ListEnrolledFingers(self, username: "s") -> "as":
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        try:
            self.enrolled_fingers = await self.backend.list_fingers()
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal", "fingerprint inventory unavailable"
            ) from error
        if not self.enrolled_fingers:
            raise DBusError(
                f"{FPRINT_ERROR}.NoEnrolledPrints",
                "no fingerprints are enrolled",
            )
        return list(self.enrolled_fingers)

    @method()
    def VerifyStart(self, finger_name: "s"):
        self._require_claim_owner()
        if self.verify_task is not None:
            raise DBusError(f"{FPRINT_ERROR}.AlreadyInUse", "verification is active")
        if finger_name != "any" and finger_name not in self.enrolled_fingers:
            raise DBusError(
                f"{FPRINT_ERROR}.NoEnrolledPrints", "finger is not enrolled"
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        if finger_name != "any":
            self.VerifyFingerSelected(finger_name)
        self.verify_task = asyncio.create_task(
            self._run_verification(finger_name)
        )

    @method()
    async def VerifyStop(self):
        self._require_claim_owner()
        await self._stop_verification(require_running=True)

    async def _run_verification(self, requested_finger: str) -> None:
        current_task = asyncio.current_task()
        try:
            verdict, result = await self.backend.verify_fprint(requested_finger)
            if requested_finger == "any" and verdict == "verify-match":
                if "resolved_any_match_gate" in result:
                    selected = resolved_any_finger_from_result(result)
                    if selected is None:
                        raise RuntimeError("matched any-finger result has no identity")
                else:
                    selected = ENROLLED_FINGER
                self.VerifyFingerSelected(selected)
                self.VerifyFingerMatched(selected)
            elif verdict == "verify-match":
                self.VerifyFingerMatched(requested_finger)
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
            self._clear_claim()
        self.claim_expiry_task = None

    async def _expire_unstarted_claim(self) -> None:
        await asyncio.sleep(UNSTARTED_CLAIM_SECONDS)
        if self.verify_task is None:
            self._clear_claim()
        self.claim_expiry_task = None

    async def sender_departed(self, sender: str) -> None:
        async with self.claim_lock:
            if sender != self.claimed_sender:
                return
            await self._stop_verification(require_running=False)
            self._clear_claim()

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
        self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.Internal", "enroll in macOS")

    @method()
    def EnrollStop(self):
        self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.NoActionInProgress", "enroll is disabled")

    @method()
    def DeleteEnrolledFingers(self, username: "s"):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    def DeleteEnrolledFingers2(self):
        self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    def DeleteEnrolledFinger(self, finger_name: "s"):
        self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @signal()
    def VerifyFingerSelected(self, finger_name: "s") -> "s":
        return finger_name

    @signal()
    def VerifyFingerMatched(self, finger_name: "s") -> "s":
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


def legacy_property_reply(message: Message, device: FprintDevice):
    """Serve fprint's historical hyphenated property names."""
    if (
        not isinstance(message, Message)
        or not isinstance(device, FprintDevice)
        or message.message_type != MessageType.METHOD_CALL
        or message.path != DEVICE_PATH
        or message.interface != "org.freedesktop.DBus.Properties"
    ):
        return False
    values = {
        "name": Variant("s", "Apple T2 Touch ID"),
        "num-enroll-stages": Variant("i", -1),
        "scan-type": Variant("s", "press"),
        "finger-present": Variant("b", device.finger_present),
        "finger-needed": Variant("b", device.finger_needed),
    }
    if (
        message.member == "Get"
        and message.body
        and message.body[0] == "net.reactivated.Fprint.Device"
        and len(message.body) == 2
        and message.body[1] in values
    ):
        return Message.new_method_return(
            message, signature="v", body=[values[message.body[1]]]
        )
    if (
        message.member == "GetAll"
        and message.body == ["net.reactivated.Fprint.Device"]
    ):
        return Message.new_method_return(
            message, signature="a{sv}", body=[values]
        )
    return False


async def main_async(args: argparse.Namespace) -> None:
    project_dir = Path(
        os.environ.get(
            "T2_TOUCHID_PROJECT_DIR", Path(__file__).resolve().parent.parent
        )
    )
    backend = T2Backend(project_dir, args.match_seconds)
    bus = await SenderAwareMessageBus(
        bus_type=BusType.SYSTEM, negotiate_unix_fd=True
    ).connect()
    device = FprintDevice(backend, bus)

    # fprintd's historical ABI contains hyphenated property names, although
    # D-Bus member-name validators (including dbus-next's) reject hyphens.
    # Intercept the compatibility property before dbus-next's property layer.
    def legacy_property_handler(message: Message):
        return legacy_property_reply(message, device)

    def sender_departure_handler(message: Message):
        if (
            message.message_type == MessageType.SIGNAL
            and message.sender == "org.freedesktop.DBus"
            and message.path == "/org/freedesktop/DBus"
            and message.interface == "org.freedesktop.DBus"
            and message.member == "NameOwnerChanged"
            and len(message.body) == 3
            and message.body[0] == message.body[1]
            and not message.body[2]
        ):
            asyncio.create_task(device.sender_departed(message.body[0]))
        return False

    bus.add_message_handler(legacy_property_handler)
    bus.add_message_handler(sender_departure_handler)
    bus.export(MANAGER_PATH, FprintManager())
    bus.export(DEVICE_PATH, device)
    await bus.request_name(BUS_NAME)
    await asyncio.get_running_loop().create_future()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match-seconds", type=float, default=20.0)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
