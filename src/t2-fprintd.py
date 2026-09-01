#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Minimal fprintd-compatible D-Bus facade for Apple T2 Touch ID.

Verification is always available after the ordinary readiness gates. Native
enrollment and single-name deletion have separately gated worker paths and
remain disabled unless the daemon receives their explicit research activation
flags. Bulk deletion remains disabled. Authentication stays fail-closed and
accepts only an identity
selected from the scoped Apple-user identity list.
"""

import argparse
import asyncio
import json
import os
from pathlib import Path
import pwd
import stat
import sys

LOCAL_SOURCE = Path(__file__).resolve().parent
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from dbus_next import BusType, DBusError, Message, MessageType, Variant
from dbus_next.constants import PropertyAccess
from dbus_next import introspection as dbus_introspection
from dbus_next.service import ServiceInterface, dbus_property, method, signal

import t2_fprint_projection
import t2_fprint_runtime
import t2_fprint_enrollment_runtime
import t2_fprint_deletion_runtime
import t2_fprint_worker_client
import t2_fprint_delete_worker_client
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
AUTO_SYNC_ADAPTIVE_VALUE = os.environ.get(
    "T2_TOUCHID_AUTO_SYNC_ADAPTIVE", "0"
)
ALLOWED_PAM_USERS = (LINUX_USER,)
UNSTARTED_CLAIM_SECONDS = 5.0
COMPLETED_CLAIM_SECONDS = 0.5
DESKTOP_FEEDBACK_UNITS = frozenset(
    {
        "t2-touchid-alert.service",
        "t2-touchid-success.service",
        "t2-touchid-failure.service",
    }
)

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
if AUTO_SYNC_ADAPTIVE_VALUE not in {"0", "1"}:
    raise RuntimeError("T2_TOUCHID_AUTO_SYNC_ADAPTIVE is invalid")
AUTO_SYNC_ADAPTIVE = AUTO_SYNC_ADAPTIVE_VALUE == "1"


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


def desktop_user_unit_command(unit: object) -> tuple[str, ...] | None:
    """Return a command bound to the configured desktop user's live bus.

    The fprint facade is a root system service.  Root's environment is not a
    desktop user session, and ``systemctl --machine=... --user`` is not a
    reliable substitute for the target user's runtime bus.  Refuse an absent,
    replaced, or wrong-owner socket and let feedback remain best-effort.
    """

    if unit not in DESKTOP_FEEDBACK_UNITS or not LINUX_USER:
        return None
    try:
        account = pwd.getpwnam(LINUX_USER)
    except (KeyError, OSError):
        return None
    if account.pw_uid <= 0:
        return None
    runtime_dir = Path(f"/run/user/{account.pw_uid}")
    bus = runtime_dir / "bus"
    try:
        runtime_info = runtime_dir.stat(follow_symlinks=False)
        bus_info = bus.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != account.pw_uid
        or runtime_info.st_nlink < 1
        or runtime_info.st_mode & 0o077
        or not stat.S_ISSOCK(bus_info.st_mode)
        or bus_info.st_uid != account.pw_uid
        or bus_info.st_nlink != 1
    ):
        return None
    return (
        "/usr/bin/runuser",
        "-u",
        LINUX_USER,
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR={runtime_dir}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}",
        "/usr/bin/systemctl",
        "--user",
        "start",
        "--no-block",
        unit,
    )


class T2Backend:
    def __init__(
        self,
        project_dir: Path,
        match_seconds: float,
        auto_sync_adaptive: bool = AUTO_SYNC_ADAPTIVE,
    ) -> None:
        if not LINUX_USER:
            raise RuntimeError("T2_TOUCHID_USER is not configured")
        self.project_dir = project_dir
        self.match_seconds = match_seconds
        self.process: asyncio.subprocess.Process | None = None
        self.operation_lock = asyncio.Lock()
        if type(auto_sync_adaptive) is not bool:
            raise RuntimeError("adaptive Catacomb sync activation is invalid")
        self.auto_sync_adaptive = auto_sync_adaptive
        self.adaptive_sync_tasks: set[asyncio.Task] = set()
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

    async def _request_adaptive_sync(self) -> None:
        """Ask systemd to persist an adaptive update outside authentication."""

        process = await asyncio.create_subprocess_exec(
            "/usr/bin/systemctl",
            "start",
            "--no-block",
            "t2-touchid-adaptive-sync.service",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=3
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise RuntimeError("adaptive Catacomb sync request timed out")
        if process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "adaptive Catacomb sync request failed")

    @staticmethod
    def _consume_adaptive_sync_task(task: asyncio.Task) -> None:
        try:
            task.result()
        except BaseException as error:
            print(f"Adaptive Catacomb sync request failed: {error}", flush=True)

    def schedule_adaptive_sync(self) -> None:
        """Coalesce a best-effort post-verdict persistence request."""

        if not self.auto_sync_adaptive:
            return
        task = asyncio.create_task(self._request_adaptive_sync())
        self.adaptive_sync_tasks.add(task)
        task.add_done_callback(self.adaptive_sync_tasks.discard)
        task.add_done_callback(self._consume_adaptive_sync_task)

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
        command = desktop_user_unit_command(unit)
        if command is None:
            return
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
        enrollment_client=None,
        deletion_client=None,
    ) -> None:
        super().__init__("net.reactivated.Fprint.Device")
        self.backend = backend
        self.identity_bus = identity_bus
        self.caller_collector = caller_collector
        self.claim_evidence_collector = claim_evidence_collector
        self.enrollment_client = enrollment_client
        self.deletion_client = deletion_client
        self.claim_lock = asyncio.Lock()
        self.claimed_user: str | None = None
        self.claimed_sender: str | None = None
        self.claimed_caller: t2_dbus_identity.PinnedDBusCaller | None = None
        self.claimed_evidence: t2_fprint_claim.ClaimEvidence | None = None
        self.verify_task: asyncio.Task | None = None
        self.delete_task: asyncio.Task | None = None
        self.claim_expiry_task: asyncio.Task | None = None
        self.enrolled_fingers: tuple[str, ...] = (ENROLLED_FINGER,)
        self.finger_present = False
        self.finger_needed = False

    @staticmethod
    def _consume_signal_send(result: object) -> None:
        if not isinstance(result, asyncio.Future):
            return

        def consume(future: asyncio.Future) -> None:
            try:
                future.exception()
            except BaseException:
                pass

        result.add_done_callback(consume)

    def _set_finger_state(self, present: object, needed: object) -> None:
        """Update and publish fprintd's historical dynamic properties."""

        if (
            type(present) is not bool
            or type(needed) is not bool
            or (present and needed)
        ):
            raise RuntimeError("finger property state is invalid")
        changed: dict[str, Variant] = {}
        if present != self.finger_present:
            self.finger_present = present
            changed["finger-present"] = Variant("b", present)
        if needed != self.finger_needed:
            self.finger_needed = needed
            changed["finger-needed"] = Variant("b", needed)
        if not changed:
            return
        send = getattr(self.identity_bus, "send", None)
        if not callable(send):
            return
        try:
            result = send(
                Message.new_signal(
                    path=DEVICE_PATH,
                    interface="org.freedesktop.DBus.Properties",
                    member="PropertiesChanged",
                    signature="sa{sv}as",
                    body=[
                        "net.reactivated.Fprint.Device",
                        changed,
                        [],
                    ],
                )
            )
        except Exception:
            # The D-Bus connection itself owns delivery failure. Never turn a
            # best-effort UI property notification into a biometric replay.
            return
        self._consume_signal_send(result)

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
                # NameOwnerChanged delivery can trail a short-lived PAM
                # client's replacement by a few milliseconds.  The pinned
                # process identity is stronger evidence than D-Bus signal
                # ordering: reap only a claim whose exact process is already
                # provably gone.  A live owner remains strictly exclusive.
                old_caller = self.claimed_caller
                old_caller_dead = False
                if old_caller is not None:
                    try:
                        old_caller.verify()
                    except t2_dbus_identity.DBusIdentityError:
                        old_caller_dead = True
                if old_caller_dead:
                    await self._stop_verification(require_running=False)
                    await self._stop_enrollment(require_running=False)
                    await self._wait_deletion(require_running=False)
                    self._clear_claim()
                else:
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
        await self._stop_enrollment(require_running=False)
        await self._wait_deletion(require_running=False)
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
    async def VerifyStart(self, finger_name: "s"):
        self._require_claim_owner()
        if (
            self.verify_task is not None
            or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            )
            or self.delete_task is not None
        ):
            raise DBusError(f"{FPRINT_ERROR}.AlreadyInUse", "verification is active")
        if (
            finger_name != "any"
            and finger_name not in t2_fprint_projection.FINGER_NAME_SET
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "verification requires any or a canonical finger name",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        current_task = asyncio.current_task()
        if current_task is None:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "verification task identity is unavailable",
            )
        self.verify_task = current_task
        started = False
        try:
            async with self.backend.operation_lock:
                view = await self.backend.runtime_projection()
            self._require_claim_owner()
            if self.verify_task is not current_task:
                raise RuntimeError("verification task binding changed")
            if (
                self.delete_task is not None
                or (
                    self.enrollment_client is not None
                    and getattr(self.enrollment_client, "task", None) is not None
                )
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError(
                    "fprint projection returned an invalid result"
                )
            self.enrolled_fingers = view.listed_fingers
            try:
                t2_fprint_runtime.resolve_match(view, finger_name)
            except t2_fprint_runtime.FprintRuntimeError as error:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoEnrolledPrints",
                    "finger is not enrolled",
                ) from error
            # fprint's ABI explicitly permits "any" on this signal to tell
            # clients that any enrolled identity may be presented. Emit the
            # instruction before capture; the exact successful identity is
            # reported later through VerifyFingerMatched. Emitting a resolved
            # VerifyFingerSelected after capture makes pam_fprintd display a
            # stale "place your finger" prompt after authentication.
            self.VerifyFingerSelected(finger_name)
            operation = asyncio.create_task(
                self._run_verification(finger_name)
            )
            self.verify_task = operation
            self._set_finger_state(False, True)
            started = True
        except DBusError:
            raise
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "verification could not be started",
            ) from error
        finally:
            if not started and self.verify_task is current_task:
                self.verify_task = None
            self._arm_unstarted_claim_expiry()

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
                self.VerifyFingerMatched(selected)
            elif verdict == "verify-match":
                self.VerifyFingerMatched(requested_finger)
            self.VerifyStatus(verdict, True)
            if verdict == "verify-match":
                # Authentication is already terminal. Persistence is a
                # separately journaled best-effort operation and can neither
                # delay nor replace the emitted verdict.
                try:
                    self.backend.schedule_adaptive_sync()
                except Exception as error:
                    print(
                        f"Adaptive Catacomb sync scheduling failed: {error}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.backend.notify_feedback("verify-unknown-error")
            self.VerifyStatus("verify-unknown-error", True)
        finally:
            self._set_finger_state(False, False)
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
        if (
            self.verify_task is None
            and (
                self.enrollment_client is None
                or getattr(self.enrollment_client, "task", None) is None
            )
            and self.delete_task is None
        ):
            self._clear_claim()
        self.claim_expiry_task = None

    async def sender_departed(self, sender: str) -> None:
        async with self.claim_lock:
            if sender != self.claimed_sender:
                return
            await self._stop_verification(require_running=False)
            await self._stop_enrollment(require_running=False)
            await self._wait_deletion(require_running=False)
            self._clear_claim()

    async def _stop_verification(self, require_running: bool) -> None:
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None
        task = self.verify_task
        if task is None:
            self._set_finger_state(False, False)
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
        self._set_finger_state(False, False)

    def _arm_unstarted_claim_expiry(self) -> None:
        """Restore bounded claim lifetime after a mutation call returns."""

        client = self.enrollment_client
        if (
            self.claimed_user is not None
            and self.claim_expiry_task is None
            and self.verify_task is None
            and self.delete_task is None
            and (
                client is None
                or getattr(client, "task", None) is None
            )
        ):
            self.claim_expiry_task = asyncio.create_task(
                self._expire_unstarted_claim()
            )

    @method()
    async def EnrollStart(self, finger_name: "s"):
        self._require_claim_owner()
        client = self.enrollment_client
        if client is None:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal", "native enrollment is disabled"
            )
        if (
            self.verify_task is not None
            or getattr(client, "task", None) is not None
            or self.delete_task is not None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.AlreadyInUse", "a biometric operation is active"
            )
        if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "enrollment requires a canonical finger name",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        try:
            # Enrollment persists ``finger_name`` as presentation metadata.
            # Require a fresh, complete projection before mutation so a
            # standard fprint client cannot compound legacy/duplicate labels
            # or silently replace an already enrolled canonical name.
            async with self.backend.operation_lock:
                view = await self.backend.runtime_projection()
            self._require_claim_owner()
            if (
                self.verify_task is not None
                or getattr(client, "task", None) is not None
                or self.delete_task is not None
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError("fprint projection returned an invalid result")
            if not view.complete:
                raise DBusError(
                    f"{FPRINT_ERROR}.Internal",
                    "existing fingerprint labels require migration",
                )
            if finger_name in view.finger_names:
                raise DBusError(
                    f"{FPRINT_ERROR}.InvalidFingername",
                    "finger name is already enrolled",
                )
            client.start(
                finger_name,
                self.claimed_caller,
                self.claimed_evidence,
                self._enrollment_update,
            )
        except DBusError:
            raise
        except Exception as error:
            self._set_finger_state(False, False)
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "native enrollment could not be started",
            ) from error
        finally:
            # This also covers coroutine cancellation while collecting the
            # projection; a failed D-Bus call must not leave an immortal claim.
            self._arm_unstarted_claim_expiry()

    @method()
    async def EnrollStop(self):
        self._require_claim_owner()
        await self._stop_enrollment(require_running=True)

    def _enrollment_update(self, update: object) -> None:
        if not isinstance(
            update, t2_fprint_enrollment_runtime.EnrollmentUpdate
        ):
            raise RuntimeError("enrollment worker emitted malformed state")
        self._set_finger_state(update.finger_present, update.finger_needed)
        if update.status is not None:
            self.EnrollStatus(update.status, update.done)
        if update.done:
            client = self.enrollment_client
            task = getattr(client, "task", None) if client is not None else None
            if task is None:
                raise RuntimeError("terminal enrollment has no retained task")
            self.claim_expiry_task = asyncio.create_task(
                self._expire_stale_enrollment_claim(task)
            )

    async def _expire_stale_enrollment_claim(self, completed_task) -> None:
        try:
            await asyncio.sleep(COMPLETED_CLAIM_SECONDS)
            client = self.enrollment_client
            if client is not None and getattr(client, "task", None) is completed_task:
                try:
                    await client.stop()
                except Exception:
                    pass
                finally:
                    self._set_finger_state(False, False)
                    self._clear_claim()
        finally:
            self.claim_expiry_task = None

    async def _stop_enrollment(self, require_running: bool) -> None:
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None
        client = self.enrollment_client
        task = getattr(client, "task", None) if client is not None else None
        if task is None:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoActionInProgress",
                    "enrollment is not active",
                )
            self._set_finger_state(False, False)
            return
        try:
            await client.stop()
        except Exception as error:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.Internal",
                    "native enrollment did not stop cleanly",
                ) from error
        finally:
            self._set_finger_state(False, False)

    async def _wait_deletion(self, require_running: bool) -> None:
        task = self.delete_task
        if task is None:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoActionInProgress",
                    "deletion is not active",
                )
            return
        if task is asyncio.current_task():
            raise RuntimeError("deletion task cannot wait for itself")
        await asyncio.gather(asyncio.shield(task), return_exceptions=True)
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None

    @method()
    def DeleteEnrolledFingers(self, username: "s"):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    def DeleteEnrolledFingers2(self):
        self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    async def DeleteEnrolledFinger(self, finger_name: "s"):
        self._require_claim_owner()
        client = self.deletion_client
        if client is None:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "native single-finger deletion is disabled",
            )
        if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "deletion requires a canonical finger name",
            )
        if (
            self.verify_task is not None
            or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            )
            or self.delete_task is not None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.AlreadyInUse",
                "a biometric operation is active",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        current_task = asyncio.current_task()
        if current_task is None:
            raise DBusError(
                f"{FPRINT_ERROR}.PrintsNotDeleted",
                "deletion task identity is unavailable",
            )
        self.delete_task = current_task
        try:
            async with self.backend.operation_lock:
                view = await self.backend.runtime_projection()
            self._require_claim_owner()
            if self.delete_task is not current_task:
                raise RuntimeError("deletion task binding changed")
            if self.verify_task is not None or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError("fprint projection returned an invalid result")
            if not view.complete:
                raise DBusError(
                    f"{FPRINT_ERROR}.PrintsNotDeleted",
                    "existing fingerprint labels require migration",
                )
            if finger_name not in view.finger_names:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoEnrolledPrints",
                    "finger is not enrolled",
                )
            if view.reconciled_identity_count <= 1:
                raise DBusError(
                    f"{FPRINT_ERROR}.PrintsNotDeleted",
                    "the final fingerprint identity cannot be deleted",
                )
            operation = asyncio.create_task(
                client.delete(
                    finger_name,
                    self.claimed_caller,
                    self.claimed_evidence,
                )
            )
            try:
                result = await asyncio.shield(operation)
            except asyncio.CancelledError:
                # Once the injected client has accepted the request, caller
                # cancellation cannot kill or replay a possibly dispatched
                # delete. Wait for its journaled reconciliation boundary.
                await asyncio.gather(operation, return_exceptions=True)
                raise
            if (
                type(result)
                is not t2_fprint_deletion_runtime.DeletionCompletion
                or result.finger_name != finger_name
            ):
                raise RuntimeError("deletion client returned an invalid result")
        except DBusError:
            raise
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PrintsNotDeleted",
                "single-finger deletion did not reconcile",
            ) from error
        finally:
            if self.delete_task is current_task:
                self.delete_task = None
            self._arm_unstarted_claim_expiry()

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


def enrollment_client_for_arguments(args: argparse.Namespace):
    """Construct no mutation client unless the process flag is exactly set."""

    if not isinstance(args, argparse.Namespace):
        raise RuntimeError("fprintd arguments are invalid")
    enabled = getattr(args, "enable_native_enrollment", None)
    if type(enabled) is not bool:
        raise RuntimeError("native enrollment activation is invalid")
    return (
        t2_fprint_worker_client.EnrollmentWorkerClient()
        if enabled
        else None
    )


def deletion_client_for_arguments(args: argparse.Namespace):
    """Construct no deletion worker client unless its flag is exactly set."""

    if not isinstance(args, argparse.Namespace):
        raise RuntimeError("fprintd arguments are invalid")
    enabled = getattr(args, "enable_native_deletion", None)
    if type(enabled) is not bool:
        raise RuntimeError("native deletion activation is invalid")
    return (
        t2_fprint_delete_worker_client.DeletionWorkerClient()
        if enabled
        else None
    )


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


def legacy_introspection_reply(message: Message, device: FprintDevice):
    """Advertise the same historical properties served by the raw handler."""

    if (
        not isinstance(message, Message)
        or not isinstance(device, FprintDevice)
        or message.message_type != MessageType.METHOD_CALL
        or message.path != DEVICE_PATH
        or message.interface != "org.freedesktop.DBus.Introspectable"
        or message.member != "Introspect"
        or message.body
        or str(message.signature)
    ):
        return False
    node = dbus_introspection.Node.default(DEVICE_PATH)
    node.interfaces.append(device.introspect())
    document = node.tostring()
    closing = document.rfind("</interface>")
    if closing < 0:
        raise RuntimeError("fprint introspection has no device interface")
    # dbus-next correctly rejects hyphens as D-Bus member names, while
    # fprintd's long-standing property ABI nevertheless uses them. The raw
    # Get/GetAll handler already serves these exact names; inject only their
    # XML declarations into the final exported interface.
    declarations = "".join(
        f'    <property name="{name}" type="{signature}" access="read" />\n'
        for name, signature in (
            ("num-enroll-stages", "i"),
            ("scan-type", "s"),
            ("finger-present", "b"),
            ("finger-needed", "b"),
        )
    )
    document = document[:closing] + declarations + document[closing:]
    return Message.new_method_return(
        message, signature="s", body=[document]
    )


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
    device = FprintDevice(
        backend,
        bus,
        enrollment_client=enrollment_client_for_arguments(args),
        deletion_client=deletion_client_for_arguments(args),
    )

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

    def legacy_introspection_handler(message: Message):
        return legacy_introspection_reply(message, device)

    bus.add_message_handler(legacy_introspection_handler)
    bus.add_message_handler(legacy_property_handler)
    bus.add_message_handler(sender_departure_handler)
    bus.export(MANAGER_PATH, FprintManager())
    bus.export(DEVICE_PATH, device)
    await bus.request_name(BUS_NAME)
    await asyncio.get_running_loop().create_future()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--match-seconds", type=float, default=20.0)
    parser.add_argument(
        "--enable-native-enrollment",
        action="store_true",
        help=(
            "activate the credential-scoped journaled enrollment worker; "
            "omit until every installed hardware gate passes"
        ),
    )
    parser.add_argument(
        "--enable-native-deletion",
        action="store_true",
        help=(
            "activate the credential-free journaled single-delete worker; "
            "omit until every installed hardware gate passes"
        ),
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
