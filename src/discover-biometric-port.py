#!/usr/bin/env python3
"""Discover the T2 BiometricKit BridgeXPC port through RemoteXPC.

Run this with the repository virtual environment, which installs
``pymobiledevice3``. Only the service port is printed; device identifiers from
the RemoteXPC peer record are never emitted.
"""

import argparse
import asyncio
import os
import socket
import sys


RSD_SERVICE = "com.apple.eos.BiometricKit"
FIRST_DYNAMIC_PORT = 49152
LAST_DYNAMIC_PORT = 65535
HTTP2_SETTINGS = 4


async def probe_port(
    host: str,
    port: int,
    scope_id: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> int | None:
    async with semaphore:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port, 0, scope_id)), timeout
            )
            greeting = await asyncio.wait_for(loop.sock_recv(sock, 21), timeout)
            if (
                len(greeting) >= 9
                and greeting[3] == HTTP2_SETTINGS
                and greeting[5:9] == b"\0\0\0\0"
            ):
                return port
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            sock.close()
    return None


async def discover_rsd_ports(
    host: str, interface: str, timeout: float, concurrency: int
) -> list[int]:
    scope_id = socket.if_nametoindex(interface)
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(
            probe_port(host, port, scope_id, semaphore, timeout)
        )
        for port in range(FIRST_DYNAMIC_PORT, LAST_DYNAMIC_PORT + 1)
    ]
    ports = [port for port in await asyncio.gather(*tasks) if port is not None]
    if not ports:
        raise RuntimeError("T2 Remote Service Discovery endpoint was not found")
    return ports


async def main_async(args: argparse.Namespace) -> None:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with .venv-re/bin/python and "
            "PYTHONPATH=third-party/pymobiledevice3"
        ) from error

    candidate_ports = await discover_rsd_ports(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    scoped_host = f"{args.host}%{args.interface}"
    for candidate_port in candidate_ports:
        connection = RemoteXPCConnection((scoped_host, candidate_port))
        try:
            async def receive_peer_record() -> dict:
                await connection.connect()
                await connection.send_device_handshake()
                return await connection.receive_response()

            peer = await asyncio.wait_for(receive_peer_record(), 2.0)
            if args.list_services:
                services = peer.get("Services", {})
                if isinstance(services, dict) and services:
                    for name in sorted(services):
                        print(name)
                    return
                continue
            service = peer.get("Services", {}).get(RSD_SERVICE)
            if not isinstance(service, dict) or "Port" not in service:
                continue
            port = int(service["Port"])
            if not FIRST_DYNAMIC_PORT <= port <= LAST_DYNAMIC_PORT:
                raise RuntimeError("T2 advertised an invalid BiometricKit port")
            print(port)
            return
        except Exception:
            # Several other T2 services use the same HTTP/2 transport but
            # reject the RSD peer-record request.  They are expected decoys,
            # not discovery failures.
            continue
        finally:
            await connection.close()
    raise RuntimeError(f"T2 did not advertise {RSD_SERVICE}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument(
        "--interface", default=os.environ.get("T2_TOUCHID_INTERFACE")
    )
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--concurrency", type=int, default=512)
    parser.add_argument(
        "--list-services",
        action="store_true",
        help="print advertised service names without ports or device identifiers",
    )
    args = parser.parse_args()
    if not args.host or not args.interface:
        parser.error(
            "set --host/--interface or T2_TOUCHID_HOST/T2_TOUCHID_INTERFACE"
        )
    if not 1 <= args.concurrency <= 2048:
        parser.error("--concurrency must be between 1 and 2048")
    try:
        asyncio.run(main_async(args))
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
