"""Bounded loopback HTTP traffic authority for research integration tests.

The authority runs in a process separate from the gate. It owns the only
client-facing port and answers route queries over a private Unix socket.
It is not a production reverse proxy or a general deployment controller.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import stat
import struct
import threading
import time
from contextlib import suppress
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from vllm_hust_ext.exposure_gate import (
    GateError,
    LeaseAuthority,
    LeaseGrant,
    RouteState,
)

MAX_MESSAGE = 64 * 1024
MAX_BODY = 1024 * 1024


class LoopbackTrafficAdapter:
    """Control client for a separately running traffic-authority process."""

    behavioral_restore = False

    def __init__(self, socket_path: Path, grant: LeaseGrant):
        self.socket_path = socket_path
        self.authority = LeaseAuthority(grant)

    def _call(self, operation: str, **fields: Any) -> dict[str, Any]:
        payload = json.dumps(
            {"operation": operation, **fields}, sort_keys=True, separators=(",", ":")
        ).encode()
        if len(payload) > MAX_MESSAGE:
            raise GateError("traffic control request too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(self.socket_path))
            client.sendall(payload + b"\n")
            response = bytearray()
            while not response.endswith(b"\n"):
                chunk = client.recv(4096)
                if not chunk or len(response) + len(chunk) > MAX_MESSAGE:
                    raise GateError(
                        "traffic authority response incomplete or oversized"
                    )
                response.extend(chunk)
        value = json.loads(response)
        if not isinstance(value, dict):
            raise GateError("traffic authority returned a non-object response")
        if value.get("ok") is not True:
            raise GateError(
                str(value.get("error", "traffic authority rejected request"))
            )
        return value

    def close(self, generation: int) -> None:
        self._call("close", generation=generation)

    def open(
        self,
        generation: int,
        fence: str,
        snapshot: dict[str, Any],
        grant: LeaseGrant,
        now: int,
    ) -> None:
        self._call(
            "open",
            generation=generation,
            fence=fence,
            snapshot=snapshot,
            grant=asdict(grant),
            now=now,
        )

    def close_all(self) -> None:
        self._call("close_all")

    def restore(
        self, generation: int, fence: str, snapshot: dict[str, Any]
    ) -> RouteState:
        self._call("restore", generation=generation, fence=fence, snapshot=snapshot)
        return self.query_route()

    def lease_valid(self, grant: LeaseGrant, now: int) -> bool:
        return self._call("lease_valid", grant=asdict(grant), now=now)["valid"] is True

    def query_route(self) -> RouteState:
        value = self._call("query")["route"]
        return RouteState(value["generation"], value["fence"], value["snapshot"])


class _Authority:
    def __init__(
        self,
        route: RouteState,
        grant: LeaseGrant,
        predecessor: tuple[str, int],
        candidate: tuple[str, int],
    ):
        self.route = route
        self.grant = grant
        self.predecessor = predecessor
        self.candidate = candidate
        self.lock = threading.Lock()

    def apply(self, value: dict[str, Any]) -> dict[str, Any]:
        operation = value.get("operation")
        with self.lock:
            if operation == "query":
                return {"route": asdict(self.route)}
            if operation == "lease_valid":
                return {"valid": self._valid(value)}
            if operation == "close":
                if (
                    self.route.generation is None
                    or value.get("generation") != self.route.generation + 1
                ):
                    raise GateError("candidate generation does not follow predecessor")
                return {}
            if operation == "open":
                if not self._valid(value):
                    raise GateError("traffic lease changed or expired")
                generation = value.get("generation")
                fence = value.get("fence")
                snapshot = value.get("snapshot")
                if (
                    self.route.generation is None
                    or generation != self.route.generation + 1
                    or not isinstance(fence, str)
                    or not fence.startswith("gate-")
                    or not isinstance(snapshot, dict)
                ):
                    raise GateError("invalid candidate route transition")
                self.route = RouteState(generation, fence, snapshot)
                return {}
            if operation == "close_all":
                self.route = RouteState(None, "closed", None)
                return {}
            if operation == "restore":
                generation = value.get("generation")
                fence = value.get("fence")
                snapshot = value.get("snapshot")
                if (
                    generation is None
                    or fence != f"fence-{generation}"
                    or not isinstance(snapshot, dict)
                ):
                    raise GateError("invalid predecessor restoration")
                self.route = RouteState(generation, fence, snapshot)
                return {"route": asdict(self.route)}
        raise GateError("unknown traffic control operation")

    def _valid(self, value: dict[str, Any]) -> bool:
        try:
            supplied = LeaseGrant(**value["grant"])
            now = int(value["now"])
        except (KeyError, TypeError, ValueError):
            return False
        return (
            supplied == self.grant
            and self.grant.expires_at >= now
            and self.grant.expires_at >= int(time.time())
        )


class _ProxyHandler(BaseHTTPRequestHandler):
    server: _ProxyServer

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def _forward(self) -> None:
        with self.server.authority.lock:
            route = self.server.authority.route
        if route.generation is None:
            self.send_error(503, "traffic gate closed")
            return
        backend = (
            self.server.authority.predecessor
            if route.fence.startswith("fence-")
            else self.server.authority.candidate
        )
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_error(400, "chunked requests unsupported")
            return
        try:
            body_size = int(self.headers.get("Content-Length", "0"))
            if body_size < 0 or body_size > MAX_BODY:
                raise ValueError
        except ValueError:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(body_size)
        try:
            connection = http.client.HTTPConnection(*backend, timeout=5)
            try:
                connection.request(
                    self.command,
                    self.path,
                    body=body,
                    headers={"Content-Type": self.headers.get("Content-Type", "")},
                )
                response = connection.getresponse()
                payload = response.read(MAX_BODY + 1)
                if len(payload) > MAX_BODY:
                    raise GateError("backend response too large")
                self.send_response(response.status)
                self.send_header("Content-Type", response.getheader("Content-Type", ""))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                connection.close()
        except (OSError, GateError):
            self.send_error(502, "backend unavailable")

    def log_message(self, _format: str, *_args: Any) -> None:
        pass


class _ProxyServer(ThreadingHTTPServer):
    def __init__(self, authority: _Authority):
        super().__init__(("127.0.0.1", 0), _ProxyHandler)
        self.authority = authority


def _admin(socket_path: Path, authority: _Authority, port: int) -> None:
    parent = socket_path.parent.stat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o077
    ):
        raise GateError("traffic control directory must be private and owned")
    if os.path.lexists(socket_path):
        raise GateError("traffic control socket already exists")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        print(json.dumps({"port": port}), flush=True)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _pid, uid, _gid = struct.unpack("3i", peer)
                if uid != os.getuid():
                    continue
                request = bytearray()
                while not request.endswith(b"\n") and len(request) <= MAX_MESSAGE:
                    try:
                        chunk = connection.recv(4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    request.extend(chunk)
                try:
                    if len(request) > MAX_MESSAGE or not request.endswith(b"\n"):
                        raise GateError("invalid traffic control message")
                    value = json.loads(request)
                    if not isinstance(value, dict):
                        raise GateError("traffic control request must be an object")
                    result = {"ok": True, **authority.apply(value)}
                except (GateError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    result = {"ok": False, "error": str(exc)}
                with suppress(OSError):
                    connection.sendall(
                        json.dumps(result, separators=(",", ":")).encode() + b"\n"
                    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--predecessor-port", type=int, required=True)
    parser.add_argument("--candidate-port", type=int, required=True)
    parser.add_argument("--predecessor-snapshot", required=True)
    parser.add_argument("--grant-holder", required=True)
    parser.add_argument("--grant-token", type=int, required=True)
    parser.add_argument("--grant-expires-at", type=int, required=True)
    args = parser.parse_args()
    predecessor = json.loads(args.predecessor_snapshot)
    if not isinstance(predecessor, dict) or not isinstance(
        predecessor.get("generation"), int
    ):
        raise GateError("predecessor snapshot requires generation")
    authority = _Authority(
        RouteState(
            predecessor["generation"], f"fence-{predecessor['generation']}", predecessor
        ),
        LeaseGrant(args.grant_holder, args.grant_token, args.grant_expires_at),
        ("127.0.0.1", args.predecessor_port),
        ("127.0.0.1", args.candidate_port),
    )
    server = _ProxyServer(authority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop(_signal: int, _frame: Any) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        _admin(args.socket, authority, server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
