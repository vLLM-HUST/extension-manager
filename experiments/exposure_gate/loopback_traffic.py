"""Bounded loopback HTTP traffic authority for research integration tests.

The authority runs in a process separate from the gate. It owns the only
client-facing port and answers route queries over a private Unix socket.
It is not a production reverse proxy or a general deployment controller.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
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
from vllm_hust_ext.host_evidence import EntryPointBinding
from vllm_hust_ext.host_observer import observe_bound_invocations
from vllm_hust_ext.plan_artifact import read_plan_artifact

MAX_MESSAGE = 64 * 1024
MAX_BODY = 1024 * 1024
MAX_JOURNAL = 4 * 1024 * 1024
JOURNAL_SCHEMA = "ecpa-loopback-route-journal/v1"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
JOURNAL_KINDS = {
    "authority.start",
    "authority.stop",
    "route.close_checked",
    "route.open.intent",
    "route.open.applied",
    "route.restore.intent",
    "route.restore.applied",
    "route.close_all",
    "request.admit",
    "request.reject",
}


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


class _TrafficJournal:
    """Traffic-process-owned route/admission trace, not a host-effect receipt."""

    def __init__(self, path: Path):
        parent = path.parent.stat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
            or os.path.lexists(path)
        ):
            raise GateError(
                "traffic journal requires a new path in a private directory"
            )
        stat_fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        self.start_ticks = int(stat_fields[19])
        self.pid = os.getpid()
        self.sequence = 0
        self.previous = "sha256:" + "0" * 64
        self.fd = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
        )

    def record(self, kind: str, route: RouteState, **detail: Any) -> None:
        next_sequence = self.sequence + 1
        event = {
            "schema": JOURNAL_SCHEMA,
            "sequence": next_sequence,
            "previous_sha256": self.previous,
            "at_ns": time.time_ns(),
            "proxy_pid": self.pid,
            "proxy_start_ticks": self.start_ticks,
            "kind": kind,
            "route": {
                "generation": route.generation,
                "fence": route.fence,
                "snapshot_sha256": "sha256:"
                + hashlib.sha256(_canonical({"snapshot": route.snapshot})).hexdigest(),
            },
            "detail": detail,
        }
        payload = _canonical(event)
        line = payload + b"\n"
        if os.fstat(self.fd).st_size + len(line) > MAX_JOURNAL:
            raise OSError("traffic journal capacity exceeded")
        written = 0
        while written < len(line):
            count = os.write(self.fd, line[written:])
            if count <= 0:
                raise OSError("traffic journal write failed")
            written += count
        os.fsync(self.fd)
        self.sequence = next_sequence
        self.previous = "sha256:" + hashlib.sha256(payload).hexdigest()

    def close(self) -> None:
        os.close(self.fd)


def read_traffic_journal(path: Path) -> list[dict[str, Any]]:
    """Validate an integration trace without promoting it to formal evidence."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            mode = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(mode.st_mode)
                or mode.st_uid != os.getuid()
                or mode.st_mode & 0o077
                or mode.st_size > MAX_JOURNAL
            ):
                raise GateError("traffic journal owner, mode, or size invalid")
            data = source.read(MAX_JOURNAL + 1)
    except OSError as exc:
        raise GateError("traffic journal cannot be opened safely") from exc
    if not data or len(data) > MAX_JOURNAL or not data.endswith(b"\n"):
        raise GateError("traffic journal is empty, oversized, or incomplete")
    previous = "sha256:" + "0" * 64
    events: list[dict[str, Any]] = []
    identity: tuple[int, int] | None = None
    for sequence, line in enumerate(data.splitlines(), 1):
        try:
            event = json.loads(line)
            canonical = isinstance(event, dict) and _canonical(event) == line
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise GateError("traffic journal contains invalid JSON") from exc
        if (
            not canonical
            or event.get("schema") != JOURNAL_SCHEMA
            or event.get("sequence") != sequence
            or event.get("previous_sha256") != previous
        ):
            raise GateError(
                "traffic journal sequence, chain, or canonical form changed"
            )
        route = event.get("route")
        if (
            event.get("kind") not in JOURNAL_KINDS
            or not isinstance(event.get("proxy_pid"), int)
            or event["proxy_pid"] <= 0
            or not isinstance(event.get("proxy_start_ticks"), int)
            or event["proxy_start_ticks"] <= 0
            or not isinstance(event.get("at_ns"), int)
            or not isinstance(event.get("detail"), dict)
            or not isinstance(route, dict)
            or set(route) != {"generation", "fence", "snapshot_sha256"}
            or not (route["generation"] is None or isinstance(route["generation"], int))
            or not isinstance(route["fence"], str)
            or not isinstance(route["snapshot_sha256"], str)
            or SHA256.fullmatch(route["snapshot_sha256"]) is None
        ):
            raise GateError("traffic journal event shape invalid")
        observed_identity = (event["proxy_pid"], event["proxy_start_ticks"])
        if identity is None:
            identity = observed_identity
        elif observed_identity != identity:
            raise GateError("traffic journal process identity changed")
        if event["kind"] == "request.admit" and route["generation"] is None:
            raise GateError("traffic journal admitted a closed route")
        if event["kind"] == "request.reject" and route["generation"] is not None:
            raise GateError("traffic journal rejected an open route")
        previous = "sha256:" + hashlib.sha256(line).hexdigest()
        events.append(event)
    if events[0]["kind"] != "authority.start":
        raise GateError("traffic journal has no authority start")
    return events


class _HostAuthorization:
    """Frozen host-observer inputs read by the traffic process, not its caller."""

    def __init__(self, path: Path):
        if not path.is_absolute() or path.is_symlink():
            raise GateError("host authorization path must be absolute and real")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as source:
                metadata = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size > MAX_MESSAGE
                ):
                    raise GateError("host authorization file is not private")
                raw = source.read(MAX_MESSAGE + 1)
            value = json.loads(raw)
        except (OSError, ValueError, UnicodeError) as exc:
            raise GateError("host authorization cannot be read safely") from exc
        fields = {
            "schema",
            "plan_path",
            "journal_dir",
            "journal_device",
            "journal_inode",
            "launch_id",
            "controller_instance",
            "local_host",
            "bindings",
            "required_processes",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise GateError("host authorization fields do not match schema")
        if value["schema"] != "ecpa-loopback-host-authorization/v1":
            raise GateError("unsupported host authorization schema")
        try:
            self.plan = read_plan_artifact(value["plan_path"]).plan
            self.root = Path(value["journal_dir"])
            self.directory_identity = (
                value["journal_device"],
                value["journal_inode"],
            )
            self.launch_id = value["launch_id"]
            self.controller_instance = value["controller_instance"]
            self.local_host = value["local_host"]
            self.bindings = tuple(
                EntryPointBinding(**binding) for binding in value["bindings"]
            )
            self.required_processes = tuple(value["required_processes"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError("host authorization values are invalid") from exc
        if (
            not isinstance(self.launch_id, str)
            or not self.launch_id
            or not isinstance(self.controller_instance, str)
            or not self.controller_instance
            or not isinstance(self.local_host, str)
            or not self.local_host
            or not self.root.is_absolute()
            or self.root.is_symlink()
            or not self.required_processes
            or not self.bindings
        ):
            raise GateError("host authorization identity is incomplete")

    def authorize(self, snapshot: dict[str, Any]) -> str:
        if (
            snapshot.get("plan_id") != self.plan.plan_id
            or snapshot.get("launch_id") != self.launch_id
            or snapshot.get("controller_instance") != self.controller_instance
        ):
            raise GateError("candidate route is not bound to host authorization")
        try:
            observation = observe_bound_invocations(
                self.root,
                expected_directory_identity=self.directory_identity,
                plan=self.plan,
                launch_id=self.launch_id,
                controller_instance=self.controller_instance,
                bindings=self.bindings,
                required_processes=self.required_processes,
                local_host=self.local_host,
            )
        except Exception as exc:
            raise GateError(
                "host observation is unavailable for frozen membership"
            ) from exc
        if not observation["complete_coverage"]:
            raise GateError("host observation does not cover frozen membership")
        return "sha256:" + hashlib.sha256(_canonical(observation)).hexdigest()


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
        journal: _TrafficJournal,
        observer: _HostAuthorization | None = None,
    ):
        self.route = route
        self.grant = grant
        self.predecessor = predecessor
        self.candidate = candidate
        self.journal = journal
        self.observer = observer
        self.lock = threading.Lock()
        self.journal.record("authority.start", route)

    def _record(self, kind: str, route: RouteState, **detail: Any) -> None:
        try:
            self.journal.record(kind, route, **detail)
        except (OSError, TypeError, ValueError) as exc:
            self.route = RouteState(None, "closed", None)
            raise GateError(
                "traffic journal unavailable; routing failed closed"
            ) from exc

    def _refresh_candidate(self) -> str | None:
        if (
            self.observer is None
            or self.route.generation is None
            or not self.route.fence.startswith("gate-")
        ):
            return None
        try:
            if self.grant.expires_at < int(time.time()):
                raise GateError("traffic lease expired")
            if not isinstance(self.route.snapshot, dict):
                raise GateError("candidate route snapshot is unavailable")
            return self.observer.authorize(self.route.snapshot)
        except GateError:
            self.route = RouteState(None, "closed", None)
            self._record(
                "route.close_all", self.route, reason="host observation lost"
            )
            return None

    def apply(self, value: dict[str, Any]) -> dict[str, Any]:
        operation = value.get("operation")
        with self.lock:
            if operation == "query":
                self._refresh_candidate()
                return {"route": asdict(self.route)}
            if operation == "lease_valid":
                return {"valid": self._valid(value)}
            if operation == "close":
                if (
                    self.route.generation is None
                    or value.get("generation") != self.route.generation + 1
                ):
                    raise GateError("candidate generation does not follow predecessor")
                self._record(
                    "route.close_checked",
                    self.route,
                    candidate_generation=value["generation"],
                )
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
                observation_sha256 = (
                    self.observer.authorize(snapshot)
                    if self.observer is not None
                    else None
                )
                candidate_route = RouteState(generation, fence, snapshot)
                self._record(
                    "route.open.intent",
                    self.route,
                    candidate_generation=generation,
                    candidate_fence=fence,
                    observation_sha256=observation_sha256,
                )
                self.route = candidate_route
                self._record("route.open.applied", self.route)
                return {}
            if operation == "close_all":
                self.route = RouteState(None, "closed", None)
                self._record("route.close_all", self.route)
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
                predecessor_route = RouteState(generation, fence, snapshot)
                self._record("route.restore.intent", self.route, generation=generation)
                self.route = predecessor_route
                self._record("route.restore.applied", self.route)
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
        journal_failed = False
        with self.server.authority.lock:
            try:
                observation_sha256 = self.server.authority._refresh_candidate()
                route = self.server.authority.route
                self.server.authority._record(
                    "request.reject" if route.generation is None else "request.admit",
                    route,
                    method=self.command,
                    observation_sha256=observation_sha256,
                )
            except GateError:
                journal_failed = True
        if journal_failed:
            self.send_error(503, "traffic journal unavailable")
            return
        if route.generation is None:
            self.send_error(503, "traffic gate closed")
            return
        backend = (
            self.server.authority.predecessor
            if route.fence.startswith("fence-")
            else self.server.authority.candidate
        )
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
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--predecessor-port", type=int, required=True)
    parser.add_argument("--candidate-port", type=int, required=True)
    parser.add_argument("--predecessor-snapshot", required=True)
    parser.add_argument("--grant-holder", required=True)
    parser.add_argument("--grant-token", type=int, required=True)
    parser.add_argument("--grant-expires-at", type=int, required=True)
    parser.add_argument("--observer-config", type=Path)
    args = parser.parse_args()
    predecessor = json.loads(args.predecessor_snapshot)
    if not isinstance(predecessor, dict) or not isinstance(
        predecessor.get("generation"), int
    ):
        raise GateError("predecessor snapshot requires generation")
    observer = (
        _HostAuthorization(args.observer_config)
        if args.observer_config is not None
        else None
    )
    journal = _TrafficJournal(args.journal)
    try:
        authority = _Authority(
            RouteState(
                predecessor["generation"],
                f"fence-{predecessor['generation']}",
                predecessor,
            ),
            LeaseGrant(args.grant_holder, args.grant_token, args.grant_expires_at),
            ("127.0.0.1", args.predecessor_port),
            ("127.0.0.1", args.candidate_port),
            journal,
            observer,
        )
        server = _ProxyServer(authority)
    except Exception:
        journal.close()
        raise
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop(_signal: int, _frame: Any) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        _admin(args.socket, authority, server.server_port)
    finally:
        with authority.lock:
            authority.route = RouteState(None, "closed", None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        with authority.lock, suppress(GateError):
            authority._record("authority.stop", authority.route)
        journal.close()
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
