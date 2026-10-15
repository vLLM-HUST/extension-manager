"""Live, bounded release of ONE verified frozen response; never forwards requests.

This diagnostic authority is deliberately outside the formal traffic gate. A new
producer challenge and live process checks are mandatory for every public read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CLASSIFICATION = "REAL_LIVE_BOUNDED_RESPONSE_RELEASE_NONFORMAL"
SCOPE_KEYS = (
    "execution_plan_id",
    "native_plan_id",
    "native_launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
)
IDENTITY_KEYS = {"pid", "start_ticks", "session", "boot_id"}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def identity(pid: int) -> dict[str, Any]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    require(fields[0] not in {"Z", "X"}, "process is not live")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "session": int(fields[3]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def check_identity(expected: Any) -> None:
    require(
        isinstance(expected, dict) and set(expected) >= IDENTITY_KEYS,
        "missing process identity",
    )
    require(type(expected["pid"]) is int and expected["pid"] > 0, "invalid process PID")
    require(
        type(expected["start_ticks"]) is int and type(expected["session"]) is int,
        "invalid process epoch",
    )
    require(
        identity(expected["pid"]) == {k: expected[k] for k in IDENTITY_KEYS},
        "process epoch changed",
    )


def read_json(path: Path) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    value = json.loads(
        path.read_bytes(),
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
    )
    require(isinstance(value, dict), "JSON document is not an object")
    return value


class Journal:
    """Append-only local audit, with a fsync before answering any public request."""

    def __init__(self, path: Path):
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.sequence = 0
        self.previous = "0" * 64
        self.lock = threading.Lock()

    def append(self, event: str, **fields: Any) -> None:
        with self.lock:
            self.sequence += 1
            entry = {
                "schema": "ecpa-live-native-semantic-authority-journal/v1",
                "sequence": self.sequence,
                "previous_sha256": self.previous,
                "event": event,
                "monotonic_ns": time.monotonic_ns(),
                "classification": CLASSIFICATION,
                "formal_result": False,
                **fields,
            }
            self.previous = digest(canonical(entry))
            raw = canonical({**entry, "sha256": self.previous}) + b"\n"
            view = memoryview(raw)
            while view:
                written = os.write(self.fd, view)
                require(written > 0, "journal write failed")
                view = view[written:]
            os.fsync(self.fd)

    def close(self) -> None:
        os.close(self.fd)


class Authority:
    def __init__(
        self, registration_path: Path, descriptor_path: Path, journal_path: Path
    ):
        self.registration_path = registration_path
        self.registration_raw = registration_path.read_bytes()
        self.registration = read_json(registration_path)
        self.registration_sha256 = digest(canonical(self.registration))
        self.descriptor_path = descriptor_path
        self.descriptor_raw = descriptor_path.read_bytes()
        self.descriptor = read_json(descriptor_path)
        r, d = self.registration, self.descriptor
        require(
            r.get("schema") == "ecpa-live-native-semantic-registration/v1"
            and r.get("formal_result") is False,
            "registration schema/scope differs",
        )
        require(
            d.get("schema") == "ecpa-live-native-semantic-producer-ready/v1",
            "producer descriptor schema differs",
        )
        require(
            d.get("registration_sha256") == self.registration_sha256,
            "producer registration binding differs",
        )
        require(
            type(r.get("max_validity_ns")) is int
            and 0 < r["max_validity_ns"] <= 30_000_000_000,
            "lease bound invalid",
        )
        self.max_validity_ns = r["max_validity_ns"]
        plan = read_json(Path(r["plan_path"]))
        execution_id = r.get(
            "execution_plan_id",
            plan.get("execution_plan_id", plan.get("plan_id", plan.get("id"))),
        )
        require(
            isinstance(execution_id, str) and bool(execution_id),
            "execution plan identity missing",
        )
        self.scope = {key: r[key] for key in SCOPE_KEYS if key != "execution_plan_id"}
        self.scope["execution_plan_id"] = execution_id
        require(
            all(
                value is not None and not isinstance(value, (dict, list, bool))
                for value in self.scope.values()
            ),
            "scope value invalid",
        )
        self.source_path = Path(
            r.get(
                "producer_source_path",
                d.get(
                    "source_path",
                    str(Path(__file__).with_name("live_semantic_producer.py")),
                ),
            )
        )
        require(
            d.get("source_sha256")
            == r.get(
                "producer_source_sha256", r.get("source_sha256", d.get("source_sha256"))
            )
            == digest(self.source_path.read_bytes()),
            "producer source binding differs",
        )
        require(
            d.get("socket_path") == r.get("producer_socket"), "producer socket differs"
        )
        recipe = read_json(Path(r["recipe_path"]))
        phases = [
            phase
            for phase in recipe["phases"]
            if phase.get("phase_id") == r["phase_id"]
        ]
        require(len(phases) == 1, "frozen phase is ambiguous")
        self.phase = phases[0]
        self.method = self.phase.get("method", "POST")
        require(self.method == "POST", "frozen method differs")
        parsed = urlsplit(self.phase["url"])
        self.request_path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        self.output = Path(r["probe_output"])
        self.frozen_request = canonical(self.phase["payload"])
        require(
            self.frozen_request == canonical(self.phase["payload"]),
            "frozen request binding differs",
        )
        self.request_sha256 = digest(self.frozen_request)
        require(
            isinstance(self.phase.get("external_request_id"), str)
            and bool(self.phase["external_request_id"]),
            "external request identity missing",
        )
        self.journal = Journal(journal_path)
        self.last_ready: bool | None = None
        self.journal.append(
            "authority-started",
            authority=identity(os.getpid()),
            registration_sha256=self.registration_sha256,
            producer=d["producer"],
            scope=self.scope,
        )

    def _socket_identity(self) -> None:
        path = Path(self.descriptor["socket_path"])
        meta = path.lstat()
        parent = path.parent.stat()
        require(
            path.is_absolute() and path.parent.resolve() == path.parent,
            "producer socket directory is not canonical",
        )
        require(
            parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
            "producer socket parent is not private",
        )
        require(
            stat.S_ISSOCK(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and not stat.S_IMODE(meta.st_mode) & 0o077,
            "producer socket is not private",
        )
        require(
            self.descriptor["socket_identity"]
            == {"device": meta.st_dev, "inode": meta.st_ino},
            "producer socket was replaced",
        )

    def _epochs(self) -> None:
        check_identity(self.descriptor["producer"])
        check_identity(self.registration["manager_identity"])
        check_identity(self.registration["owner_identity"])
        peers = self.registration["source_peers"]
        require(isinstance(peers, list) and bool(peers), "live source peers missing")
        for peer in peers:
            check_identity(
                peer.get("process", peer) if isinstance(peer, dict) else peer
            )

    def _response(self, proof: dict[str, Any]) -> bytes:
        body = (self.output / "response.bin").read_bytes()
        metadata = read_json(self.output / "response-metadata.json")
        require(
            metadata.get("schema") == "ecpa-observed-KV-HTTP-response/v2"
            and type(metadata.get("status")) is int
            and metadata["status"] == 200,
            "probe HTTP response is not successful",
        )
        require(
            metadata.get("request_sha256")
            == self.request_sha256
            == proof["request_sha256"]
            and metadata.get("response_sha256")
            == digest(body)
            == proof["response_sha256"]
            and metadata.get("url") == self.phase["url"],
            "probe response binding differs",
        )
        require(
            (self.output / "request.bin").read_bytes() == self.frozen_request,
            "frozen request file changed",
        )
        return body

    def challenge(self) -> tuple[dict[str, Any], bytes | None]:
        require(
            self.registration_path.read_bytes() == self.registration_raw
            and self.descriptor_path.read_bytes() == self.descriptor_raw,
            "registered documents changed",
        )
        require(
            digest(self.source_path.read_bytes()) == self.descriptor["source_sha256"],
            "producer source changed",
        )
        self._epochs()
        self._socket_identity()
        nonce = secrets.token_hex(32)
        started = time.monotonic_ns()
        query = {
            "schema": "ecpa-live-native-semantic-query/v1",
            "nonce": nonce,
            "registration_sha256": self.registration_sha256,
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            connection.connect(self.descriptor["socket_path"])
            pid, uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            require(
                pid == self.descriptor["producer"]["pid"] and uid == os.geteuid(),
                "producer peer credentials differ",
            )
            self._socket_identity()
            connection.sendall(canonical(query) + b"\n")
            raw = bytearray()
            while b"\n" not in raw:
                piece = connection.recv(4096)
                require(bool(piece), "producer closed incomplete quote")
                raw.extend(piece)
                require(len(raw) <= 131072, "producer quote exceeds limit")
            require(
                raw[-1:] == b"\n" and raw.count(b"\n") == 1,
                "producer quote framing differs",
            )
        quote = json.loads(raw)
        require(
            isinstance(quote, dict)
            and set(quote)
            == {
                "schema",
                "nonce",
                "registration_sha256",
                "producer",
                "ready",
                "reason",
                "scope",
                "proof",
                "formal_result",
            },
            "producer quote fields differ",
        )
        require(
            quote["schema"] == "ecpa-live-native-semantic-quote/v1"
            and quote["nonce"] == nonce
            and quote["registration_sha256"] == self.registration_sha256
            and quote["producer"] == self.descriptor["producer"]
            and quote["scope"] == self.scope
            and quote["formal_result"] is False
            and type(quote["ready"]) is bool
            and isinstance(quote["reason"], str),
            "producer quote identity/scope differs",
        )
        self._epochs()
        self._socket_identity()
        if not quote["ready"]:
            require(quote["proof"] is None, "unready producer provided proof")
            return quote, None
        proof = quote["proof"]
        require(
            isinstance(proof, dict)
            and set(proof)
            == {
                "observation_sha256",
                "request_sha256",
                "response_sha256",
                "issued_monotonic_ns",
                "expires_monotonic_ns",
                "tensor_receipts",
                "operator_receipts",
                "full_prefix_records",
                "worker_closures",
            },
            "proof fields differ",
        )
        for key in ("observation_sha256", "request_sha256", "response_sha256"):
            value = proof[key]
            require(
                isinstance(value, str)
                and len(value) == 64
                and all(char in "0123456789abcdef" for char in value),
                "invalid proof digest",
            )
        now = time.monotonic_ns()
        require(
            type(proof["issued_monotonic_ns"]) is int
            and type(proof["expires_monotonic_ns"]) is int
            and started
            <= proof["issued_monotonic_ns"]
            <= now
            < proof["expires_monotonic_ns"]
            and 0
            < proof["expires_monotonic_ns"] - proof["issued_monotonic_ns"]
            <= self.max_validity_ns,
            "producer quote lease stale/invalid",
        )
        require(
            all(
                type(proof[key]) is int
                for key in (
                    "tensor_receipts",
                    "operator_receipts",
                    "full_prefix_records",
                    "worker_closures",
                )
            )
            and proof["tensor_receipts"] == 56
            and proof["operator_receipts"] == 56
            and proof["worker_closures"] == 2
            and proof["full_prefix_records"] >= 118,
            "producer proof does not cover complete phase",
        )
        body = self._response(proof)
        require(
            time.monotonic_ns() < proof["expires_monotonic_ns"],
            "lease expired during response validation",
        )
        return quote, body

    def handle(
        self,
        method: str,
        path: str,
        body: bytes,
        request_id: str | None,
        framing_valid: bool = True,
    ) -> tuple[int, bytes, dict[str, str]]:
        validation_started = time.monotonic_ns()
        quote = None
        response = None
        reason = "unavailable"
        ready = False
        try:
            quote, response = self.challenge()
            ready = quote["ready"]
            reason = (
                quote["reason"] if not ready else "verified frozen response available"
            )
        except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
            reason = "live validation failed"
        validation_completed = time.monotonic_ns()
        quote_hash = digest(canonical(quote)) if quote is not None else None
        if ready != self.last_ready:
            self.journal.append(
                "ready-transition", ready=ready, reason=reason, quote_sha256=quote_hash
            )
            self.last_ready = ready
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "X-ECPA-Classification": CLASSIFICATION,
        }
        allowed = (
            framing_valid
            and method == self.method
            and path == self.request_path
            and digest(body) == self.request_sha256
            and request_id == self.phase["external_request_id"]
        )
        status_read = (
            framing_valid
            and method == "GET"
            and path == "/__semantic_status"
            and not body
        )
        status = 200 if ready and (allowed or status_read) else 503
        if status == 200 and allowed:
            payload = response
            require(payload is not None, "ready proof has no response")
        else:
            payload = canonical(
                {
                    "ready": ready if status_read else False,
                    "quote_sha256": quote_hash,
                    "formal_result": False,
                    "classification": CLASSIFICATION,
                }
            )
        self.journal.append(
            "public-request",
            method=method,
            path_sha256=digest(path.encode()),
            request_sha256=digest(body),
            status=status,
            ready=ready,
            matched_frozen_request=allowed,
            quote_sha256=quote_hash,
            producer_quote=quote,
            validation_started_monotonic_ns=validation_started,
            validation_completed_monotonic_ns=validation_completed,
            response_sha256=digest(payload),
        )
        return status, payload, headers


def make_handler(authority: Authority) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _serve(self) -> None:
            framing = True
            raw_lengths = self.headers.get_all("Content-Length", [])
            try:
                require(
                    not self.headers.get_all("Transfer-Encoding"),
                    "transfer encoding forbidden",
                )
                require(len(raw_lengths) <= 1, "duplicate content length")
                length = int(raw_lengths[0]) if raw_lengths else 0
                require(0 <= length <= 4 * 1024 * 1024, "request too large")
                require(
                    self.command != "POST" or len(raw_lengths) == 1,
                    "POST length missing",
                )
                self.connection.settimeout(5)
                body = self.rfile.read(length)
                require(len(body) == length, "incomplete request")
            except (ValueError, OSError):
                framing, body = False, b""
            request_ids = self.headers.get_all("X-ECPA-Request-ID", [])
            request_id = request_ids[0] if len(request_ids) == 1 else None
            code, payload, headers = authority.handle(
                self.command, self.path, body, request_id, framing
            )
            self.send_response(code)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _serve

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", required=True, type=Path)
    parser.add_argument("--producer-descriptor", required=True, type=Path)
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--journal", required=True, type=Path)
    args = parser.parse_args()
    authority = Authority(args.registration, args.producer_descriptor, args.journal)
    try:
        with HTTPServer(
            ("127.0.0.1", args.listen_port), make_handler(authority)
        ) as server:
            descriptor = {
                "schema": "ecpa-live-native-semantic-authority-ready/v1",
                "authority": identity(os.getpid()),
                "listen_host": "127.0.0.1",
                "listen_port": server.server_port,
                "source_sha256": digest(Path(__file__).read_bytes()),
                "registration_sha256": authority.registration_sha256,
                "classification": CLASSIFICATION,
                "formal_result": False,
            }
            authority.journal.append("authority-listening", descriptor=descriptor)
            print(canonical(descriptor).decode(), flush=True)
            server.serve_forever(poll_interval=0.1)
    finally:
        authority.journal.close()


if __name__ == "__main__":
    main()
