"""Actual public-arrival forwarding with full-prefix verification before reply.

No seed probe is run and no cached response grants another request permission.
The bounded predeclared serial workload remains prospective and nonformal.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import request_phasebook as books

canonical, digest, require = books.canonical, books.digest, books.require
PREFIX = "ecpa-request-sealed-global-prefix/v1"
TICKET = "ecpa-request-once-response-release/v1"
MAX_BYTES = 8 * 1024 * 1024


def read_regular(path, limit=MAX_BYTES):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "noncanonical evidence path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and metadata.st_size <= limit,
            "evidence owner/type/size differs",
        )
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "evidence oversized")
    return raw


def seal_prefix(journal_path, receipt, phase_id, output):
    """Copy every original row up to the source-authenticated immutable root.

    Caller must obtain receipt with the new live client, never from public input.
    The independent new consumer checks the receipt's raw bytes and source clock.
    No phase filtering, event rewriting or chain rehashing takes place here.
    """
    from . import request_drain_collector

    status = receipt["status"]
    require(
        status["failed"] is False
        and status["schema"] == "ecpa-request-native-collector-status/v1",
        "new request collector status required",
    )
    require(
        status["source_drain"]["schema"] == request_drain_collector.POLICY,
        "new source drain policy required",
    )
    candidates = [
        state
        for state in status["source_drain"]["runtimes"].values()
        if state["phase"]["phase_id"] == phase_id
    ]
    require(len(candidates) == 1, "phase runtime is absent or ambiguous")
    state = candidates[0]
    require(
        state["complete"] is True and state["ranks"] == [0, 1],
        "both genuine source closures required",
    )
    root = state["sealed_prefix"]
    count = state["sealed_prefix_bytes"]
    require(
        type(count) is int and 0 < count <= 64 * 1024 * 1024,
        "sealed prefix byte count invalid",
    )
    journal_path = Path(journal_path)
    raw = read_regular(journal_path, 64 * 1024 * 1024)
    prefix = raw[:count]
    require(
        len(prefix) == count
        and prefix.endswith(b"\n")
        and digest(prefix) == state["sealed_prefix_sha256"],
        "source-sealed exact prefix bytes changed",
    )
    rows = [json.loads(line) for line in prefix.splitlines()]
    previous = "0" * 64
    artifacts = {}
    for number, row in enumerate(rows):
        unsigned = dict(row)
        claimed = unsigned.pop("event_sha256")
        require(
            row["sequence"] == number
            and row["previous_sha256"] == previous
            and digest(canonical(unsigned)) == claimed,
            "global source prefix chain changed",
        )
        previous = claimed
        if "artifact" in row:
            item = row["artifact"]
            name = item["basename"]
            require(
                Path(name).name == name and name not in (".", ".."),
                "unsafe artifact basename",
            )
            payload = read_regular(journal_path.parent / name)
            require(
                len(payload) == item["size"] and digest(payload) == item["sha256"],
                "original global-prefix artifact changed",
            )
            if name in artifacts:
                require(
                    artifacts[name] == payload, "artifact name aliases different bytes"
                )
            artifacts[name] = payload
    require(
        root == {"next_sequence": len(rows), "last_event_sha256": previous},
        "authenticated global prefix root differs",
    )
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    files = [books.write_new(output / "native.jsonl", prefix)]
    files.extend(
        books.write_new(output / name, payload) for name, payload in artifacts.items()
    )
    manifest = {
        "schema": PREFIX,
        "phase_id": phase_id,
        "collector": status["collector"],
        "original_journal_path": str(journal_path),
        "sealed_prefix": root,
        "sealed_prefix_bytes": count,
        "sealed_prefix_sha256": digest(prefix),
        "source_sealed_monotonic_ns": state["sealed_monotonic_ns"],
        "receipt_sha256": digest(canonical(receipt)),
        "files": files,
        "unfiltered_global_chain": True,
        "formal_result": False,
    }
    books.write_new(output / "prefix-manifest.json", canonical(manifest))
    return manifest


def execute_phase(
    book,
    phase_id,
    output,
    *,
    descriptor,
    socket_path,
    spec_path,
    policy_path,
    drain_policy_path,
    collector_source_path,
    journal_path,
):
    """Producer performs one real HTTP request, then validates its own full proof."""
    from . import request_collector_client, request_drain_consumer

    books.validate(book)
    phase = next(p for p in book["recipe"]["phases"] if p["phase_id"] == phase_id)

    def authenticate():
        return request_collector_client.authenticate(
            Path(socket_path),
            descriptor,
            Path(spec_path),
            Path(collector_source_path),
            drain_policy_path=Path(drain_policy_path),
        )

    before = authenticate()
    output = Path(output)
    from . import request_http_runner

    result = request_http_runner.run_rpc_only(book["recipe"], phase_id, output)
    output.chmod(0o700)
    require(
        result["rpc_task_passed"] is True,
        "actual upstream request failed frozen task oracle",
    )
    books.write_new(output / "collector-before.json", canonical(before))
    deadline = before["authentication_clock"]["dispatch_monotonic_ns"] + int(
        phase["rpc_budget_s"] * 1e9
    )
    while True:
        after = authenticate()
        states = [
            state
            for state in after["status"]["source_drain"]["runtimes"].values()
            if state["phase"]["phase_id"] == phase_id
        ]
        if len(states) == 1 and states[0]["complete"] is True:
            break
        require(
            time.monotonic_ns() < deadline,
            "source closure exceeds predeclared request budget",
        )
        time.sleep(0.01)
    books.write_new(output / "collector-after.json", canonical(after))
    manifest = seal_prefix(journal_path, after, phase_id, output / "snapshot")
    observed = request_drain_consumer.verify_observation(
        book["recipe"],
        phase_id,
        output,
        descriptor=descriptor,
        spec_path=Path(spec_path),
        journal_path=output / "snapshot/native.jsonl",
        policy_path=Path(policy_path),
        drain_policy_path=Path(drain_policy_path),
    )
    require(
        observed["schema"] == "ecpa-request-native-observation/v1"
        and observed["phase_id"] == phase_id
        and observed["external_request_id"] == phase["external_request_id"],
        "producer observation scope differs",
    )
    require(
        observed["tensor_receipt_count"] == observed["operator_receipt_count"] == 56
        and observed["full_phase_source_drained"] is True,
        "producer56/56/source closure missing",
    )
    response = read_regular(output / "response.bin")
    require(
        observed["request_sha256"] == digest(canonical(phase["payload"]))
        and observed["actual_raw_response_sha256"] == digest(response)
        and observed["full_global_prefix"] == manifest["sealed_prefix"],
        "producer actual request/response/prefix differs",
    )
    books.write_new(
        output / "producer-independent-observation.json", canonical(observed)
    )
    return {
        "phase_id": phase_id,
        "response_sha256": digest(response),
        "observation_sha256": digest(canonical(observed)),
        "prefix_sha256": manifest["sealed_prefix_sha256"],
        "formal_result": False,
    }


class RequestForwarder:
    """One actual private HTTP execution per matching public request arrival.

    Root owns the service and enrolled Host/collector processes. Membership loss
    closes the issuer; this class never fabricates future PIDs or auto-renews a
    completed proof. It does not issue formal deployment/Manager admission.
    """

    def __init__(
        self,
        book,
        enrollment,
        *,
        output,
        descriptor,
        socket_path,
        spec_path,
        policy_path,
        drain_policy_path,
        collector_source_path,
        journal_path,
        key=None,
    ):
        books.enrollment_current(book, enrollment)
        self.book = json.loads(canonical(book))
        self.enrollment = json.loads(canonical(enrollment))
        self.descriptor = json.loads(canonical(descriptor))
        self.socket_path = Path(socket_path)
        self.spec_path = Path(spec_path)
        self.policy_path = Path(policy_path)
        self.drain_policy_path = Path(drain_policy_path)
        self.collector_source_path = Path(collector_source_path)
        self.journal_path = Path(journal_path)
        spec = json.loads(read_regular(self.spec_path))
        require(
            spec["senders"] == enrollment["source_peers"]
            and digest(read_regular(self.spec_path)) == enrollment["spec"]["sha256"],
            "forwarder native peer enrollment differs",
        )
        self.references = [
            {"path": str(path), "sha256": digest(read_regular(path))}
            for path in (
                self.spec_path,
                self.policy_path,
                self.drain_policy_path,
                self.collector_source_path,
            )
        ]
        self.output = Path(output)
        self.output.mkdir(mode=0o700, exist_ok=False)
        self.output.chmod(0o700)
        self.key = secrets.token_bytes(32) if key is None else key
        require(
            isinstance(self.key, bytes) and len(self.key) >= 32, "issuer key too short"
        )
        self.lock = threading.Lock()
        self.next_phase = 0
        self.failure = None
        self.pending = None
        books.write_new(self.output / "phasebook.json", canonical(self.book))
        books.write_new(
            self.output / "source-enrollment.json", canonical(self.enrollment)
        )
        self.producer = None
        self.producer_identity = None
        self.producer_reference = None
        self.producer_ready = None

    def _current(self):
        require(self.failure is None, "request issuer permanently closed")
        books.enrollment_current(self.book, self.enrollment)
        books.sources_current(self.references)
        require(
            books.native.identity(self.descriptor["collector"]["pid"])
            == self.descriptor["collector"],
            "independent collector epoch gone",
        )
        self._authenticate()  # Exact live Unix peer/socket/source; loss closes release.
        if self.producer is not None:
            from . import request_live_producer

            require(
                self.producer.poll() is None
                and books.native.identity(self.producer.pid) == self.producer_identity,
                "independent producer epoch gone",
            )
            require(
                digest(read_regular(Path(request_live_producer.__file__)))
                == self.producer_reference["sha256"],
                "independent producer source changed",
            )
            require(
                digest(read_regular(self.producer_registration["path"]))
                == self.producer_registration["sha256"],
                "independent producer registration bytes changed",
            )

    def start_producer(self, *, timeout_s=30):
        """Root observes a distinct actual child before permitting public work."""
        from . import request_live_producer

        require(
            self.producer is None, "producer cannot be restarted under old enrollment"
        )
        self._current()
        source = Path(request_live_producer.__file__).resolve()
        self.producer_reference = {
            "path": str(source),
            "sha256": digest(read_regular(source)),
        }
        source_paths = [
            Path(__file__).resolve(),
            source,
            Path(books.__file__).resolve(),
        ]
        from . import (
            request_collector_client,
            request_drain_collector,
            request_drain_consumer,
            request_http_runner,
        )

        source_paths.extend(
            Path(module.__file__).resolve()
            for module in (
                request_collector_client,
                request_drain_collector,
                request_drain_consumer,
                request_http_runner,
            )
        )
        sources = [
            {"path": str(path), "sha256": digest(read_regular(path))}
            for path in source_paths
        ]
        sources.extend(self.references)
        registration = {
            "schema": request_live_producer.REGISTRATION,
            "phasebook": self.book,
            "enrollment": self.enrollment,
            "descriptor": self.descriptor,
            "socket_path": str(self.output / "producer.sock"),
            "ready_path": str(self.output / "producer-ready.json"),
            "output_root": str(self.output),
            "sources": sources,
            "execution": {
                "descriptor": self.descriptor,
                "socket_path": str(self.socket_path),
                "spec_path": str(self.spec_path),
                "policy_path": str(self.policy_path),
                "drain_policy_path": str(self.drain_policy_path),
                "collector_source_path": str(self.collector_source_path),
                "journal_path": str(self.journal_path),
            },
            "formal_result": False,
        }
        reference = self._record("producer-registration.json", registration)
        self.producer_registration = reference
        self.producer_log = (self.output / "producer.log").open("xb")
        self.producer_pidfd = None
        try:
            self.producer = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "experiments.native_attention_candidate.request_live_producer",
                    "--registration",
                    reference["path"],
                    "--expected-sha256",
                    reference["sha256"],
                ],
                stdout=self.producer_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.producer_pidfd = os.pidfd_open(self.producer.pid)
            self.producer_identity = books.native.identity(self.producer.pid)
            expected = {
                self.enrollment["owner"]["pid"],
                self.producer.pid,
                self.descriptor["collector"]["pid"],
                *(s["process"]["pid"] for s in self.enrollment["source_peers"]),
            }
            require(
                len(expected) == 6,
                "independent owner/API/W0/W1/producer/collector roles collapsed",
            )
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                require(self.producer.poll() is None, "producer exited before READY")
                ready_path = self.output / "producer-ready.json"
                if ready_path.exists():
                    try:
                        ready = json.loads(read_regular(ready_path))
                    except json.JSONDecodeError:
                        time.sleep(0.01)
                        continue
                    require(
                        ready["schema"] == request_live_producer.READY
                        and ready["producer"] == self.producer_identity
                        and ready["registration_sha256"] == reference["sha256"]
                        and ready["producer_source_sha256"]
                        == self.producer_reference["sha256"],
                        "producer READY differs from observed kernel/source",
                    )
                    socket_path = self.output / "producer.sock"
                    meta = socket_path.lstat()
                    require(
                        stat.S_ISSOCK(meta.st_mode)
                        and stat.S_IMODE(meta.st_mode) == 0o600
                        and meta.st_uid == os.geteuid()
                        and ready["socket_identity"] == [meta.st_dev, meta.st_ino],
                        "producer socket ownership differs",
                    )
                    self.producer_ready = ready
                    return dict(ready)
                time.sleep(0.01)
            raise TimeoutError("producer READY timed out")
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                original.cleanup_error = repr(cleanup)
            raise

    def _produce(self, phase, output, admission):
        from . import request_live_producer

        require(self.producer_ready is not None, "independent live producer not ready")
        self._current()
        meta = (self.output / "producer.sock").lstat()
        require(
            [meta.st_dev, meta.st_ino] == self.producer_ready["socket_identity"],
            "producer socket replaced",
        )
        nonce = admission["admission_nonce"]
        command = {
            "schema": request_live_producer.COMMAND,
            "operation": "execute",
            "phase_id": phase["phase_id"],
            "request_sha256": digest(canonical(phase["payload"])),
            "nonce": nonce,
            "public_arrived_monotonic_ns": admission["public_arrived_monotonic_ns"],
            "deadline_monotonic_ns": admission["deadline_monotonic_ns"],
        }
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            remaining = (admission["deadline_monotonic_ns"] - time.monotonic_ns()) / 1e9
            require(
                remaining > 0, "total request deadline expired before producer command"
            )
            channel.settimeout(remaining)
            channel.connect(str(self.output / "producer.sock"))
            pid, uid, _ = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            require(
                uid == os.geteuid()
                and books.native.identity(pid) == self.producer_identity,
                "connected producer kernel peer differs",
            )
            channel.sendall(canonical(command) + b"\n")
            response = request_live_producer.receive(channel)
            require(
                response["schema"] == request_live_producer.COMPLETION
                and response["nonce"] == nonce
                and "failed" not in response,
                "independent producer request failed: " + str(response.get("failed")),
            )
            require(
                response["producer"] == self.producer_identity
                and response["registration_sha256"]
                == self.producer_registration["sha256"],
                "producer completion owner/source registration differs",
            )
        self._current()
        require(
            output == self.output / f"request-{self.next_phase:04d}",
            "producer output location differs",
        )
        return response["completion"]

    def close(self):
        """Reclaim only the owned producer; never stop Host/collector processes."""
        import signal

        try:
            if self.producer is not None and self.producer.poll() is None:
                if self.producer_pidfd is not None:
                    with suppress(ProcessLookupError):
                        signal.pidfd_send_signal(self.producer_pidfd, signal.SIGTERM)
                else:
                    self.producer.terminate()
                try:
                    self.producer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if self.producer_pidfd is not None:
                        with suppress(ProcessLookupError):
                            signal.pidfd_send_signal(
                                self.producer_pidfd, signal.SIGKILL
                            )
                    else:
                        self.producer.kill()
                    self.producer.wait(timeout=5)
        finally:
            try:
                if getattr(self, "producer_pidfd", None) is not None:
                    descriptor = self.producer_pidfd
                    self.producer_pidfd = None
                    os.close(descriptor)
            finally:
                if getattr(self, "producer_log", None) is not None:
                    self.producer_log.close()

    def _authenticate(self):
        from . import request_collector_client

        return request_collector_client.authenticate(
            self.socket_path,
            self.descriptor,
            self.spec_path,
            self.collector_source_path,
            drain_policy_path=self.drain_policy_path,
        )

    def _record(self, name, value):
        return books.write_new(self.output / name, canonical(value))

    def forward_request(self, *, method, path, headers, body):
        """Called once by the handler after reading this public request's bytes."""
        require(
            self.lock.acquire(blocking=False),
            "another predeclared request is in flight",
        )
        try:
            self._current()
            phases = self.book["recipe"]["phases"]
            require(self.next_phase < len(phases), "all predeclared requests consumed")
            phase = books.match_request(
                self.book,
                phases[self.next_phase]["phase_id"],
                method=method,
                path=path,
                headers=headers,
                body=body,
            )
            admission = secrets.token_hex(32)
            arrived = time.monotonic_ns()
            claim = {
                "phase_id": phase["phase_id"],
                "request_sha256": digest(body),
                "headers_sha256": digest(canonical(headers)),
                "public_arrived_monotonic_ns": arrived,
                "deadline_monotonic_ns": arrived
                + self.book["total_request_budget_s"] * 1_000_000_000,
                "admission_nonce": admission,
                "formal_result": False,
            }
            self._record(f"claim-{self.next_phase:04d}.json", claim)
            try:
                output = self.output / f"request-{self.next_phase:04d}"
                completion = self._produce(phase, output, claim)
                from . import request_drain_consumer

                observed = request_drain_consumer.verify_observation(
                    self.book["recipe"],
                    phase["phase_id"],
                    output,
                    descriptor=self.descriptor,
                    spec_path=self.spec_path,
                    journal_path=output / "snapshot/native.jsonl",
                    policy_path=self.policy_path,
                    drain_policy_path=self.drain_policy_path,
                )
                manifest = json.loads(
                    read_regular(output / "snapshot/prefix-manifest.json")
                )
                response = read_regular(output / "response.bin")
                require(
                    observed["schema"] == "ecpa-request-native-observation/v1"
                    and observed["phase_id"] == phase["phase_id"]
                    and observed["external_request_id"] == phase["external_request_id"],
                    "independent owner observation scope differs",
                )
                require(
                    observed["tensor_receipt_count"]
                    == observed["operator_receipt_count"]
                    == 56
                    and observed["full_phase_source_drained"] is True,
                    "owner independent56/56/closures missing",
                )
                require(
                    observed["request_sha256"] == digest(body)
                    and observed["actual_raw_response_sha256"] == digest(response)
                    and observed["full_global_prefix"] == manifest["sealed_prefix"],
                    "owner independent body/response/prefix differs",
                )
                require(
                    completion["response_sha256"] == digest(response)
                    and completion["observation_sha256"] == digest(canonical(observed)),
                    "producer and owner independent full verification differ",
                )
                self._current()
                books.write_new(
                    output / "owner-independent-observation.json", canonical(observed)
                )
                now = time.monotonic_ns()
                require(
                    now < claim["deadline_monotonic_ns"],
                    "total request deadline expired during independent verification",
                )
                ticket = {
                    "schema": TICKET,
                    "owner": self.enrollment["owner"],
                    "phasebook_sha256": digest(canonical(self.book)),
                    "enrollment_sha256": digest(canonical(self.enrollment)),
                    "admission": claim,
                    "phase_index": self.next_phase,
                    "response": {
                        "path": str(output / "response.bin"),
                        "sha256": digest(response),
                    },
                    "prefix_manifest": manifest,
                    "observation_sha256": digest(canonical(observed)),
                    "issued_monotonic_ns": now,
                    "expires_monotonic_ns": min(
                        now + 30_000_000_000, claim["deadline_monotonic_ns"]
                    ),
                    "formal_result": False,
                }
                envelope = {
                    "body": ticket,
                    "mac": hmac.digest(self.key, canonical(ticket), "sha256").hex(),
                }
                books.write_new(output / "one-use-ticket.json", canonical(envelope))
                self.pending = envelope
                # Consumption and response delivery belong to this same public
                # handler; a second public request cannot obtain this response.
                return self._consume(envelope, claim)
            except BaseException as error:
                self.failure = str(error)
                try:
                    self._record(
                        f"failure-{self.next_phase:04d}.json",
                        {
                            "reason": str(error),
                            "phase_id": phase["phase_id"],
                            "formal_result": False,
                        },
                    )
                except BaseException as audit_error:
                    error.audit_error = repr(audit_error)
                raise
        finally:
            self.lock.release()

    def _consume(self, envelope, admission):
        self._current()
        require(self.pending == envelope, "response ticket absent or already consumed")
        ticket = envelope["body"]
        require(
            hmac.compare_digest(
                envelope["mac"],
                hmac.digest(self.key, canonical(ticket), "sha256").hex(),
            ),
            "response ticket authentication failed",
        )
        require(
            ticket["admission"] == admission
            and ticket["phase_index"] == self.next_phase
            and time.monotonic_ns() < ticket["expires_monotonic_ns"],
            "ticket request/order/original expiry differs",
        )
        manifest = ticket["prefix_manifest"]
        prefix = read_regular(Path(manifest["files"][0]["path"]))
        require(
            digest(prefix) == manifest["sealed_prefix_sha256"],
            "frozen global prefix changed",
        )
        for reference in manifest["files"]:
            require(
                digest(read_regular(reference["path"])) == reference["sha256"],
                "snapshot input changed",
            )
        response = read_regular(ticket["response"]["path"])
        require(
            digest(response) == ticket["response"]["sha256"],
            "verified actual response changed",
        )
        self._record(
            f"consume-{self.next_phase:04d}.json",
            {
                "ticket_sha256": digest(canonical(envelope)),
                "admission_nonce": admission["admission_nonce"],
                "consumed_monotonic_ns": time.monotonic_ns(),
                "formal_result": False,
            },
        )
        self.pending = None
        self.next_phase += 1
        return response


class RequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            values = self.headers.get_all("Content-Length", [])
            require(
                len(values) == 1 and values[0].isdigit(), "ambiguous public body length"
            )
            count = int(values[0])
            require(
                self.headers.get("Transfer-Encoding") is None,
                "chunked public input unsupported",
            )
            require(0 < count <= 2 * 1024 * 1024, "public request size invalid")
            self.connection.settimeout(5)
            raw = self.rfile.read(count)
            require(len(raw) == count, "public body incomplete")
            for name in ("Content-Type", "X-Request-Id"):
                require(
                    len(self.headers.get_all(name, [])) == 1,
                    "ambiguous public request header",
                )
            body = self.server.forwarder.forward_request(
                method="POST",
                path=self.path,
                headers={
                    "Content-Type": self.headers["Content-Type"],
                    "X-Request-Id": self.headers["X-Request-Id"],
                },
                body=raw,
            )
            status = 200
        except Exception:
            status, body = 503, b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class RequestServer(ThreadingHTTPServer):
    def __init__(self, address, forwarder):
        require(address[0] == "127.0.0.1", "prospective authority is loopback only")
        self.forwarder = forwarder
        super().__init__(address, RequestHandler)
