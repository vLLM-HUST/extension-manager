"""Closed-public baseline controller for a single verified frozen response.

Preparation is not authority. Full native verification and durable commit precede
OPEN; each response rechecks actual epochs, sealed collector and original expiry.
No forwarding, arbitrary inference or formal qualification is implemented.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from experiments.native_attention_candidate import baseline_cell_issuer as authority
from experiments.native_attention_candidate import baseline_live_producer as producer
from experiments.native_attention_candidate import live_route_reader as inputs_module
from experiments.native_attention_candidate import semantic_producer_registry as util

TICKET = "ecpa-baseline-local-verified-cached-cell-ticket/v1"
CONTROL = "ecpa-baseline-prepared-cell-controller-state/v1"


def _copy(value):
    return json.loads(util.canonical(value))


class _HTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self._serve()

    do_GET = do_POST
    do_HEAD = do_POST
    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST
    do_OPTIONS = do_POST

    def _serve(self):
        self.connection.settimeout(5)
        try:
            sizes = self.headers.get_all("Content-Length") or ["0"]
            util.require(
                len(sizes) == 1 and self.headers.get("Transfer-Encoding") is None,
                "baseline HTTP framing differs",
            )
            size = int(sizes[0])
            util.require(0 <= size <= 131072, "baseline HTTP body oversized")
            body = self.rfile.read(size)
            util.require(len(body) == size, "baseline HTTP request incomplete")
            phase = self.server.controller.phase
            util.require(
                all(
                    self.headers.get_all(key) == [str(value)]
                    for key, value in phase.get("headers", {}).items()
                ),
                "baseline frozen request headers differ",
            )
            status, response = self.server.controller.authorize_cached(
                self.command,
                self.path,
                body,
                self.headers.get_all("X-ECPA-Request-ID") or [],
            )
        except Exception:
            status, response = 503, b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response)

    def log_message(self, *_args):
        pass


class BaselineProducerClient:
    def __init__(self, *, socket_path, producer_kernel, registration_sha256):
        self.path = str(inputs_module._path(socket_path))
        self.producer = _copy(producer_kernel)
        self.registration_sha256 = registration_sha256
        self.identity = None

    def exchange(self, nonce):
        util._kernel(self.producer)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        try:
            connection.connect(self.path)
            identity = util._socket(self.path, connection, self.producer)
            if self.identity is None:
                self.identity = identity
            util.require(identity == self.identity, "baseline producer socket replaced")
            connection.sendall(
                util.canonical(
                    {
                        "schema": producer.QUERY,
                        "nonce": nonce,
                        "registration_sha256": self.registration_sha256,
                    }
                )
                + b"\n"
            )
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = connection.recv(4096)
                util.require(
                    chunk and len(raw) + len(chunk) <= 131072,
                    "baseline quote framing incomplete/oversized",
                )
                raw += chunk
            util.require(raw.count(b"\n") == 1, "baseline quote trailing frame")
            quote = json.loads(raw)
            util._kernel(self.producer)
            util.require(
                util._socket(self.path, connection, self.producer) == self.identity,
                "baseline producer socket changed during exchange",
            )
            return quote, connection
        except BaseException:
            connection.close()
            raise


class BaselineCachedController:
    def __init__(self, issuer, permit, *, recipe, journal_path, public_port=0):
        self.issuer, self.permit = issuer, _copy(permit)
        self.value = issuer._permit(permit)
        self.cell = self.value["cell"]
        util.require(
            util.sha(util.canonical(recipe)) == self.cell["recipe_sha256"],
            "baseline controller recipe differs",
        )
        self.phase = _copy(recipe["phases"][0])
        self.scope = authority._object(self.value["baseline_scope_reference"])
        self.owner = util.process_identity(os.getpid())
        self.state, self.prepared, self.ticket = "CLOSED", None, None
        self.lock, self.transition, self.journal_lock = (
            threading.RLock(),
            threading.RLock(),
            threading.Lock(),
        )
        self._close_lock, self._closed = threading.Lock(), False
        path = inputs_module._path(journal_path)
        util.require(
            path.parent.stat().st_uid == os.geteuid()
            and path.parent.stat().st_mode & 0o077 == 0,
            "baseline controller journal parent not private",
        )
        self.journal = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        self.sequence, self.previous = -1, "0" * 64
        self.verifier = authority.BaselineQuoteVerifier(issuer)
        self.server = None
        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", public_port), _HTTPHandler)
            self.server.controller = self
            self.thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self._record("baseline.controller.created", public_open=False)
            self.thread.start()
        except BaseException:
            try:
                if self.server is not None:
                    self.server.server_close()
            finally:
                os.close(self.journal)
            raise

    def _record(self, event, **fields):
        try:
            with self.journal_lock:
                row = {
                    "schema": CONTROL,
                    "origin": authority.ORIGIN,
                    "event": event,
                    "sequence": self.sequence + 1,
                    "previous_sha256": self.previous,
                    "monotonic_ns": time.monotonic_ns(),
                    "formal_result": False,
                    **fields,
                }
                digest = util.sha(util.canonical(row))
                raw = memoryview(util.canonical({**row, "sha256": digest}) + b"\n")
                while raw:
                    count = os.write(self.journal, raw)
                    util.require(count > 0, "baseline controller journal write failed")
                    raw = raw[count:]
                os.fsync(self.journal)
                self.sequence, self.previous = row["sequence"], digest
        except BaseException:
            with self.lock:
                self.state, self.ticket, self.prepared = "REVOKED", None, None
            raise

    def read_route(self):
        """Pinned bound method reads actual local prepared state, never caller JSON."""
        util._kernel(self.owner)
        inputs_module._check_file_states(self.value["inputs"]["file_state"])
        with self.lock:
            util.require(
                self.state in {"PREPARED", "VERIFYING", "OPEN"} and self.prepared,
                "baseline actual controller is closed/revoked",
            )
            return _copy(self.prepared)

    def prepare(self, quote):
        with self.transition, self.lock:
            util.require(self.state == "CLOSED", "baseline preparation is one-shot")
            expiry = quote["proof"]["expires_monotonic_ns"]
            now = time.monotonic_ns()
            util.require(
                type(expiry) is int and now < expiry <= now + 30_000_000_000,
                "baseline preliminary expiry invalid",
            )
            self.prepared = {
                k: self.scope[k]
                for k in (
                    "observer_trial_id",
                    "arm",
                    "activation_profile_sha256",
                    "common_query_sha256",
                )
            }
            self.prepared.update(
                controller_instance="baseline-controller:" + secrets.token_hex(32),
                generation=1,
                membership_epoch=0,
                fence=secrets.token_hex(32),
                lease_expires_monotonic_ns=expiry,
            )
            self._record(
                "baseline.candidate.prepared", prepared=self.prepared, public_open=False
            )
            self.state = "PREPARED"
            return _copy(self.prepared)

    def _files(self):
        r = self.registration
        output = inputs_module._path(r["probe_output"])
        paths = {p for p in output.rglob("*") if p.is_file()}
        paths.update(
            {
                inputs_module._path(r["journal_path"]),
                inputs_module._path(
                    self.bound["artifacts"]["registration"]["path"]
                ).with_name(producer.RESERVED_OUTPUTS[0]),
            }
        )
        return {
            str(inputs_module._path(p)): inputs_module._state(p.stat())
            for p in sorted(paths)
        }

    def commit(self, deployment, client, *, observation_arguments):
        with self.transition:
            with self.lock:
                util.require(
                    self.state == "PREPARED", "baseline candidate not prepared"
                )
                self.state = "VERIFYING"
            try:
                self.bound = self.issuer._open(deployment, authority.DEPLOYMENT)
                self.deployment, self.client = _copy(deployment), client
                self.registration = authority._object(
                    self.bound["artifacts"]["registration"]
                )
                util.require(
                    util.canonical(self.bound["route"])
                    == util.canonical(self.prepared),
                    "baseline deployment prepared route differs",
                )
                self.arguments = observation_arguments
                before = self._files()
                nonce = secrets.token_hex(32)
                self.verifier.expect(nonce)
                quote, connection = client.exchange(nonce)
                with connection:
                    verdict = self.verifier.verify(
                        self.permit,
                        deployment,
                        quote,
                        connection=connection,
                        route_reader=self.read_route,
                        observation_arguments=observation_arguments,
                    )
                    output = Path(self.registration["probe_output"])
                    response = (output / "response.bin").read_bytes()
                    metadata = json.loads(
                        (output / "response-metadata.json").read_bytes()
                    )
                    util.require(
                        metadata["schema"] == "ecpa-observed-KV-HTTP-response/v2"
                        and type(metadata["status"]) is int
                        and metadata["status"] == 200
                        and metadata["request_sha256"] == self.cell["request_sha256"]
                        and metadata["response_sha256"]
                        == util.sha(response)
                        == quote["proof"]["response_sha256"]
                        and metadata["url"] == self.phase["url"]
                        and (output / "request.bin").read_bytes()
                        == util.canonical(self.phase["payload"]),
                        "baseline cached response binding differs",
                    )
                    self.issuer._live(
                        self.issuer._permit(self.permit),
                        self.bound,
                        connection,
                        self.read_route,
                    )
                    util.require(
                        before == self._files(),
                        "baseline verified raw evidence changed",
                    )
                    ticket = self.issuer._seal(
                        {
                            "schema": TICKET,
                            "origin": authority.ORIGIN,
                            "permit_sha256": self.permit["sha256"],
                            "deployment_sha256": deployment["sha256"],
                            "prepared": self.prepared,
                            "proof_identity": authority._proof_identity(quote["proof"]),
                            "verdict": verdict,
                            "file_state": before,
                            "formal_result": False,
                        }
                    )
                    self._record(
                        "baseline.candidate.commit",
                        ticket=ticket,
                        quote=quote,
                        public_open=True,
                    )
                    with self.lock:
                        util.require(
                            time.monotonic_ns()
                            < quote["proof"]["expires_monotonic_ns"],
                            "baseline proof expired during durable commit",
                        )
                        self.ticket, self.response, self.state = (
                            ticket,
                            response,
                            "OPEN",
                        )
                return _copy(ticket)
            except BaseException:
                self.revoke("baseline independent commit failed")
                raise

    def revoke(self, reason):
        with self.transition, self.lock:
            self.state, self.ticket, self.prepared = "REVOKED", None, None
            self._record("baseline.candidate.revoked", reason=reason, public_open=False)

    def authorize_cached(self, method, path, body, request_ids):
        expected = urlsplit(self.phase["url"])
        target = expected.path + ("?" + expected.query if expected.query else "")
        if (
            method != "POST"
            or path != target
            or body != util.canonical(self.phase["payload"])
            or request_ids != [self.phase["external_request_id"]]
        ):
            return 503, b""
        with self.lock:
            if self.state != "OPEN":
                return 503, b""
        with self.transition:
            with self.lock:
                if self.state != "OPEN":
                    return 503, b""
            try:
                ticket = self.issuer._open(self.ticket, TICKET)
                util.require(
                    ticket["permit_sha256"] == self.permit["sha256"]
                    and ticket["deployment_sha256"] == self.deployment["sha256"]
                    and util.canonical(ticket["prepared"])
                    == util.canonical(self.prepared)
                    and ticket["file_state"] == self._files(),
                    "baseline durable ticket/raw evidence changed",
                )
                nonce = secrets.token_hex(32)
                started = time.monotonic_ns()
                quote, connection = self.client.exchange(nonce)
                with connection:
                    util.require(
                        set(quote)
                        == {
                            "schema",
                            "origin",
                            "nonce",
                            "registration_sha256",
                            "producer",
                            "scope",
                            "ready",
                            "reason",
                            "proof",
                            "formal_result",
                        }
                        and quote["schema"] == producer.QUOTE
                        and quote["origin"] == authority.ORIGIN
                        and quote["nonce"] == nonce
                        and quote["ready"] is True
                        and quote["formal_result"] is False
                        and quote["registration_sha256"]
                        == self.client.registration_sha256
                        and util.canonical(quote["producer"])
                        == util.canonical(self.bound["producer"])
                        and util.canonical(quote["scope"]) == util.canonical(self.scope)
                        and type(quote["proof"]["issued_monotonic_ns"]) is int
                        and started
                        <= quote["proof"]["issued_monotonic_ns"]
                        <= time.monotonic_ns()
                        and util.canonical(authority._proof_identity(quote["proof"]))
                        == util.canonical(ticket["proof_identity"]),
                        "baseline fresh quote identity/expiry changed",
                    )
                    self.issuer._live(
                        self.issuer._permit(self.permit),
                        self.bound,
                        connection,
                        self.read_route,
                    )
                    authority._collector(self.registration, self.phase)
                    util.require(
                        self._files() == ticket["file_state"]
                        and util.sha(self.response) == quote["proof"]["response_sha256"]
                        and time.monotonic_ns()
                        < quote["proof"]["expires_monotonic_ns"],
                        "baseline cached proof/raw evidence expired or drifted",
                    )
                    self._record(
                        "baseline.request.cached_response",
                        quote=quote,
                        ticket_sha256=self.ticket["sha256"],
                        public_open=True,
                    )
                    util.require(
                        time.monotonic_ns() < quote["proof"]["expires_monotonic_ns"],
                        "baseline proof expired during response fsync",
                    )
                    return 200, self.response
            except Exception as exc:
                self.revoke(str(exc))
                return 503, b""

    def close(self):
        # Revocation uses the reentrant transition lock, then releases it before
        # waiting for HTTP threads. Never leave listeners/fds behind on log failure.
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            failures = []
            for operation in (
                lambda: self.revoke("baseline owner cleanup"),
                self.server.shutdown,
                self.server.server_close,
                lambda: self.thread.join(3),
                lambda: os.close(self.journal),
            ):
                try:
                    operation()
                except BaseException as exc:
                    failures.append(exc)
            if failures:
                raise failures[0]


def bind_and_commit_cached(
    controller,
    *,
    producer_kernel,
    artifacts,
    observation_arguments,
    producer_wait_s=180,
):
    """Wire a real already-launched producer; never launch or manufacture facts.

    Owner must freeze/audit all exact source+wheel/model/tokenizer inputs and
    independently admit source observations before creating the permit. Host
    scope must be installed before spawn, raw Host receipt captured afterwards,
    unchanged collector contexts provisioned, and producer separately launched.
    This helper keeps public CLOSED until full independent commit completes.
    """
    registration = authority._object(artifacts["registration"])
    client = BaselineProducerClient(
        socket_path=registration["producer_socket"],
        producer_kernel=producer_kernel,
        registration_sha256=util.sha(util.canonical(registration)),
    )
    deadline = time.monotonic() + producer_wait_s
    while True:
        quote, connection = client.exchange(secrets.token_hex(32))
        try:
            controller._record(
                "baseline.producer.preliminary", quote=quote, public_open=False
            )
            if quote.get("ready") is True and quote.get("proof") is not None:
                controller.prepare(quote)
                deployment = controller.issuer.bind_deployment(
                    controller.permit,
                    artifacts=artifacts,
                    producer_kernel=producer_kernel,
                    connection=connection,
                    route_reader=controller.read_route,
                )
                break
        finally:
            connection.close()
        util.require(
            not Path(artifacts["registration"]["path"])
            .with_name(producer.RESERVED_OUTPUTS[1])
            .exists(),
            "baseline producer failed; preserve original failure evidence",
        )
        util.require(
            time.monotonic() < deadline, "baseline actual producer deadline exceeded"
        )
        time.sleep(0.1)
    ticket = controller.commit(
        deployment, client, observation_arguments=observation_arguments
    )
    return {
        "deployment": deployment,
        "ticket": ticket,
        "public_port": controller.server.server_port,
        "classification": "baseline-bounded-cached-response-cell-only",
        "formal_result": False,
    }
