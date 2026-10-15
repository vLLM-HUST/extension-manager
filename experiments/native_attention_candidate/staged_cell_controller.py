"""Prepared, closed-public controller for one verified cached response only.

No backend forwarding, NPU launch, source-publication claim or formal admission.
The original producer's fixed expiry is the only deadline. Preparation and a
preliminary producer quote never authorize public exposure.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import struct
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)

TICKET = "ecpa-local-verified-cached-cell-ticket/v1"
CONTROL = "ecpa-prepared-cell-controller-state/v1"
QUERY = "ecpa-live-native-semantic-query/v1"
QUOTE = "ecpa-live-native-semantic-quote/v1"
MAX_QUOTE = 131072


def _copy(value):
    return json.loads(registry.canonical(value))


def _proof_identity(proof):
    # Issuance is freshly sampled per nonce by the real existing producer. The
    # observation, counts, request/response and original expiry cannot change.
    return {key: value for key, value in proof.items() if key != "issued_monotonic_ns"}


class ProducerQuoteClient:
    """Fresh actual Unix peer exchange; never manufacture a producer quote."""

    def __init__(self, *, socket_path, producer, registration_sha256):
        self.path = str(routes._path(socket_path))
        self.producer = _copy(producer)
        self.registration_sha256 = registration_sha256
        self.socket_identity = None

    def exchange(self, nonce):
        registry._kernel(self.producer)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        try:
            connection.connect(self.path)
            identity = registry._socket(self.path, connection, self.producer)
            if self.socket_identity is None:
                self.socket_identity = identity
            registry.require(
                identity == self.socket_identity, "producer socket replaced"
            )
            connection.sendall(
                registry.canonical(
                    {
                        "schema": QUERY,
                        "nonce": nonce,
                        "registration_sha256": self.registration_sha256,
                    }
                )
                + b"\n"
            )
            raw = bytearray()
            while not raw.endswith(b"\n"):
                chunk = connection.recv(4096)
                registry.require(
                    chunk and len(raw) + len(chunk) <= MAX_QUOTE,
                    "producer quote incomplete or oversized",
                )
                raw.extend(chunk)
            registry.require(raw.count(b"\n") == 1, "producer quote framing differs")
            quote = json.loads(raw)
            registry._kernel(self.producer)
            registry.require(
                registry._socket(self.path, connection, self.producer)
                == self.socket_identity,
                "producer socket replaced",
            )
            return quote, connection
        except BaseException:
            connection.close()
            raise


class PreparedCandidateReader(routes.LiveRouteReader):
    """Read actual prepared control state; this is NOT an open-route witness."""

    def __init__(
        self,
        *,
        socket_path,
        authority,
        authority_sources,
        authority_command_sha256,
        inputs,
        expected_cell,
        scope,
    ):
        self.socket_path = routes._path(socket_path)
        self.authority = _copy(authority)
        self.authority_sources = _copy(authority_sources)
        self.authority_command_sha256 = authority_command_sha256
        self.inputs = _copy(inputs)
        self.expected_cell, self.scope = _copy(expected_cell), _copy(scope)
        registry.require(
            set(scope) == set(registry.SCOPE_KEYS), "prepared scope differs"
        )
        registry.require(
            expected_cell["inputs_sha256"] == registry.sha(registry.canonical(inputs)),
            "prepared input audit differs",
        )
        self._inputs_current()
        self.socket_identity = self._identity()
        self.expiry = None

    def read(self):
        self._inputs_current()
        before = self._call("prepared_query")
        after = self._call("prepared_query")
        registry.require(
            before["prepared"] == after["prepared"], "prepared candidate changed"
        )
        prepared = after["prepared"]
        registry.require(
            after["schema"] == CONTROL and prepared is not None,
            "prepared candidate unavailable",
        )
        registry.require(
            prepared["semantic_cell"] == self.expected_cell,
            "prepared semantic cell differs",
        )
        route = prepared["binding"]
        registry.require(
            set(route)
            == {
                "generation",
                "membership_epoch",
                "controller_instance",
                "execution_plan_id",
                "native_launch_id",
                "fence",
                "lease_expires_monotonic_ns",
            },
            "prepared binding fields differ",
        )
        for field in (
            "membership_epoch",
            "controller_instance",
            "execution_plan_id",
            "native_launch_id",
        ):
            registry.require(
                route[field] == self.scope[field], "prepared candidate scope differs"
            )
        registry.require(
            type(route["generation"]) is int
            and route["generation"] == self.scope["candidate_generation"]
            and route["fence"].startswith("gate-prepared-")
            and type(route["lease_expires_monotonic_ns"]) is int
            and time.monotonic_ns() < route["lease_expires_monotonic_ns"],
            "prepared candidate fence/lease invalid",
        )
        if self.expiry is None:
            self.expiry = route["lease_expires_monotonic_ns"]
        registry.require(
            self.expiry == route["lease_expires_monotonic_ns"], "prepared lease renewed"
        )
        self._inputs_current()
        return route


class _HTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self._serve()

    def do_GET(self):
        self._serve()

    def _serve(self):
        self.connection.settimeout(5)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            registry.require(
                0 <= size <= MAX_QUOTE
                and self.headers.get("Transfer-Encoding") is None,
                "public request framing invalid",
            )
            body = self.rfile.read(size)
            registry.require(len(body) == size, "public request incomplete")
            ids = self.headers.get_all("X-ECPA-Request-ID") or []
            registry.require(
                all(
                    self.headers.get_all(key) == [str(value)]
                    for key, value in self.server.controller.phase.get(
                        "headers", {}
                    ).items()
                ),
                "frozen public request headers differ",
            )
            status, response = self.server.controller.authorize_cached(
                self.command, self.path, body, ids
            )
        except Exception:
            status, response = 503, b""
        self.send_response(status)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class StagedCellController:
    """Single-owner prepared lifecycle with a local authenticated verification ticket.

    Prepare is one-shot. Closed/revoked states cannot be reopened. Reads expose
    distinct public state and prepared binding. Commit retains the exact fence,
    scope and original fixed lease captured by deployment. A new controller,
    permit/deployment and fresh proof are required after restart or revocation.
    """

    def __init__(
        self,
        *,
        issuer,
        permit,
        expected_cell,
        scope,
        control_path,
        phase,
        journal_path,
        public_port=0,
    ):
        self.issuer, self.permit = issuer, _copy(permit)
        self.cell = issuer._permit(permit)["cell"]
        self.expected_cell, self.scope, self.phase = (
            _copy(expected_cell),
            _copy(scope),
            _copy(phase),
        )
        registry.require(
            expected_cell["permit_sha256"] == permit["sha256"],
            "controller permit differs",
        )
        registry.require(
            registry.sha(registry.canonical(phase["payload"]))
            == self.cell["request_sha256"],
            "controller frozen request differs",
        )
        self.control_path = routes._path(control_path)
        parent = self.control_path.parent.stat()
        registry.require(
            parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
            "controller directory not private",
        )
        self._state_lock, self._transition = threading.RLock(), threading.RLock()
        self.state, self.prepared, self.ticket = "CLOSED", None, None
        self._prepared_once = False
        self.verifier = registry.QuoteVerifier(issuer)
        self.journal = os.open(
            journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        self._sequence, self._previous = 0, "0" * 64
        self._journal_lock = threading.Lock()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.control_path))
        os.chmod(self.control_path, 0o600)
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.server = ThreadingHTTPServer(("127.0.0.1", public_port), _HTTPHandler)
        self.server.controller = self
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._control, daemon=True),
            threading.Thread(target=self.server.serve_forever, daemon=True),
        ]
        self._record("controller.created", public_open=False)
        for thread in self._threads:
            thread.start()

    def _record(self, event, **fields):
        try:
            self._write_record(event, **fields)
        except BaseException:
            # Journal failure never leaves an authorizable cached response.
            with self._state_lock:
                self.state, self.prepared, self.ticket = "REVOKED", None, None
            raise

    def _write_record(self, event, **fields):
        with self._journal_lock:
            row = {
                "schema": CONTROL,
                "event": event,
                "sequence": self._sequence + 1,
                "previous_sha256": self._previous,
                "monotonic_ns": time.monotonic_ns(),
                "formal_result": False,
                **fields,
            }
            digest = registry.sha(registry.canonical(row))
            raw = memoryview(registry.canonical({**row, "sha256": digest}) + b"\n")
            while raw:
                count = os.write(self.journal, raw)
                registry.require(count > 0, "controller journal write failed")
                raw = raw[count:]
            os.fsync(self.journal)
            self._sequence, self._previous = row["sequence"], digest

    def _control(self):
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                try:
                    connection.settimeout(2)
                    _, uid, _ = struct.unpack(
                        "3i",
                        connection.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
                        ),
                    )
                    registry.require(
                        uid == os.geteuid(), "controller caller UID differs"
                    )
                    raw = bytearray()
                    while not raw.endswith(b"\n"):
                        piece = connection.recv(4096)
                        registry.require(
                            piece and len(raw) + len(piece) <= routes.MAX_MESSAGE,
                            "controller request framing invalid",
                        )
                        raw.extend(piece)
                    registry.require(
                        json.loads(raw) == {"operation": "prepared_query"},
                        "controller operation is read-only",
                    )
                    with self._state_lock:
                        response = {
                            "ok": True,
                            "schema": CONTROL,
                            "state": self.state,
                            "public_open": self.state == "OPEN",
                            "prepared": self.prepared,
                        }
                    connection.sendall(registry.canonical(response) + b"\n")
                except Exception:
                    with suppress(OSError):
                        connection.sendall(b'{"ok":false}\n')

    def prepare(self, preliminary_quote):
        """An unverified quote supplies only a deadline, never public authority."""
        with self._transition, self._state_lock:
            registry.require(
                not self._prepared_once and self.state == "CLOSED",
                "prepare is one-shot",
            )
            expiry = preliminary_quote["proof"]["expires_monotonic_ns"]
            now = time.monotonic_ns()
            registry.require(
                type(expiry) is int and now < expiry <= now + 30_000_000_000,
                "preliminary fixed proof expiry invalid",
            )
            self._prepared_once = True
            self.prepared = {
                "semantic_cell": self.expected_cell,
                "binding": {
                    "generation": self.scope["candidate_generation"],
                    **{
                        key: self.scope[key]
                        for key in (
                            "membership_epoch",
                            "controller_instance",
                            "execution_plan_id",
                            "native_launch_id",
                        )
                    },
                    "fence": "gate-prepared-" + secrets.token_hex(32),
                    "lease_expires_monotonic_ns": expiry,
                },
            }
            self._record(
                "candidate.prepared", prepared=self.prepared, public_open=False
            )
            self.state = "PREPARED"
            return _copy(self.prepared)

    def _files(self, observation_arguments):
        output = routes._path(observation_arguments["output"])
        registration = json.loads(
            Path(self.bound["artifacts"]["registration"]["path"]).read_bytes()
        )
        paths = {p for p in output.rglob("*") if p.is_file()}
        paths.add(routes._path(registration["journal_path"]))
        return {str(routes._path(p)): routes._state(p.stat()) for p in sorted(paths)}

    def _quote_fields(self, quote, nonce, started):
        registry.require(
            set(quote)
            == {
                "schema",
                "nonce",
                "registration_sha256",
                "producer",
                "scope",
                "ready",
                "reason",
                "proof",
                "formal_result",
            }
            and quote["schema"] == QUOTE
            and quote["nonce"] == nonce
            and quote["registration_sha256"] == self.client.registration_sha256
            and registry.canonical(quote["producer"])
            == registry.canonical(self.bound["producer"])
            and registry.canonical(quote["scope"])
            == registry.canonical(self.bound["scope"])
            and quote["ready"] is True
            and quote["formal_result"] is False,
            "fresh quote identity differs",
        )
        proof = quote["proof"]
        registry.require(
            type(proof["issued_monotonic_ns"]) is int
            and started
            <= proof["issued_monotonic_ns"]
            <= time.monotonic_ns()
            < proof["expires_monotonic_ns"],
            "fresh quote issue/expiry invalid",
        )

    def commit(
        self,
        *,
        deployment,
        client,
        route_reader,
        observation_verifier,
        observation_arguments,
    ):
        """Recompute full typed evidence once, then seal its immutable short ticket."""
        with self._transition:
            with self._state_lock:
                registry.require(self.state == "PREPARED", "candidate is not prepared")
                self.state = "VERIFYING"
            try:
                self.bound = self.issuer._open(deployment, registry.DEPLOYMENT)
                self.deployment, self.client = _copy(deployment), client
                self.route_reader, self.observation_arguments = (
                    route_reader,
                    observation_arguments,
                )
                registry.require(
                    self.bound["route"] == self.prepared["binding"],
                    "deployment prepared binding differs",
                )
                before = self._files(observation_arguments)
                nonce = secrets.token_hex(32)
                self.verifier.expect(nonce)
                quote, connection = client.exchange(nonce)
                with connection:
                    verdict = self.verifier.verify(
                        self.permit,
                        deployment,
                        quote,
                        connection=connection,
                        route_reader=route_reader,
                        observation_verifier=observation_verifier,
                        observation_arguments=observation_arguments,
                    )
                    registry.require(
                        before == self._files(observation_arguments),
                        "verified raw inputs changed",
                    )
                    output = Path(observation_arguments["output"])
                    response = (output / "response.bin").read_bytes()
                    metadata = json.loads(
                        (output / "response-metadata.json").read_bytes()
                    )
                    registry.require(
                        metadata["schema"] == "ecpa-observed-KV-HTTP-response/v2"
                        and type(metadata["status"]) is int
                        and metadata["status"] == 200
                        and metadata["request_sha256"] == self.cell["request_sha256"]
                        and metadata["response_sha256"]
                        == registry.sha(response)
                        == quote["proof"]["response_sha256"]
                        and metadata["url"] == self.phase["url"]
                        and (output / "request.bin").read_bytes()
                        == registry.canonical(self.phase["payload"]),
                        "verified frozen response binding differs",
                    )
                    self.issuer._live(
                        self.issuer._permit(self.permit),
                        self.bound,
                        connection,
                        route_reader,
                    )
                    registry.require(
                        time.monotonic_ns() < quote["proof"]["expires_monotonic_ns"]
                        and before == self._files(observation_arguments),
                        "proof expired or verified raw changed during commit",
                    )
                    ticket = self.issuer._seal(
                        {
                            "schema": TICKET,
                            "formal_result": False,
                            "permit_sha256": self.permit["sha256"],
                            "deployment_sha256": deployment["sha256"],
                            "prepared": self.prepared,
                            "proof_identity": _proof_identity(quote["proof"]),
                            "verified_observation": verdict,
                            "file_state": before,
                        }
                    )
                    self._record(
                        "candidate.commit", ticket=ticket, quote=quote, public_open=True
                    )
                    with self._state_lock:
                        registry.require(
                            time.monotonic_ns()
                            < quote["proof"]["expires_monotonic_ns"],
                            "fixed proof expired during commit log fsync",
                        )
                        self.ticket, self.response, self.state = (
                            ticket,
                            response,
                            "OPEN",
                        )
                return _copy(ticket)
            except BaseException:
                self.revoke("commit verification failed")
                raise

    def revoke(self, reason):
        with self._transition, self._state_lock:
            self.state, self.prepared, self.ticket = "REVOKED", None, None
            self._record("candidate.revoked", reason=reason, public_open=False)

    def authorize_cached(self, method, path, body, request_ids):
        """Only the frozen request; never a general inference or forwarding grant."""
        expected = urlsplit(self.phase["url"])
        target = expected.path + ("?" + expected.query if expected.query else "")
        if (
            method != "POST"
            or path != target
            or body != registry.canonical(self.phase["payload"])
            or request_ids != [self.phase["external_request_id"]]
        ):
            self._record(
                "request.reject",
                reason="outside exact frozen request",
                public_open=False,
            )
            return 503, b""
        # Do not queue a public request behind expensive commit verification:
        # PREPARED/VERIFYING are publicly closed at arrival, not delayed grants.
        with self._state_lock:
            if self.state != "OPEN":
                return 503, b""
        with self._transition:
            with self._state_lock:
                if self.state != "OPEN":
                    return 503, b""
            try:
                ticket = self.issuer._open(self.ticket, TICKET)
                registry.require(
                    ticket["permit_sha256"] == self.permit["sha256"]
                    and ticket["deployment_sha256"] == self.deployment["sha256"]
                    and ticket["prepared"] == self.prepared,
                    "local verification ticket binding differs",
                )
                registry.require(
                    self._files(self.observation_arguments) == ticket["file_state"],
                    "verified raw/response inputs changed",
                )
                nonce, started = secrets.token_hex(32), time.monotonic_ns()
                quote, connection = self.client.exchange(nonce)
                with connection:
                    self._quote_fields(quote, nonce, started)
                    registry.require(
                        registry.canonical(_proof_identity(quote["proof"]))
                        == registry.canonical(ticket["proof_identity"]),
                        "verified proof identity or fixed expiry changed",
                    )
                    self.issuer._live(
                        self.issuer._permit(self.permit),
                        self.bound,
                        connection,
                        self.route_reader,
                    )
                    registry.require(
                        self._files(self.observation_arguments) == ticket["file_state"]
                        and registry.sha(self.response)
                        == quote["proof"]["response_sha256"]
                        and time.monotonic_ns()
                        < quote["proof"]["expires_monotonic_ns"],
                        "cached response or fixed proof lease changed",
                    )
                    self._record(
                        "request.cached_response",
                        quote=quote,
                        ticket_sha256=self.ticket["sha256"],
                        response_sha256=registry.sha(self.response),
                        public_open=True,
                    )
                    registry.require(
                        time.monotonic_ns() < quote["proof"]["expires_monotonic_ns"],
                        "fixed proof expired during response log fsync",
                    )
                    return 200, self.response
            except Exception as exc:
                self.revoke(str(exc))
                return 503, b""

    def close(self):
        self.revoke("owner cleanup")
        self._stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.listener.close()
        for thread in self._threads:
            thread.join(3)
        self.control_path.unlink(missing_ok=True)
        os.close(self.journal)


def bind_and_commit_cached(
    controller,
    *,
    handoff,
    manager,
    peers,
    producer,
    producer_socket,
    artifacts,
    inputs,
    authority_sources,
    observation_verifier,
    observation_arguments,
    producer_wait_s=180,
):
    """Owner integration after actual producer startup; never launches a process.

    Construct the permit/input binding and capture original Manager handoff before
    launch. After starting the existing producer with its actual registration,
    construct this closed controller and call this function inside the owner's
    existing whole-RPC watchdog. Public stays closed throughout producer waiting
    and full independent verification. Keep controller alive for exact-request
    checks/fault injection and always close it in the owner's cleanup finally.
    """
    registration = Path(artifacts["registration"]["path"]).read_bytes()
    client = ProducerQuoteClient(
        socket_path=producer_socket,
        producer=producer,
        registration_sha256=registry.sha(registration),
    )
    deadline = time.monotonic() + producer_wait_s
    while True:
        quote, connection = client.exchange(secrets.token_hex(32))
        controller._record("producer.preliminary", quote=quote, public_open=False)
        if quote.get("ready") is True and quote.get("proof") is not None:
            break
        connection.close()
        registry.require(
            not (
                Path(artifacts["registration"]["path"]).parent / "producer-failure.txt"
            ).exists(),
            "actual producer probe failed; preserve producer-failure.txt",
        )
        registry.require(
            time.monotonic() < deadline, "producer did not finish before owner deadline"
        )
        time.sleep(0.1)
    try:
        controller.prepare(quote)
        mandatory = {
            str(Path(module.__file__).resolve()): routes._hash(module.__file__)
            for module in (routes, registry)
        }
        mandatory[str(Path(__file__).resolve())] = routes._hash(__file__)
        registry.require(
            all(
                authority_sources.get(path) == digest
                for path, digest in mandatory.items()
            ),
            "controller protocol source pins incomplete",
        )
        admitted_sources = dict(inputs["source_files"])
        admitted_sources.update(controller.cell["native_sources"])
        admitted_sources.update(
            {
                ref["path"]: ref["sha256"]
                for ref in controller.cell["protocol_sources"].values()
            }
        )
        registry.require(
            all(
                admitted_sources.get(path) == digest
                for path, digest in authority_sources.items()
            ),
            "controller source is outside independently admitted inputs",
        )
        reader = PreparedCandidateReader(
            socket_path=controller.control_path,
            authority=registry.process_identity(os.getpid()),
            authority_sources=authority_sources,
            authority_command_sha256=routes._hash(f"/proc/{os.getpid()}/cmdline"),
            inputs=inputs,
            expected_cell=controller.expected_cell,
            scope=controller.scope,
        )
        deployment = controller.issuer.bind_deployment(
            controller.permit,
            handoff=handoff,
            scope=controller.scope,
            manager=manager,
            peers=peers,
            producer=producer,
            socket_path=producer_socket,
            connection=connection,
            artifacts=artifacts,
            route_reader=reader.read,
        )
    finally:
        connection.close()
    ticket = controller.commit(
        deployment=deployment,
        client=client,
        route_reader=reader.read,
        observation_verifier=observation_verifier,
        observation_arguments=observation_arguments,
    )
    return {
        "deployment": deployment,
        "ticket": ticket,
        "public_port": controller.server.server_port,
        "classification": "bounded-cached-response-cell-only",
        "formal_result": False,
    }
