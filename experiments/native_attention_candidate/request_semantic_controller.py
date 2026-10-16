"""Actual private route reader and per-arrival Plan obligation consumer.

PREPARED permits only exact declared execution behind the public handler. It is
never a cached OPEN route or evidence that an unexecuted request has completed.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path

from experiments.exposure_gate import loopback_traffic

from . import live_route_reader as routes
from . import request_semantic_authority as semantic
from . import semantic_producer_registry as registry
from .request_prefix_ticket import RequestForwarder

CONTROL = "ecpa-request-semantic-prepared-route/v1"
MAX_ROUTE_LEASE_NS = 1800_000_000_000
canonical, sha, require = semantic.canonical, semantic.sha, semantic.require


class IndependentGrantObserver(routes.LiveRouteReader):
    """Authenticate an independently owned real traffic authority, not a Grant DTO."""

    def __init__(self, descriptor, input_audits):
        self.authority = descriptor["kernel"]
        self.authority_sources = descriptor["sources"]
        self.authority_command_sha256 = descriptor["command_sha256"]
        self.socket_path = routes._path(descriptor["socket_path"])
        self.input_audits = input_audits
        self._inputs_current()
        self.socket_identity = self._identity()
        require(
            list(self.socket_identity) == descriptor["socket_identity"],
            "independently observed grant endpoint changed",
        )

    def _inputs_current(self):
        require(self.input_audits, "independent grant input/source audits missing")
        for audit in self.input_audits.values():
            semantic.require_audited_sources(audit, self.authority_sources)

    def exchange(self, operation, **fields):
        require(self._identity() == self.socket_identity, "grant endpoint replaced")
        dispatched = time.monotonic_ns()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(self.socket_path))
            pid, uid, _ = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            require(
                uid == os.geteuid() and pid == self.authority["pid"],
                "independent grant SO_PEERCRED differs",
            )
            client.sendall(canonical({"operation": operation, **fields}) + b"\n")
            raw = b""
            while not raw.endswith(b"\n"):
                piece = client.recv(4096)
                require(
                    piece and len(raw) + len(piece) <= routes.MAX_MESSAGE,
                    "grant response framing differs",
                )
                raw += piece
        completed = time.monotonic_ns()
        require(
            self._identity() == self.socket_identity,
            "grant source/kernel/socket changed during query",
        )
        value = json.loads(raw)
        require(value.get("ok") is True, "independent authority rejected grant query")
        return value, {
            "raw_base64": base64.b64encode(raw).decode(),
            "raw_sha256": sha(raw),
            "dispatched_monotonic_ns": dispatched,
            "completed_monotonic_ns": completed,
            "kernel_peer": {"pid": pid, "uid": uid},
        }


def _authority_argv(kernel):
    argv = [
        part.decode()
        for part in Path(f"/proc/{kernel['pid']}/cmdline").read_bytes().split(b"\0")
        if part
    ]
    require(
        argv[:3]
        == [sys.executable, "-m", "experiments.exposure_gate.loopback_traffic"],
        "grant authority is not the actual pinned controller module",
    )

    def flag(name):
        require(
            argv.count(name) == 1 and not any(s.startswith(name + "=") for s in argv),
            "grant authority argv flag ambiguous",
        )
        return argv[argv.index(name) + 1]

    return argv, flag


def observe_route_grant(authority_process, *, socket_path, launch, input_audits):
    """Read a real owned authority's original CLI grant and actual closed check.

    The external query remains the predecessor route. This observes permission
    for candidate=predecessor+1 and never relabels that query as candidate OPEN.
    """
    require(
        isinstance(authority_process, subprocess.Popen)
        and authority_process.poll() is None,
        "independent original authority Popen is required",
    )
    kernel = registry.process_identity(authority_process.pid)
    argv, flag = _authority_argv(kernel)
    require(
        argv == authority_process.args and flag("--socket") == str(socket_path),
        "original authority Popen/endpoint invocation differs",
    )
    original_grant = {
        "holder": flag("--grant-holder"),
        "fencing_token": int(flag("--grant-token")),
        "expires_at": int(flag("--grant-expires-at")),
    }
    require(
        original_grant["holder"] == launch["controller_instance"]
        and original_grant["fencing_token"] > 0,
        "actual independent grant holder/token differs from compiled scope",
    )
    source = Path(loopback_traffic.__file__).resolve()
    meta = Path(socket_path).lstat()
    descriptor = {
        "kernel": kernel,
        "sources": {str(source): sha(source.read_bytes())},
        "command_sha256": sha(Path(f"/proc/{kernel['pid']}/cmdline").read_bytes()),
        "socket_path": str(socket_path),
        "socket_identity": [meta.st_dev, meta.st_ino, meta.st_uid],
        "argv": argv,
        "journal_path": flag("--journal"),
    }
    reader = IndependentGrantObserver(descriptor, input_audits)
    mono, wall = time.monotonic_ns(), time.time_ns()
    before, raw_before = reader.exchange("query")
    valid, raw_valid = reader.exchange(
        "lease_valid", grant=original_grant, now=int(time.time())
    )
    after, raw_after = reader.exchange("query")
    require(
        before == after and valid.get("valid") is True,
        "actual independent grant/route changed or expired",
    )
    route = after["route"]
    require(
        type(route["generation"]) is int
        and route["generation"] + 1 == launch["candidate_generation"],
        "prepared candidate is not the real predecessor successor",
    )
    events = loopback_traffic.read_traffic_journal(Path(descriptor["journal_path"]))
    require(
        all(
            e["proxy_pid"] == kernel["pid"]
            and e["proxy_start_ticks"] == kernel["start_ticks"]
            and e["proxy_boot_id"] == kernel["boot_id"]
            for e in events
        ),
        "real authority journal belongs to another kernel",
    )
    checked = [
        e
        for e in events
        if e["kind"] == "route.close_checked"
        and e["detail"].get("candidate_generation") == launch["candidate_generation"]
    ]
    require(
        checked
        and not any(
            e["kind"]
            in {
                "route.open.intent",
                "route.open.applied",
                "route.restore.intent",
                "route.restore.applied",
                "route.close_all",
                "authority.stop",
            }
            for e in events[checked[-1]["sequence"] :]
        ),
        "original candidate close-check missing or superseded",
    )
    journal = semantic.read_regular(descriptor["journal_path"])
    expiry = mono + original_grant["expires_at"] * 1_000_000_000 - wall
    require(
        mono < expiry <= mono + MAX_ROUTE_LEASE_NS,
        "original independent lease outside bounded window",
    )
    return {
        "schema": "ecpa-observed-independent-prepared-grant/v1",
        "descriptor": descriptor,
        "grant": original_grant,
        "original_route": route,
        "candidate_generation": launch["candidate_generation"],
        "original_monotonic_expiry_ns": expiry,
        "anchored_monotonic_ns": mono,
        "anchored_wall_ns": wall,
        "query_before": raw_before,
        "lease_valid": raw_valid,
        "query_after": raw_after,
        "close_checked_sequence": checked[-1]["sequence"],
        "journal_prefix_bytes": len(journal),
        "journal_prefix_sha256": sha(journal),
        "observer": registry.process_identity(os.getpid()),
        "observer_source": semantic.reference(__file__),
        "formal_result": False,
    }


def route_grant_current(observation, input_audits):
    descriptor, grant = observation["descriptor"], observation["grant"]
    registry._kernel(descriptor["kernel"])
    argv, flag = _authority_argv(descriptor["kernel"])
    require(
        argv == descriptor["argv"]
        and {
            "holder": flag("--grant-holder"),
            "fencing_token": int(flag("--grant-token")),
            "expires_at": int(flag("--grant-expires-at")),
        }
        == grant,
        "original independent grant invocation changed",
    )
    reader = IndependentGrantObserver(descriptor, input_audits)
    before, _ = reader.exchange("query")
    valid, _ = reader.exchange("lease_valid", grant=grant, now=int(time.time()))
    after, _ = reader.exchange("query")
    require(
        before == after
        and after["route"] == observation["original_route"]
        and valid.get("valid") is True
        and time.monotonic_ns() < observation["original_monotonic_expiry_ns"],
        "original independently authenticated grant/route expired or changed",
    )
    raw = semantic.read_regular(descriptor["journal_path"])
    require(
        sha(raw[: observation["journal_prefix_bytes"]])
        == observation["journal_prefix_sha256"],
        "original authority close-check prefix changed",
    )
    events = loopback_traffic.read_traffic_journal(Path(descriptor["journal_path"]))
    require(
        not any(
            e["kind"]
            in {
                "route.open.intent",
                "route.open.applied",
                "route.restore.intent",
                "route.restore.applied",
                "route.close_all",
                "authority.stop",
            }
            for e in events[observation["close_checked_sequence"] :]
        ),
        "prepared grant superseded by later route action",
    )
    return observation["original_monotonic_expiry_ns"]


class RequestRouteControl:
    """Owner-local genuine Unix authority with a nonrenewable prepared lease."""

    def __init__(self, semantic_authority, permit, prepared_grant):
        self.semantic_authority, self.permit, self.prepared_grant = (
            semantic_authority,
            permit,
            prepared_grant,
        )
        root = semantic_authority.prepared_grant_current(permit, prepared_grant)
        require(
            root["controller"] == registry.process_identity(os.getpid()),
            "prepared service must be the original admitted controller",
        )
        self.path = Path(root["socket_path"])
        require(
            self.path.is_absolute()
            and self.path.resolve() == self.path
            and not os.path.lexists(self.path),
            "fresh canonical control socket required",
        )
        parent = self.path.parent.stat()
        require(
            parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700,
            "private owned control directory required",
        )
        self.route = json.loads(canonical(root["route"]))
        self.authority = root["controller"]
        self.closed = False
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.listener.bind(str(self.path))
            os.chmod(self.path, 0o600)
            meta = self.path.lstat()
            self.socket_identity = (meta.st_dev, meta.st_ino)
            self.listener.listen(8)
            self.listener.settimeout(0.2)
            self.thread = threading.Thread(target=self._serve, daemon=True)
            self.thread.start()
        except BaseException:
            self.listener.close()
            if hasattr(self, "socket_identity"):
                self._unlink()
            raise

    def _unlink(self):
        with suppress(FileNotFoundError):
            meta = self.path.lstat()
            if (meta.st_dev, meta.st_ino) == self.socket_identity:
                self.path.unlink()

    def _serve(self):
        while not self.stop.is_set():
            try:
                channel, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with channel:
                try:
                    channel.settimeout(2)
                    _, uid, _ = struct.unpack(
                        "3i",
                        channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                    )
                    require(uid == os.geteuid(), "request route caller UID differs")
                    raw = bytearray()
                    while not raw.endswith(b"\n"):
                        piece = channel.recv(4096)
                        require(
                            piece and len(raw) + len(piece) <= routes.MAX_MESSAGE,
                            "route frame invalid",
                        )
                        raw.extend(piece)
                    require(
                        json.loads(raw) == {"operation": "request_binding_query"},
                        "route operation is read-only",
                    )
                    with self.lock:
                        live = (
                            not self.closed
                            and time.monotonic_ns()
                            < self.route["lease_expires_monotonic_ns"]
                        )
                        response = {
                            "ok": live,
                            "schema": CONTROL,
                            "state": "PREPARED" if live else "REVOKED",
                            "semantic_ready": False,
                            "blanket_public_open": False,
                            "binding": self.route if live else None,
                        }
                    channel.sendall(canonical(response) + b"\n")
                except Exception:
                    with suppress(OSError):
                        channel.sendall(b'{"ok":false}\n')

    def revoke(self):
        with self.lock:
            self.closed = True

    def close(self):
        self.revoke()
        self.stop.set()
        self.listener.close()
        self.thread.join(3)
        self._unlink()


class PreparedRequestRouteReader(routes.LiveRouteReader):
    """Reuse original real SO_PEERCRED/socket/source reader, with a new schema."""

    def __init__(self, semantic_authority, permit, prepared_grant):
        self.semantic_authority, self.permit, self.prepared_grant = (
            semantic_authority,
            permit,
            prepared_grant,
        )
        root = semantic_authority.prepared_grant_current(permit, prepared_grant)
        self.socket_path = routes._path(root["socket_path"])
        self.authority = root["controller"]
        self.authority_sources = root["sources"]
        self.authority_command_sha256 = root["command_sha256"]
        self.expected_binding = root["route"]
        self._inputs_current()
        self.socket_identity = self._identity()

    def _inputs_current(self):
        root = self.semantic_authority.prepared_grant_current(
            self.permit, self.prepared_grant
        )
        require(
            root["route"] == self.expected_binding, "original prepared root changed"
        )

    def read(self):
        self._inputs_current()
        before = self._call("request_binding_query")
        after = self._call("request_binding_query")
        require(
            before == after
            and after["schema"] == CONTROL
            and after["state"] == "PREPARED"
            and after["semantic_ready"] is False
            and after["blanket_public_open"] is False
            and after["binding"] == self.expected_binding
            and time.monotonic_ns() < after["binding"]["lease_expires_monotonic_ns"],
            "actual prepared controller scope/fence/original lease changed",
        )
        self._inputs_current()
        return json.loads(canonical(after["binding"]))


class SemanticRequestForwarder(RequestForwarder):
    """Consume compiled obligations only on this handler's genuine new response."""

    def __init__(
        self,
        *args,
        semantic_authority,
        semantic_permit,
        authentic_handoff,
        prepared_grant,
        route_reader,
        **kwargs,
    ):
        self.semantic_authority = semantic_authority
        self.semantic_permit = json.loads(canonical(semantic_permit))
        self.authentic_handoff = json.loads(canonical(authentic_handoff))
        self.prepared_grant = json.loads(canonical(prepared_grant))
        self.semantic_route_reader = route_reader
        self.semantic_deployment = None
        self._starting = False
        value = semantic_authority.permit_current(semantic_permit)
        require(
            (args[0] if args else kwargs.get("book")) == value["phasebook"],
            "forwarder book differs from actual Plan permit",
        )
        super().__init__(*args, **kwargs)

    def _current(self):
        try:
            super()._current()
            if self.semantic_deployment is not None:
                self.semantic_authority.deployment_current(
                    self.semantic_permit,
                    self.semantic_deployment,
                    self.semantic_route_reader,
                )
            else:
                require(self._starting, "Plan-bound request deployment is not prepared")
                self.semantic_authority.permit_current(self.semantic_permit)
        except Exception as error:
            self.failure = "semantic deployment permanently closed: " + str(error)
            raise

    def forward_request(self, **kwargs):
        require(self.semantic_deployment is not None, "semantic deployment not bound")
        try:
            return super().forward_request(**kwargs)
        except BaseException:
            self._discard_pending_semantic_completion()
            raise

    def _discard_pending_semantic_completion(self):
        capability = getattr(self, "_pending_semantic_capability", None)
        self._pending_semantic_capability = None
        if capability is not None:
            self.semantic_authority.discard_verified_completion(capability)

    def close(self):
        self._discard_pending_semantic_completion()
        self.failure = "semantic owner cleanup"
        super().close()

    def start_producer(self, *, timeout_s=30):
        require(self.semantic_deployment is None, "semantic deployment cannot restart")
        self._starting = True
        try:
            ready = super().start_producer(timeout_s=timeout_s)
            self.semantic_deployment = self.semantic_authority.bind_request_deployment(
                self.semantic_permit,
                handoff=self.authentic_handoff,
                prepared_grant=self.prepared_grant,
                enrollment=self.enrollment,
                descriptor=self.descriptor,
                producer=self.producer_identity,
                producer_ready=ready,
                producer_registration=self.producer_registration,
                route_reader=self.semantic_route_reader,
            )
            self._record("semantic-deployment.json", self.semantic_deployment)
            return ready
        except BaseException:
            self.failure = "semantic producer/deployment binding failed"
            self.close()
            raise
        finally:
            self._starting = False

    def _producer_completion_registration(self):
        root = self.semantic_authority.prepared_grant_current(
            self.semantic_permit, self.prepared_grant
        )
        return {
            "completion_domain": semantic.request_live_producer.FIXED_COMPLETION,
            "original_route_expires_monotonic_ns": root["route"][
                "lease_expires_monotonic_ns"
            ],
        }

    def _verify_owner_observation(self, phase, output, admission, completion):
        self._current()
        require(
            getattr(self, "_pending_semantic_capability", None) is None,
            "prior owner verification capability remains pending",
        )
        args = {
            "recipe": self.book["recipe"],
            "phase_id": phase["phase_id"],
            "output": output,
            "descriptor": self.descriptor,
            "spec_path": self.spec_path,
            "journal_path": output / "snapshot/native.jsonl",
            "policy_path": self.policy_path,
            "drain_policy_path": self.drain_policy_path,
        }
        capability = self.semantic_authority.verify_request_completion(
            self.semantic_permit,
            self.semantic_deployment,
            route_reader=self.semantic_route_reader,
            admission=admission,
            phase_index=self.next_phase,
            output=output,
            observation_arguments=args,
            producer_receipt=self._producer_completion_receipt,
        )
        ticket, observed = self.semantic_authority.verified_completion(capability)
        self._pending_semantic_capability = capability
        self._record(f"semantic-ticket-{self.next_phase:04d}.json", ticket)
        return observed

    def _consume(self, envelope, admission):
        self._current()
        require(self.semantic_deployment is not None, "semantic deployment absent")
        capability = self._pending_semantic_capability
        self._pending_semantic_capability = None
        ticket, _ = self.semantic_authority.verified_completion(capability)

        def persist():
            self._record(
                f"semantic-consume-{self.next_phase:04d}.json",
                {
                    "ticket_sha256": ticket["sha256"],
                    "admission_nonce": admission["admission_nonce"],
                    "obligation_id": ticket["body"]["compiled_obligation"][
                        "obligation_id"
                    ],
                    "consumed_monotonic_ns": time.monotonic_ns(),
                    "formal_result": False,
                },
            )

        self.semantic_authority.consume_request(
            self.semantic_permit,
            self.semantic_deployment,
            capability,
            route_reader=self.semantic_route_reader,
            admission=admission,
            persist=persist,
        )
        response = super()._consume(envelope, admission)
        self._release_guard(ticket, admission)
        return response

    def _release_guard(self, ticket, admission):
        """Check after all response IO; a spent completion never revives on failure."""
        try:
            semantic.check_completion_files(ticket["body"])
            self._current()
            now = time.monotonic_ns()
            require(
                now < ticket["body"]["expires_monotonic_ns"]
                and now < admission["deadline_monotonic_ns"],
                "original completion/public deadline expired after response IO",
            )
        except Exception as error:
            self.failure = "semantic release permanently closed: " + str(error)
            raise
