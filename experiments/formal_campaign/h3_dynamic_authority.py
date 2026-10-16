#!/usr/bin/env python3
"""Independent dynamic backend authority, with a distinct journal domain.

Only source-admitted Plan obligations whose actual event is ``invoked`` are
implemented. Semantic/native completion remains unsupported and fail closed.
No old authority artifact or static backend registration is rewritten.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from contextlib import suppress
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from jsonschema import Draft7Validator

from experiments.exposure_gate.loopback_traffic import _Authority
from experiments.formal_campaign.h3_dynamic_bindings import (
    BindingGuard,
    default_native_plan_binding,
    verify_binding_artifact,
)
from experiments.formal_campaign.h3_worker_recovery import (
    capture_parent_worker_ancestry,
)
from experiments.formal_campaign.h3_worker_relaunch import identity
from vllm_hust_ext.exposure_gate import GateError, LeaseGrant, RouteState
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.plan_artifact import read_plan_artifact

HERE = Path(__file__).resolve().parent
PROFILE = "ecpa-source-owned-dynamic-backend-enrollment/v1"
JOURNAL = "ecpa-h3-dynamic-authority-journal/v1"
MAX_BODY = 1024 * 1024
MAX_CONTROL = 1024 * 1024


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(value, why):
    if not value:
        raise GateError(why)


def check_ref(ref):
    path = Path(ref["path"])
    require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        "actual canonical source/Plan file missing",
    )
    raw = path.read_bytes()
    require(digest(raw) == ref["sha256"], "registered source/Plan bytes changed")
    return path


def validate_policy(policy):
    Draft7Validator(
        json.loads((HERE / "h3-dynamic-policy.schema.json").read_bytes())
    ).validate(policy)
    require(
        policy["allowed_events"] == ["invoked"],
        "semantic or other obligations need their own real producer",
    )
    require(
        policy["worker_ordinals"] == [0, 1],
        "this actual carrier scope is the declared TP2 role set",
    )
    endpoint = urlparse(policy["backend_endpoint"])
    require(
        endpoint.hostname == "127.0.0.1" and endpoint.port,
        "only the registered loopback endpoint is supported",
    )
    for ref in policy["source_refs"] + policy["plan_artifacts"]:
        check_ref(ref)
    derived = [verify_binding_artifact(ref) for ref in policy["binding_artifacts"]]
    require(
        {p.plan_id for p, _ in derived}
        == {read_plan_artifact(check_ref(r)).plan_id for r in policy["plan_artifacts"]},
        (
            "every Plan must have independently installed/contract-derived "
            "binding provenance"
        ),
    )
    for _, bindings in derived:
        require(
            bindings == policy["bindings"],
            "bare policy binding differs from actual artifact-derived ownership",
        )
    require(
        len({b["obligation_id"] for b in policy["bindings"]}) == len(policy["bindings"])
        and len({canonical(b["entry_point"]) for b in policy["bindings"]})
        == len(policy["bindings"]),
        "duplicate obligation or entrypoint binding",
    )
    require(
        policy["host_evidence_paths"] or policy["host_evidence_roots"],
        "actual Host evidence observation scope missing",
    )
    aliases = [default_native_plan_binding(ref) for ref in policy["binding_artifacts"]]
    require(
        policy["native_plan_bindings"] == aliases
        and len({a["runtime_plan_id"] for a in aliases}) == len(aliases),
        "native-to-execution Plan binding must be independently source-derived",
    )
    return policy


class DynamicJournal:
    schema = JOURNAL

    def __init__(self, path: Path, policy_sha: str):
        parent = path.parent.stat()
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == os.getuid()
            and not parent.st_mode & 0o077,
            "authority journal directory must be private and owned",
        )
        self.fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_NOFOLLOW,
            0o600,
        )
        self.owner = identity(os.getpid())
        self.policy_sha = policy_sha
        self.sequence, self.previous, self.last_ns = 0, "sha256:" + "0" * 64, 0
        self.lock = threading.Lock()

    def record(self, kind, route, **detail):
        with self.lock:
            now = max(time.monotonic_ns(), self.last_ns + 1)
            event = {
                "schema": self.schema,
                "sequence": self.sequence + 1,
                "previous_sha256": self.previous,
                "monotonic_ns": now,
                "authority": self.owner,
                "policy_sha256": self.policy_sha,
                "kind": kind,
                "route": {
                    "generation": route.generation,
                    "fence": route.fence,
                    "snapshot_sha256": digest(canonical({"snapshot": route.snapshot})),
                },
                "detail": detail,
            }
            raw = canonical(event)
            require(
                os.fstat(self.fd).st_size + len(raw) < 32 * 1024 * 1024,
                "dynamic journal capacity exceeded",
            )
            remaining = memoryview(raw + b"\n")
            while remaining:
                count = os.write(self.fd, remaining)
                require(count > 0, "dynamic journal write failed")
                remaining = remaining[count:]
            os.fsync(self.fd)
            self.sequence += 1
            self.previous = digest(raw)
            self.last_ns = now

    def close(self):
        os.close(self.fd)


def read_dynamic_journal(path, *, domain=JOURNAL):
    require(
        Path(path).stat().st_size <= 32 * 1024 * 1024,
        "dynamic journal exceeds source bound",
    )
    raw = Path(path).read_bytes()
    require(raw and raw.endswith(b"\n"), "dynamic authority journal is incomplete")
    previous, last, owner, policy = "sha256:" + "0" * 64, 0, None, None
    events = []
    for index, line in enumerate(raw.splitlines(), 1):
        event = json.loads(line)
        require(
            canonical(event) == line
            and event.get("schema") == domain
            and event.get("sequence") == index
            and event.get("previous_sha256") == previous,
            "dynamic journal domain/chain differs; old journal projection is forbidden",
        )
        require(event["monotonic_ns"] > last, "dynamic journal order is not monotonic")
        if owner is None:
            owner, policy = event["authority"], event["policy_sha256"]
        require(
            event["authority"] == owner and event["policy_sha256"] == policy,
            "dynamic authority identity/policy changed",
        )
        events.append(event)
        previous = digest(line)
        last = event["monotonic_ns"]
    require(events[0]["kind"] == "authority.start", "dynamic authority start missing")
    require(
        sum(e["kind"] == "authority.start" for e in events) == 1,
        "dynamic authority start was replayed",
    )
    return events


class DynamicAuthority(_Authority):
    policy_validator = staticmethod(validate_policy)

    def make_binding_guards(self, policy):
        return [BindingGuard(ref) for ref in policy["binding_artifacts"]]

    def __init__(self, policy, journal):
        self.policy_validator(policy)
        self.policy = policy
        self.binding_guards = self.make_binding_guards(policy)
        self.policy_sha = digest(canonical(policy))
        self.generation = 0
        self.enrollment = None
        self.revoked_enrollments = set()
        self.used_launches, self.used_api_kernels = set(), set()
        endpoint = urlparse(policy["backend_endpoint"])
        backend = (endpoint.hostname, endpoint.port)
        grant = LeaseGrant(
            policy["grant"]["holder"],
            policy["grant"]["token"],
            policy["grant"]["expires_at"],
        )
        super().__init__(
            RouteState(None, "closed", None),
            grant,
            backend,
            backend,
            journal,
            recovery_binding={
                "launch_id": policy["start_id"],
                "registration_sha256": policy["registration_sha256"],
            },
        )

    def _lease(self, value=None):
        require(self.grant.expires_at >= time.time(), "authority lease expired")
        if value is not None:
            require(
                value.get("holder") == self.grant.holder
                and value.get("token") == self.grant.fencing_token
                and value.get("registration_sha256")
                == self.policy["registration_sha256"],
                "authority writer/registration fence differs",
            )

    def _close(self, reason):
        self.route = RouteState(None, "closed", None)
        if self.enrollment is not None:
            self.revoked_enrollments.add(self.enrollment["sha256"])
        self._record(
            "route.closed",
            self.route,
            reason=reason,
            revoked_enrollment=self.enrollment["sha256"] if self.enrollment else None,
        )

    def _source_current(self):
        for ref in self.policy["source_refs"] + self.policy["plan_artifacts"]:
            check_ref(ref)
        for guard in self.binding_guards:
            _, bindings = guard.verify()
            require(
                bindings == self.policy["bindings"],
                "installed binding provenance changed",
            )

    def observe_backend(self, port):
        observed = super().observe_backend(port)
        require(observed is not None, "backend has no actual registration")
        inode = observed["listener_inode"]
        rows = [
            line.split() for line in Path("/proc/net/tcp").read_text().splitlines()[1:]
        ]
        require(
            any(
                row[9] == inode
                and row[3] == "0A"
                and row[1] in {f"0100007F:{port:04X}", f"00000000:{port:04X}"}
                for row in rows
            ),
            "API listener is not reachable at the registered loopback endpoint",
        )
        return observed

    def _observe_members(self, supplied):
        require(len(supplied) == 3, "exact api-server plus both TP2 workers required")
        expected_slots = {("api-server", 0), ("worker", 0), ("worker", 1)}
        require(
            {(m["role"], m["ordinal"]) for m in supplied} == expected_slots,
            "actual membership role set differs",
        )
        parent = next(m for m in supplied if m["role"] == "api-server")
        observed = []
        for member in supplied:
            kernel = identity(member["identity"]["pid"])
            require(
                all(member["identity"][k] == kernel[k] for k in kernel),
                "enrollment kernel changed",
            )
            event = parse_host_event(canonical(member["event"]))
            process = event["process"]
            require(
                process.get("assignment_source") == "host"
                and process["role"] == member["role"]
                and process["ordinal"] == member["ordinal"]
                and process["pid"] == kernel["pid"]
                and int(process["start_identity"].rsplit(":", 1)[1])
                == kernel["start_ticks"],
                "Host role is not bound to this actual kernel",
            )
            require(
                event["launch_id"] == member["identity"]["launch_id"]
                and event["launch_id"] == parent["identity"]["launch_id"],
                "cross-launch membership",
            )
            ancestry = (
                capture_parent_worker_ancestry(parent["identity"], member["identity"])
                if member["role"] == "worker"
                else []
            )
            observed.append(
                {
                    "role": member["role"],
                    "ordinal": member["ordinal"],
                    "identity": member["identity"],
                    "event": event,
                    "parent_worker_ancestry": ancestry,
                }
            )
        require(
            len({m["event"]["plan_id"] for m in observed}) == 1,
            "members use different Plans",
        )
        require(
            len(
                {
                    (
                        m["identity"]["pid"],
                        m["identity"]["start_ticks"],
                        m["identity"]["boot_id"],
                    )
                    for m in observed
                }
            )
            == len(observed),
            "actual TP2 roles must be distinct kernel processes",
        )
        records = self._host_records(parent["identity"]["launch_id"])
        require(
            all(m["event"] in records for m in observed),
            "membership role events are absent from actual source-owned Host journal",
        )
        # The API must have executed the statically registered Host launch argv;
        # caller-provided role JSON alone cannot enroll a different process.
        argv = [
            v.decode()
            for v in Path(f"/proc/{parent['identity']['pid']}/cmdline")
            .read_bytes()
            .split(b"\0")
            if v
        ]
        require(
            argv in self.policy["api_argv"],
            "API kernel argv differs from static source policy",
        )
        return observed

    def _host_records(self, launch_id):
        records = []
        paths = list(self.policy["host_evidence_paths"])
        # Native Manager owns the UUID and filename. Freeze its private roots,
        # derive only after observing the actual UUID, and never guess a PID/ID.
        if self.policy["host_evidence_roots"]:
            launch = uuid.UUID(launch_id)
            require(
                launch.version == 4 and str(launch) == launch_id,
                "native launch requires an actual canonical UUID4",
            )
            paths += [
                str(Path(root) / (str(launch) + ".events.jsonl"))
                for root in self.policy["host_evidence_roots"]
            ]
        for name in paths:
            path = Path(name)
            if not path.exists():
                continue
            info = path.stat()
            parent = path.parent.stat()
            require(
                not path.is_symlink()
                and path.resolve() == path
                and info.st_uid == os.getuid()
                and not info.st_mode & 0o077
                and parent.st_uid == os.getuid()
                and not parent.st_mode & 0o077,
                "Host evidence requires a private source-owned canonical path",
            )
            data = path.read_bytes()
            require(data.endswith(b"\n"), "Host journal has incomplete record")
            records += [parse_host_event(line) for line in data.splitlines() if line]
        return records

    def _plan_and_obligations(self, enrollment):
        plan_id = enrollment["plan_id"]
        plans = [
            read_plan_artifact(check_ref(ref)).plan
            for ref in self.policy["plan_artifacts"]
        ]
        execution_id = next(
            (
                a["execution_plan_id"]
                for a in self.policy["native_plan_bindings"]
                if a["runtime_plan_id"] == plan_id
            ),
            plan_id,
        )
        plans = [p for p in plans if p.plan_id == execution_id]
        require(
            len(plans) == 1,
            "actual Plan is absent or ambiguous in static deployment policy",
        )
        plan = plans[0]
        require(
            plan.obligations and all(o.event == "invoked" for o in plan.obligations),
            (
                "semantic obligation evidence is unverified; this new domain "
                "supports actual invoked obligations only"
            ),
        )
        require(
            {b["obligation_id"] for b in self.policy["bindings"]}
            == {o.obligation_id for o in plan.obligations},
            "static bindings do not cover the actual Plan",
        )
        plugin_ids = {p.id for p in plan.plugins}
        records = self._host_records(enrollment["launch_id"])
        consumed = []
        for obligation in plan.obligations:
            binding = next(
                b
                for b in self.policy["bindings"]
                if b["obligation_id"] == obligation.obligation_id
            )
            require(
                binding["plugin_id"] in plugin_ids,
                "obligation binding names a foreign plugin",
            )
            for ordinal in obligation.required_ordinals:
                member = next(
                    (
                        m
                        for m in enrollment["members"]
                        if m["role"] == obligation.role and m["ordinal"] == ordinal
                    ),
                    None,
                )
                require(
                    member is not None,
                    "Plan required role absent from actual membership",
                )
                matches = [
                    r
                    for r in records
                    if r["event"] == "invoked"
                    and r["entry_point"] == binding["entry_point"]
                    and r["plan_id"] == plan_id
                    and r["launch_id"] == enrollment["launch_id"]
                    and r["process"] == member["event"]["process"]
                ]
                require(
                    matches,
                    "actual source-owned invocation does not cover Plan obligation",
                )
                consumed.append(matches[-1])
        return digest(canonical(consumed))

    def _recheck(self):
        self._lease()
        self._source_current()
        require(self.enrollment is not None, "no actual enrollment")
        require(
            self.enrollment["sha256"] not in self.revoked_enrollments,
            "revoked membership cannot be admitted again",
        )
        self._observe_members(self.enrollment["members"])
        self.observe_backend(self.candidate[1])
        return self._plan_and_obligations(self.enrollment)

    def _refresh_candidate(self):
        if self.route.generation is None:
            return None
        try:
            return self._recheck()
        except Exception:
            self._close("source, process, obligation, listener or lease lost")
            return None

    def apply(self, value):
        operation = value.get("operation")
        fields = {
            "capabilities": set(),
            "query": set(),
            "close_generation": {"expected_generation"},
            "enroll_generation": {
                "expected_generation",
                "actual_membership",
                "plan_id",
                "launch_id",
            },
            "admit_generation": {"generation", "membership_sha256"},
        }
        require(
            operation in fields
            and set(value)
            == {"operation", "registration_sha256", "holder", "token"}
            | fields[operation],
            "new-domain authority command fields differ",
        )
        with self.lock:
            if operation == "capabilities":
                self._lease(value)
                self._source_current()
                return {
                    "profiles": [PROFILE],
                    "registration_sha256": self.policy["registration_sha256"],
                    "policy_sha256": self.policy_sha,
                }
            if operation == "query":
                require(
                    value["holder"] == self.grant.holder
                    and value["token"] == self.grant.fencing_token
                    and value["registration_sha256"]
                    == self.policy["registration_sha256"],
                    "query writer fence differs",
                )
                self._refresh_candidate()
                return {
                    "generation": self.generation,
                    "route": asdict(self.route),
                    "policy_sha256": self.policy_sha,
                }
            self._lease(value)
            if operation == "close_generation":
                require(
                    value.get("expected_generation") == self.generation,
                    "stale generation cannot close a replacement",
                )
                self._close("registered recovery close")
                return {}
            if operation == "enroll_generation":
                require(
                    value.get("expected_generation") == self.generation,
                    "stale enrollment CAS",
                )
                self._close("close-before-enroll")
                self._source_current()
                if self.enrollment is not None:
                    for previous in self.enrollment["members"]:
                        expected = previous["identity"]
                        try:
                            current = identity(expected["pid"])
                        except (OSError, ValueError):
                            continue
                        require(
                            any(current[k] != expected[k] for k in current),
                            (
                                "previous Host member remains live; "
                                "no replacement epoch yet"
                            ),
                        )
                members = self._observe_members(value["actual_membership"])
                parent = next(m for m in members if m["role"] == "api-server")
                launch = parent["identity"]["launch_id"]
                api = (
                    parent["identity"]["pid"],
                    parent["identity"]["start_ticks"],
                    parent["identity"]["boot_id"],
                )
                require(
                    launch not in self.used_launches
                    and api not in self.used_api_kernels,
                    "dead/previous API instance cannot reenroll",
                )
                require(
                    value["plan_id"] == parent["event"]["plan_id"]
                    and value["launch_id"] == launch,
                    "caller Plan/launch differs from actual Host",
                )
                generation = self.generation + 1
                backend = {
                    "process_identity": {
                        k: parent["identity"][k]
                        for k in ("pid", "start_ticks", "boot_id")
                    },
                    "generation": generation,
                    "model": self.policy["model"],
                    "launch_id": launch,
                }
                previous = self.backend_registration
                self.backend_registration = {str(self.candidate[1]): backend}
                try:
                    actual_backend = self.observe_backend(self.candidate[1])
                except Exception:
                    self.backend_registration = previous
                    raise
                enrollment = {
                    "policy_sha256": self.policy_sha,
                    "start_id": self.policy["start_id"],
                    "registration_sha256": self.policy["registration_sha256"],
                    "nonce": uuid.uuid4().hex,
                    "generation": generation,
                    "membership_epoch": uuid.uuid4().hex,
                    "plan_id": value["plan_id"],
                    "launch_id": launch,
                    "members": members,
                    "backend": actual_backend,
                    "observed_ns": time.monotonic_ns(),
                }
                enrollment["sha256"] = digest(canonical(enrollment))
                self.generation = generation
                self.enrollment = enrollment
                self.used_launches.add(launch)
                self.used_api_kernels.add(api)
                self._record("backend.enrolled", self.route, enrollment=enrollment)
                return {
                    "admission": "closed-pending-obligations",
                    "generation": generation,
                    "membership_sha256": enrollment["sha256"],
                    "backend_registration": self.backend_registration,
                    "enrollment": enrollment,
                }
            if operation == "admit_generation":
                require(
                    self.enrollment is not None
                    and value.get("generation") == self.generation
                    and value.get("membership_sha256") == self.enrollment["sha256"],
                    "stale generation/membership cannot admit",
                )
                try:
                    observation = self._recheck()
                except Exception:
                    self._close("required evidence unverified")
                    raise
                self.route = RouteState(
                    self.generation,
                    "dynamic-" + self.enrollment["membership_epoch"],
                    {"enrollment_sha256": self.enrollment["sha256"]},
                )
                self._record(
                    "route.open.applied",
                    self.route,
                    enrollment_sha256=self.enrollment["sha256"],
                    observation_sha256=observation,
                )
                return {"generation": self.generation}
            raise GateError("unsupported new-domain authority operation")


class DynamicProxyHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self._forward()

    def do_GET(self):
        self._forward()

    def log_message(self, *_):
        pass

    def _forward(self):
        authority = self.server.authority
        enrollment = None
        try:
            require(
                self.headers.get("Transfer-Encoding") is None,
                "chunked requests unsupported",
            )
            count = int(self.headers.get("Content-Length", "0"))
            require(0 <= count <= MAX_BODY, "request body bound exceeded")
            self.connection.settimeout(5)
            body = self.rfile.read(count)
            require(len(body) == count, "incomplete request body")
            request_id, admission_id = (
                self.headers.get("X-ECPA-Request-ID", ""),
                uuid.uuid4().hex,
            )
            with authority.lock:
                require(
                    request_id
                    and len(request_id) <= 200
                    and request_id not in authority.seen_request_ids,
                    "request ID missing or replayed",
                )
                authority.seen_request_ids.add(request_id)
                authority._refresh_candidate()
                require(
                    authority.route.generation is not None, "registered route is closed"
                )
                route, enrollment = authority.route, authority.enrollment
                authority._record(
                    "request.admit",
                    route,
                    request_id=request_id,
                    admission_id=admission_id,
                    method=self.command,
                    request_sha256=digest(body),
                    enrollment_sha256=enrollment["sha256"],
                )
            connection = http.client.HTTPConnection(*authority.candidate, timeout=10)
            try:
                # Establish TCP only: no HTTP bytes may leave until this exact
                # accepted peer socket is observed in the admitted API kernel.
                # A new listener reusing the same port must not receive a body.
                connection.connect()
                connection.auto_open = 0
                with authority.lock:
                    require(
                        authority.enrollment is not None
                        and authority.enrollment["sha256"] == enrollment["sha256"]
                        and authority.route.generation == enrollment["generation"],
                        "generation closed or changed before request delivery",
                    )
                    authority._recheck()
                    peer_inode = accepted_api_socket(
                        connection.sock, enrollment["backend"]["process_identity"]
                    )
                    # Recheck under the same control lock through the actual
                    # write. http.client cannot silently reconnect elsewhere.
                    authority._recheck()
                    authority._record(
                        "request.peer-bound",
                        route,
                        admission_id=admission_id,
                        request_id=request_id,
                        enrollment_sha256=enrollment["sha256"],
                        accepted_socket_inode=peer_inode,
                        client_endpoint=list(connection.sock.getsockname()),
                        server_endpoint=list(connection.sock.getpeername()),
                    )
                    connection.request(
                        self.command,
                        self.path,
                        body=body,
                        headers={
                            "Content-Type": self.headers.get("Content-Type", ""),
                            "X-ECPA-Request-ID": request_id,
                            "X-ECPA-Admission-ID": admission_id,
                        },
                    )
                response = connection.getresponse()
                payload = response.read(MAX_BODY + 1)
                require(len(payload) <= MAX_BODY, "backend response bound exceeded")
                with authority.lock:
                    require(
                        authority.enrollment is not None
                        and authority.enrollment["sha256"] == enrollment["sha256"],
                        "backend generation changed during request",
                    )
                    authority._recheck()
                    authority._record(
                        "request.complete",
                        route,
                        request_id=request_id,
                        admission_id=admission_id,
                        method=self.command,
                        request_sha256=digest(body),
                        enrollment_sha256=enrollment["sha256"],
                        backend_host=authority.candidate[0],
                        backend_port=authority.candidate[1],
                        backend_identity=authority.observe_backend(
                            authority.candidate[1]
                        ),
                        status=response.status,
                        body_base64=base64.b64encode(payload).decode(),
                        body_sha256=digest(payload),
                    )
                self.send_response(response.status)
                self.send_header("X-ECPA-Admission-ID", admission_id)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                connection.close()
        except Exception as exc:
            with authority.lock:
                # A closed-window request or failure from the old generation
                # cannot revoke a newly enrolled replacement. Only invalidate
                # the exact generation which actually admitted this request.
                if (
                    enrollment is not None
                    and authority.enrollment is not None
                    and authority.enrollment["sha256"] == enrollment["sha256"]
                ):
                    authority._close("request unavailable: " + str(exc))
            self.send_error(503, "dynamic authority unavailable")


def accepted_api_socket(channel, expected_api):
    """Bind this established TCP four-tuple to the admitted API's accepted FD.

    Listener ownership alone is insufficient after connect. No application
    bytes have been sent when this independent kernel observation runs.
    """
    local, peer = channel.getsockname(), channel.getpeername()
    require(
        local[0] == peer[0] == "127.0.0.1",
        "backend connection is not registered IPv4 loopback",
    )

    def address(endpoint):
        return socket.inet_aton(endpoint[0])[::-1].hex().upper() + f":{endpoint[1]:04X}"

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        current = identity(expected_api["pid"])
        require(
            all(
                current[k] == expected_api[k] for k in ("pid", "start_ticks", "boot_id")
            ),
            "admitted API epoch died before HTTP delivery",
        )
        rows = [
            line.split() for line in Path("/proc/net/tcp").read_text().splitlines()[1:]
        ]
        sockets = {
            row[9]
            for row in rows
            if row[1] == address(peer) and row[2] == address(local) and row[3] == "01"
        }
        owned = set()
        for descriptor in Path(f"/proc/{expected_api['pid']}/fd").iterdir():
            with suppress(OSError):
                target = os.readlink(descriptor)
                if target.startswith("socket:["):
                    owned.add(target[8:-1])
        matched = sockets & owned
        if len(matched) == 1:
            check = identity(expected_api["pid"])
            require(
                all(
                    check[k] == expected_api[k]
                    for k in ("pid", "start_ticks", "boot_id")
                ),
                "admitted API epoch changed during accepted-socket observation",
            )
            return next(iter(matched))
        time.sleep(0.005)
    raise GateError(
        "connected TCP peer is not owned by the admitted API epoch; no HTTP bytes sent"
    )


def serve_control(path, authority):
    parent = path.parent.stat()
    require(
        parent.st_uid == os.getuid()
        and not parent.st_mode & 0o077
        and not path.exists(),
        "private fresh control socket required",
    )
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        listener.listen(8)
        while True:
            channel, _ = listener.accept()
            with channel:
                channel.settimeout(5)
                _, uid, _ = struct.unpack(
                    "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                if uid != os.getuid():
                    continue
                raw = b""
                try:
                    while not raw.endswith(b"\n"):
                        piece = channel.recv(4096)
                        require(
                            piece and len(raw) + len(piece) <= MAX_CONTROL,
                            "invalid dynamic control frame",
                        )
                        raw += piece
                    result = {"ok": True, **authority.apply(json.loads(raw))}
                except Exception as exc:
                    result = {"ok": False, "error": str(exc)}
                with suppress(OSError):
                    channel.sendall(canonical(result) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--public-port", type=int, required=True)
    parser.add_argument("--owned-stdin-lifetime", action="store_true")
    args = parser.parse_args()
    raw = args.policy.read_bytes()
    require(
        digest(raw) == args.policy_sha256,
        "static policy bytes differ from registered argv",
    )
    policy = json.loads(raw)
    validate_policy(policy)
    journal = DynamicJournal(args.journal, digest(canonical(policy)))
    authority = DynamicAuthority(policy, journal)
    server = ThreadingHTTPServer(("127.0.0.1", args.public_port), DynamicProxyHandler)
    server.authority = authority
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.owned_stdin_lifetime:
        threading.Thread(
            target=serve_control, args=(args.socket, authority), daemon=True
        ).start()
        try:
            sys.stdin.buffer.read()
        finally:
            with authority.lock:
                authority._close("independent owner lifetime ended")
            server.shutdown()
            server.server_close()
            journal.close()
            with suppress(FileNotFoundError):
                args.socket.unlink()
    else:
        serve_control(args.socket, authority)


if __name__ == "__main__":
    main()
