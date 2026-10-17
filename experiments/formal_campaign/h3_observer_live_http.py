"""Private native forwarding with original-client deadlines and guarded release.

Requires a native authority, an actually bound source-owned client and a native
verifier for the current enrollment. This module does not grant those objects
from self-reported JSON. Public admission is recorded only after full consumption.
"""

from __future__ import annotations

import base64
import http.client
import json
import sys
import time
import uuid
from pathlib import Path

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign.h3_dynamic_authority import (
    MAX_BODY,
    DynamicProxyHandler,
    accepted_api_socket,
    digest,
    require,
)
from experiments.formal_campaign.h3_worker_relaunch import identity


class BoundOriginalClient:
    """Bind an already Popen'd original generator, not a future guessed PID."""

    def __init__(self, process, spec_path, trace_path, ready_path):
        self.kernel = identity(process["pid"])
        require(
            all(self.kernel[k] == v for k, v in process.items()),
            "original client kernel differs",
        )
        self.spec_path = Path(spec_path)
        self.trace_path = Path(trace_path)
        self.source = Path(client.__file__).resolve()
        self.source_raw = self.source.read_bytes()
        self.spec_raw = self.spec_path.read_bytes()
        self.spec = json.loads(self.spec_raw)
        client.validate_spec(self.spec)
        require(
            self.spec["request_count"] == 60
            and self.spec["concurrency"] == 8
            and self.spec["interval_s"] == 0.2
            and self.spec["timeout_s"] == 10,
            "original H3 workload/window differs",
        )
        self.argv = [
            sys.executable,
            str(self.source),
            "--spec",
            str(spec_path),
            "--trace",
            str(trace_path),
            "--ready",
            str(ready_path),
        ]
        self.trace_inode = None
        self.verify()

    def verify(self):
        require(
            identity(self.kernel["pid"]) == self.kernel, "original client epoch changed"
        )
        argv = [
            x.decode()
            for x in Path(f"/proc/{self.kernel['pid']}/cmdline")
            .read_bytes()
            .split(b"\0")
            if x
        ]
        require(argv == self.argv, "original client exact argv differs")
        require(
            self.source.read_bytes() == self.source_raw
            and self.spec_path.read_bytes() == self.spec_raw,
            "original client source/spec changed",
        )

    def request(self, request_id, body, incoming_socket):
        self.verify()
        # The actual client must own the connected reverse TCP endpoint, so a
        # same-UID caller cannot steal an enrolled request ID from the trace.
        accepted_api_socket(incoming_socket, self.kernel)
        info = self.trace_path.lstat()
        require(
            not self.trace_path.is_symlink() and not info.st_mode & 0o077,
            "original client trace is not private",
        )
        inode = [info.st_dev, info.st_ino]
        if self.trace_inode is None:
            self.trace_inode = inode
        require(inode == self.trace_inode, "original client trace inode changed")
        events = client.read_client_trace(self.trace_path)
        require(
            events[0]["kind"] == "client.start"
            and events[0]["detail"]["spec_sha256"]
            == client.sha(client.canonical(self.spec)),
            "actual client start/spec binding differs",
        )
        require(
            all(
                all(
                    e["client"][k] == self.kernel[k]
                    for k in ("pid", "start_ticks", "boot_id")
                )
                for e in events
            ),
            "trace contains a different client epoch",
        )
        selected = [
            e["detail"]
            for e in events
            if e["kind"] == "request.start" and e["detail"]["request_id"] == request_id
        ]
        require(len(selected) == 1, "request lacks unique actual client send")
        start = selected[0]
        require(
            start["body_base64"] == base64.b64encode(body).decode()
            and start["body_sha256"] == client.sha(body)
            and body == client.canonical(self.spec["payload"]),
            "private forward differs from original request body",
        )
        require(
            start["deadline_ns"] - start["sent_ns"] == 10_000_000_000
            and start["sent_ns"] <= time.monotonic_ns() < start["deadline_ns"],
            "original client request deadline expired",
        )
        self.verify()
        return start


class LiveProxyHandler(DynamicProxyHandler):
    """Forward privately, consume full native evidence, then publish under fence."""

    def _forward(self):
        authority = self.server.authority
        enrollment = None
        request_id = self.headers.get("X-ECPA-Request-ID", "")
        admission_id = uuid.uuid4().hex
        try:
            require(
                self.command == "POST" and self.path == "/v1/completions",
                "native H3 only supports the original completions endpoint",
            )
            require(
                self.headers.get("Transfer-Encoding") is None, "chunked unsupported"
            )
            count = int(self.headers.get("Content-Length", "0"))
            require(0 < count <= MAX_BODY, "native request body bound exceeded")
            self.connection.settimeout(10)
            body = self.rfile.read(count)
            require(len(body) == count, "native request body incomplete")
            start = authority.bound_client.request(request_id, body, self.connection)
            deadline = start["deadline_ns"]
            with authority.lock:
                require(
                    request_id not in authority.seen_request_ids, "request replayed"
                )
                authority.seen_request_ids.add(request_id)
                authority._refresh_candidate()
                require(
                    authority.route.generation is not None,
                    "native private route is not prepared",
                )
                enrollment, route = authority.routing_enrollment(), authority.route
                verifier = authority.native_verifier_for(enrollment)
                authority._record(
                    "request.private-forward",
                    route,
                    request_id=request_id,
                    admission_id=admission_id,
                    method=self.command,
                    request_sha256=digest(body),
                    enrollment_sha256=enrollment["sha256"],
                    original_sent_ns=start["sent_ns"],
                    original_deadline_ns=deadline,
                )
            verifier.begin_request(request_id)
            remaining = (deadline - time.monotonic_ns()) / 1e9
            require(remaining > 0, "native original request expired before connect")
            connection = http.client.HTTPConnection(
                *authority.candidate, timeout=remaining
            )
            try:
                connection.connect()
                connection.auto_open = 0
                with authority.lock:
                    self._same_epoch(authority, enrollment)
                    inode = accepted_api_socket(
                        connection.sock, enrollment["backend"]["process_identity"]
                    )
                    self._same_epoch(authority, enrollment)
                    authority._record(
                        "request.peer-bound",
                        route,
                        request_id=request_id,
                        admission_id=admission_id,
                        enrollment_sha256=enrollment["sha256"],
                        accepted_socket_inode=inode,
                    )
                    require(
                        time.monotonic_ns() < deadline,
                        "native request expired before send",
                    )
                    backend_sent_ns = time.monotonic_ns()
                    connection.request(
                        "POST",
                        self.path,
                        body=body,
                        headers={
                            "Content-Type": "application/json",
                            "X-Request-Id": request_id,
                            "X-ECPA-Request-ID": request_id,
                            "X-ECPA-Admission-ID": admission_id,
                        },
                    )
                response = connection.getresponse()
                payload = response.read(MAX_BODY + 1)
                received = time.monotonic_ns()
                require(len(payload) <= MAX_BODY, "native response too large")
                proof = verifier.verify_request(
                    request_id=request_id,
                    request_body=body,
                    response_status=response.status,
                    response_body=payload,
                    sent_ns=start["sent_ns"],
                    received_ns=received,
                    backend_sent_ns=backend_sent_ns,
                    deadline_ns=deadline,
                    response_expectation=authority.bound_client.spec[
                        "response_expectation"
                    ],
                )
                with authority.lock:
                    self._same_epoch(authority, enrollment)
                    authority.bound_client.verify()
                    native_report = verifier.consume(
                        proof,
                        request_id=request_id,
                        response_body=payload,
                        deadline_ns=deadline,
                    )
                    authority.verify_native_request_current(
                        enrollment,
                        runtime_request_id=proof.runtime_request_id,
                        transaction_id=proof.transaction_id,
                        native_report=native_report,
                    )
                    self._same_epoch(authority, enrollment)
                    require(
                        proof.native_plan_id == enrollment["plan_id"]
                        and proof.native_launch_id == enrollment["launch_id"]
                        and time.monotonic_ns() <= deadline,
                        "native report epoch/deadline differs at public release",
                    )
                    authority._record(
                        "request.public-admit",
                        route,
                        request_id=request_id,
                        admission_id=admission_id,
                        method=self.command,
                        request_sha256=digest(body),
                        enrollment_sha256=enrollment["sha256"],
                        native_prefix_sha256=proof.original_prefix_sha256,
                        native_report={
                            "path": proof.snapshot_report_path,
                            "sha256": "sha256:" + proof.snapshot_report_sha256,
                        },
                        runtime_request_id=proof.runtime_request_id,
                        transaction_id=proof.transaction_id,
                        native_verified_ns=proof.verified_monotonic_ns,
                        body_sha256=digest(payload),
                        status=200,
                    )
                    self.send_response(200)
                    self.send_header("X-ECPA-Admission-ID", admission_id)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
            finally:
                connection.close()
        except Exception as exc:
            with authority.lock:
                authority._record(
                    "request.native-unavailable",
                    authority.route,
                    request_id=request_id,
                    admission_id=admission_id,
                    enrollment_sha256=enrollment["sha256"] if enrollment else None,
                    error=str(exc),
                    public_status=503,
                )
            self.send_error(
                503, "native obligations unavailable within original window"
            )

    @staticmethod
    def _same_epoch(authority, enrollment):
        require(
            authority.routing_enrollment() is not None
            and authority.routing_enrollment()["sha256"] == enrollment["sha256"]
            and authority.route.generation == enrollment["generation"],
            "native generation/membership closed or changed",
        )
        authority._recheck()
