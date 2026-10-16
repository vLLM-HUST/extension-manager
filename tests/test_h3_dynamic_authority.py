"""CPU protocol fixtures with actual processes/listeners; no formal model result."""

import copy
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_dynamic_authority import (
    DynamicAuthority,
    DynamicJournal,
    DynamicProxyHandler,
    ThreadingHTTPServer,
    canonical,
    digest,
    read_dynamic_journal,
)
from experiments.formal_campaign.h3_worker_relaunch import identity


def event(kernel, role, ordinal, plan_id, launch, entry_index=0):
    proc = {
        "host": "cpu-fixture",
        "role": role,
        "ordinal": ordinal,
        "pid": kernel["pid"],
        "start_identity": f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
        "process_epoch": kernel["start_ticks"],
        "assignment_source": "host",
    }
    value = {
        "schema": "vllm-hust-plugin-evidence/0.1",
        "event_id": "pending",
        "event": "invoked",
        "observation_kind": "loader_lifecycle",
        "entry_point": {
            "group": "vllm.general_plugins",
            "name": f"fixture{entry_index}",
            "value": f"cpu_fixture_mod_{entry_index}.plugin:register",
        },
        "process": proc,
        "observed_at_ns": time.time_ns(),
        "delivery_attempt": 1,
        "plan_id": plan_id,
        "launch_id": launch,
        "binding_status": "bound",
        "occurrence_id": None,
        "controller_instance_id": None,
        "invocation_seq": None,
        "dispatch_id": None,
        "plugin_id": None,
        "artifact_digest": None,
        "identity_status": "launch-bound",
        "detail": None,
    }
    material = [
        proc["host"],
        proc["pid"],
        proc["start_identity"],
        proc["process_epoch"],
        role,
        ordinal,
        "vllm.general_plugins",
        value["entry_point"]["name"],
        value["entry_point"]["value"],
        "invoked",
        None,
        None,
        plan_id,
        launch,
        "loader_lifecycle",
        None,
        1,
        value["observed_at_ns"],
        "host",
    ]
    value["event_id"] = hashlib.sha256(
        json.dumps(material, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def start_host(tmp_path, port, launch, plan_id):
    source = tmp_path / "cpu_host.py"
    if not source.exists():
        source.write_text("""import json, os, subprocess, sys, threading, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

workers = [
    subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.read()"], stdin=subprocess.PIPE
    )
    for _ in range(2)
]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body_in = self.rfile.read(int(self.headers["Content-Length"]))
        with open(__file__ + ".received-" + str(os.getpid()), "ab") as trace:
            trace.write(body_in + b"\\n")
        body = json.dumps(
            {
                "id": "cpu-" + uuid.uuid4().hex,
                "model": "cpu-fixture",
                "choices": [{"index": 0, "finish_reason": "stop", "text": "ok"}],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
print(json.dumps({"pid": os.getpid(), "workers": [p.pid for p in workers]}), flush=True)
sys.stdin.read()
server.shutdown()
server.server_close()
for p in workers:
    p.stdin.close()
for p in workers:
    assert p.wait(timeout=5) == 0
""")
    argv = [sys.executable, str(source), str(port)]
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    row = json.loads(process.stdout.readline())
    members = []
    for role, ordinal, pid in [("api-server", 0, row["pid"])] + [
        ("worker", i, pid) for i, pid in enumerate(row["workers"])
    ]:
        kernel = identity(pid) | {"launch_id": launch}
        members.append(
            {
                "role": role,
                "ordinal": ordinal,
                "identity": kernel,
                "event": event(kernel, role, ordinal, plan_id, launch),
            }
        )
    evidence = tmp_path / (launch + ".jsonl")
    evidence.write_bytes(b"".join(canonical(m["event"]) + b"\n" for m in members))
    evidence.chmod(0o600)
    return process, members, argv, evidence, source


def stop_host(process):
    if process.poll() is None:
        process.stdin.close()
    assert process.wait(timeout=5) == 0


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fixture(tmp_path, monkeypatch, *, semantic=False, count=1):
    from h3_dynamic_fixtures import installed_binding

    installed = installed_binding(tmp_path, monkeypatch, semantic=semantic, count=count)
    plan = installed.plan
    artifact = Path(installed.plan_ref["path"])
    port = free_port()
    process, members, argv, evidence, source = start_host(
        tmp_path, port, "phase0", plan.plan_id
    )
    from experiments.formal_campaign.h3_dynamic_bindings import (
        default_native_plan_binding,
    )

    policy = {
        "schema": "ecpa-h3-dynamic-static-policy/v1",
        "start_id": "cpu-fixture-start",
        "registration_sha256": "sha256:" + "1" * 64,
        "static_deployment_sha256": "sha256:" + "2" * 64,
        "grant": {
            "holder": "cpu-fixture",
            "token": 1,
            "expires_at": int(time.time()) + 120,
        },
        "backend_endpoint": f"http://127.0.0.1:{port}",
        "model": "cpu-fixture",
        "worker_ordinals": [0, 1],
        "allowed_events": ["invoked"],
        "source_refs": [{"path": str(source), "sha256": digest(source.read_bytes())}],
        "plan_artifacts": [
            {"path": str(artifact), "sha256": digest(artifact.read_bytes())}
        ],
        "host_evidence_paths": [str(evidence), str(tmp_path / "phase1.jsonl")],
        "api_argv": [argv],
        "native_plan_bindings": [default_native_plan_binding(installed.artifact_ref)],
        "host_evidence_roots": [],
        "bindings": installed.bindings,
        "binding_artifacts": [installed.artifact_ref],
    }
    journal = DynamicJournal(tmp_path / "authority.jsonl", digest(canonical(policy)))
    authority = DynamicAuthority(policy, journal)
    return process, members, policy, authority, journal, plan


def command(policy, op, **kw):
    return {
        "operation": op,
        "holder": policy["grant"]["holder"],
        "token": policy["grant"]["token"],
        "registration_sha256": policy["registration_sha256"],
        **kw,
    }


def enroll(authority, policy, members, generation=0):
    return authority.apply(
        command(
            policy,
            "enroll_generation",
            expected_generation=generation,
            actual_membership=members,
            plan_id=members[0]["event"]["plan_id"],
            launch_id=members[0]["identity"]["launch_id"],
        )
    )


def admit(authority, policy, enrollment):
    return authority.apply(
        command(
            policy,
            "admit_generation",
            generation=enrollment["generation"],
            membership_sha256=enrollment["membership_sha256"],
        )
    )


def test_actual_listener_membership_invocation_before_admission_and_source_loss(
    tmp_path, monkeypatch
):
    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    try:
        registered = enroll(authority, policy, members)
        assert (
            registered["admission"] == "closed-pending-obligations"
            and authority.route.generation is None
        )
        admit(authority, policy, registered)
        assert authority.route.generation == 1
        source = Path(policy["source_refs"][0]["path"])
        source.write_text(source.read_text() + "\n# source drift\n")
        authority.apply(command(policy, "query"))
        assert authority.route.generation is None
        with pytest.raises(Exception, match="source|bytes|revoked"):
            admit(authority, policy, registered)
        events = read_dynamic_journal(tmp_path / "authority.jsonl")
        assert [e["kind"] for e in events[:3]] == [
            "authority.start",
            "route.closed",
            "backend.enrolled",
        ]
    finally:
        stop_host(process)
        journal.close()


def test_actual_semantic_plan_cannot_use_invoked_observer(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="semantic/non-invoked"):
        fixture(tmp_path, monkeypatch, semantic=True)


def test_wrong_host_or_nonlistener_cannot_enroll(tmp_path, monkeypatch):
    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    other_path = tmp_path / "other"
    other_path.mkdir(mode=0o700)
    other, other_members, _, _, _ = start_host(
        other_path, free_port(), "other", plan.plan_id
    )
    try:
        crossed = copy.deepcopy(members)
        crossed[1] = copy.deepcopy(other_members[1])
        crossed[1]["identity"]["launch_id"] = "phase0"
        crossed[1]["event"] = event(
            crossed[1]["identity"], "worker", 0, plan.plan_id, "phase0"
        )
        with pytest.raises(Exception, match="subtree"):
            enroll(authority, policy, crossed)
        # A genuine API process on another port is not the registered owner.
        authority.policy["api_argv"].append(
            [sys.executable, str(other_path / "cpu_host.py"), str(other.args[-1])]
        )
        authority.policy["host_evidence_paths"].append(str(other_path / "other.jsonl"))
        with pytest.raises(Exception, match="listening endpoint"):
            enroll(authority, policy, other_members)
        assert authority.route.generation is None
    finally:
        stop_host(process)
        stop_host(other)
        journal.close()


def test_lease_loss_and_stale_cas_fail_closed(tmp_path, monkeypatch):
    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    try:
        registered = enroll(authority, policy, members)
        admit(authority, policy, registered)
        with pytest.raises(Exception, match="stale generation"):
            authority.apply(command(policy, "close_generation", expected_generation=0))
        authority.grant = replace(authority.grant, expires_at=int(time.time()) - 1)
        authority.apply(command(policy, "query"))
        assert authority.route.generation is None
    finally:
        stop_host(process)
        journal.close()


def test_actual_new_api_epoch_gets_new_generation_and_real_http(tmp_path, monkeypatch):
    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    server = ThreadingHTTPServer(("127.0.0.1", 0), DynamicProxyHandler)
    server.authority = authority
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    replacement = None
    try:
        first = enroll(authority, policy, members)
        admit(authority, policy, first)
        url = f"http://127.0.0.1:{server.server_port}/v1/completions"

        def request(rid):
            req = urllib.request.Request(
                url,
                data=canonical({"model": "cpu-fixture"}),
                headers={"X-ECPA-Request-ID": rid, "Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return json.loads(response.read())

        assert request("first")["choices"][0]["text"] == "ok"
        stop_host(process)
        authority.apply(command(policy, "query"))
        assert authority.route.generation is None
        replacement, new_members, _, _, _ = start_host(
            tmp_path,
            int(policy["backend_endpoint"].rsplit(":", 1)[1]),
            "phase1",
            plan.plan_id,
        )
        second = enroll(authority, policy, new_members, 1)
        assert (
            second["generation"] == 2
            and second["membership_sha256"] != first["membership_sha256"]
        )
        with pytest.raises(Exception, match="stale generation/membership"):
            admit(authority, policy, first)
        admit(authority, policy, second)
        assert request("second")["choices"][0]["text"] == "ok"
        with pytest.raises(Exception, match="previous Host member"):
            enroll(authority, policy, new_members, 2)
        assert authority.route.generation is None
    finally:
        stop_host(process)
        if replacement is not None:
            stop_host(replacement)
        server.shutdown()
        server.server_close()
        journal.close()


def test_same_port_replacement_before_connect_receives_no_http_body(
    tmp_path, monkeypatch
):
    import http.client

    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    server = ThreadingHTTPServer(("127.0.0.1", 0), DynamicProxyHandler)
    server.authority = authority
    threading.Thread(target=server.serve_forever, daemon=True).start()
    backend_port = int(policy["backend_endpoint"].rsplit(":", 1)[1])
    original_connect = http.client.HTTPConnection.connect
    replacement = []
    try:
        first = enroll(authority, policy, members)
        admit(authority, policy, first)

        def race_connect(connection):
            if (
                connection.host == "127.0.0.1"
                and connection.port == backend_port
                and not replacement
            ):
                # Precisely after the authority's initial admission/refresh and
                # before its TCP connect: the old API exits, a real unregistered
                # API binds the identical port. Neither is a mock backend.
                stop_host(process)
                new, new_members, _, _, _ = start_host(
                    tmp_path, backend_port, "phase1", plan.plan_id
                )
                replacement.append((new, new_members))
            return original_connect(connection)

        monkeypatch.setattr(http.client.HTTPConnection, "connect", race_connect)
        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/completions",
            data=canonical({"model": "cpu-fixture"}),
            headers={"X-ECPA-Request-ID": "race", "Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(req, timeout=10)
        assert error.value.code == 503 and replacement
        new = replacement[0][0]
        received = tmp_path / f"cpu_host.py.received-{new.pid}"
        assert not received.exists() or received.read_bytes() == b""
        events = read_dynamic_journal(tmp_path / "authority.jsonl")
        assert any(e["kind"] == "request.admit" for e in events)
        assert not any(e["kind"] == "request.complete" for e in events)
        assert authority.route.generation is None
    finally:
        stop_host(process)
        for new, _ in replacement:
            stop_host(new)
        server.shutdown()
        server.server_close()
        journal.close()


def test_two_real_distribution_obligations_cannot_consume_only_first_mod_invocation(
    tmp_path, monkeypatch
):
    process, members, policy, authority, journal, plan = fixture(
        tmp_path, monkeypatch, count=2
    )
    try:
        assert len(plan.plugins) == 2 and len(plan.obligations) == 2
        registered = enroll(authority, policy, members)
        # Actual CPU Host fixture emitted only entrypoint fixture0. No fixture1
        # invocation is authored; the second actual artifact must stay missing.
        with pytest.raises(Exception, match="does not cover Plan obligation"):
            admit(authority, policy, registered)
        assert authority.route.generation is None
    finally:
        stop_host(process)
        journal.close()


def test_pair_obligations_require_distinct_actual_entrypoint_events(
    tmp_path, monkeypatch
):
    process, members, policy, authority, journal, plan = fixture(
        tmp_path, monkeypatch, count=2
    )
    try:
        # Explicit CPU protocol fixtures; these are never model/formal evidence.
        extra = [
            event(
                m["identity"],
                m["role"],
                m["ordinal"],
                plan.plan_id,
                "phase0",
                entry_index=1,
            )
            for m in members
        ]
        with Path(policy["host_evidence_paths"][0]).open("ab") as stream:
            stream.write(b"".join(canonical(e) + b"\n" for e in extra))
        registered = enroll(authority, policy, members)
        admit(authority, policy, registered)
        assert authority.route.generation == 1 and len(plan.plugins) == 2
        assert len({canonical(b["entry_point"]) for b in policy["bindings"]}) == 2
    finally:
        stop_host(process)
        journal.close()


def test_native_runtime_plan_uuid_log_is_joined_without_relabeling(
    tmp_path, monkeypatch
):
    import uuid

    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    stop_host(process)
    journal.close()
    launch = str(uuid.uuid4())
    runtime_id = policy["native_plan_bindings"][0]["runtime_plan_id"]
    assert runtime_id != plan.plan_id
    replacement, new_members, _, evidence, _ = start_host(
        tmp_path, int(policy["backend_endpoint"].rsplit(":", 1)[1]), launch, runtime_id
    )
    policy["host_evidence_paths"] = []
    policy["host_evidence_roots"] = [str(tmp_path)]
    journal = DynamicJournal(
        tmp_path / "native-authority.jsonl", digest(canonical(policy))
    )
    authority = DynamicAuthority(policy, journal)
    try:
        # The actual observed UUID, not any guessed preregistration name,
        # selects exactly the same filename rule as the Manager handoff.
        with pytest.raises(Exception, match="actual source-owned Host journal"):
            enroll(authority, policy, new_members)
        evidence.rename(tmp_path / (launch + ".events.jsonl"))
        registered = enroll(authority, policy, new_members)
        admit(authority, policy, registered)
        assert authority.enrollment["plan_id"] == runtime_id
        assert all(
            m["event"]["plan_id"] == runtime_id for m in authority.enrollment["members"]
        )
        assert authority.route.generation == 1
    finally:
        stop_host(replacement)
        journal.close()
