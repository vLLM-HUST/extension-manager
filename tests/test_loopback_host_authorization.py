"""A separate HTTP authority verifies host evidence before route exposure."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
import time
import urllib.error
from dataclasses import asdict
from pathlib import Path

import jsonschema
import pytest

from experiments.exposure_gate.loopback_traffic import (
    LoopbackTrafficAdapter,
    read_traffic_journal,
)
from tests.test_host_observer import BINDING, PLAN, host_event
from tests.test_loopback_traffic import _BackendServer, _get
from vllm_hust_ext.exposure_gate import GateError, LeaseGrant
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def test_traffic_authority_rechecks_frozen_host_membership(
    tmp_path: Path,
) -> None:
    predecessor = _BackendServer("old")
    candidate = _BackendServer("new")
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (predecessor, candidate)
    ]
    for thread in threads:
        thread.start()
    event_dir = tmp_path / "host-events"
    event_dir.mkdir(mode=0o700)
    identity = event_dir.stat()
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(plan_artifact_bytes(PLAN))
    plan_path.chmod(0o600)
    observer_path = tmp_path / "observer.json"
    configuration = {
        "schema": "ecpa-loopback-host-authorization/v1",
        "plan_path": str(plan_path),
        "journal_dir": str(event_dir),
        "journal_device": identity.st_dev,
        "journal_inode": identity.st_ino,
        "launch_id": "launch:one",
        "controller_instance": "controller:one",
        "local_host": "host-a",
        "bindings": [asdict(BINDING)],
        "required_processes": [
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 7,
            }
        ],
    }
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "experiments/exposure_gate/host-authorization.schema.json"
    )
    jsonschema.Draft7Validator(json.loads(schema_path.read_text())).validate(
        configuration
    )
    observer_path.write_text(
        json.dumps(configuration),
        encoding="utf-8",
    )
    observer_path.chmod(0o600)
    grant = LeaseGrant("gate-test", 7, int(time.time()) + 60)
    socket_path = tmp_path / "authority.sock"
    journal_path = tmp_path / "authority.jsonl"
    command = [
        sys.executable,
        "-m",
        "experiments.exposure_gate.loopback_traffic",
        "--socket",
        str(socket_path),
        "--journal",
        str(journal_path),
        "--predecessor-port",
        str(predecessor.server_port),
        "--candidate-port",
        str(candidate.server_port),
        "--predecessor-snapshot",
        json.dumps({"generation": 0, "plan_id": "old"}),
        "--grant-holder",
        grant.holder,
        "--grant-token",
        str(grant.fencing_token),
        "--grant-expires-at",
        str(grant.expires_at),
        "--observer-config",
        str(observer_path),
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    worker: subprocess.Popen[str] | None = None
    port: int | None = None
    try:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready, "traffic authority did not become ready"
        port = json.loads(process.stdout.readline())["port"]
        adapter = LoopbackTrafficAdapter(socket_path, grant)
        snapshot = {
            "plan_id": PLAN.plan_id,
            "launch_id": "launch:one",
            "controller_instance": "controller:one",
        }
        assert _get(port) == "old"
        with pytest.raises(GateError, match="frozen membership"):
            adapter.open(1, "gate-1-test", snapshot, grant, int(time.time()))
        assert _get(port) == "old"
        with pytest.raises(GateError, match="not bound"):
            adapter.open(
                1,
                "gate-1-test",
                {**snapshot, "launch_id": "wrong"},
                grant,
                int(time.time()),
            )
        with pytest.raises(GateError, match="not bound"):
            adapter.open(
                1,
                "gate-1-test",
                {**snapshot, "plan_id": "plan:wrong"},
                grant,
                int(time.time()),
            )
        worker = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        journal = event_dir / "host.jsonl"
        journal.write_bytes(host_event(pid=worker.pid, epoch=6) + b"\n")
        journal.chmod(0o600)
        with pytest.raises(GateError, match="frozen membership"):
            adapter.open(1, "gate-1-test", snapshot, grant, int(time.time()))
        assert _get(port) == "old"
        journal.write_bytes(host_event(pid=worker.pid, epoch=7) + b"\n")
        adapter.open(1, "gate-1-test", snapshot, grant, int(time.time()))
        assert _get(port) == "new"
        worker.terminate()
        worker.wait(timeout=5)
        with pytest.raises(urllib.error.HTTPError) as closed:
            _get(port)
        assert closed.value.code == 503
        assert adapter.query_route().generation is None
        assert _get(predecessor.server_port) == "old"
        assert _get(candidate.server_port) == "new"
    finally:
        if worker is not None and worker.poll() is None:
            worker.terminate()
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
        assert process.poll() is not None
        for server in (predecessor, candidate):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
    assert not socket_path.exists()
    events = read_traffic_journal(journal_path)
    assert [event["kind"] for event in events].count("route.open.applied") == 1
    assert any(
        event["kind"] == "route.close_all"
        and event["detail"].get("reason") == "host observation lost"
        for event in events
    )
    open_digest = next(
        event["detail"]["observation_sha256"]
        for event in events
        if event["kind"] == "route.open.intent"
    )
    assert open_digest.startswith("sha256:") and len(open_digest) == 71
    candidate_admissions = [
        event
        for event in events
        if event["kind"] == "request.admit"
        and event["route"]["generation"] == 1
    ]
    assert len(candidate_admissions) == 1
    assert candidate_admissions[0]["detail"]["observation_sha256"] == open_digest
    assert [
        event["route"]["generation"]
        for event in events
        if event["kind"] == "request.admit"
    ] == [0, 0, 0, 1]
