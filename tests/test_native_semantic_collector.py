"""Actual four CPU processes test kernel authentication and raw durable ACKs.

Serving/native-upload metadata is explicitly fixture-only; no NPU evidence.
"""

from __future__ import annotations

import base64
import json
import os
import select
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate.native_semantic_collector import (
    ACK,
    MAPPING,
    SPEC,
    UPLOAD,
    canonical,
    probe_collector,
    sha,
    submit_fact,
    verify_journal,
)

MODULE = "experiments.exposure_gate.native_semantic_collector"
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/exposure_gate/native_semantic_collector.py"

SENDER_CODE = """import json,sys,time
from experiments.exposure_gate.native_semantic_collector import identity,submit_fact
process=identity(__import__('os').getpid())|dict(host="cpu-fixture-only",role=sys.argv[1],ordinal=int(sys.argv[2]),process_epoch=9,assignment_source="host")
print(json.dumps(process),flush=True)
for line in sys.stdin:
 command=json.loads(line)
 fact=command['fact']
 fact.setdefault('process',process)
 fact.setdefault('monotonic_ns',time.monotonic_ns())
 if fact.get('observed_after_barrier_monotonic_ns')=='NOW':
  fact['observed_after_barrier_monotonic_ns']=time.monotonic_ns()
 try:
  if command.get('bootstrap'):
   from experiments.exposure_gate.native_semantic_bootstrap import callback_from_context
   ack=callback_from_context(__import__('pathlib').Path(command['bootstrap']))(fact)
  else:
   ack=submit_fact(__import__('pathlib').Path(command['socket']),fact,expected_collector=command['ready']['collector'],expected_socket_identity=tuple(command['ready']['socket_identity']),expected_collector_source_sha256=command['ready']['collector_source_sha256'],expected_archive_identity=command['ready']['archive_identity'])
  print(json.dumps({'ack':ack}),flush=True)
 except Exception as exc:
  print(json.dumps({'rejected':str(exc)}),flush=True)
"""


def read_line(process):
    assert select.select([process.stdout], [], [], 5)[0], "CPU process did not respond"
    line = process.stdout.readline()
    assert line, process.stderr.read()
    return json.loads(line)


@pytest.fixture
def running(tmp_path):
    tmp_path.chmod(0o700)
    source = tmp_path / "sender_fixture.py"
    source.write_text(SENDER_CODE)
    processes = []
    senders = []
    env = os.environ | {"PYTHONPATH": str(ROOT / "src") + ":" + str(ROOT)}
    try:
        for role, ordinal in [("api-server", 0), ("worker", 0), ("worker", 1)]:
            child = subprocess.Popen(
                [sys.executable, str(source), role, str(ordinal)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            processes.append(child)
            process = read_line(child)
            senders.append(
                {
                    "process": process,
                    "peer_uid": os.getuid(),
                    "peer_gid": os.getgid(),
                    "cmdline_sha256": sha(
                        Path(f"/proc/{child.pid}/cmdline").read_bytes()
                    ),
                    "source_files": [
                        {"path": str(source), "sha256": sha(source.read_bytes())},
                        {"path": str(SOURCE), "sha256": sha(SOURCE.read_bytes())},
                    ],
                }
            )
        spec = {
            "schema": SPEC,
            "classification": "CPU_REVIEW_CANDIDATE_ONLY",
            "formal_producer_registration": False,
            "native_plan_id": "native-plan",
            "native_launch_id": "native-launch",
            "frozen_monotonic_ns": time.monotonic_ns(),
            "max_event_age_ns": 60_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": senders,
            "phases": [
                {
                    "phase_id": "phase-1",
                    "client_request_id": "client-1",
                    "challenge_nonce": "nonce-1",
                    "external_request_id": "chatcmpl-client-1",
                    "expected_ranks": [0, 1],
                }
            ],
        }
        path = tmp_path / "spec.json"
        path.write_bytes(canonical(spec))
        path.chmod(0o600)
        sock = tmp_path / "collector.sock"
        journal = tmp_path / "raw.jsonl"
        authority = subprocess.Popen(
            [
                sys.executable,
                "-m",
                MODULE,
                "--spec",
                str(path),
                "--socket",
                str(sock),
                "--journal",
                str(journal),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        processes.append(authority)
        ready = read_line(authority)
        assert ready["spec_sha256"] == sha(path.read_bytes())
        assert ready["collector_source_sha256"] == sha(SOURCE.read_bytes())
        yield dict(
            root=tmp_path,
            children=processes[:3],
            authority=authority,
            ready=ready,
            spec=spec,
            spec_path=path,
            socket=sock,
            journal=journal,
            source=source,
        )
    finally:
        for child in reversed(processes):
            child.terminate()
            child.wait(timeout=5)


def command(run, index, fact):
    child = run["children"][index]
    child.stdin.write(
        json.dumps({"fact": fact, "ready": run["ready"], "socket": str(run["socket"])})
        + "\n"
    )
    child.stdin.flush()
    return read_line(child)


def mapping():
    return {
        "schema": MAPPING,
        "plan_id": "native-plan",
        "launch_id": "native-launch",
        "external_request_id": "chatcmpl-client-1",
        "runtime_request_id": "actual-runtime-1",
    }


def upload():
    rows = [{"group": 0, "row": 2, "blocks": [10, 11]}]
    return {
        "schema": UPLOAD,
        "plan_id": "native-plan",
        "launch_id": "native-launch",
        "runtime_request_id": "actual-runtime-1",
        "observed_after_barrier_monotonic_ns": "NOW",
        "device": "npu:0",
        "uploaded_rows": rows,
        "uploaded_rows_sha256": sha(canonical(rows)),
        "scope": "NPU-block-table-prefix-readback-only",
        "kv_tensor_equivalence": None,
        "attention_consumed_observed_tensor": None,
        "full_generation_quality": None,
    }


def test_actual_cpu_api_and_two_worker_peers_ack_exact_raw_journal(running):
    run = running
    responses = [
        command(run, 0, mapping()),
        command(run, 1, upload()),
        command(run, 2, upload()),
    ]
    assert all(x["ack"]["schema"] == ACK for x in responses)
    events = [json.loads(line) for line in run["journal"].read_bytes().splitlines()]
    assert len(events) == 4
    status = probe_collector(
        run["socket"],
        expected_collector=run["ready"]["collector"],
        expected_socket_identity=tuple(run["ready"]["socket_identity"]),
        expected_collector_source_sha256=run["ready"]["collector_source_sha256"],
        expected_spec_sha256=run["ready"]["spec_sha256"],
        expected_archive_identity=run["ready"]["archive_identity"],
    )
    result = verify_journal(
        run["spec_path"],
        run["journal"],
        acknowledged_prefix=status["acknowledged_prefix"],
    )
    assert result["complete_two_rank_transport_phases"] == 1
    assert result["GPU_semantic_qualification"] is None
    unsealed = verify_journal(run["spec_path"], run["journal"])
    assert unsealed["complete_two_rank_transport_phases"] is None
    assert unsealed["durable_ACK_status"] == "unverified"
    previous = "0" * 64
    for sequence, event in enumerate(events):
        assert event["sequence"] == sequence
        assert event["previous_sha256"] == previous
        assert (
            sha(canonical({k: v for k, v in event.items() if k != "event_sha256"}))
            == event["event_sha256"]
        )
        previous = event["event_sha256"]
        if sequence:
            raw = base64.b64decode(event["raw_base64"])
            ack = responses[sequence - 1]["ack"]
            assert sha(raw) == ack["raw_sha256"] == event["raw_sha256"]
            assert ack["event_sha256"] == event["event_sha256"]
            assert event["peer"]["pid"] == run["children"][sequence - 1].pid
            assert event["phase"]["challenge_nonce"] == "nonce-1"
            assert ack["formal_producer_registration"] is False


@pytest.mark.parametrize(
    "case",
    [
        "missing-map",
        "wrong-role",
        "wrong-launch",
        "wrong-epoch",
        "missing-upload",
        "promoted-quality",
        "stale",
        "changed-source",
    ],
)
def test_missing_native_bindings_rejected_over_real_peer_socket(running, case):
    run = running
    if case != "missing-map":
        assert "ack" in command(run, 0, mapping())
    fact = upload()
    sender = 1
    if case == "wrong-role":
        sender = 0
    if case == "wrong-launch":
        fact["launch_id"] = "other"
    if case == "wrong-epoch":
        fact["process"] = run["spec"]["senders"][1]["process"] | {"start_ticks": 1}
    if case == "missing-upload":
        fact.pop("uploaded_rows")
    if case == "promoted-quality":
        fact["full_generation_quality"] = True
    if case == "stale":
        fact["monotonic_ns"] = 1
    if case == "changed-source":
        run["source"].write_text(SENDER_CODE + "\n# changed after freeze\n")
    result = command(run, sender, fact)
    assert "rejected" in result
    events = [json.loads(x) for x in run["journal"].read_bytes().splitlines()]
    assert len(events) == (1 if case == "missing-map" else 2)


def test_kernel_peer_cannot_impersonate_registered_api_or_ack_authority(running):
    run = running
    fact = mapping() | {
        "process": run["spec"]["senders"][0]["process"],
        "monotonic_ns": time.monotonic_ns(),
    }
    with pytest.raises(ValueError, match="registered source sender"):
        submit_fact(
            run["socket"],
            fact,
            expected_collector=run["ready"]["collector"],
            expected_socket_identity=tuple(run["ready"]["socket_identity"]),
            expected_collector_source_sha256=run["ready"]["collector_source_sha256"],
            expected_archive_identity=run["ready"]["archive_identity"],
        )
    command_ready = run["ready"] | {
        "collector": run["ready"]["collector"] | {"start_ticks": 1}
    }
    old = run["ready"]
    run["ready"] = command_ready
    assert "rejected" in command(run, 0, mapping())
    run["ready"] = old
    assert len(run["journal"].read_bytes().splitlines()) == 1


def test_repeated_mapping_is_rejected_but_fresh_later_rank_facts_are_retained(running):
    run = running
    assert "ack" in command(run, 0, mapping())
    assert "rejected" in command(run, 0, mapping())
    assert "ack" in command(run, 1, upload())
    assert "ack" in command(run, 1, upload())
    assert "ack" in command(run, 2, upload())
    assert len(run["journal"].read_bytes().splitlines()) == 5
    status = probe_collector(
        run["socket"],
        expected_collector=run["ready"]["collector"],
        expected_socket_identity=tuple(run["ready"]["socket_identity"]),
        expected_collector_source_sha256=run["ready"]["collector_source_sha256"],
        expected_spec_sha256=run["ready"]["spec_sha256"],
        expected_archive_identity=run["ready"]["archive_identity"],
    )
    result = verify_journal(
        run["spec_path"],
        run["journal"],
        acknowledged_prefix=status["acknowledged_prefix"],
    )
    assert result["complete_two_rank_transport_phases"] == 1
    assert result["source_authenticated_native_envelopes"] == 4


def test_read_only_describe_cannot_emit_native_facts(running):
    run = running
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(str(run["socket"]))
        channel.sendall(canonical({"op": "describe"}) + b"\n")
        status = json.loads(channel.recv(65536))
    assert status["spec_sha256"] == run["ready"]["spec_sha256"]
    assert status["collector_source_sha256"] == run["ready"]["collector_source_sha256"]
    assert status["formal_producer_registration"] is False
    assert len(run["journal"].read_bytes().splitlines()) == 1


@pytest.mark.parametrize("missing", ["nonce", "sender-role", "source", "session"])
def test_missing_frozen_binding_never_starts_admitting_collector(running, missing):
    from experiments.exposure_gate.native_semantic_collector import Collector

    spec = json.loads(running["spec_path"].read_bytes())
    if missing == "nonce":
        spec["phases"][0].pop("challenge_nonce")
    if missing == "sender-role":
        spec["senders"][0]["process"].pop("role")
    if missing == "source":
        spec["senders"][0]["source_files"] = []
    if missing == "session":
        spec["senders"][0]["process"].pop("session")
    path = running["root"] / "missing.json"
    path.write_bytes(canonical(spec))
    path.chmod(0o600)
    with pytest.raises(ValueError):
        Collector(path, running["root"] / "never-admitted.jsonl")


def test_independent_raw_chain_rejects_rehashed_cross_request_phase(running):
    run = running
    assert "ack" in command(run, 0, mapping())
    events = [json.loads(line) for line in run["journal"].read_bytes().splitlines()]
    events[1]["phase"]["challenge_nonce"] = "invented"
    events[1]["event_sha256"] = sha(
        canonical({k: v for k, v in events[1].items() if k != "event_sha256"})
    )
    path = run["root"] / "tampered.jsonl"
    path.write_bytes(b"".join(canonical(x) + b"\n" for x in events))
    with pytest.raises(ValueError, match="challenge join differs"):
        verify_journal(run["spec_path"], path)


def test_bootstrap_registers_real_source_peer_and_preserves_native_bytes(running):
    from experiments.exposure_gate.native_semantic_bootstrap import write_context

    run = running
    context = run["root"] / "bootstrap.json"
    write_context(
        context,
        spec_path=run["spec_path"],
        ready=run["ready"],
        source_files=[{"path": str(SOURCE), "sha256": sha(SOURCE.read_bytes())}],
    )
    child = run["children"][0]
    child.stdin.write(
        json.dumps(
            {
                "fact": mapping(),
                "ready": run["ready"],
                "socket": str(run["socket"]),
                "bootstrap": str(context),
            }
        )
        + "\n"
    )
    child.stdin.flush()
    result = read_line(child)
    assert "ack" in result
    event = json.loads(run["journal"].read_bytes().splitlines()[1])
    fact = json.loads(base64.b64decode(event["raw_base64"]))
    assert "challenge_nonce" not in fact
    assert fact["runtime_request_id"] == "actual-runtime-1"
    assert event["peer"]["pid"] == child.pid


def test_absent_bootstrap_does_not_fake_observer_or_fail_native_warmup(
    tmp_path, monkeypatch
):
    from experiments.exposure_gate.native_semantic_bootstrap import (
        ENV,
        ensure_registered,
    )

    calls = []
    monkeypatch.delenv(ENV, raising=False)
    assert ensure_registered(calls.append) is False
    monkeypatch.setenv(ENV, str(tmp_path / "not-published.json"))
    assert ensure_registered(calls.append) is False
    assert not calls


def test_failed_collector_fsync_returns_no_ack_over_real_socket(running, monkeypatch):
    import threading

    from experiments.exposure_gate.native_semantic_collector import Collector, Server

    run = running
    collector = Collector(run["spec_path"], run["root"] / "failed-journal.jsonl")
    path = run["root"] / "failed.sock"
    server = Server(path, collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ready = run["ready"] | {
        "collector": collector.collector_identity,
        "socket_identity": [path.stat().st_dev, path.stat().st_ino],
        "archive_identity": collector.archive_identity,
    }
    old_ready, old_socket = run["ready"], run["socket"]
    run["ready"], run["socket"] = ready, path

    def failed(_fd):
        raise OSError("injected actual collector fsync failure")

    monkeypatch.setattr(os, "fsync", failed)
    try:
        assert "rejected" in command(run, 0, mapping())
        assert collector.failed is True
        assert collector.sequence == 1
        assert (
            len((run["root"] / "failed-journal.jsonl").read_bytes().splitlines()) == 2
        )
        with pytest.raises(ValueError, match="ACK prefix"):
            verify_journal(
                run["spec_path"],
                run["root"] / "failed-journal.jsonl",
                acknowledged_prefix={
                    "next_sequence": collector.sequence,
                    "last_event_sha256": collector.previous,
                },
            )
        assert "rejected" in command(run, 0, mapping())
    finally:
        run["ready"], run["socket"] = old_ready, old_socket
        server.shutdown()
        server.server_close()
        thread.join(3)
        os.close(collector.fd)


def test_native_bootstrap_patch_applies_to_pinned_observer_source(tmp_path):
    import ast

    root = ROOT / "experiments/exposure_gate/native_semantic_source"
    binding = json.loads((root / "source-binding.json").read_bytes())
    raw = (root / "observer-532b72.py.snapshot").read_bytes()
    assert sha(raw) == binding["native_observer_preimage_sha256"]
    target = tmp_path / "vllm/plugins/native_block_table_observer.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    subprocess.run(
        ["git", "apply", str(root / "native-observer-bootstrap.patch")],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    assert sha(target.read_bytes()) == binding["native_observer_patched_sha256"]
    ast.parse(target.read_text())
    assert binding["registered_formal_producer"] is False


def test_exact_raw_upload_replay_is_rejected_but_fresh_step_is_acknowledged(running):
    run = running
    assert "ack" in command(run, 0, mapping())
    fact = upload()
    fact["monotonic_ns"] = time.monotonic_ns()
    fact["observed_after_barrier_monotonic_ns"] = time.monotonic_ns()
    assert "ack" in command(run, 1, fact)
    assert "rejected" in command(run, 1, fact)
    assert "ack" in command(run, 1, upload())
    assert len(run["journal"].read_bytes().splitlines()) == 4
