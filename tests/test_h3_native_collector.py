"""Real Unix CPU multi-phase intake only; synthetic tensors are not NPU evidence."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.formal_campaign import h3_native_client as client
from experiments.formal_campaign import h3_native_collector as intake
from experiments.native_attention_candidate import collector as attention
from experiments.native_attention_candidate import drain_collector as original
from experiments.native_attention_candidate import operator_observer, phase_drain
from experiments.native_kv_tensor_candidate import (
    artifact_transport,
    runtime_contract,
    witness,
)

ROOT = Path(__file__).resolve().parents[1]


def read(child):
    assert select.select([child.stdout], [], [], 20)[0], "CPU peer timeout"
    raw = child.stdout.readline()
    assert raw, child.stderr.read()
    return json.loads(raw)


def write(path, value):
    path.write_bytes(native.canonical(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def live(tmp_path):
    tmp_path.chmod(0o700)
    # Adapt a COPY of the explicitly synthetic source fixture for distinct runtimes.
    # Its exact transformed source bytes are enrolled; old fixtures remain untouched.
    source = tmp_path / "CPU_multi_peer.py"
    text = (ROOT / "tests/fixtures/native_attention_drain_cpu_peer.py").read_text()
    text = text.replace('"CPU-runtime"', "runtime").replace(
        "    c = json.loads(line)",
        '    c = json.loads(line)\n    runtime = c["runtime"]',
    )
    text = text.replace(
        "                materializations[layer] = (f, actual_ack)",
        "                materializations[layer] = (f, actual_ack)\n"
        "                if registered:\n"
        "                    observer.remember_acknowledged_materialization"
        "(f, actual_ack)",
    )
    source.write_text(text)
    procs, senders = [], []
    env = os.environ | {"PYTHONPATH": str(ROOT) + ":" + str(ROOT / "src")}
    files = [
        source,
        *[
            Path(m.__file__)
            for m in (
                native,
                artifact_transport,
                witness,
                runtime_contract,
                attention,
                operator_observer,
                original,
                phase_drain,
                intake,
            )
        ],
    ]
    try:
        for role, rank in (("api-server", 0), ("worker", 0), ("worker", 1)):
            child = subprocess.Popen(
                [sys.executable, str(source), role, str(rank)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            procs.append(child)
            process = read(child)
            senders.append(
                {
                    "process": process,
                    "peer_uid": os.getuid(),
                    "peer_gid": os.getgid(),
                    "cmdline_sha256": native.sha(
                        Path(f"/proc/{child.pid}/cmdline").read_bytes()
                    ),
                    "source_files": [
                        {"path": str(p), "sha256": native.sha(p.read_bytes())}
                        for p in files
                    ],
                }
            )
        phases = [
            {
                "phase_id": f"phase-{i}",
                "client_request_id": f"client-{i}",
                "challenge_nonce": str(i) * 64,
                "external_request_id": f"external-{i}",
                "expected_ranks": [0, 1],
            }
            for i in range(1, 61)
        ]
        spec = {
            "schema": native.KV_SPEC_V2,
            "classification": "CPU_REVIEW_CANDIDATE_ONLY",
            "formal_producer_registration": False,
            "native_plan_id": "plan",
            "native_launch_id": "launch",
            "frozen_monotonic_ns": time.monotonic_ns(),
            "max_event_age_ns": 120_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": senders,
            "phases": phases,
            "kv_requirements": {
                p["phase_id"]: {
                    "attention_group": 0,
                    "semantic_anchor": 1201,
                    "physical_anchor": 1024,
                    "allocation_block_size": 128,
                    "compression_threshold_tokens": 1152,
                    "destination_block_count": 8,
                }
                for p in phases
            },
        }
        spec_path = write(tmp_path / "spec.json", spec)
        directories = {}
        for child in procs[1:]:
            path = tmp_path / f"worker-{child.pid}"
            path.mkdir(mode=0o700)
            path.chmod(0o700)
            meta = path.stat()
            directories[str(child.pid)] = {
                "path": str(path),
                "identity": [meta.st_dev, meta.st_ino],
            }
        policy = {
            "schema": artifact_transport.RUNTIME_POLICY,
            "classification": "REAL_RUNTIME_UNQUALIFIED",
            "formal_registration": False,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "worker_directories": directories,
            "requirements": {
                p["phase_id"]: {
                    "layer_indices": list(range(28)),
                    "semantic_anchor": 1201,
                    "physical_anchor": 1024,
                }
                for p in phases
            },
        }
        policy_path = write(tmp_path / "policy.json", policy)
        drain_policy = {
            "schema": intake.POLICY,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "tensor_policy_sha256": native.sha(policy_path.read_bytes()),
            "phase_ids": [p["phase_id"] for p in phases],
            "required_ranks": [0, 1],
            "formal_registration": False,
        }
        drain_path = write(tmp_path / "drain.json", drain_policy)
        journal, sock = tmp_path / "native.jsonl", tmp_path / "native.sock"
        collector = subprocess.Popen(
            [
                sys.executable,
                "-m",
                intake.__name__,
                "--spec",
                str(spec_path),
                "--policy",
                str(policy_path),
                "--drain-policy",
                str(drain_path),
                "--journal",
                str(journal),
                "--socket",
                str(sock),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        procs.append(collector)
        ready = read(collector)
        descriptor = ready | {
            "launcher_observed_identity": ready["collector"],
            "launcher_observed_cmdline_sha256": native.sha(
                Path(f"/proc/{collector.pid}/cmdline").read_bytes()
            ),
        }

        def command(index, op, runtime, **fields):
            child = procs[index]
            child.stdin.write(
                json.dumps(
                    {
                        "op": op,
                        "runtime": runtime,
                        "ready": ready,
                        "dir": directories.get(str(child.pid)),
                        **fields,
                    }
                )
                + "\n"
            )
            child.stdin.flush()
            result = read(child)
            if "rejected" in result:
                raise ValueError(result["rejected"])
            return result

        def authenticate():
            return client.authenticate(
                sock,
                descriptor,
                spec_path,
                Path(intake.__file__),
                drain_policy_path=drain_path,
            )

        def complete(number):
            runtime = f"CPU-runtime-{number}"
            command(0, "mapping", runtime, external=f"external-{number}")
            for index in (1, 2):
                command(index, "facts", runtime)
                command(index, "drain", runtime)
            return authenticate()

        yield {
            "root": tmp_path,
            "command": command,
            "complete": complete,
            "authenticate": authenticate,
            "spec": spec,
            "spec_path": spec_path,
            "policy": policy_path,
            "drain": drain_path,
            "journal": journal,
            "socket": sock,
            "descriptor": descriptor,
        }
    finally:
        for child in reversed(procs):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


def test_eight_actual_unix_mappings_do_not_invent_a_source_closed_prefix(live):
    for i in range(1, 9):
        live["command"](0, "mapping", f"CPU-runtime-{i}", external=f"external-{i}")
    status = live["authenticate"]()["status"]
    states = status["source_drain"]["runtimes"]
    assert len(states) == 8
    assert all(v["complete"] is False for v in states.values())
    assert all(v["sealed_prefix"] is None for v in states.values())


def test_original_global_history_verifies_both_overlapping_native_requests(live):
    from experiments.native_attention_candidate.attention_consumer import (
        verify_attention_archive,
    )

    command = live["command"]
    for i in (1, 2):
        command(0, "mapping", f"CPU-runtime-{i}", external=f"external-{i}")
    for i in (1, 2):
        for worker in (1, 2):
            command(worker, "facts", f"CPU-runtime-{i}")
            command(worker, "attention", f"CPU-runtime-{i}")
            command(worker, "drain", f"CPU-runtime-{i}")
        state = live["authenticate"]()["status"]["source_drain"]["runtimes"]
        assert all(v["complete"] is (i == 2) for v in state.values())
    raw = live["journal"].read_bytes()
    report = verify_attention_archive(
        live["spec_path"],
        live["policy"],
        live["journal"],
        acknowledged_prefix=live["authenticate"]()["status"]["acknowledged_prefix"],
        drain_policy_path=live["drain"],
        drain_protocol=intake,
    )
    assert len(report["attention_complete_transactions"]) == 2
    assert report["full_phase_source_drained"] is True
    assert len({v["sealed_prefix_sha256"] for v in state.values()}) == 1
    assert all(v["sealed_prefix_sha256"] == native.sha(raw) for v in state.values())
    command(0, "mapping", "CPU-runtime-3", external="external-3")
    later = live["authenticate"]()["status"]["source_drain"]["runtimes"]
    assert later["CPU-runtime-1"] == state["CPU-runtime-1"]
    assert later["CPU-runtime-3"]["complete"] is False


def test_ninth_unfinished_actual_unix_mapping_rejects(live):
    for i in range(1, 9):
        live["command"](0, "mapping", f"CPU-runtime-{i}", external=f"external-{i}")
    with pytest.raises(ValueError, match="concurrency bound"):
        live["command"](0, "mapping", "CPU-runtime-9", external="external-9")


def test_closed_runtime_waiting_for_global_seal_does_not_consume_concurrency(live):
    for i in range(1, 9):
        live["command"](0, "mapping", f"CPU-runtime-{i}", external=f"external-{i}")
    for worker in (1, 2):
        live["command"](worker, "facts", "CPU-runtime-1")
        live["command"](worker, "drain", "CPU-runtime-1")
    live["command"](0, "mapping", "CPU-runtime-9", external="external-9")
    states = live["authenticate"]()["status"]["source_drain"]["runtimes"]
    assert len(states) == 9
    assert states["CPU-runtime-1"]["ranks"] == [0, 1]
    assert states["CPU-runtime-1"]["complete"] is False
    with pytest.raises(ValueError, match="concurrency bound"):
        live["command"](0, "mapping", "CPU-runtime-10", external="external-10")
