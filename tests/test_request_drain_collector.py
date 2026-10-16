"""Real Unix CPU multi-phase intake only; synthetic tensors are not NPU evidence."""

from __future__ import annotations

import base64
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_attention_candidate import collector as attention
from experiments.native_attention_candidate import drain_collector as original
from experiments.native_attention_candidate import operator_observer, phase_drain
from experiments.native_attention_candidate import request_collector_client as client
from experiments.native_attention_candidate import request_drain_collector as intake
from experiments.native_challenge_candidate import collector_client as old_client
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
            for i in (1, 2)
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


def test_real_unix_later_phase_append_preserves_first_complete_original_prefix(live):
    first = live["complete"](1)
    raw_first = live["journal"].read_bytes()
    state = first["status"]["source_drain"]["runtimes"]["CPU-runtime-1"]
    assert state["sealed_prefix_bytes"] == len(raw_first)
    assert state["sealed_prefix_sha256"] == native.sha(raw_first)
    assert state["sealed_prefix"] == first["status"]["acknowledged_prefix"]
    second = live["complete"](2)
    raw_second = live["journal"].read_bytes()
    assert raw_second.startswith(raw_first) and len(raw_second) > len(raw_first)
    assert second["status"]["source_drain"]["runtimes"]["CPU-runtime-1"] == state
    assert second["status"]["acknowledged_prefix"] != state["sealed_prefix"]
    assert intake.verify_raw_prefix(raw_first, state["sealed_prefix"]) > 4
    assert (
        intake.verify_raw_prefix(raw_second, second["status"]["acknowledged_prefix"])
        > 4
    )
    assert first["authentication_clock"]["client_source_sha256"] == native.sha(
        Path(client.__file__).read_bytes()
    )
    with pytest.raises(ValueError, match="extension differs|status differs"):
        old_client.authenticate(
            live["socket"],
            live["descriptor"],
            live["spec_path"],
            Path(intake.__file__),
            drain_policy_path=live["drain"],
        )


def test_real_unix_rejects_overlap_and_facts_after_sealed_phase(live):
    command = live["command"]
    command(0, "mapping", "CPU-runtime-1", external="external-1")
    before = live["journal"].read_bytes()
    with pytest.raises(ValueError, match="one unfinished phase"):
        command(0, "mapping", "CPU-runtime-2", external="external-2")
    assert live["journal"].read_bytes() == before
    for index in (1, 2):
        command(index, "facts", "CPU-runtime-1")
        command(index, "drain", "CPU-runtime-1")
    sealed = live["authenticate"]()
    before = live["journal"].read_bytes()
    event = next(
        json.loads(line)
        for line in before.splitlines()
        if json.loads(line)["kind"] == "attention.worker.drained"
    )
    fact = json.loads(base64.b64decode(event["raw_base64"]))
    with pytest.raises(ValueError, match="after authenticated source drain"):
        command(1, "attack", "CPU-runtime-1", fact=fact)
    assert live["journal"].read_bytes() == before
    with pytest.raises(ValueError, match="status differs"):
        live["authenticate"]()
    assert sealed["status"]["source_drain"]["runtimes"]["CPU-runtime-1"]["complete"]


@pytest.mark.parametrize("kind", ["old-schema", "over-bound"])
def test_explicit_new_policy_and_phase_bound_reject_before_creating_journal(
    tmp_path, kind
):
    spec = {
        "phases": [
            {"phase_id": str(i)} for i in range(65 if kind == "over-bound" else 1)
        ]
    }
    spec_path = write(tmp_path / "spec.json", spec)
    policy = write(tmp_path / "tensor.json", {})
    drain = write(tmp_path / "drain.json", {"schema": original.POLICY})
    journal = tmp_path / "never-created.jsonl"
    with pytest.raises(ValueError, match="request drain policy"):
        intake.RequestDrainCollector(spec_path, journal, policy, drain)
    assert not journal.exists()


def test_whole_original_chain_cannot_be_filtered_or_reordered():
    events = []
    previous = "0" * 64
    for sequence in range(3):
        event = {
            "kind": "CPU_HASHCHAIN_GUARD_ONLY",
            "sequence": sequence,
            "previous_sha256": previous,
        }
        event["event_sha256"] = native.sha(native.canonical(event))
        previous = event["event_sha256"]
        events.append(native.canonical(event) + b"\n")
    prefix = {"next_sequence": 3, "last_event_sha256": previous}
    assert intake.verify_raw_prefix(b"".join(events), prefix) == 3
    for raw in (
        events[0] + events[2],
        b"".join(reversed(events)),
        b"".join(events)[:-1],
    ):
        with pytest.raises(ValueError, match="prefix|hashchain"):
            intake.verify_raw_prefix(raw, prefix)
