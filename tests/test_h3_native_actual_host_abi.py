"""CPU ABI regressions only; no Host/model/accelerator qualification."""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from experiments.formal_campaign import h3_native_authority as authority
from experiments.formal_campaign import h3_native_bootstrap
from experiments.formal_campaign import h3_owned_worker_carrier as carrier
from experiments.formal_campaign.h3_worker_recovery import verify_parent_worker_ancestry
from experiments.formal_campaign.h3_worker_relaunch import identity
from test_host_evidence import PLAN, raw_event
from vllm_hust_ext.exposure_gate import GateError
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def host_process(pid, role="worker", ordinal=0):
    kernel = identity(pid)
    return {
        "host": "CPU-ABI-only",
        "role": role,
        "ordinal": ordinal,
        "pid": pid,
        "start_identity": f"pid:{pid}:start_ticks:{kernel['start_ticks']}",
        "process_epoch": 1,
        "assignment_source": "host",
    }


def test_real_parser_role_and_actual_kernel_remain_distinct():
    process = parse_host_event(raw_event(process=host_process(os.getpid())))["process"]
    original = copy.deepcopy(process)
    assert not {"start_ticks", "session", "boot_id"} & process.keys()
    kernel = authority.observed_host_kernel(process)
    assert kernel == identity(os.getpid())
    assert process == original
    sender = {**process, **kernel}
    assert set(sender) == {
        "host",
        "role",
        "ordinal",
        "pid",
        "start_identity",
        "process_epoch",
        "assignment_source",
        "start_ticks",
        "session",
        "boot_id",
    }


def test_actual_kernel_join_rejects_stale_host_identity():
    process = host_process(os.getpid())
    process["start_identity"] = f"pid:{os.getpid()}:start_ticks:0"
    with pytest.raises(GateError, match="start identity"):
        authority.observed_host_kernel(process)


def test_tp2_observed_target_keeps_worker_zero_ancestry(tmp_path, monkeypatch):
    # Two real short-lived CPU children exercise actual /proc ancestry. All
    # Host events and Popen transport here are explicit nonqualifying fixtures.
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import sys;print('ready',flush=True);sys.stdin.buffer.read()",
            ],
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    try:
        for child in children:
            assert child.stdout.readline() == b"ready\n"
        kernels = [identity(child.pid) for child in children]
        parent = identity(os.getpid())
        evidence = tmp_path / "CPU-fixture.events.jsonl"
        parent_raw = parse_host_event(
            raw_event(process=host_process(os.getpid(), "api-server"))
        )
        events = [
            parse_host_event(raw_event(process=host_process(k["pid"], "worker", i)))
            for i, k in enumerate(kernels)
        ]
        workers = [
            {"ordinal": i, "identity": k, "raw": event}
            for i, (k, event) in enumerate(zip(kernels, events, strict=True))
        ]
        source_path = tmp_path / "CPU-source.py"
        source_path.write_text("# CPU ABI fixture only\n")
        senders = []
        for original in [parent_raw["process"], *[e["process"] for e in events]]:
            process = {**original, **authority.observed_host_kernel(original)}
            senders.append(
                {
                    "process": process,
                    "cmdline_sha256": h3_native_bootstrap.native.sha(
                        Path(f"/proc/{process['pid']}/cmdline").read_bytes()
                    ),
                    "source_files": [
                        {
                            "path": str(source_path),
                            "sha256": h3_native_bootstrap.native.sha(
                                source_path.read_bytes()
                            ),
                        }
                    ],
                }
            )
        h3_native_bootstrap.verify_senders(senders)
        raw_only = copy.deepcopy(senders)
        raw_only[0]["process"] = parent_raw["process"]
        with pytest.raises(KeyError, match="start_ticks"):
            h3_native_bootstrap.verify_senders(raw_only)
        plan_path = tmp_path / "CPU-plan.json"
        plan_bytes = plan_artifact_bytes(PLAN)
        plan_path.write_bytes(plan_bytes)
        phase = {
            "origin": "host-baseline",
            "environment": {},
            "argv": [sys.executable, "CPU-transport-is-mocked"],
            "handoff_path": None,
            "plan_artifact": {
                "path": str(plan_path),
                "sha256": carrier.sha(plan_bytes),
            },
            "launch_id": "launch-1",
            "evidence_path": str(evidence),
            "cwd": str(tmp_path),
            "required_worker_ordinals": [0, 1],
            "worker_ordinal": 0,
        }

        def fake_popen(*args, **kwargs):
            evidence.write_bytes(
                b"\n".join(json.dumps(e).encode() for e in [parent_raw, *events])
                + b"\n"
            )
            return SimpleNamespace(pid=os.getpid(), poll=lambda: None)

        monkeypatch.setattr(carrier.subprocess, "Popen", fake_popen)
        monkeypatch.setattr(
            carrier, "worker", lambda spec, *args: workers[spec["target_ordinal"]]
        )
        monkeypatch.setattr(
            carrier,
            "owned_sessions",
            lambda owner: ([owner], {k["pid"]: k for k in [parent, *kernels]}),
        )
        monkeypatch.setattr(carrier, "cleanup", lambda *args: None)
        _, _, _, observed = carrier.launch_phase(
            phase, "manual-integration", tmp_path, 0, 1
        )
        assert observed["worker"]["pid"] == kernels[0]["pid"]
        assert observed["parent_worker_ancestry"][-1]["pid"] == kernels[0]["pid"]
        verify_parent_worker_ancestry(observed)
        wrong = copy.deepcopy(observed)
        membership = json.loads(
            (tmp_path / "phase0.actual-membership.json").read_bytes()
        )
        wrong["parent_worker_ancestry"] = membership[-1]["parent_worker_ancestry"]
        with pytest.raises(ValueError, match="subtree"):
            verify_parent_worker_ancestry(wrong)
    finally:
        for child in children:
            child.stdin.close()
            child.wait(timeout=3)
