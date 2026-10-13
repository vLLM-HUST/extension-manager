"""Recompute ECPA-only two-live-backend crash qualification from raw artifacts."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from experiments.formal_campaign.h3_authority_chain import (
    snapshot_digest,
    verify_native_recovery,
    verify_recovery_chain,
)
from experiments.formal_campaign.h3_phase_barrier import (
    read_native_recovery,
    rows_digest,
)
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.host_observer import parse_linux_start_ticks
from vllm_hust_ext.plan_artifact import read_plan_artifact


def verify_archive(path: Path, *, expected_model: str = "ecpa-h3-model") -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with tarfile.open(path, "r:gz") as archive:
            archive.extractall(root, filter="data")
        return verify(root, expected_model=expected_model)


def verify(root: Path, *, expected_model: str = "ecpa-h3-model") -> dict:
    def load(name):
        return json.loads((root / name).read_text())

    inputs = load("inputs.json")
    audit = load("preflight.json")
    if (
        not audit["passed"]
        or audit["manager"]["dirty"]
        or audit["manager"]["commit"] != inputs["manager_commit"]
    ):
        raise ValueError("frozen source audit is not clean or bound")
    binding = load("runtime-source-binding.json")
    if binding["commit"] != inputs["manager_commit"]:
        raise ValueError("retained source commit differs")
    for name, expected in binding["sha256"].items():
        if hashlib.sha256(
            (root / "runtime-source" / name).read_bytes()
        ).hexdigest() != expected or (
            name in audit["manager"]["source_files"]
            and audit["manager"]["source_files"][name] != expected
        ):
            raise ValueError("retained runtime source differs")
    if any(row["mismatches"] for row in audit["wheels"].values()):
        raise ValueError("installed wheel source mismatch")
    for name, expected in inputs["cpu_preflight_sha256"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError("CPU preflight changed")
    if not load("cpu-preflight/result.json")["passed"]:
        raise ValueError("CPU preflight was not passed")
    for name, expected in inputs["sha256"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError("frozen input changed: " + name)
    if inputs["classification"] != "QUALIFIED_NONFORMAL" or any(
        inputs[k]
        for k in ("formal_result", "matched_three_arm_result", "performance_result")
    ):
        raise ValueError("qualification scope misreported")
    configs = inputs["configs"]
    if [c["label"] for c in configs] != ["predecessor", "candidate"]:
        raise ValueError("two independent live backends required")
    if len({c["port"] for c in configs}) != 2:
        raise ValueError("backend ports overlap")
    plan = read_plan_artifact(root / "plan.json").plan
    worker_sets = []
    for c in configs:
        if "ASCEND_RT_VISIBLE_DEVICES" in c["env"]:
            raise ValueError("physical device visibility override")
        argv = c["argv"]
        if argv[argv.index("--tensor-parallel-size") + 1] != "2":
            raise ValueError("TP2 command missing")
        if argv[argv.index("--served-model-name") + 1] != expected_model:
            raise ValueError("served model differs from frozen qualification oracle")
        observation = load(c["label"] + "/invocation-observation.json")
        if not observation["complete_coverage"]:
            raise ValueError("Host invocation coverage incomplete")
        members = load(c["label"] + "/membership.json")
        workers = {p["pid"] for p in members if p["role"] == "worker"}
        if len(workers) != 2:
            raise ValueError("two live worker identities required")
        slots = set()
        raw_workers = set()
        for obligation in observation["obligations"].values():
            for record in obligation["effect_records"]:
                raw = base64.b64decode(record["raw_base64"], validate=True)
                lines = (
                    (root / c["label"] / "events" / record["journal"])
                    .read_bytes()
                    .splitlines()
                )
                if (
                    lines[record["line_number"] - 1] != raw
                    or record["raw_sha256"]
                    != "sha256:" + hashlib.sha256(raw).hexdigest()
                ):
                    raise ValueError("Host invocation raw bytes changed")
                event = parse_host_event(raw)
                proc = event["process"]
                ticks = parse_linux_start_ticks(
                    (
                        root / c["label"] / "proc" / str(proc["pid"]) / "stat"
                    ).read_bytes()
                )
                if (
                    event["entry_point"]
                    != {
                        "group": "vllm.general_plugins",
                        "name": "kv_materialization",
                        "value": "vllm_kv_materialization.plugin:register_plugin",
                    }
                    or event["event"] != "invoked"
                    or event["plan_id"] != plan.plan_id
                    or event["launch_id"] != c["env"]["VLLM_ECPA_LAUNCH_ID"]
                    or proc["assignment_source"] != "host"
                    or proc["role"] != "worker"
                    or proc["start_identity"]
                    != f"pid:{proc['pid']}:start_ticks:{ticks}"
                ):
                    raise ValueError("Host invocation launch/process identity differs")
                slots.add(proc["ordinal"])
                raw_workers.add(proc["pid"])
        if slots != {0, 1} or raw_workers != workers:
            raise ValueError("retained raw worker coverage differs")
        worker_sets.append(workers)
    if worker_sets[0] & worker_sets[1]:
        raise ValueError("predecessor and candidate share worker processes")
    proof = load("prepare-proof.json")
    rows = proof["native_rows"]
    barrier = proof["barrier"]
    if rows_digest(rows) != barrier["native_rows_sha256"]:
        raise ValueError("native prepare journal digest changed")
    pending = [r for r in rows if r["operation"] == "close" and r["kind"] == "intent"]
    receipts = [r for r in rows if r["operation"] == "close" and r["kind"] == "receipt"]
    if len(pending) != 1 or receipts or barrier["launch_id"] != inputs["launch_id"]:
        raise ValueError("native durable prepare missing")
    fault = load("fault.json")
    restart = load("restart.json")
    if fault["signal"] != "SIGKILL" or fault["returncode"] != -9:
        raise ValueError("controller was not killed")
    if fault["target"] != barrier["manager"] or restart["identity"] == fault["target"]:
        raise ValueError("controller process epoch did not change")
    if (
        not barrier["observed_monotonic_ns"]
        <= proof["verified_monotonic_ns"]
        < fault["monotonic_ns"]
    ):
        raise ValueError("fault preceded durable prepare verification")
    verify_native_recovery(
        proof, read_native_recovery(root / "coordinator/gate.sqlite")
    )
    completions = (
        ("predecessor/direct-before.json", "ECPA-H3-PREDECESSOR"),
        ("candidate/direct-before.json", "ECPA-H3-CANDIDATE"),
        ("proxy-before.json", "ECPA-H3-PREDECESSOR"),
        ("predecessor/during-crash.json", "ECPA-H3-PREDECESSOR"),
        ("candidate/during-crash.json", "ECPA-H3-CANDIDATE"),
        ("proxy-after.json", "ECPA-H3-PREDECESSOR"),
        ("candidate/direct-after.json", "ECPA-H3-CANDIDATE"),
    )
    ids = []
    for name, marker in completions:
        http = load(name)
        body = json.loads(http["body"])
        if (
            http["status"] != 200
            or body["model"] != expected_model
            or body["usage"]["completion_tokens"] <= 0
            or body["choices"][0]["message"]["content"].strip() != marker
            or http["request"]["messages"][0]["content"] != "Reply exactly " + marker
        ):
            raise ValueError("real model marker completion invalid: " + name)
        ids.append(body["id"])
        if "during-crash" in name and not (
            fault["monotonic_ns"]
            < http["started_monotonic_ns"]
            < http["finished_monotonic_ns"]
            < restart["monotonic_ns"]
        ):
            raise ValueError("backend liveness was not measured during crash")
    if len(set(ids)) != len(ids):
        raise ValueError("completion responses replayed")
    first = json.loads((root / "authority.jsonl").read_text().splitlines()[0])
    spec = load("spec.json")
    native = proof["native_state"]
    predecessor = spec["predecessor"]
    native_digest = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                predecessor, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
    )
    if (
        json.loads(native["predecessor_json"]) != predecessor
        or native["predecessor_digest"] != native_digest
        or native["predecessor_generation"] != predecessor["generation"]
        or native["route_fence"] != f"fence-{predecessor['generation']}"
    ):
        raise ValueError("native prepared predecessor differs from frozen spec")
    expected_route = {
        "generation": predecessor["generation"],
        "fence": f"fence-{predecessor['generation']}",
        "snapshot_sha256": snapshot_digest(predecessor),
    }
    if first["route"] != expected_route or load("route-before.json") != {
        "generation": predecessor["generation"],
        "fence": f"fence-{predecessor['generation']}",
        "snapshot": predecessor,
    }:
        raise ValueError("prepared authority predecessor differs from frozen spec")
    for name in ("proxy-after.json", "candidate/direct-after.json"):
        if load(name)["started_monotonic_ns"] <= restart["monotonic_ns"]:
            raise ValueError("post-recovery completion preceded restart")
    completion = load("proxy-after.json")
    chain = verify_recovery_chain(
        root / "authority.jsonl",
        expected_proxy=load("proxy-identity.json"),
        registration_sha256="sha256:"
        + hashlib.sha256((root / "spec.json").read_bytes()).hexdigest(),
        launch_id=inputs["launch_id"],
        prepared_route=first["route"],
        fault_ns=fault["monotonic_ns"],
        restart_ns=restart["monotonic_ns"],
        completion_ns=completion["finished_monotonic_ns"],
    )
    if load("route-before.json") != load("route-after.json"):
        raise ValueError("predecessor route was not preserved")
    reclaimed = load("cleanup-owned-processes.json")
    expected_pids = set().union(
        *worker_sets,
        {
            fault["target"]["pid"],
            restart["identity"]["pid"],
            load("proxy-identity.json")["pid"],
        },
    )
    observed_pids = {p["pid"] for p in reclaimed["processes"]}
    if not expected_pids <= observed_pids or any(
        p["proc_stat_exists"] for p in reclaimed["processes"]
    ):
        raise ValueError("owned process reclamation incomplete")
    if reclaimed["observed_monotonic_ns"] <= max(
        load(name)["finished_monotonic_ns"] for name, _ in completions
    ):
        raise ValueError("process cleanup predates final model completion")
    if any(value == 0 for value in load("cleanup-ports.json").values()):
        raise ValueError("owned listening ports remain live")
    if (
        "No running processes found in NPU 3"
        not in (root / "cleanup-npu.txt").read_text()
        or "No running processes found in NPU 6"
        not in (root / "cleanup-npu.txt").read_text()
    ):
        raise ValueError("allocated devices were not cleaned")
    return {
        "classification": "QUALIFIED_NONFORMAL",
        "passed": True,
        "formal_result": False,
        "matched_three_arm_result": False,
        "performance_result": False,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "observed_marker_task_passed": True,
        "two_distinct_tp2_backend_worker_sets": True,
        "real_model_completions": len(completions),
        "authority": chain,
        "limitation": (
            "ECPA-only close.before_effect controller crash; "
            "no matched baselines or formal source admission"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    result = verify(args.root) if args.root.is_dir() else verify_archive(args.root)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
