"""Recompute the retained real-model finite delivery window and native crash."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path

from experiments.exposure_gate.loopback_traffic import read_traffic_journal
from experiments.formal_campaign.h3_authority_chain import verify_recovery_chain
from experiments.formal_campaign.h3_client_trace import (
    canonical,
    read_client_trace,
    verify_window,
)
from experiments.formal_campaign.h3_model_qualification import verify as verify_model

MODEL = "ecpa-h3-model-window"


def verify_archive(path: Path) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        with tarfile.open(path, "r:gz") as archive:
            archive.extractall(root, filter="data")
        return verify(root)


def verify(root: Path) -> dict:
    def load(name):
        return json.loads((root / name).read_text())

    base = verify_model(root, expected_model=MODEL)
    spec = load("client-spec.json")
    frozen = load("frozen-client-inputs.json")
    if (
        hashlib.sha256((root / "client-spec.json").read_bytes()).hexdigest()
        != frozen["spec_sha256"]
    ):
        raise ValueError("frozen client spec bytes changed")
    expected_ids = [spec["start_id"] + f"/request-{i:05d}" for i in range(60)]
    if frozen["request_ids"] != expected_ids or spec["request_count"] != 60:
        raise ValueError("frozen finite request IDs changed")
    expected_policy = {
        "interval_s": 0.2,
        "timeout_s": 10,
        "dispatch_slack_s": 0.5,
        "concurrency": 8,
        "retry_policy": "single-attempt-no-retry",
    }
    if any(spec[k] != value for k, value in expected_policy.items()):
        raise ValueError("finite client schedule differs from frozen runner policy")
    recipe = load("model-request-inputs.json")
    prompt = (root / "model-prompt.txt").read_bytes()
    if (
        hashlib.sha256(prompt).hexdigest() != recipe["prompt_sha256"]
        or spec["payload"] != recipe["payload"]
        or spec["response_expectation"] != recipe["response_expectation"]
        or recipe["payload"]["prompt"].encode() != prompt
    ):
        raise ValueError("model prompt/oracle changed after freezing")
    if (
        spec["request_url"] != recipe["request_url"]
        or spec["payload"]["model"] != MODEL
    ):
        raise ValueError("client endpoint/model differs from frozen oracle")
    if (
        frozen["request_bytes_sha256"]
        != "sha256:" + hashlib.sha256(canonical(spec["payload"])).hexdigest()
    ):
        raise ValueError("frozen client request bytes changed")
    audit = load("preflight.json")
    if any(
        audit["model"]["files"][name] != sha
        for name, sha in recipe["tokenizer_files"].items()
    ):
        raise ValueError("tokenizer recipe differs from exact audited model")
    equivalence = load("cpu-to-model-source-equivalence.json")
    if (
        equivalence["model_source"] != audit["manager"]["commit"]
        or equivalence["cpu_source"]
        != load("cpu-preflight/protocol.json")["source_commit"]
    ):
        raise ValueError("CPU/model source equivalence is not execution bound")
    binding = load("runtime-source-binding.json")
    if any(
        binding["sha256"].get(name) != sha
        for name, sha in equivalence["checked_equal_files"].items()
    ):
        raise ValueError("CPU-tested runtime differs from frozen model runtime")
    client = read_client_trace(root / "client.jsonl")
    if frozen["frozen_ns"] >= client[0]["monotonic_ns"]:
        raise ValueError("client registration was not frozen before its start")
    if spec["start_id"] != load("inputs.json")["launch_id"]:
        raise ValueError("finite window belongs to another native launch")
    authority_identity = load("proxy-identity.json")
    if any(
        spec["authority_process_identity"][k] != authority_identity[k]
        for k in ("pid", "start_ticks", "boot_id")
    ):
        raise ValueError(
            "client authority identity differs from real launched authority"
        )
    native_spec_sha = (
        "sha256:" + hashlib.sha256((root / "spec.json").read_bytes()).hexdigest()
    )
    if spec["authority_registration_sha256"] != native_spec_sha:
        raise ValueError("client registration is not frozen-native-spec bound")
    if spec["backend_registration"] != load("backend-registration.json"):
        raise ValueError("live backend registration changed")
    backend_ports = set()
    for config in load("inputs.json")["configs"]:
        label = config["label"]
        backend_ports.add(str(config["port"]))
        registered = spec["backend_registration"][str(config["port"])]
        launcher = load(label + "/launcher-identity.json")
        if (
            any(
                registered["process_identity"][k] != launcher[k]
                for k in ("pid", "start_ticks", "boot_id")
            )
            or registered["model"] != MODEL
            or registered["launch_id"] != config["env"]["VLLM_ECPA_LAUNCH_ID"]
            or registered["generation"] != (0 if label == "predecessor" else 1)
        ):
            raise ValueError(
                "backend response registration does not bind actual launch"
            )
    if set(spec["backend_registration"]) != backend_ports:
        raise ValueError("unexpected backend descriptors")
    fault = load("fault.json")
    recovery = load("recovery-marker.json")
    restart = load("restart.json")
    if (
        recovery["identity"] != restart["identity"]
        or recovery["restart_ns"] != restart["monotonic_ns"]
        or not fault["monotonic_ns"] + 3e9
        <= restart["monotonic_ns"]
        <= recovery["observed_ns"]
    ):
        raise ValueError("actual native fault/recovery window is not bound")
    events = read_traffic_journal(root / "authority.jsonl")
    applied = [e for e in events if e["kind"] == "route.restore.applied"]
    if (
        len(applied) != 1
        or not restart["monotonic_ns"]
        < applied[0]["monotonic_ns"]
        <= recovery["observed_ns"]
        <= load("proxy-after.json")["started_monotonic_ns"]
    ):
        raise ValueError("native recovery marker precedes actual authority restoration")
    window = verify_window(
        spec,
        root / "client.jsonl",
        root / "authority.jsonl",
        expected_client=load("client-identity.json"),
        fault_ns=fault["monotonic_ns"],
        recovery_ns=recovery["observed_ns"],
    )
    if window["coverage"] != "complete-finite-delivery-window":
        raise ValueError("finite delivery coverage incomplete; counts remain unknown")
    sends = [e["detail"]["sent_ns"] for e in client if e["kind"] == "request.start"]
    if (
        fault["monotonic_ns"] - client[0]["detail"]["schedule_anchor_ns"] < 2e9
        or max(sends) - recovery["observed_ns"] < 2e9
    ):
        raise ValueError("finite trace lacks frozen pre/post recovery duration")
    finishes = [
        e["detail"]["finished_ns"] for e in client if e["kind"] == "request.finish"
    ]
    if client[-1]["detail"].get("request_count") != spec["request_count"]:
        raise ValueError("finite end marker is not frozen-request-count bound")
    window_end_ns = client[-1]["monotonic_ns"]
    if window_end_ns <= max(finishes):
        raise ValueError("finite window end precedes completed requests")
    full_chain = verify_recovery_chain(
        root / "authority.jsonl",
        expected_proxy=authority_identity,
        registration_sha256=native_spec_sha,
        launch_id=spec["start_id"],
        prepared_route=events[0]["route"],
        fault_ns=fault["monotonic_ns"],
        restart_ns=restart["monotonic_ns"],
        completion_ns=window_end_ns,
    )
    delivered_generations = {
        e["route"]["generation"]
        for e in events
        if e["kind"] == "request.complete"
        and e["detail"].get("request_id") in set(expected_ids)
    }
    if delivered_generations != {0}:
        raise ValueError("finite delivery window exposed a candidate generation")
    reclaimed = load("cleanup-owned-processes.json")
    client_pid = load("client-identity.json")["pid"]
    if not any(
        p["pid"] == client_pid and not p["proc_stat_exists"]
        for p in reclaimed["processes"]
    ) or reclaimed["observed_monotonic_ns"] <= max(finishes):
        raise ValueError("client cleanup predates actual request completion")
    return {
        "classification": "QUALIFIED_NONFORMAL",
        "passed": True,
        "formal_result": False,
        "matched_three_arm_result": False,
        "performance_result": False,
        "full_objective_satisfied": None,
        "phase_marker_completions": base["real_model_completions"],
        "finite_delivery_window": window,
        "authority": full_chain,
        "verified_window_end_monotonic_ns": window_end_ns,
        "scope": (
            "ECPA-only native before-effect controller crash; "
            "finite 60-request model delivery window"
        ),
        "backend_side_effect_exactly_once": None,
        "candidate_exposed": False,
        "observed_delivered_generations": sorted(delivered_generations),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    result = verify(args.root) if args.root.is_dir() else verify_archive(args.root)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
