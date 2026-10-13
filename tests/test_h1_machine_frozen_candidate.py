from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path("experiments/false_effective")
CANDIDATE_ROOT = ROOT / "deployment-candidates"
CANDIDATE = CANDIDATE_ROOT / "h1-machine-frozen-inputs-20261013.json"
QUALIFICATION = CANDIDATE_ROOT / "h1-reachable-stack-tp2-qualification-20261013.json"
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def _load(path: Path) -> dict[str, object]:
    return json.loads(path.read_text())


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def test_h1_machine_candidate_binds_repository_inputs() -> None:
    candidate = _load(CANDIDATE)
    assert candidate["classification"] == "unregistered-machine-facts-not-formal-real"

    for source in candidate["sources"].values():
        assert GIT_SHA.fullmatch(source["commit"])
        assert GIT_SHA.fullmatch(source["tree"])
        assert source["repository_reachable"] is True

    for section in ("workload", "fault"):
        record = candidate[section]
        assert _digest(CANDIDATE_ROOT / record["path"]) == record["sha256"]

    model = candidate["model"]
    assert _digest(CANDIDATE_ROOT / model["manifest"]) == model["manifest_sha256"]
    assert model["file_count"] == 14

    assert SHA256.fullmatch(candidate["installed_environment"]["digest"])
    assert candidate["installed_environment"]["candidate_applicable"] is False
    qualification = _load(QUALIFICATION)
    environment = candidate["candidate_environment"]
    assert environment["status"] == "exact-reachable-stack-functional-tp2-qualified"
    assert environment["digest"] == qualification["environment"]["digest"]
    assert environment["formal_registration_eligible"] is False
    assert environment["required_source_commits"] == {
        name: source["commit"] for name, source in candidate["sources"].items()
    }
    assert environment["wheel_sha256"] == qualification["environment"]["wheel_sha256"]
    assert environment["packages"] == qualification["environment"]["packages"]
    assert environment["qualification_receipt_sha256"] == _digest(QUALIFICATION)
    versions = candidate["installed_environment"]["versions"]
    assert versions["vllm"].endswith("+gb093ae009.empty")
    assert versions["vllm_ascend"].endswith("+hust.20260903.4.gfd70a5c81")
    assert versions["cann_runtime"] == "9.1.0"
    assert versions["ascend_driver"] == "25.2.1"
    assert SHA256.fullmatch(candidate["container"]["image_id"])
    assert candidate["container"]["authority"] == "kubernetes-pod-status"
    assert candidate["activation_probe"] == {
        "formal_h1_start": False,
        "all_three_arms_passed": True,
        "artifact_sha256": _digest(QUALIFICATION),
        "status": "exact-reachable-stack-functional-qualification-passed",
    }
    observer = candidate["production_observer"]
    assert observer["reachable_stack_tp2_qualification"]["status"] == "passed"
    assert observer["reachable_stack_tp2_qualification"]["formal_h1_starts"] == 0
    assert observer["reachable_stack_tp2_qualification"]["performance_result"] is False
    assert observer["console_script"] == "ecpa-formal-observer"
    assert observer["authority"] == "host-observer"
    assert observer["accepts_sut_truth"] is False
    assert observer["accepts_sut_causal_ack"] is False
    assert observer["formal_h1_start"] is False
    preflight = observer["real_tp2_preflight"]
    assert preflight["candidate_applicable"] is False
    for field in ("result_sha256", "observer_result_sha256", "process_snapshot_sha256"):
        assert SHA256.fullmatch(preflight[field])
    assert preflight["classification"] == (
        "historical-different-source-stack-unregistered-preflight"
    )
    assert preflight["formal_h1_start"] is False
    assert preflight["performance_result"] is False
    assert preflight["membership_freeze"] == "passed"
    assert preflight["effective_claim"] is True
    assert preflight["quarantined_worker_ordinal"] == 0
    assert preflight["observed_worker_ordinals"] == [1]
    assert preflight["coverage"] == 0.5
    assert preflight["cleanup_proven"] is True
    three_arm = observer["three_arm_real_tp2_preflights"]
    assert three_arm["candidate_applicable"] is False
    assert three_arm["formal_h1_starts"] == 0
    assert three_arm["performance_results"] is False
    assert set(three_arm["arms"]) == {
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    }
    for arm in three_arm["arms"].values():
        assert all(SHA256.fullmatch(value) for value in arm.values())
    assert three_arm["common_observation"] == {
        "health_status": 200,
        "completion_status": 200,
        "completion_nonempty": True,
        "membership_freeze": "passed",
        "quarantined_worker_ordinal": 0,
        "effective_claim": True,
        "observed_worker_ordinals": [1],
        "coverage": 0.5,
        "cleanup_proven": True,
    }
    hardware = candidate["hardware"]
    assert hardware["physical_device_ids"] == hardware["npu_smi_device_ids"] == [3, 6]
    assert hardware["runtime_logical_device_ids"] == [0, 1]
    assert (
        hardware["runtime_visibility_policy"] == "inherit-container-device-assignment"
    )
    assert hardware["explicit_ascend_rt_visible_devices"] is None

    assert candidate["sources"]["runtime"]["commit"].startswith("973d9ef5")
    assert candidate["sources"]["mod"]["commit"].startswith("e343fc5c")
    assert candidate["sources"]["manager"]["commit"].startswith("b734a923")
    assert candidate["sources"]["accelerator_plugin"]["commit"].startswith("87358402")
    assert (
        candidate["sources"]["accelerator_plugin"]["qualification"]
        == "exact-qwen2.5-7b-eager-tp2-passed"
    )


def test_machine_candidate_remains_qualification_after_official_admission() -> None:
    candidate = _load(CANDIDATE)
    study = _load(ROOT / "first-formal-real-study.json")
    deployment = _load(ROOT / "first-formal-real-deployment.json")
    registry = _load(ROOT / "verified-adapters.json")

    assert candidate["qualification"]["registration_state"] == "unregistered"
    assert candidate["qualification"]["formal_h1_starts"] == 0
    assert study["status"] == "admitted"
    assert study["admissible"] is True
    assert all(
        value is not None
        for key, value in study["fixed_identity"].items()
        if key != "container_digest"
    )
    assert deployment["registration_state"] == "registered"
    assert deployment["admissible"] is True
    assert deployment["blockers"] == []
    assert [entry["arm"] for entry in registry["adapters"]] == study["arms"]
