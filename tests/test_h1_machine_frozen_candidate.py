from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path("experiments/false_effective")
CANDIDATE_ROOT = ROOT / "deployment-candidates"
CANDIDATE = CANDIDATE_ROOT / "h1-machine-frozen-inputs-20261013.json"
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

    for section in ("workload", "fault"):
        record = candidate[section]
        assert _digest(CANDIDATE_ROOT / record["path"]) == record["sha256"]

    model = candidate["model"]
    assert _digest(CANDIDATE_ROOT / model["manifest"]) == model["manifest_sha256"]
    assert model["file_count"] == 14

    assert SHA256.fullmatch(candidate["installed_environment"]["digest"])
    assert SHA256.fullmatch(candidate["container"]["image_id"])
    assert candidate["container"]["authority"] == "kubernetes-pod-status"
    assert SHA256.fullmatch(candidate["activation_probe"]["artifact_sha256"])


def test_machine_candidate_does_not_admit_the_formal_study() -> None:
    candidate = _load(CANDIDATE)
    study = _load(ROOT / "first-formal-real-study.json")
    deployment = _load(ROOT / "first-formal-real-deployment.json")
    registry = _load(ROOT / "verified-adapters.json")

    assert candidate["qualification"]["registration_state"] == "unregistered"
    assert candidate["qualification"]["formal_h1_starts"] == 0
    assert study["status"] == "pre-admission"
    assert study["admissible"] is False
    assert all(value is None for value in study["fixed_identity"].values())
    assert deployment["registration_state"] == "unregistered"
    assert deployment["admissible"] is False
    assert all(value is None for value in deployment["deployment_identity"].values())
    assert registry == {"adapters": [], "schema": "ecpa-formal-adapter-registry/v2"}
