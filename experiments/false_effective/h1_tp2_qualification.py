"""Build and validate the exact reachable-stack TP2 qualification receipt.

These runs qualify one functional source/wheel/profile tuple.  They are not
formal H1 starts and carry no performance result.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from harness import canonical, digest_bytes, digest_file

HERE = Path(__file__).resolve().parent
DEFAULT_EVIDENCE_ROOT = Path("/root/ecpa-audit-20261013")
SCHEMA = "ecpa-h1-reachable-stack-tp2-qualification/v1"
CLASSIFICATION = "exact-reachable-stack-functional-qualification"
SOURCE_COMMITS = {
    "accelerator_plugin": "873584026f8a683ac73523f15127569e9f6ab34b",
    "host": "973d9ef5acd2b9beb03e399dec1511a41fc941b5",
    "manager": "e583852ac3cb7ea0003ac4b5798c09d369151514",
    "mod": "e343fc5ce6b4c64611a79df5d797b3db12cd6dac",
}
WHEEL_SHA256 = {
    "accelerator_plugin": (
        "sha256:16438dc60e86c7bc4741a3520d80d5f9de54676daabe2035ebff0d6b2dceefcf"
    ),
    "host": "sha256:97b27b347889d6e140415e674509519f2ed65848cc51e4b888189fb28f29671a",
    "manager": (
        "sha256:c377a9b1218d1db15ab211a721bf93ccab06e8242e67bea47ad7836936adcc4f"
    ),
    "mod": "sha256:581caaff07a610bfc3ce9280c315e9548b532fb119731d14fff002aea6825b1c",
    "triton_ascend": (
        "sha256:10c14f7de72854a94827d41b6a9cf2fc5ce1c2fd94690895a6d0c8f9ccb3459d"
    ),
}
PACKAGES = {
    "torch": "2.13.0+cpu",
    "torch-npu": "2.13.0rc1",
    "triton-ascend": "3.6.0+git92513dba",
    "vllm": "0.31.1.post1.dev163+g973d9ef5a.empty",
    "vllm-ascend": "0.25.1rc2.dev872+hust.20260903.4.g873584026",
    "vllm-hust-ext": "0.3.0",
    "vllm-kv-materialization": "0.1.0",
}
RUNS = (
    (
        "vanilla-vllm-entry-points",
        "e583-stock-vanilla-tp2",
        "sha256:a557197d15c2afc162d2e862ba007475d23ee9243195c261d411c3621c96234c",
        "ecpa-host-launch",
    ),
    (
        "manual-integration",
        "e583-stock-manual-tp2",
        "sha256:a54db94a5add74f80d9334ec81d36c04a5d5932760abd4c42e30c87671a5ef38",
        "ecpa-host-launch",
    ),
    (
        "ecpa",
        "e583-stock-ecpa-python-target-tp2",
        "sha256:5c5bd3fb39b8ce3d230c1a6863d6c366b1912e525c649199181eec7f976ed71e",
        "direct-venv-python-module",
    ),
)
FAILED_SCRIPT_TARGET = (
    "pr54-stock-ecpa-tp2",
    "sha256:f8a3e2bcb435833bd4861a8492c27d2fd91e6580b19a38ff26942438d413edbd",
)
FAILURE_REASON = (
    "formal-run executing the ecpa-host-launch Python console script made "
    "multiprocessing spawn treat the Manager fd 3 launch pipe as the main-path "
    "preparation channel and deadlocked before service health"
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _environment() -> dict[str, Any]:
    core = {
        "source_commits": SOURCE_COMMITS,
        "wheel_sha256": WHEEL_SHA256,
        "packages": PACKAGES,
    }
    return {**copy.deepcopy(core), "digest": digest_bytes(canonical(core))}


def _run_record(
    evidence_root: Path,
    arm: str,
    directory: str,
    expected_result: str,
    target_kind: str,
) -> dict[str, Any]:
    run = evidence_root / directory / "run"
    result_path = run / "result.json"
    result = _load(result_path)
    if digest_file(result_path) != expected_result:
        raise ValueError(f"{arm} result digest differs from the qualified bytes")
    if result.get("source_commits") != SOURCE_COMMITS:
        raise ValueError(f"{arm} source commits differ from the qualified tuple")
    if result.get("wheel_sha256") != WHEEL_SHA256 or result.get("packages") != PACKAGES:
        raise ValueError(
            f"{arm} installed environment differs from the qualified tuple"
        )
    required = {
        "success": True,
        "formal_h1_start": False,
        "performance_result": False,
        "health_status": 200,
        "completion_status": 200,
        "completion_nonempty": True,
        "cleanup_proven": True,
        "port_refused_after_stop": True,
        "allocated_npu_process_tables_empty": True,
        "surviving_owned_processes": [],
    }
    if any(result.get(key) != value for key, value in required.items()):
        raise ValueError(
            f"{arm} did not complete the functional qualification boundary"
        )
    identities = result.get("process_identities")
    launch_identity = (
        result.get("manager_identity") if arm == "ecpa" else result.get("root_identity")
    )
    if (
        not isinstance(identities, list)
        or not identities
        or not isinstance(launch_identity, dict)
    ):
        raise ValueError(f"{arm} live process identities are incomplete")
    if not isinstance(launch_identity.get("pid"), int) or not isinstance(
        launch_identity.get("start_ticks"), int
    ):
        raise ValueError(f"{arm} launch identity lacks a Linux process epoch")
    argv = result.get("host_argv") if arm == "ecpa" else result.get("argv")
    if arm == "ecpa":
        if not isinstance(argv, list) or argv[1:3] != [
            "-m",
            "vllm.entrypoints.cli.main",
        ]:
            raise ValueError(
                "ECPA qualification did not use direct Python module launch"
            )
    elif not isinstance(argv, list) or Path(argv[0]).name != "ecpa-host-launch":
        raise ValueError(f"{arm} qualification did not use ecpa-host-launch")
    manifest = run / "sha256.json"
    return {
        "arm": arm,
        "classification": "functional-qualification-not-formal-h1",
        "target_kind": target_kind,
        "evidence_dir": str(run),
        "result_sha256": expected_result,
        "artifact_manifest_sha256": digest_file(manifest),
        "process_identities_digest": digest_bytes(canonical(identities)),
        "process_identity_count": len(identities),
        "launch_identity": launch_identity,
        **required,
    }


def _failed_record(evidence_root: Path) -> dict[str, Any]:
    directory, expected_result = FAILED_SCRIPT_TARGET
    run = evidence_root / directory / "run"
    result_path = run / "result.json"
    result = _load(result_path)
    if digest_file(result_path) != expected_result:
        raise ValueError("failed script-target result digest differs")
    # This retained negative control predates the protocol amendment and is not
    # part of the newly qualified three-arm tuple. Its own bytes remain bound.
    host_argv = result.get("host_argv")
    if (
        result.get("success") is not False
        or result.get("formal_h1_start") is not False
        or result.get("performance_result") is not False
        or result.get("cleanup_proven") is not True
        or result.get("surviving_owned_processes") != []
        or not isinstance(host_argv, list)
        or Path(host_argv[0]).name != "ecpa-host-launch"
    ):
        raise ValueError("failed script-target boundary is incomplete")
    return {
        "classification": "rejected-functional-qualification-attempt",
        "target_kind": "managed-ecpa-host-launch-console-script",
        "evidence_dir": str(run),
        "result_sha256": expected_result,
        "artifact_manifest_sha256": digest_file(run / "sha256.json"),
        "cleanup_proven": True,
        "formal_h1_start": False,
        "performance_result": False,
        "reason": FAILURE_REASON,
    }


def build_receipt(evidence_root: Path = DEFAULT_EVIDENCE_ROOT) -> dict[str, Any]:
    runs = [
        _run_record(evidence_root, arm, directory, digest, target)
        for arm, directory, digest, target in RUNS
    ]
    core = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "profile": (
            "Qwen2.5-7B-Instruct/single-host/Ascend-910B2/TP2/eager/KV-materialization"
        ),
        "environment": _environment(),
        "runs": runs,
        "rejected_target_attempt": _failed_record(evidence_root),
        "qualification": {
            "exact_environment_frozen": True,
            "exact_runtime_ascend_profile_qualified": True,
            "all_three_activation_arms_qualified": True,
        },
        "formal_h1_starts": 0,
        "formal_h1_result": False,
        "performance_result": False,
        "official_files_mutated": False,
        "non_claims": [
            "This receipt is a functional qualification and is not a formal H1 start.",
            "This receipt contains no throughput, latency, or performance conclusion.",
            "The failed console-script target is retained and is not promoted.",
        ],
    }
    return {**core, "receipt_digest": digest_bytes(canonical(core))}


def validate_receipt(value: dict[str, Any], *, live: bool = False) -> None:
    if value.get("schema") != SCHEMA or value.get("classification") != CLASSIFICATION:
        raise ValueError("qualification receipt identity drifted")
    digest = value.get("receipt_digest")
    core = {key: item for key, item in value.items() if key != "receipt_digest"}
    if digest != digest_bytes(canonical(core)):
        raise ValueError("qualification receipt digest is stale")
    if value.get("environment") != _environment():
        raise ValueError("qualification environment drifted")
    if [row.get("arm") for row in value.get("runs", [])] != [row[0] for row in RUNS]:
        raise ValueError("qualification arms drifted")
    for actual, (arm, _directory, result_digest, target_kind) in zip(
        value["runs"], RUNS, strict=True
    ):
        if (
            actual.get("arm") != arm
            or actual.get("result_sha256") != result_digest
            or actual.get("target_kind") != target_kind
            or actual.get("classification") != "functional-qualification-not-formal-h1"
            or actual.get("success") is not True
            or actual.get("formal_h1_start") is not False
            or actual.get("performance_result") is not False
            or actual.get("cleanup_proven") is not True
            or actual.get("process_identity_count", 0) < 1
        ):
            raise ValueError(f"{arm} qualification boundary drifted")
    rejected = value.get("rejected_target_attempt", {})
    if (
        rejected.get("result_sha256") != FAILED_SCRIPT_TARGET[1]
        or rejected.get("target_kind") != "managed-ecpa-host-launch-console-script"
        or rejected.get("reason") != FAILURE_REASON
        or rejected.get("cleanup_proven") is not True
        or rejected.get("formal_h1_start") is not False
        or rejected.get("performance_result") is not False
    ):
        raise ValueError("rejected script-target evidence drifted")
    if value.get("qualification") != {
        "exact_environment_frozen": True,
        "exact_runtime_ascend_profile_qualified": True,
        "all_three_activation_arms_qualified": True,
    }:
        raise ValueError("qualification conclusion drifted")
    if value.get("formal_h1_starts") != 0 or value.get("formal_h1_result") is not False:
        raise ValueError("qualification receipt was promoted to formal H1")
    if value.get("performance_result") is not False:
        raise ValueError("qualification receipt was promoted to performance evidence")
    if live and value != build_receipt(DEFAULT_EVIDENCE_ROOT):
        raise ValueError("qualification receipt differs from live evidence")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.evidence_root)
    validate_receipt(receipt)
    args.output.write_bytes(canonical(receipt) + b"\n")


if __name__ == "__main__":
    main()
