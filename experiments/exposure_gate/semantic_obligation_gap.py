"""Recompute the precise semantic gap in sealed real invocation qualification.

This audit cannot admit a route. It validates the retained qualification and
classifies the actual source/Plan/observation, preserving historical evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from experiments.exposure_gate.qualification_verify import (
    unpack_qualification,
    verify_qualification,
)
from scripts.benchmark_inputs import resolve_original
from vllm_hust_ext.plan_artifact import read_plan_artifact

PACKAGE = (
    "experiments/exposure_gate/artifacts/real-invocation-gate-qualification-20261013"
)


def verify_gap(package: Path) -> dict:
    package = resolve_original(package)
    manifest = json.loads((package / "manifest.json").read_bytes())
    if (
        manifest.get("schema") != "ecpa-real-invocation-gate-retention/v1"
        or manifest.get("classification") != "QUALIFIED_NONFORMAL"
        or any(
            manifest.get(key) is not False
            for key in (
                "formal_result",
                "performance_result",
                "effective_semantics_result",
            )
        )
    ):
        raise ValueError("invocation archive manifest promotes semantic evidence")
    with tempfile.TemporaryDirectory() as directory:
        raw = Path(directory)
        unpack_qualification(package, raw)
        historical = verify_qualification(raw)
        plan = read_plan_artifact(raw / "plan.json").plan
        # The sealed verifier establishes invocation coverage from raw journal
        # bytes and Linux identities; a semantic-looking summary cannot alter it.
        obligations = [
            {"obligation_id": item.obligation_id, "event": item.event}
            for item in plan.obligations
        ]
        if not obligations or any(item["event"] != "invoked" for item in obligations):
            raise ValueError("sealed qualification is not invocation-only")
        return {
            "schema": "ecpa-semantic-obligation-gap/v1",
            "archive_sha256": hashlib.sha256(
                (package / "retained.tar.gz").read_bytes()
            ).hexdigest(),
            "evidence_type": "source-bound-worker-invocation-only",
            "historical_qualification": historical,
            "observed_obligations": obligations,
            "semantic_obligation_status": "unverified",
            "formal_traffic_admissible": False,
            "runtime_effectiveness": None,
            "missing_edges": [
                "registered-source-owned-live-semantic-event-producer",
                "semantic-operation-and-required-effect-predicate",
                "authority-probe-request-id-to-host-runtime-request-id",
                "operation-to-worker-pid-start-ticks-boot-and-membership-epoch",
                "semantic-operation-to-plan-launch-controller-generation",
                "per-required-worker-semantic-result-to-authority-observed-response",
            ],
            "available_offline_only": {
                "compression_transaction": (
                    "experiments/real_mod_composition/"
                    "verify_h2_compression_transaction.py"
                ),
                "bindings": [
                    "EngineCore commit to TP0/TP1 acknowledgement",
                    "runtime request to HTTP response and profiler completion",
                ],
                "live_authority_semantic_admission": False,
                "reason": (
                    "Separate stdout/profiler archive and threshold workload; "
                    "not a registered live observer for this invocation Plan."
                ),
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        type=Path,
        default=Path(__file__).resolve().parents[2] / PACKAGE,
    )
    args = parser.parse_args()
    print(json.dumps(verify_gap(args.package), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
