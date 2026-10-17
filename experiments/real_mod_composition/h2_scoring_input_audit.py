"""Exclude an oracle-supplied diagnosis from independent H2 detection scores."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from vllm_hust_ext.manifest import load_manifest
from vllm_hust_ext.providers.production_stack import ProductionStackProvider

AUDIT = (
    "experiments/real_mod_composition/artifacts/"
    "h2-scoring-input-audit-20261013/audit.json"
)
CASE = "external-authority-production-stack-keda"
HISTORICAL_PROVIDER = (
    "experiments/real_mod_composition/artifacts/"
    "h2-remaining-surfaces-oracle-20261013/snapshots/"
    "production-stack-provider-source.py.snapshot"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(root: Path) -> dict:
    audit = json.loads((root / AUDIT).read_text())
    paths = audit["historical_paths"]
    prediction = json.loads((root / paths["prediction"]).read_text())
    if (
        audit.get("schema") != "ecpa-h2-prediction-input-audit/v1"
        or audit.get("case_id") != CASE
        or audit.get("classification")
        != "source-bound-conflict-report-consumption-only"
        or audit.get("score_eligible") is not False
        or audit.get("historical_oracle_preserved") is not True
        or audit.get("runtime_claim") is not False
        or audit.get("performance_claim") is not False
        or audit["historical_prediction_sha256"] != digest(root / paths["prediction"])
        or paths["provider"] != "src/vllm_hust_ext/providers/production_stack.py"
        or audit["provider_source_sha256"] != digest(root / HISTORICAL_PROVIDER)
        or audit["provider_source_sha256"]
        != prediction["manager"]["provider_source_sha256"]
    ):
        raise ValueError("H2 scoring input audit is unbound or promoted")
    configs = audit["configurations"]
    supplied = configs["with_report"]
    without = configs["without_report"]
    if (
        supplied != prediction["configuration"]
        or not supplied.get("ownership_conflicts")
        or without != {k: v for k, v in supplied.items() if k != "ownership_conflicts"}
    ):
        raise ValueError("H2 counterfactual changes more than the supplied verdict")
    manifest = load_manifest(root / paths["manifest"])
    actual = json.loads(
        json.dumps(
            {
                name: asdict(ProductionStackProvider().check(manifest, config))
                for name, config in configs.items()
            }
        )
    )
    if (
        actual != audit["actual_checks"]
        or actual["with_report"]["compatible"] is not False
        or actual["without_report"]["compatible"] is not None
        or any(
            item.startswith("ownership conflict:")
            for item in actual["without_report"]["evidence"]
        )
    ):
        raise ValueError("H2 report consumption comparison is not reproducible")
    expected = {
        "case_id": CASE,
        "applies_to": "independent-H2-conflict-detection-score",
        "excluded_true_negatives": 1,
        "corrected_definite_subset": {
            "case_count": 4,
            "true_positive": 2,
            "true_negative": 2,
            "false_positive": 0,
            "false_negative": 0,
        },
    }
    if audit["scoring_exclusion"] != expected:
        raise ValueError("H2 report-only evidence was retained as a detection score")
    return expected | {
        "score_eligible": False,
        "unreported_conflict_detection": "unverified",
        "runtime_claim": False,
        "performance_claim": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[2]
    )
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
