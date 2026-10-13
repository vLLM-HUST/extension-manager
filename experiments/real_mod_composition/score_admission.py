#!/usr/bin/env python3
"""Fail closed before real-MOD evidence enters the H2 score."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAMPAIGN = ROOT / "experiments/real_mod_composition/runtime_campaign.json"
DEFAULT_PREFLIGHTS = (
    ROOT
    / "experiments/real_mod_composition/artifacts"
    / "kvcompress-knorm-install-order-preflight.json",
    ROOT
    / "experiments/real_mod_composition/artifacts"
    / "kvcompress-knorm-legacy-0.23.0-runtime-preflight.json",
    ROOT
    / "experiments/real_mod_composition/artifacts"
    / "kvcompress-knorm-documented-legacy-source-pair-preflight.json",
)
FORMAL_RECORD_CLASS = "formal-real-host-composition"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def assess(
    campaign_path: Path,
    preflight_paths: tuple[Path, ...],
    *,
    oracle_path: Path | None = None,
    record_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    campaign = _load(campaign_path)
    if campaign.get("schema") != "ecpa-h2-real-mod-runtime-campaign/0.1":
        raise ValueError("unsupported H2 campaign schema")
    expected_orders = {
        item["order_id"] for item in campaign.get("installation_orders", [])
    }
    if not expected_orders:
        raise ValueError("campaign must freeze at least one installation order")

    inputs: dict[str, Any] = {
        "campaign": {"path": str(campaign_path), "sha256": _sha256(campaign_path)},
        "preflights": [
            {"path": str(path), "sha256": _sha256(path)} for path in preflight_paths
        ],
    }
    blockers: set[str] = set()
    excluded: list[dict[str, Any]] = []
    for path in preflight_paths:
        artifact = _load(path)
        if artifact.get("classification") == FORMAL_RECORD_CLASS:
            raise ValueError(f"{path} is a record, not a preflight")
        if artifact.get("score_eligible") is not False:
            raise ValueError(f"{path} does not fail closed on score eligibility")
        excluded.append(
            {
                "path": str(path),
                "classification": artifact.get("classification"),
                "reason": "preflight-is-not-formal-real",
            }
        )

    oracle: dict[str, Any] | None = None
    oracle_digest: str | None = None
    if oracle_path is None:
        blockers.add("independent-oracle-missing")
    else:
        oracle = _load(oracle_path)
        oracle_digest = _sha256(oracle_path)
        if (
            oracle.get("schema") != "ecpa-h2-real-mod-oracle/v1"
            or oracle.get("status") != "automated-independent-reviewed"
            or oracle.get("campaign_sha256") != inputs["campaign"]["sha256"]
            or oracle.get("review", {}).get("verdict") != "PASS"
            or oracle.get("review", {}).get("kind") != "automated-independent"
        ):
            blockers.add("independent-oracle-invalid")

    schema = _load(
        ROOT / "experiments/real_mod_composition/formal-runtime-record.schema.json"
    )
    validator = jsonschema.Draft7Validator(schema)
    accepted: list[dict[str, Any]] = []
    observed_orders: set[str] = set()
    for path in record_paths:
        record = _load(path)
        errors = sorted(validator.iter_errors(record), key=lambda item: list(item.path))
        if errors:
            raise ValueError(f"{path}: {errors[0].message}")
        if record["campaign_sha256"] != inputs["campaign"]["sha256"]:
            raise ValueError(f"{path} does not bind the campaign")
        if oracle_digest is None or record["oracle_sha256"] != oracle_digest:
            raise ValueError(f"{path} does not bind the admitted oracle")
        if record["case_id"] != campaign["case_id"]:
            raise ValueError(f"{path} does not bind the campaign case")
        if record["order_id"] not in expected_orders:
            raise ValueError(f"{path} names an unregistered installation order")
        if record["order_id"] in observed_orders:
            raise ValueError(f"{path} duplicates an installation order")
        if record["planner_decision"] == "admit":
            evidence = record["runtime_evidence"]
            if not all(
                (
                    evidence["host_started"],
                    evidence["model_loaded"],
                    evidence["workload_completed"],
                    evidence["process_owned_observation"],
                    evidence["cleanup_complete"],
                )
            ):
                raise ValueError(f"{path} lacks admitted-host execution evidence")
        accepted.append(
            {
                "path": str(path),
                "sha256": _sha256(path),
                "order_id": record["order_id"],
                "planner_decision": record["planner_decision"],
            }
        )
        observed_orders.add(record["order_id"])

    if not accepted:
        blockers.add("formal-real-runtime-records-missing")
    if observed_orders != expected_orders:
        blockers.add("installation-order-coverage-incomplete")
    oracle_decision: str | None = None
    if oracle is not None and "independent-oracle-invalid" not in blockers:
        label = next(
            (
                item
                for item in oracle.get("labels", [])
                if item.get("case_id") == campaign["case_id"]
            ),
            None,
        )
        if label is None or label.get("decision") not in {"admit", "reject"}:
            blockers.add("oracle-case-label-missing")
        else:
            oracle_decision = label["decision"]

    eligible = not blockers
    return {
        "schema": "ecpa-h2-score-admission/v1",
        "classification": "formal-real-score-admission-status",
        "status": "ADMITTED" if eligible else "INCOMPLETE",
        "score_eligible": eligible,
        "inputs": inputs,
        "oracle_sha256": oracle_digest,
        "oracle_decision": oracle_decision,
        "accepted_records": accepted,
        "excluded_preflights": excluded,
        "blockers": sorted(blockers),
        "metrics": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--preflight", type=Path, action="append")
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--record", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = assess(
        args.campaign,
        tuple(args.preflight or DEFAULT_PREFLIGHTS),
        oracle_path=args.oracle,
        record_paths=tuple(args.record),
    )
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    return 0 if result["score_eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
