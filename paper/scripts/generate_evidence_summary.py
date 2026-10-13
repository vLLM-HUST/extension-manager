#!/usr/bin/env python3
"""Generate fail-closed LaTeX evidence macros from checked artifacts."""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
# Support direct invocation from paper/ as well as installed-package CI.
sys.path[:0] = [str(ROOT), str(ROOT / "src")]
OUTPUT = ROOT / "paper/generated/evidence-summary.tex"
WORKSHOP_SOURCE_IDENTITY = {
    "repository": "vLLM-HUST/vllm-hust-website",
    "repository_id": 1141990731,
    "node_id": "R_kgDORBFlSw",
    "default_branch": "main",
    "commit_sha": "8336f5b67c69910aa7d5dfc3b5b94407e99928bd",
    "metadata_path": "data/plugin-workshop-metadata.json",
    "metadata_snapshot_path": "docs/corpus/plugin-workshop-metadata.snapshot.json",
    "metadata_blob_sha": "04b6d4a23f62ba5fc4b3d53dff5a712b117560f2",
    "metadata_sha256": (
        "94164486d075671dde0e2992557d5117073644c402054be518673cea68bbd08e"
    ),
    "source_rows_sha256": (
        "aabd0a6dbd49e2314c816e115fe90307a1e2e085e91665eb5a8ec672c2625adf"
    ),
    "audit_rows_sha256": (
        "be253c011bc72e159a8390cea9cc1ba3d615468672ce1019c8c4475358301c4e"
    ),
    "mod_count": 24,
}
WORKSHOP_SOURCE_FIELDS = (
    "id",
    "repository",
    "repository_id",
    "node_id",
    "visibility",
    "default_branch",
    "head_commit",
)

# This campaign was frozen from a clean wheel environment on bare metal, so it
# has no container artifact to bind.  Every other registered identity is
# required to be concrete.
REGISTERED_NULLABLE_IDENTITIES = frozenset({"container_digest"})


def load_json(root: Path, relative: str) -> dict[str, Any]:
    value = json.loads((root / relative).read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{relative} must contain one JSON object")
    return value


def require_schema(value: dict[str, Any], expected: str, source: str) -> None:
    if value.get("schema") != expected:
        raise ValueError(f"{source} has an unsupported schema")


def require_count(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def digest(root: Path, relative: str) -> str:
    return hashlib.sha256((root / relative).read_bytes()).hexdigest()


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def recompute_transaction_model(root: Path) -> dict[str, Any]:
    path = root / "experiments/transaction_model/explore.py"
    module_name = "ecpa_paper_transaction_model"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load bounded transaction model")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        result = module.explore()
    finally:
        sys.modules.pop(module_name, None)
    if not isinstance(result, dict):
        raise ValueError("bounded transaction model did not return an object")
    return result


def validate_schema(root: Path, artifact: dict[str, Any], relative: str) -> None:
    schema = load_json(root, relative)
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(artifact)


def load_jsonl(root: Path, relative: str) -> list[dict[str, Any]]:
    records = []
    for line_number, line in enumerate((root / relative).read_text().splitlines(), 1):
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{relative}:{line_number} must be one JSON object")
        records.append(value)
    return records


def corpus_evidence_path(value: str) -> str:
    return re.sub(r":[0-9]+(?:-[0-9]+)?$", "", value).rstrip("/")


def validate_h1_r5(root: Path) -> dict[str, int | str]:
    """Validate the checked projection of the authoritative r5 formal campaign."""
    prefix = "paper/artifacts/h1-r5"
    binding = load_json(root, f"{prefix}/source-binding.json")
    aggregate = load_json(root, f"{prefix}/formal-aggregate.json")
    summary = load_json(root, f"{prefix}/formal-aggregate-summary.json")
    results = load_jsonl(root, f"{prefix}/paper-results.jsonl")
    with (root / f"{prefix}/paper-table.csv").open(newline="") as stream:
        table_rows = list(csv.DictReader(stream))
    result_schema = load_json(root, "paper/artifacts/results.schema.json")
    validator = jsonschema.Draft7Validator(result_schema)
    for result in results:
        validator.validate(result)

    digest_pattern = re.compile(r"^sha256:[0-9a-f]{64}$")
    records = binding.get("records")
    design = binding.get("design")
    cleanup = binding.get("post_cleanup_validation")
    if (
        binding.get("schema") != "ecpa-h1-paper-intake/v1"
        or binding.get("campaign") != "r5"
        or binding.get("classification") != "formal-real"
        or binding.get("runner_commit") != "73ba06ede8a94f6ee7323a4fa5add60439845595"
        or not all(
            digest_pattern.fullmatch(binding.get(name, ""))
            for name in (
                "formal_manifest_pointer_sha256",
                "generation_index_sha256",
                "records_jsonl_sha256",
            )
        )
        or not isinstance(records, list)
        or len(records) != 9
        or len({row.get("start_id") for row in records}) != 9
        or any(not digest_pattern.fullmatch(row.get("sha256", "")) for row in records)
        or not isinstance(design, dict)
        or design.get("scenario") != "partial-worker-coverage"
        or design.get("arms")
        != ["vanilla-vllm-entry-points", "manual-integration", "ecpa"]
        or design.get("repetitions") != 3
        or design.get("schedule") != "registered-3x3-latin-square"
        or design.get("lifecycle_sources")
        != [
            "service-ready",
            "workload-complete",
            "fault-injected",
            "observer-captured",
            "service-shutdown",
        ]
        or cleanup
        != {
            "load_formal_manifest": "PASS",
            "validate_batch_formal": "PASS",
            "npu_processes": 0,
            "port_8187": "free",
            "driver_sut_observer_processes": 0,
        }
        or binding.get("excluded_campaigns") != ["r2", "r3", "r4"]
    ):
        raise ValueError("H1 r5 source binding is incomplete or mixed")

    arms = ["vanilla-vllm-entry-points", "manual-integration", "ecpa"]
    if (
        len(results) != 9
        or {row.get("arm") for row in results} != set(arms)
        or any(sum(row.get("arm") == arm for row in results) != 3 for arm in arms)
        or any(
            row.get("schema") != "ecpa-result/v1"
            or row.get("status") != "complete"
            or row.get("hypothesis") != "H1"
            or row.get("cell_id") != "partial-worker-coverage"
            or row.get("protocol", {}).get("repetition") not in {1, 2, 3}
            or row.get("outcome", {}).get("false_effective") is not True
            or row.get("outcome", {}).get("activation_event_coverage") != 0.5
            or row.get("outcome", {}).get("throughput") is not None
            or row.get("outcome", {}).get("latency_p99_ms") is not None
            for row in results
        )
        or any(
            sorted(
                row["protocol"]["repetition"] for row in results if row["arm"] == arm
            )
            != [1, 2, 3]
            for arm in arms
        )
    ):
        raise ValueError("H1 r5 projected results are incomplete or overclaim scope")

    measured_cells = [
        row
        for row in aggregate.get("cells", [])
        if row.get("scenario") == "partial-worker-coverage"
    ]
    measured_table_rows = [
        row for row in table_rows if row.get("scenario") == "partial-worker-coverage"
    ]
    if (
        aggregate.get("schema") != "ecpa-false-effective-aggregate/v1"
        or aggregate.get("formal") is not True
        or aggregate.get("completed_cells") != 1
        or aggregate.get("failure_missing_modes")
        != {"excluded": 0, "failed": 0, "planned": 0}
        or aggregate.get("metrics", {}).get("n_starts") != 9
        or len(measured_cells) != 3
        or len(measured_table_rows) != 3
        or any(
            row.get("arm") not in arms
            or row.get("complete_starts") != "3"
            or row.get("false_effective_rate") != "1.0"
            or row.get("reason") != ""
            for row in measured_table_rows
        )
        or any(
            row.get("status_counts", {}).get("complete") != 3
            or row.get("false_effective", {}).get("numerator") != 3
            or row.get("false_effective", {}).get("denominator") != 3
            or row.get("false_effective", {}).get("rate") != 1.0
            or row.get("quality", {}).get("coverage_samples") != [0.5, 0.5, 0.5]
            for row in measured_cells
        )
        or summary.get("completed_cells") != 1
        or summary.get("planned_records") != 0
        or summary.get("metrics", {}).get("n_starts") != 9
    ):
        raise ValueError("H1 r5 aggregate differs from the projected formal records")

    return {
        "formal_completed": 1,
        "formal_starts": 9,
        "formal_lifecycle_sources": 5,
        "h1_false_effective_numerator": 3,
        "h1_false_effective_denominator": 3,
        "h1_coverage": "0.5",
    }


def validate_h2_real_source_subset(root: Path) -> dict[str, int | str]:
    """Recompute the scored, definite subset of the source-bound H2 corpus."""
    prefix = (
        "experiments/real_mod_composition/artifacts/"
        "h2-minimal-real-source-corpus-r2-20261013"
    )
    campaign = load_json(root, f"{prefix}/campaign.json")
    oracle = load_json(root, f"{prefix}/oracle-index.json")
    status = load_json(root, f"{prefix}/status.json")
    carrier_prefix = (
        "experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013"
    )
    carrier_oracle = load_json(root, f"{carrier_prefix}/oracle.json")
    carrier_predictions = load_json(root, f"{carrier_prefix}/manager-predictions.json")
    remaining_prefix = (
        "experiments/real_mod_composition/artifacts/"
        "h2-remaining-surfaces-oracle-20261013"
    )
    remaining_oracle = load_json(root, f"{remaining_prefix}/oracle.json")
    remaining_receipt = load_json(root, f"{remaining_prefix}/review-receipt.json")
    remaining_prediction = load_json(
        root, f"{remaining_prefix}/manager-prediction.json"
    )
    scheduler_prefix = (
        "experiments/real_mod_composition/artifacts/h2-pipeline-bidkv-oracle-20261013"
    )
    scheduler_campaign = load_json(root, f"{scheduler_prefix}/campaign.json")
    scheduler_oracle = load_json(root, f"{scheduler_prefix}/oracle.json")
    scheduler_freeze = load_json(root, f"{scheduler_prefix}/oracle-freeze-receipt.json")
    scheduler_prediction = load_json(
        root, f"{scheduler_prefix}/manager-prediction.json"
    )
    if (
        campaign.get("schema") != "ecpa-h2-minimal-real-source-corpus/v2"
        or campaign.get("revision") != 2
        or campaign.get("evidence_ordering", {}).get(
            "labels_reassigned_after_predictions"
        )
        is not False
        or campaign.get("scoring_policy", {}).get("positive_class") != "admit"
        or campaign.get("scoring_policy", {}).get("negative_class") != "reject"
        or oracle.get("schema") != "ecpa-h2-real-source-oracle-index/v2"
        or status.get("schema") != "ecpa-h2-minimal-corpus-status/v2"
        or status.get("campaign_sha256")
        != f"sha256:{digest(root, f'{prefix}/campaign.json')}"
        or status.get("oracle_index_sha256")
        != f"sha256:{digest(root, f'{prefix}/oracle-index.json')}"
        or oracle.get("campaign_sha256") != status.get("campaign_sha256")
    ):
        raise ValueError("H2 source-bound corpus identities or ordering are invalid")

    cases = campaign.get("cases")
    labels = oracle.get("labels")
    if not isinstance(cases, list) or not isinstance(labels, list):
        raise ValueError("H2 source-bound corpus must contain cases and labels")
    labels_by_id = {row.get("case_id"): row for row in labels}
    if len(labels_by_id) != len(labels) or {row.get("case_id") for row in cases} != set(
        labels_by_id
    ):
        raise ValueError("H2 oracle index does not exactly cover the successor corpus")

    counts = {
        "true_positive": 0,
        "true_negative": 0,
        "false_positive": 0,
        "false_negative": 0,
    }
    scored = []
    for case in cases:
        label = labels_by_id[case["case_id"]]
        if label.get("decision") != case.get("oracle_decision") or label.get(
            "score_eligible"
        ) != case.get("score_eligible"):
            raise ValueError("H2 successor case differs from its indexed oracle label")
        if case.get("score_eligible") is not True:
            continue
        prediction = case.get("prediction", {})
        actual = case.get("oracle_decision")
        predicted = prediction.get("decision")
        if actual not in {"admit", "reject"} or predicted not in {"admit", "reject"}:
            raise ValueError("H2 scored subset contains a non-binary decision")
        source = prediction.get("source")
        source_sha256 = prediction.get("source_sha256")
        if (
            not isinstance(source, str)
            or not isinstance(source_sha256, str)
            or source_sha256 != f"sha256:{digest(root, source)}"
        ):
            raise ValueError("H2 scored prediction is not bound to its source artifact")
        if actual == "admit" and predicted == "admit":
            counts["true_positive"] += 1
        elif actual == "reject" and predicted == "reject":
            counts["true_negative"] += 1
        elif actual == "reject" and predicted == "admit":
            counts["false_positive"] += 1
        else:
            counts["false_negative"] += 1
        scored.append(case)

    matrix = status.get("confusion_matrix")
    acceptance = status.get("acceptance")
    augmentation = status.get("surface_augmentation")
    if (
        matrix != {"case_count": len(scored), "positive_class": "admit", **counts}
        or len(scored) != 3
        or counts
        != {
            "true_positive": 1,
            "true_negative": 2,
            "false_positive": 0,
            "false_negative": 0,
        }
        or status.get("h2_acceptance_complete") is not False
        or not isinstance(acceptance, dict)
        or acceptance.get("paper_demotes_synthetic_seed") is not True
        or acceptance.get("requested_population_surface_coverage_complete") is not False
        or not isinstance(augmentation, dict)
        or augmentation.get("sha256")
        != f"sha256:{digest(root, augmentation.get('path', ''))}"
        or augmentation.get("oracle_pending_cases") != 4
        or len(status.get("remaining_gaps", [])) < 5
    ):
        raise ValueError("H2 partial result or its explicit incompleteness has drifted")

    tp, tn = counts["true_positive"], counts["true_negative"]
    fp, fn = counts["false_positive"], counts["false_negative"]
    admit_precision = tp / (tp + fp)
    admit_recall = tp / (tp + fn)
    reject_precision = tn / (tn + fn)
    reject_recall = tn / (tn + fp)
    expected_metrics = {
        "accuracy": (tp + tn) / len(scored),
        "admit_precision": admit_precision,
        "admit_recall": admit_recall,
        "reject_precision": reject_precision,
        "reject_recall": reject_recall,
        "threshold": 0.95,
        "threshold_met": min(
            admit_precision, admit_recall, reject_precision, reject_recall
        )
        >= 0.95,
    }
    if status.get("metrics") != expected_metrics:
        raise ValueError("H2 reported metrics differ from the recomputed subset")

    remaining_cases = remaining_oracle.get("cases")
    external_case = next(
        (
            row
            for row in remaining_cases or []
            if row.get("case_id") == "external-authority-production-stack-keda"
        ),
        None,
    )
    cli_case = next(
        (
            row
            for row in remaining_cases or []
            if row.get("case_id") == "scheduler-config-collision-search"
        ),
        None,
    )
    expected_external_aggregate = {
        "case_count": 4,
        "true_positive": 1,
        "true_negative": 3,
        "false_positive": 0,
        "false_negative": 0,
        "admit_precision": 1.0,
        "admit_recall": 1.0,
        "reject_precision": 1.0,
        "reject_recall": 1.0,
    }
    if (
        remaining_oracle.get("schema")
        != "ecpa-h2-independent-remaining-surfaces-oracle/v1"
        or remaining_receipt.get("schema") != "ecpa-h2-independent-review-receipt/v2"
        or remaining_receipt.get("oracle_sha256")
        != digest(root, f"{remaining_prefix}/oracle.json")
        or remaining_oracle.get("oracle_summary")
        != {
            "admit": 0,
            "reject": 1,
            "unresolved": 1,
            "score_eligible": 1,
            "runtime_claim": False,
            "performance_claim": False,
        }
        or not isinstance(external_case, dict)
        or external_case.get("decision") != "reject"
        or external_case.get("score_eligible") is not True
        or external_case.get("dimension") != "external-authority-conflict"
        or not isinstance(cli_case, dict)
        or cli_case.get("decision") != "unresolved"
        or cli_case.get("score_eligible") is not False
        or cli_case.get("dimension") != "CLI/config-collision"
        or remaining_prediction.get("schema")
        != "ecpa-h2-remaining-surface-manager-prediction/v1"
        or remaining_prediction.get("oracle")
        != {
            "frozen_commit": "dfc533d33582f80fae0ee172e17aa47406d98e48",
            "sha256": digest(root, f"{remaining_prefix}/oracle.json"),
            "receipt_sha256": digest(root, f"{remaining_prefix}/review-receipt.json"),
            "frozen_before_prediction": True,
        }
        or remaining_prediction.get("case_id") != external_case.get("case_id")
        or remaining_prediction.get("classification")
        != "source-bound-pre-launch-provider-check"
        or remaining_prediction.get("prediction") != "reject"
        or remaining_prediction.get("oracle_decision") != "reject"
        or remaining_prediction.get("decision_match") is not True
        or remaining_prediction.get("score_eligible") is not True
        or remaining_prediction.get("h2_complete") is not False
        or remaining_prediction.get("process_boundary", {}).get("host_process_started")
        is not False
        or any(
            remaining_prediction.get("process_boundary", {})
            .get(name, {})
            .get("no_running_processes_for_allocated_devices")
            is not True
            for name in ("npu_before", "npu_after")
        )
        or remaining_prediction.get("manager", {}).get("provider_source_sha256")
        != digest(
            root,
            remaining_prediction.get("manager", {}).get("provider_source", ""),
        )
        or remaining_prediction.get("aggregate_definite_subset")
        != expected_external_aggregate
    ):
        raise ValueError("H2 remaining-surface evidence is invalid or overclaimed")

    counts["true_negative"] += 1
    scored.append(external_case)

    scheduler_sources = scheduler_campaign.get("sources")
    scheduler_host = scheduler_campaign.get("host")
    scheduler_boundary = scheduler_prediction.get("process_boundary")
    scheduler_runtime = scheduler_prediction.get("runtime")
    expected_scheduler_aggregate = {
        "case_count": 5,
        "true_positive": 2,
        "true_negative": 3,
        "false_positive": 0,
        "false_negative": 0,
        "admit_precision": 1.0,
        "admit_recall": 1.0,
    }
    expected_scheduler_options = {
        "org.vllm-hust.pipeline-microbatch": {
            "--batch-admission-policy": (
                "vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy"
            )
        },
        "org.vllm-hust.bidkv": {
            "--preemption-policy": (
                "bidkv.adapters.vllm_hust.selector.BidkvPreemptionPolicy"
            )
        },
    }
    if (
        digest(root, f"{scheduler_prefix}/campaign.json")
        != "a0c36781ee9776935f673e4d5904ec3dc03ffe6401971227b35b3904438eb7a5"
        or digest(root, f"{scheduler_prefix}/oracle.json")
        != "9ba8f59096de7ecc8864a67a25f27cd5a41cf8f4f182636410f1a2e3ac410a45"
        or scheduler_campaign.get("schema") != "ecpa-h2-source-bound-case/v1"
        or scheduler_campaign.get("classification")
        != "source-bound-pre-launch-oracle-input"
        or scheduler_campaign.get("case_id")
        != "pair-pipeline-microbatch-bidkv-vllm-0281"
        or not isinstance(scheduler_host, dict)
        or scheduler_host.get("repository") != "vLLM-HUST/vllm-hust"
        or scheduler_host.get("commit") != "3e57b2f75cffffd26dda0df4d9bcac890cfe99fc"
        or scheduler_host.get("tree") != "b0e682747b3b7242c1b857841136b784f6c7f6a3"
        or scheduler_campaign.get("planned_evaluation")
        != {
            "host_launch": False,
            "manager_prediction_after_oracle_freeze": True,
            "runtime_execution": False,
        }
        or not isinstance(scheduler_sources, dict)
        or any(
            not isinstance(source, dict)
            or source.get("sha256")
            != f"sha256:{digest(root, source.get('snapshot', ''))}"
            for source in scheduler_sources.values()
        )
        or scheduler_oracle.get("schema") != "ecpa-h2-independent-source-oracle/v3"
        or scheduler_oracle.get("decision") != "admit"
        or scheduler_oracle.get("score_eligible") is not True
        or scheduler_oracle.get("scope") != "source-bound-pre-launch-composition"
        or scheduler_oracle.get("runtime_claim") is not False
        or scheduler_oracle.get("performance_claim") is not False
        or scheduler_freeze.get("schema") != "ecpa-h2-independent-oracle-freeze/v1"
        or scheduler_freeze.get("manager_prediction_present_at_freeze") is not False
        or scheduler_freeze.get("campaign_sha256")
        != f"sha256:{digest(root, f'{scheduler_prefix}/campaign.json')}"
        or scheduler_freeze.get("oracle_sha256")
        != f"sha256:{digest(root, f'{scheduler_prefix}/oracle.json')}"
        or scheduler_prediction.get("schema")
        != "ecpa-h2-scheduler-pair-manager-prediction/v1"
        or scheduler_prediction.get("captured_utc", "")
        <= scheduler_freeze.get("frozen_utc", "")
        or scheduler_prediction.get("oracle_sha256")
        != scheduler_freeze.get("oracle_sha256")
        or scheduler_prediction.get("prediction") != "admit"
        or scheduler_prediction.get("oracle_decision") != "admit"
        or scheduler_prediction.get("matched") is not True
        or scheduler_prediction.get("score_eligible") is not True
        or scheduler_prediction.get("performance_claim") is not False
        or scheduler_prediction.get("projected_options") != expected_scheduler_options
        or not isinstance(scheduler_boundary, dict)
        or scheduler_boundary.get("host_process_started") is not False
        or not isinstance(scheduler_runtime, dict)
        or scheduler_runtime.get("claim") is not False
        or scheduler_runtime.get("host_launch_command_invoked") is not False
        or "PP2+TP2 on four devices; only two devices are allocated"
        not in scheduler_runtime.get("reason", "")
        or scheduler_prediction.get("corpus_update", {}).get("current")
        != expected_scheduler_aggregate
        or scheduler_prediction.get("corpus_update", {}).get("h2_complete") is not False
    ):
        raise ValueError("H2 scheduler-pair evidence is invalid or overclaimed")

    counts["true_positive"] += 1
    scored.append(scheduler_oracle)
    tp, tn = counts["true_positive"], counts["true_negative"]
    fp, fn = counts["false_positive"], counts["false_negative"]
    admit_precision = tp / (tp + fp)
    admit_recall = tp / (tp + fn)
    reject_precision = tn / (tn + fn)
    reject_recall = tn / (tn + fp)

    carrier_cases = carrier_oracle.get("cases")
    carrier_rows = carrier_predictions.get("predictions")
    if (
        carrier_oracle.get("schema") != "ecpa-h2-independent-process-carrier-oracle/v1"
        or carrier_oracle.get("oracle_summary")
        != {
            "admit": 0,
            "reject": 0,
            "abstain": 2,
            "score_eligible": 0,
            "runtime_claim": False,
            "performance_claim": False,
        }
        or carrier_predictions.get("schema")
        != "ecpa-h2-process-carrier-manager-predictions/v1"
        or carrier_predictions.get("h2_complete") is not False
        or carrier_predictions.get("oracle", {}).get("frozen_before_planner")
        is not True
        or carrier_predictions.get("oracle", {}).get("sha256")
        != digest(root, f"{carrier_prefix}/oracle.json")
        or not isinstance(carrier_cases, list)
        or not isinstance(carrier_rows, list)
        or len(carrier_cases) != 2
        or len(carrier_rows) != 2
        or {row.get("case_id") for row in carrier_cases}
        != {row.get("case_id") for row in carrier_rows}
        or any(
            row.get("decision") != "abstain" or row.get("score_eligible") is not False
            for row in carrier_cases
        )
        or any(
            row.get("oracle_decision") != "abstain"
            or row.get("score_eligible") is not False
            or row.get("runtime_claim") is not False
            or row.get("performance_claim") is not False
            for row in carrier_rows
        )
    ):
        raise ValueError("H2 process-carrier abstentions were promoted into the score")

    compatible = next(case for case in scored if case["oracle_decision"] == "admit")
    runtime = compatible.get("formal_runtime", {})
    runtime_source = runtime.get("source")
    if (
        not isinstance(runtime_source, str)
        or runtime.get("source_sha256") != f"sha256:{digest(root, runtime_source)}"
        or runtime.get("compatible_host_execution") is not True
        or runtime.get("accepted_installation_orders") != 2
        or runtime.get("compression_transaction") is not False
        or runtime.get("performance") is not False
    ):
        raise ValueError("H2 compatible pair scope has been broadened")

    return {
        "h2_scored_cases": len(scored),
        "h2_true_positive": tp,
        "h2_true_negative": tn,
        "h2_false_positive": fp,
        "h2_false_negative": fn,
        "h2_admit_precision": f"{admit_precision:.1f}",
        "h2_admit_recall": f"{admit_recall:.1f}",
        "h2_reject_precision": f"{reject_precision:.1f}",
        "h2_reject_recall": f"{reject_recall:.1f}",
        "h2_accepted_orders": runtime["accepted_installation_orders"],
    }


def validate_h2_compression_transaction(root: Path) -> dict[str, int | str]:
    """Recompute the bounded, explicitly non-formal compression qualification."""
    prefix = (
        "experiments/real_mod_composition/artifacts/h2-compression-transaction-20261013"
    )
    verifier_path = (
        root / "experiments/real_mod_composition/verify_h2_compression_transaction.py"
    )
    spec = importlib.util.spec_from_file_location(
        "ecpa_paper_h2_compression_verifier", verifier_path
    )
    if spec is None or spec.loader is None:
        raise ValueError("cannot load H2 compression-transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        recomputed = module.verify(root / prefix)
    finally:
        sys.modules.pop(spec.name, None)
    admission = load_json(root, f"{prefix}/admission.json")
    campaign = load_json(root, f"{prefix}/campaign.json")
    if admission != recomputed:
        raise ValueError("H2 compression admission differs from raw recomputation")
    runs = admission.get("runs")
    boundary = admission.get("qualification_boundary")
    if (
        admission.get("schema") != "ecpa-h2-compression-transaction-admission/v1"
        or admission.get("status") != "QUALIFIED_NONFORMAL"
        or admission.get("score_eligible") is not False
        or admission.get("performance_result") is not False
        or not isinstance(runs, list)
        or len(runs) != 2
        or {row.get("order") for row in runs}
        != {"profiler-then-kvcompress", "kvcompress-then-profiler"}
        or any(
            row.get("semantic_tokens") != 1201
            or row.get("physical_tokens") != 1024
            or row.get("worker_ack_count") != 2
            or row.get("engine_core", {}).get("argv") != ["VLLM::EngineCore"]
            for row in runs
        )
        or not isinstance(boundary, dict)
        or boundary.get("formal_h2_result") is not False
        or boundary.get("preregistered_timestamp_claim") is not False
        or "frozen_utc is later than the observed first launch"
        not in boundary.get("reason", "")
        or campaign.get("frozen_utc") != "2026-10-13T17:48:00Z"
        or campaign.get("formal_runs") != []
    ):
        raise ValueError("H2 compression qualification boundary has drifted")
    return {
        "h2_compression_orders": len(runs),
        "h2_compression_semantic_tokens": 1201,
        "h2_compression_physical_tokens": 1024,
        "h2_compression_worker_acks": 2,
    }


def validate_real_invocation_gate(root: Path) -> dict[str, int | str]:
    """Recompute invocation-only evidence from the sealed raw archive."""
    from experiments.exposure_gate.qualification_verify import (
        unpack_qualification,
        verify_qualification,
    )

    prefix = (
        "experiments/exposure_gate/artifacts/"
        "real-invocation-gate-qualification-20261013"
    )
    package = root / prefix
    with tempfile.TemporaryDirectory() as directory:
        retained = Path(directory)
        unpack_qualification(package, retained)
        recomputed = verify_qualification(retained)
        failed = json.loads((retained / "failed-attempts-index.json").read_bytes())
        if not isinstance(failed, list) or {row.get("attempt") for row in failed} != {
            1,
            2,
            3,
            4,
        }:
            raise ValueError("real gate failed-attempt retention changed")
        for row in failed:
            for name, binding in row["files"].items():
                raw = (
                    retained / "failed-attempts" / str(row["attempt"]) / name
                ).read_bytes()
                if (
                    len(raw) != binding["size"]
                    or hashlib.sha256(raw).hexdigest() != binding["sha256"]
                ):
                    raise ValueError("real gate failed-attempt raw binding changed")
    stated = load_json(package, "qualification.json")
    manifest = load_json(package, "manifest.json")
    if stated != recomputed:
        raise ValueError("real gate qualification differs from raw recomputation")
    if (
        recomputed["classification"] != "QUALIFIED_NONFORMAL"
        or any(
            recomputed[name] is not False
            for name in (
                "formal_result",
                "performance_result",
                "effective_semantics_result",
            )
        )
        or manifest.get("classification") != "QUALIFIED_NONFORMAL"
        or any(
            manifest.get(name) is not False
            for name in (
                "formal_result",
                "performance_result",
                "effective_semantics_result",
            )
        )
        or len(manifest["files"]) != 95
    ):
        raise ValueError("real gate invocation-only qualification boundary drifted")
    return {
        "real_gate_completions": recomputed["real_model_completions"],
        "real_gate_blocked_requests": recomputed["blocked_requests"],
        "real_gate_raw_files": len(manifest["files"]),
        "real_gate_failed_attempts": len(failed),
        "real_gate_complete_coverage": str(
            recomputed["worker_invocation_coverage_complete"]
        ),
        "real_gate_partial_coverage": str(
            recomputed["worker_invocation_coverage_partial"]
        ),
    }


def collect_summary(root: Path = ROOT) -> dict[str, int | str]:
    workshop = load_json(root, "docs/corpus/workshop-mods.json")
    workshop_metadata = load_json(
        root, "docs/corpus/plugin-workshop-metadata.snapshot.json"
    )
    plugins = load_json(root, "docs/corpus/plugins.json")
    snapshots = load_json(root, "docs/corpus/source-snapshots.json")
    cases = load_json(root, "experiments/contract_planner/cases.json")
    taxonomy = load_json(root, "spec/0.1/contract-taxonomy.json")
    oracle = load_json(root, "experiments/contract_planner/oracle.json")
    metrics = load_json(root, "experiments/contract_planner/results/metrics.json")
    decisions = load_jsonl(root, "experiments/contract_planner/results/decisions.jsonl")
    aggregate = load_json(
        root, "experiments/false_effective/artifacts/formal-aggregate-summary.json"
    )
    scenarios = load_json(root, "experiments/false_effective/scenarios.json")
    protocol = load_json(root, "experiments/false_effective/protocol.json")
    registry = load_json(root, "experiments/false_effective/verified-adapters.json")
    reference = load_json(
        root, "experiments/false_effective/artifacts/reference-summary.json"
    )
    claims_matrix = load_json(root, "docs/research/claims-to-experiment-matrix.json")
    first_study = load_json(
        root, "experiments/false_effective/first-formal-real-study.json"
    )
    deployment = load_json(
        root, "experiments/false_effective/first-formal-real-deployment.json"
    )
    transaction_model = load_json(
        root, "experiments/transaction_model/artifacts/result-summary.json"
    )
    release = load_json(root, "docs/release-readiness.json")
    native_qualification = (
        root / "docs/evidence/native-current-npu-qualification-2026-10-11.md"
    ).read_text()
    normalized_native_qualification = " ".join(native_qualification.split())
    h1 = validate_h1_r5(root)
    h2 = validate_h2_real_source_subset(root)
    h2_compression = validate_h2_compression_transaction(root)
    real_gate = validate_real_invocation_gate(root)

    for artifact, schema in (
        (workshop, "docs/corpus/workshop-mods.schema.json"),
        (plugins, "docs/corpus/plugins.schema.json"),
        (snapshots, "docs/corpus/source-snapshots.schema.json"),
        (cases, "experiments/contract_planner/cases.schema.json"),
        (taxonomy, "spec/0.1/contract-taxonomy.schema.json"),
        (oracle, "experiments/contract_planner/oracle.schema.json"),
        (metrics, "experiments/contract_planner/metrics.schema.json"),
        (
            claims_matrix,
            "docs/research/claims-to-experiment-matrix.schema.json",
        ),
        (
            first_study,
            "experiments/false_effective/first-formal-real-study.schema.json",
        ),
        (
            deployment,
            "experiments/false_effective/first-formal-real-deployment.schema.json",
        ),
        (
            transaction_model,
            "experiments/transaction_model/result-summary.schema.json",
        ),
        (release, "docs/release-readiness.schema.json"),
    ):
        validate_schema(root, artifact, schema)
    decision_schema = load_json(
        root, "experiments/contract_planner/decision.schema.json"
    )
    jsonschema.Draft7Validator.check_schema(decision_schema)
    decision_validator = jsonschema.Draft7Validator(decision_schema)
    for decision in decisions:
        decision_validator.validate(decision)

    require_schema(workshop, "ecpa-workshop-mod-corpus/v1", "workshop MOD corpus")
    require_schema(plugins, "ecpa-plugin-corpus/v1", "planner seed corpus")
    require_schema(
        snapshots, "ecpa-corpus-source-snapshots/0.1", "source snapshot corpus"
    )
    require_schema(cases, "ecpa-contract-planner-cases/0.1", "planner cases")
    require_schema(taxonomy, "ecpa-contract-taxonomy/0.1-draft", "taxonomy")
    require_schema(oracle, "ecpa-contract-planner-oracle/0.1", "planner oracle")
    require_schema(metrics, "ecpa-contract-planner-results/0.1", "planner metrics")
    require_schema(aggregate, "ecpa-false-effective-aggregate/v1", "formal aggregate")
    require_schema(scenarios, "ecpa-false-effective-scenarios/v1", "scenarios")
    require_schema(protocol, "ecpa-false-effective-protocol/v1", "protocol")
    require_schema(registry, "ecpa-formal-adapter-registry/v2", "adapter registry")
    require_schema(
        reference, "ecpa-false-effective-selftest-summary/v1", "reference summary"
    )
    require_schema(
        claims_matrix, "ecpa-claims-to-experiments/v1", "research claim graph"
    )
    require_schema(first_study, "ecpa-first-formal-real-study/v1", "first formal study")
    require_schema(
        deployment,
        "ecpa-formal-real-deployment-registration/v1",
        "first formal deployment registration",
    )
    require_schema(
        transaction_model,
        "ecpa-bounded-transaction-model/v1",
        "bounded transaction model",
    )

    release_inventory = release.get("inventory")
    release_gates = release.get("gates")
    if (
        release.get("schema_version") != "1.0"
        or release.get("package_version") != "0.3.0"
        or release.get("manifest_api") != "0.3"
        or release.get("decision") != "go"
        or release.get("publication_authorized") is not True
        or not isinstance(release_inventory, dict)
        or not isinstance(release_gates, list)
        or not release_gates
        or len({gate["id"] for gate in release_gates}) != len(release_gates)
        or any(gate["required"] is not True for gate in release_gates)
        or any(gate["status"] != "passed" for gate in release_gates)
        or any(
            not (root / evidence).is_file()
            for gate in release_gates
            for evidence in gate["evidence"]
        )
        or not (root / "spec/manifest-0.3/manifest.schema.json").is_file()
    ):
        raise ValueError(
            "published ECPA release evidence is not closed and reproducible"
        )
    native_gate = next(
        (gate for gate in release_gates if gate["id"] == "native-current-host-npu"),
        None,
    )
    required_native_statements = (
        "it is not a performance result",
        "two HTTP completion requests",
        "process-owned evidence",
        "port 8100 became bindable",
        "does not assert throughput improvement",
    )
    if (
        native_gate is None
        or "docs/evidence/native-current-npu-qualification-2026-10-11.md"
        not in native_gate["evidence"]
        or any(
            text not in normalized_native_qualification
            for text in required_native_statements
        )
    ):
        raise ValueError("native lifecycle qualification boundary is incomplete")

    workshop_rows = workshop.get("mods")
    plugin_rows = plugins.get("plugins")
    source_rows = snapshots.get("sources")
    case_rows = cases.get("cases")
    excluded_rows = cases.get("excluded_candidates")
    scenario_rows = scenarios.get("scenarios")
    arms = protocol.get("arms")
    adapters = registry.get("adapters")
    claim_rows = claims_matrix.get("claims")
    if not all(
        isinstance(rows, list)
        for rows in (
            workshop_rows,
            plugin_rows,
            source_rows,
            case_rows,
            excluded_rows,
            scenario_rows,
            arms,
            adapters,
            claim_rows,
        )
    ):
        raise ValueError("paper evidence inputs must contain arrays")

    workshop_counts = workshop.get("counts")
    if not isinstance(workshop_counts, dict):
        raise ValueError("workshop MOD corpus is missing derived counts")
    integration_counts: dict[str, int] = {}
    test_counts: dict[str, int] = {}
    build_counts: dict[str, int] = {}
    for row in workshop_rows:
        integration = row["integration_class"]
        local_test = row["local_test"]
        package_build = row["package_build"]
        integration_counts[integration] = integration_counts.get(integration, 0) + 1
        test_counts[local_test] = test_counts.get(local_test, 0) + 1
        build_counts[package_build] = build_counts.get(package_build, 0) + 1
    expected_workshop_counts = {
        "mods": len(workshop_rows),
        "ecpa_bundle_namespace": integration_counts.get("ecpa_bundle_namespace", 0),
        "namespace_mismatch": integration_counts.get("namespace_mismatch", 0),
        "general_plugin_only": integration_counts.get("general_plugin_only", 0),
        "direct_or_non_entry_integration": integration_counts.get(
            "direct_or_non_entry_integration", 0
        ),
        "source_only": integration_counts.get("source_only", 0),
        "package_projects": build_counts.get("pass", 0)
        + build_counts.get("qualified_staging_required", 0),
        "local_package_build_pass": build_counts.get("pass", 0),
        "local_tests_pass": test_counts.get("pass", 0),
        "environment_blocked": test_counts.get("environment_blocked", 0),
        "no_automated_tests": test_counts.get("no_automated_tests", 0),
    }
    population = workshop.get("population")
    workshop_source_rows = [
        {field: row[field] for field in WORKSHOP_SOURCE_FIELDS} for row in workshop_rows
    ]
    metadata_plugins = workshop_metadata.get("plugins")
    if not isinstance(population, dict) or population != WORKSHOP_SOURCE_IDENTITY:
        raise ValueError(
            "workshop page source identity differs from the frozen authority"
        )
    if (
        digest(root, population["metadata_snapshot_path"])
        != population["metadata_sha256"]
        or canonical_digest(workshop_source_rows) != population["source_rows_sha256"]
        or canonical_digest(workshop_rows) != population["audit_rows_sha256"]
        or workshop_metadata.get("schema_version") != "plugin-workshop-metadata/v1"
        or not isinstance(metadata_plugins, dict)
        or list(metadata_plugins) != [row["id"] for row in workshop_rows]
        or any(
            metadata_plugins[row["id"]].get("repository") != row["repository"]
            for row in workshop_rows
        )
    ):
        raise ValueError("workshop rows are not bound to the frozen page snapshot")
    if (
        workshop_counts != expected_workshop_counts
        or len(workshop_rows) != 24
        or workshop.get("population", {}).get("mod_count") != len(workshop_rows)
        or len({row["id"] for row in workshop_rows}) != len(workshop_rows)
        or len({row["repository_id"] for row in workshop_rows}) != len(workshop_rows)
        or any(not row["repository"].startswith("vLLM-HUST/") for row in workshop_rows)
    ):
        raise ValueError("workshop MOD population or derived counts are inconsistent")

    counts = plugins.get("counts")
    if not isinstance(counts, dict) or counts != {
        "registered_extensions": len(plugin_rows),
        "adaptation_candidates": len(plugins["candidates"]),
    }:
        raise ValueError("plugin corpus declared counts differ from its rows")
    candidate_repositories = [row["repository"] for row in plugins["candidates"]]
    if (
        len(candidate_repositories) != len(set(candidate_repositories))
        or candidate_repositories != excluded_rows
    ):
        raise ValueError("planner exclusions do not exactly match corpus candidates")

    corpus_records = [*plugin_rows, *plugins["candidates"]]
    snapshot_repositories = [row["requested_repository"] for row in source_rows]
    expected_repositories = {row["repository"] for row in corpus_records}
    if (
        len(snapshot_repositories) != len(set(snapshot_repositories))
        or set(snapshot_repositories) != expected_repositories
    ):
        raise ValueError("source snapshots do not exactly cover corpus repositories")
    snapshots_by_repository = {row["requested_repository"]: row for row in source_rows}
    expected_paths_by_repository: dict[str, set[str]] = {}
    for row in corpus_records:
        expected_paths_by_repository.setdefault(row["repository"], set()).update(
            corpus_evidence_path(path) for path in row["evidence"]
        )
    for repository, expected_paths in expected_paths_by_repository.items():
        object_paths = [
            item["path"]
            for item in snapshots_by_repository[repository]["evidence_objects"]
        ]
        if (
            len(object_paths) != len(set(object_paths))
            or set(object_paths) != expected_paths
        ):
            raise ValueError(
                "source snapshot objects do not exactly cover corpus evidence paths"
            )

    plugin_ids = [row["id"] for row in plugin_rows]
    evidence_contract_sources = [
        row["source_plugin"]
        for row in cases["contracts"]
        if row["model_kind"] == "evidence-backed-abstraction"
    ]
    if (
        len(plugin_ids) != len(set(plugin_ids))
        or len(evidence_contract_sources) != len(set(evidence_contract_sources))
        or set(evidence_contract_sources) != set(plugin_ids)
        or any(
            row["source_plugin"] is not None
            for row in cases["contracts"]
            if row["model_kind"] == "synthetic-control"
        )
    ):
        raise ValueError("planner source contracts do not exactly cover corpus plugins")

    input_digests = {
        "cases_sha256": digest(root, "experiments/contract_planner/cases.json"),
        "taxonomy_sha256": digest(root, "spec/0.1/contract-taxonomy.json"),
        "source_corpus_sha256": digest(root, "docs/corpus/plugins.json"),
        "source_snapshots_sha256": digest(root, "docs/corpus/source-snapshots.json"),
    }
    oracle_digest = digest(root, "experiments/contract_planner/oracle.json")
    if (
        oracle.get("status") != "independently-reviewed"
        or oracle.get("review", {}).get("verdict") != "MERGE"
        or any(oracle.get(field) != value for field, value in input_digests.items())
        or any(
            oracle.get("review", {}).get(field) != value
            for field, value in input_digests.items()
        )
    ):
        raise ValueError("planner oracle does not bind every current input")
    expected_metric_inputs = {**input_digests, "oracle_sha256": oracle_digest}
    expected_implementation = {
        "evaluator_sha256": digest(root, "experiments/contract_planner/evaluate.py"),
        "contract_compiler_sha256": digest(
            root, "src/vllm_hust_ext/contract_compiler.py"
        ),
    }
    if (
        metrics.get("inputs") != expected_metric_inputs
        or metrics.get("oracle", {}).get("sha256") != oracle_digest
        or metrics.get("implementation") != expected_implementation
        or metrics.get("decisions_sha256")
        != digest(root, "experiments/contract_planner/results/decisions.jsonl")
    ):
        raise ValueError("planner metrics do not bind current inputs and outputs")

    overall = metrics.get("overall")
    if not isinstance(overall, dict):
        raise ValueError("planner metrics are missing overall counts")
    planner_cases = require_count(metrics.get("case_count"), "planner case count")
    planner_admits = require_count(overall.get("true_admit"), "true admits")
    planner_rejects = require_count(overall.get("true_reject"), "true rejects")
    if (
        metrics.get("classification") != "modeled-static-contract-corpus"
        or len(case_rows) != planner_cases
        or len(decisions) != planner_cases
        or planner_admits + planner_rejects != planner_cases
        or overall.get("false_admit") != 0
        or overall.get("false_reject") != 0
        or metrics.get("all_decisions_match") is not True
        or metrics.get("all_errors_match") is not True
    ):
        raise ValueError("modeled planner evidence is internally inconsistent")

    source_objects = 0
    for row in source_rows:
        if not isinstance(row, dict) or not isinstance(
            row.get("evidence_objects"), list
        ):
            raise ValueError("source snapshot evidence objects are malformed")
        source_objects += len(row["evidence_objects"])

    completed = require_count(aggregate.get("completed_cells"), "completed cells")
    planned = require_count(aggregate.get("planned_records"), "planned records")
    expected_planned = len(scenario_rows) * len(arms)
    if planned != expected_planned:
        raise ValueError("formal planned records differ from scenarios times arms")
    if completed > planned:
        raise ValueError("formal completed cells exceed the preregistered plan")
    if completed and not adapters:
        raise ValueError("formal completed cells require a verified adapter")
    if completed:
        raise ValueError(
            "formal completed cells require record-level validation before rendering"
        )
    if (
        aggregate.get("metrics") is not None
        or aggregate.get("paired_contrasts") is not None
    ):
        raise ValueError("an empty formal aggregate must not contain metrics")

    minimum_starts = require_count(protocol.get("minimum_starts"), "minimum starts")
    schedule = protocol.get("schedule")
    if (
        len(arms) != len(set(arms))
        or not isinstance(schedule, list)
        or len(schedule) != minimum_starts
        or any(
            not isinstance(row, list) or sorted(row) != sorted(arms) for row in schedule
        )
        or any(
            len({schedule[row][column] for row in range(len(schedule))}) != len(arms)
            for column in range(len(arms))
        )
    ):
        raise ValueError("formal protocol is not a square balanced arm schedule")
    first_study_starts = require_count(
        first_study.get("planned_starts"), "first study starts"
    )
    study_status = first_study.get("status")
    if (
        study_status not in {"pre-admission", "admitted", "running", "complete"}
        or (study_status == "pre-admission") != (first_study.get("admissible") is False)
        or first_study.get("scenario") != "partial-worker-coverage"
        or first_study.get("arms") != arms
        or first_study.get("repetitions") != minimum_starts
        or first_study.get("schedule") != schedule
        or first_study_starts != len(arms) * minimum_starts
    ):
        raise ValueError("first formal study differs from the frozen protocol")
    deployment_arms = deployment.get("arm_registrations")
    deployment_sources = deployment.get("source_registrations")
    deployment_blockers = deployment.get("blockers")
    common_deployment_invalid = (
        deployment.get("study_id") != first_study.get("study_id")
        or deployment.get("producer_candidate") != first_study.get("producer_candidate")
        or not isinstance(deployment_arms, list)
        or [row.get("arm") for row in deployment_arms] != arms
        or not isinstance(deployment_sources, list)
        or len(deployment_sources) != 5
        or not isinstance(deployment_blockers, list)
        or len(deployment_blockers) != len(set(deployment_blockers))
    )
    unregistered_invalid = deployment.get("registration_state") == "unregistered" and (
        deployment.get("admissible") is not False
        or deployment.get("producer_admission_receipt") is not None
        or any(
            value is not None
            for value in deployment.get("deployment_identity", {}).values()
        )
        or any(row.get("registration") is not None for row in deployment_arms)
        or any(row.get("registration") is not None for row in deployment_sources)
        or any(deployment.get("reviews", {}).values())
        or set(deployment_blockers) != set(first_study.get("blockers", []))
        or study_status != "pre-admission"
    )
    registered_invalid = deployment.get("registration_state") == "registered" and (
        deployment.get("admissible") is not True
        or not isinstance(deployment.get("producer_admission_receipt"), dict)
        or any(
            value is None
            for key, value in deployment.get("deployment_identity", {}).items()
            if key not in REGISTERED_NULLABLE_IDENTITIES
        )
        or any(row.get("registration") is None for row in deployment_arms)
        or any(row.get("registration") is None for row in deployment_sources)
        or not all(deployment.get("reviews", {}).values())
        or deployment_blockers
        or study_status == "pre-admission"
    )
    if common_deployment_invalid or unregistered_invalid or registered_invalid:
        raise ValueError("first formal deployment registration is not fail closed")
    transaction_states = require_count(
        transaction_model.get("reachable_states"), "transaction-model states"
    )
    transaction_edges = require_count(
        transaction_model.get("valid_edges"), "transaction-model edges"
    )
    transaction_rejections = require_count(
        transaction_model.get("rejected_state_action_pairs"),
        "transaction-model rejected pairs",
    )
    if (
        transaction_model != recompute_transaction_model(root)
        or transaction_model.get("classification") != "exhaustive-finite-abstract-model"
        or transaction_model.get("implementation_sha256")
        != digest(root, "experiments/transaction_model/explore.py")
        or transaction_model.get("formal_real_result") is not False
        or transaction_model.get("fixed_point_reached") is not True
        or transaction_model.get("counterexamples") != []
        or transaction_states == 0
        or transaction_edges == 0
        or transaction_rejections == 0
    ):
        raise ValueError("bounded transaction model is not valid modeled evidence")
    reference_starts = require_count(reference.get("starts"), "reference starts")
    reference_scenarios = reference.get("scenarios")
    if (
        reference.get("evidence_class") != "reference-synthetic"
        or reference.get("seed") != protocol.get("seed")
        or reference.get("arms") != arms
        or not isinstance(reference_scenarios, list)
        or len(reference_scenarios) != len(set(reference_scenarios))
        or not set(reference_scenarios)
        <= {scenario.get("id") for scenario in scenario_rows}
        or reference.get("starts_per_arm_per_scenario") != minimum_starts
        or reference_starts != len(reference_scenarios) * len(arms) * minimum_starts
        or reference.get("formal_completed_cells") != completed
        or reference.get("timing_summary") is not None
    ):
        raise ValueError("reference summary is inconsistent with protocol and status")

    reject_precision = overall.get("reject_precision")
    reject_recall = overall.get("reject_recall")
    admit_recall = overall.get("admit_recall")
    formatted_metrics: dict[str, str] = {}
    for label, metric in (
        ("reject precision", reject_precision),
        ("reject recall", reject_recall),
        ("admit recall", admit_recall),
    ):
        if not isinstance(metric, dict) or metric.get("value") != 1:
            raise ValueError(f"{label} differs from the reviewed modeled result")
        formatted_metrics[label] = f"{float(metric['value']):.1f}"

    return {
        "workshop_mods": len(workshop_rows),
        "workshop_bundle_namespace": workshop_counts["ecpa_bundle_namespace"],
        "workshop_test_pass": workshop_counts["local_tests_pass"],
        "workshop_environment_blocked": workshop_counts["environment_blocked"],
        "planner_seed_extensions": len(plugin_rows),
        "adaptation_candidates": len(excluded_rows),
        "planner_cases": planner_cases,
        "planner_admits": planner_admits,
        "planner_rejects": planner_rejects,
        "planner_reject_precision": formatted_metrics["reject precision"],
        "planner_reject_recall": formatted_metrics["reject recall"],
        "planner_admit_recall": formatted_metrics["admit recall"],
        "source_repositories": len(source_rows),
        "source_objects": source_objects,
        "formal_completed": h1["formal_completed"],
        "formal_starts": h1["formal_starts"],
        "formal_lifecycle_sources": h1["formal_lifecycle_sources"],
        "h1_false_effective_numerator": h1["h1_false_effective_numerator"],
        "h1_false_effective_denominator": h1["h1_false_effective_denominator"],
        "h1_coverage": h1["h1_coverage"],
        **h2,
        **h2_compression,
        **real_gate,
        "formal_planned": planned,
        "verified_adapters": len(adapters),
        "reference_starts": reference_starts,
        "formal_arms": len(arms),
        "minimum_starts": minimum_starts,
        "schedule_rows": len(schedule),
        "research_claims": len(claim_rows),
        "first_study_starts": first_study_starts,
        "deployment_blockers": len(deployment_blockers),
        "registered_deployment_arms": sum(
            row["registration"] is not None for row in deployment_arms
        ),
        "transaction_model_states": transaction_states,
        "transaction_model_edges": transaction_edges,
        "transaction_model_rejections": transaction_rejections,
        "transaction_model_invariants": len(transaction_model["invariants"]),
        "release_version": release["package_version"],
        "manifest_version": release["manifest_api"],
        "release_distributions": require_count(
            release_inventory.get("distributions"), "release distributions"
        ),
        "release_registrations": require_count(
            release_inventory.get("registrations"), "release registrations"
        ),
        "release_activation_intent": require_count(
            release_inventory.get("activation_intent"), "activation-intent bundles"
        ),
        "release_inspect_only": require_count(
            release_inventory.get("inspect_only"), "inspect-only bundles"
        ),
        "release_gates": len(release_gates),
        "native_lifecycle_qualifications": 1,
    }


def render(summary: dict[str, int | str]) -> str:
    macros = (
        ("ECPAWorkshopMods", "workshop_mods"),
        ("ECPAWorkshopBundleNamespace", "workshop_bundle_namespace"),
        ("ECPAWorkshopTestPass", "workshop_test_pass"),
        ("ECPAWorkshopEnvironmentBlocked", "workshop_environment_blocked"),
        ("ECPAPlannerSeedExtensions", "planner_seed_extensions"),
        ("ECPAAdaptationCandidates", "adaptation_candidates"),
        ("ECPAPlannerCases", "planner_cases"),
        ("ECPAPlannerAdmits", "planner_admits"),
        ("ECPAPlannerRejects", "planner_rejects"),
        ("ECPAPlannerRejectPrecision", "planner_reject_precision"),
        ("ECPAPlannerRejectRecall", "planner_reject_recall"),
        ("ECPAPlannerAdmitRecall", "planner_admit_recall"),
        ("ECPASourceRepositories", "source_repositories"),
        ("ECPASourceObjects", "source_objects"),
        ("ECPAFormalCompleted", "formal_completed"),
        ("ECPAFormalStarts", "formal_starts"),
        ("ECPAFormalLifecycleSources", "formal_lifecycle_sources"),
        ("ECPAHOneFalseEffectiveNumerator", "h1_false_effective_numerator"),
        ("ECPAHOneFalseEffectiveDenominator", "h1_false_effective_denominator"),
        ("ECPAHOneCoverage", "h1_coverage"),
        ("ECPAHTwoScoredCases", "h2_scored_cases"),
        ("ECPAHTwoTruePositive", "h2_true_positive"),
        ("ECPAHTwoTrueNegative", "h2_true_negative"),
        ("ECPAHTwoFalsePositive", "h2_false_positive"),
        ("ECPAHTwoFalseNegative", "h2_false_negative"),
        ("ECPAHTwoAdmitPrecision", "h2_admit_precision"),
        ("ECPAHTwoAdmitRecall", "h2_admit_recall"),
        ("ECPAHTwoRejectPrecision", "h2_reject_precision"),
        ("ECPAHTwoRejectRecall", "h2_reject_recall"),
        ("ECPAHTwoAcceptedOrders", "h2_accepted_orders"),
        ("ECPAHTwoCompressionOrders", "h2_compression_orders"),
        ("ECPAHTwoCompressionSemanticTokens", "h2_compression_semantic_tokens"),
        ("ECPAHTwoCompressionPhysicalTokens", "h2_compression_physical_tokens"),
        ("ECPAHTwoCompressionWorkerAcks", "h2_compression_worker_acks"),
        ("ECPARealGateCompletions", "real_gate_completions"),
        ("ECPARealGateBlockedRequests", "real_gate_blocked_requests"),
        ("ECPARealGateRawFiles", "real_gate_raw_files"),
        ("ECPARealGateFailedAttempts", "real_gate_failed_attempts"),
        ("ECPARealGateCompleteCoverage", "real_gate_complete_coverage"),
        ("ECPARealGatePartialCoverage", "real_gate_partial_coverage"),
        ("ECPAFormalPlanned", "formal_planned"),
        ("ECPAVerifiedAdapters", "verified_adapters"),
        ("ECPAReferenceStarts", "reference_starts"),
        ("ECPAFormalArms", "formal_arms"),
        ("ECPAMinimumStarts", "minimum_starts"),
        ("ECPAScheduleRows", "schedule_rows"),
        ("ECPAResearchClaims", "research_claims"),
        ("ECPAFirstStudyStarts", "first_study_starts"),
        ("ECPADeploymentBlockers", "deployment_blockers"),
        ("ECPARegisteredDeploymentArms", "registered_deployment_arms"),
        ("ECPATransactionModelStates", "transaction_model_states"),
        ("ECPATransactionModelEdges", "transaction_model_edges"),
        ("ECPATransactionModelRejections", "transaction_model_rejections"),
        ("ECPATransactionModelInvariants", "transaction_model_invariants"),
        ("ECPAReleaseVersion", "release_version"),
        ("ECPAManifestVersion", "manifest_version"),
        ("ECPAReleaseDistributions", "release_distributions"),
        ("ECPAReleaseRegistrations", "release_registrations"),
        ("ECPAReleaseActivationIntent", "release_activation_intent"),
        ("ECPAReleaseInspectOnly", "release_inspect_only"),
        ("ECPAReleaseGates", "release_gates"),
        ("ECPANativeLifecycleQualifications", "native_lifecycle_qualifications"),
    )
    lines = [
        "% Generated by paper/scripts/generate_evidence_summary.py; do not edit.",
        "% Values are modeled/static or status evidence unless the paper says",
        "% otherwise.",
    ]
    lines.extend(
        f"\\newcommand{{\\{macro}}}{{{summary[key]}}}" for macro, key in macros
    )
    return "\n".join(lines) + "\n"


def write_atomic(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".evidence-", dir=output.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the checked-in summary equals the artifact-derived output",
    )
    args = parser.parse_args()
    content = render(collect_summary())
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text() != content:
            raise SystemExit("paper evidence summary is stale; regenerate it")
        return 0
    write_atomic(OUTPUT, content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
