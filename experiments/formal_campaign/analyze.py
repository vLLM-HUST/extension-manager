#!/usr/bin/env python3
"""Fail-closed intake and paired analysis for formal H3/H4 campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parent


def h3_response_correctness(
    response: Any, payload: dict[str, Any], expected: dict[str, Any]
) -> bool:
    """Check the frozen task oracle, not HTTP body presence or a runner boolean."""
    if not isinstance(response, dict) or response.get("model") != payload["model"]:
        return False
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        return False
    choice = choices[0]
    return (
        isinstance(choice, dict)
        and choice.get("index") == 0
        and choice.get("finish_reason") == "stop"
        and choice.get("text") == expected["text_equals"]
    )


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def load_protocol(root: Path = ROOT) -> dict[str, Any]:
    protocol = _load_object(root / "protocol.json")
    schema = _load_object(root / "protocol.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(protocol)
    arms = protocol["arms"]
    schedule = protocol["schedule"]
    if any(sorted(row) != sorted(arms) for row in schedule):
        raise ValueError("protocol schedule rows must contain every arm exactly once")
    if any(
        len({schedule[row][column] for row in range(3)}) != 3 for column in range(3)
    ):
        raise ValueError("protocol schedule must be a balanced Latin square")
    if protocol["h4"]["manual_baseline"] != "manual-integration":
        raise ValueError("H4 must retain manual integration as its primary baseline")
    return protocol


def load_h3_campaign(path: Path) -> dict[str, Any]:
    campaign = _load_object(path)
    schema = _load_object(ROOT / "h3-campaign.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(campaign)
    if campaign.get("schema") != "ecpa-h3-exact-stack-cell-campaign/v1":
        raise ValueError("H3 campaign uses an unsupported schema")
    required = {
        "campaign_id",
        "cell_id",
        "arms",
        "fixed_identity",
        "fault",
        "objective",
    }
    missing = sorted(required - campaign.keys())
    if missing:
        raise ValueError(f"H3 campaign lacks {', '.join(missing)}")
    arms = campaign["arms"]
    if not isinstance(arms, list) or {row.get("id") for row in arms} != {
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    }:
        raise ValueError("H3 campaign must freeze all three arms")
    campaign["_sha256"] = _digest_bytes(path)
    campaign["_path"] = str(path.resolve())
    return campaign


def load_h4_campaign(path: Path) -> dict[str, Any]:
    campaign = _load_object(path)
    schema = _load_object(ROOT / "h4-campaign.schema.json")
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(campaign),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError(f"H4 campaign: {errors[0].message}")
    required = {
        "campaign_id",
        "cell_id",
        "arms",
        "schedule",
        "fixed_identity",
        "workload",
    }
    missing = sorted(required - campaign.keys())
    if missing:
        raise ValueError(f"H4 campaign lacks {', '.join(missing)}")
    campaign["_sha256"] = _digest_bytes(path)
    campaign["_path"] = str(path.resolve())
    campaign["arms_by_id"] = {item["id"]: item for item in campaign["arms"]}
    if len(campaign["arms_by_id"]) != 3:
        raise ValueError("H4 campaign contains duplicate arms")
    schedule = [row["order"] for row in campaign["schedule"]]
    arms = set(campaign["arms_by_id"])
    if any(set(row) != arms or len(row) != len(arms) for row in schedule):
        raise ValueError("H4 campaign schedule does not cover every arm")
    if any(len({row[column] for row in schedule}) != 3 for column in range(3)):
        raise ValueError("H4 campaign schedule is not a balanced Latin square")
    workload_path = (path.parent / campaign["workload"]["path"]).resolve()
    if _digest_bytes(workload_path) != campaign["workload"]["sha256"]:
        raise ValueError("H4 workload digest differs from frozen campaign")
    campaign["workload"] = _load_object(workload_path) | {
        "sha256": campaign["workload"]["sha256"]
    }
    return campaign


def load_records(path: Path, root: Path = ROOT) -> list[dict[str, Any]]:
    schema = _load_object(root / "record.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    validator = jsonschema.Draft7Validator(schema)
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number} must contain one JSON object")
        errors = sorted(
            validator.iter_errors(value), key=lambda error: list(error.path)
        )
        if errors:
            raise ValueError(f"{path}:{line_number}: {errors[0].message}")
        records.append(value)
    return records


def _verify_artifacts(record: dict[str, Any], artifact_root: Path) -> None:
    root = artifact_root.resolve()
    resolved: dict[str, Path] = {}
    for label, binding in record["artifacts"].items():
        path = (root / binding["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(
                f"{record['start_id']} {label} is outside artifact root or missing"
            )
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != binding["sha256"]:
            raise ValueError(f"{record['start_id']} {label} digest differs")
        resolved[label] = path

    receipt_binding = record["artifacts"]["deployment_receipt"]
    if receipt_binding["sha256"] != record["deployment"]["receipt_sha256"]:
        raise ValueError(
            f"{record['start_id']} deployment receipt digest differs from record"
        )
    try:
        receipt = _load_object(resolved["deployment_receipt"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            f"{record['start_id']} deployment receipt is not valid JSON"
        ) from exc
    documents = receipt.get("documents")
    if documents is None:
        deployment = receipt
    elif isinstance(documents, dict):
        deployment = documents.get("deployment")
    else:
        deployment = None
    if (
        not isinstance(deployment, dict)
        or deployment.get("registration_state") != "registered"
        or deployment.get("admissible") is not True
        or (
            receipt.get("schema") == "ecpa-h1-atomic-formal-registration/v1"
            and receipt.get("ready") is not True
        )
    ):
        raise ValueError(
            f"{record['start_id']} deployment receipt is not an admissible registration"
        )


def _digest_bytes(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _load_h4_raw_schema(root: Path = ROOT) -> dict[str, Any]:
    schema = _load_object(root / "h4-raw-artifact.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    return schema


def _verify_h4_receipt(
    record: dict[str, Any], receipt_path: Path, campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    receipt = _load_object(receipt_path)
    schema = _load_object(ROOT / "h4-deployment-receipt.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(receipt),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError(
            f"{record['start_id']} deployment receipt: {errors[0].message}"
        )
    expected = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "manager_commit": record["identity"]["manager_commit"],
        "host_commit": record["identity"]["host_commit"],
        "accelerator_commit": record["identity"]["accelerator_commit"],
        "plugin_commits": record["identity"]["plugin_commits"],
        "model_digest": record["identity"]["model_digest"],
        "workload_digest": record["identity"]["workload_digest"],
        "hardware": record["identity"]["hardware"],
        "topology": record["identity"]["topology"],
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise ValueError(f"{record['start_id']} receipt {name} is not bound")
    if receipt["campaign_sha256"] != campaign_spec["_sha256"]:
        raise ValueError(f"{record['start_id']} receipt campaign digest differs")
    admission = receipt["host_source_admission"]
    if _canonical_digest(admission) != receipt["host_source_admission_sha256"]:
        raise ValueError(f"{record['start_id']} Host admission digest differs")
    if admission["candidate_commit"] != receipt["host_commit"]:
        raise ValueError(f"{record['start_id']} Host admission commit differs")
    if receipt["arm_command_digests"].keys() != set(campaign_spec["arms_by_id"]):
        raise ValueError(f"{record['start_id']} receipt does not cover all arms")
    return receipt


def _schema_errors(value: Any, schema_name: str) -> list[jsonschema.ValidationError]:
    schema = _load_object(ROOT / schema_name)
    jsonschema.Draft7Validator.check_schema(schema)
    return sorted(
        jsonschema.Draft7Validator(schema).iter_errors(value),
        key=lambda error: list(error.path),
    )


def _verify_h3_receipt(
    record: dict[str, Any], receipt_path: Path, campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    receipt = _load_object(receipt_path)
    errors = _schema_errors(receipt, "h3-deployment-receipt.schema.json")
    if errors:
        raise ValueError(
            f"{record['start_id']} H3 deployment receipt: {errors[0].message}"
        )
    expected = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "manager_commit": record["identity"]["manager_commit"],
        "host_commit": record["identity"]["host_commit"],
        "accelerator_commit": record["identity"]["accelerator_commit"],
        "plugin_commits": record["identity"]["plugin_commits"],
        "model_digest": record["identity"]["model_digest"],
        "workload_digest": record["identity"]["workload_digest"],
        "hardware": record["identity"]["hardware"],
        "topology": record["identity"]["topology"],
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise ValueError(f"{record['start_id']} receipt {name} is not bound")
    if receipt["campaign_sha256"] != campaign_spec["_sha256"]:
        raise ValueError(f"{record['start_id']} receipt campaign digest differs")
    host_admission = receipt["host_source_admission"]
    if _canonical_digest(host_admission) != receipt["host_source_admission_sha256"]:
        raise ValueError(f"{record['start_id']} Host admission digest differs")
    if host_admission["candidate_commit"] != receipt["host_commit"]:
        raise ValueError(f"{record['start_id']} Host admission commit differs")
    arm_commands = {
        row["id"]: _canonical_digest({"argv": row["launch_command"]})
        for row in campaign_spec["arms"]
    }
    if receipt["arm_command_digests"] != arm_commands:
        raise ValueError(f"{record['start_id']} receipt arm commands differ")
    if receipt["fault_command_digest"] != _canonical_digest(campaign_spec["fault"]):
        raise ValueError(f"{record['start_id']} receipt fault command differs")
    if receipt["state_command_digest"] != _canonical_digest(
        {"argv": campaign_spec["probe"]["state_command"]}
    ) or receipt["cleanup_command_digest"] != _canonical_digest(
        {"argv": campaign_spec["probe"]["cleanup_command"]}
    ):
        raise ValueError(f"{record['start_id']} receipt authority commands differ")
    return receipt


def _recompute_h3_metrics(
    record: dict[str, Any], raw: dict[str, Any], campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    start_id = record["start_id"]
    bindings = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "start_id": start_id,
        "arm": record["arm"],
        "repetition": record["repetition"],
        "arm_order": record["arm_order"],
        "deployment_receipt_sha256": record["deployment"]["receipt_sha256"],
    }
    for name, expected in bindings.items():
        if raw.get(name) != expected:
            raise ValueError(f"{start_id} raw H3 artifact {name} is not bound")
    if raw["campaign_sha256"] != campaign_spec["_sha256"]:
        raise ValueError(f"{start_id} raw H3 campaign digest differs")
    if raw["process_identity"] != record["process_identity"]:
        raise ValueError(f"{start_id} raw H3 process identity differs")
    for label, digest in raw["artifact_sha256"].items():
        if record["artifacts"][label]["sha256"] != digest:
            raise ValueError(f"{start_id} raw H3 manifest differs for {label}")

    events = raw["events"]
    sequences = [event["sequence"] for event in events]
    if sequences != list(range(1, len(events) + 1)):
        raise ValueError(f"{start_id} H3 event sequence is not contiguous")
    timestamps = [event["monotonic_ns"] for event in events]
    if timestamps != sorted(timestamps):
        raise ValueError(f"{start_id} H3 event time moves backwards")
    kinds: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)

    faults = kinds.get("fault-triggered", [])
    if len(faults) != 1:
        raise ValueError(f"{start_id} requires exactly one fault trigger")
    fault = faults[0]
    if fault["detail"].get("fault_id") != campaign_spec["fault"]["id"]:
        raise ValueError(f"{start_id} fault trigger differs from campaign")
    target = raw["fault_target"]
    if target["role"] != campaign_spec["fault"]["target_role"]:
        raise ValueError(f"{start_id} fault target role differs from campaign")
    for key in ("pid", "start_ticks", "boot_id"):
        if fault["detail"].get(key) != target[key]:
            raise ValueError(f"{start_id} fault target {key} is not bound")
    observed = kinds.get("fault-observed", [])
    if len(observed) != 1 or any(
        observed[0]["detail"].get(key) != target[key]
        for key in ("pid", "start_ticks", "boot_id")
    ):
        raise ValueError(f"{start_id} fault observation is not target-bound")
    if observed[0]["monotonic_ns"] < fault["monotonic_ns"]:
        raise ValueError(f"{start_id} fault was observed before it was triggered")

    recovery = kinds.get("recovery-complete", [])
    if len(recovery) != 1 or recovery[0]["monotonic_ns"] < observed[0]["monotonic_ns"]:
        raise ValueError(f"{start_id} lacks one ordered recovery completion")
    recovery_ms = (recovery[0]["monotonic_ns"] - fault["monotonic_ns"]) / 1_000_000
    final = recovery[0]["detail"]
    objective = campaign_spec["objective"]
    request_events = kinds.get("request-result", [])
    if len(request_events) != campaign_spec["probe"]["request_count"]:
        raise ValueError(f"{start_id} request count differs from frozen probe")
    payload = campaign_spec["probe"]["request_payload"]
    payload_sha = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
    )
    for event in request_events:
        detail = event["detail"]
        if (
            detail.get("request_method") != "POST"
            or detail.get("request_payload_sha256") != payload_sha
        ):
            raise ValueError(f"{start_id} request is not bound to frozen POST payload")
        response_raw = detail.get("response_body", "")
        if not isinstance(response_raw, str):
            raise ValueError(f"{start_id} response body must be retained")
        if (
            detail.get("response_sha256")
            != "sha256:" + hashlib.sha256(response_raw.encode()).hexdigest()
        ):
            raise ValueError(f"{start_id} response digest mismatch")
        try:
            response = json.loads(response_raw)
        except (ValueError, TypeError):
            response = None
        correct = detail.get("status_code") == 200 and h3_response_correctness(
            response, payload, campaign_spec["probe"]["response_expectation"]
        )
        if detail.get("functional_correctness") is not correct:
            raise ValueError(
                f"{start_id} response correctness is not derived from frozen oracle"
            )
    ids = [event["detail"]["request_id"] for event in request_events]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{start_id} has duplicate request observations")
    lost = sum(event["detail"]["outcome"] == "lost" for event in request_events)
    duplicated = sum(
        event["detail"]["outcome"] == "duplicated" for event in request_events
    )
    unsupported_served = any(
        event["detail"]["outcome"] == "served"
        and event["detail"]["tuple_supported"] is False
        for event in request_events
    )
    predecessor_preserved = final.get("predecessor_digest") == raw["pre_fault"][
        "predecessor_digest"
    ] and not kinds.get("predecessor-destroyed")
    functional_correctness = bool(final.get("functional_correctness")) and all(
        event["detail"]["functional_correctness"]
        for event in request_events
        if event["detail"]["outcome"] == "served"
    )
    identity_preserved = (
        final.get("evidence_identity_sha256")
        == raw["pre_fault"]["evidence_identity_sha256"]
    )
    operator_actions = len(kinds.get("operator-action", []))
    rollback = final.get("rollback_classification")
    objective_met = (
        recovery_ms <= objective["max_recovery_ms"]
        and lost <= objective["max_lost_requests"]
        and duplicated <= objective["max_duplicated_requests"]
        and operator_actions <= objective["max_operator_actions"]
        and final.get("final_route") == objective["expected_final_route"]
        and rollback in objective["allowed_rollback_classifications"]
        and not unsupported_served
        and predecessor_preserved
        and functional_correctness
        and identity_preserved
    )
    return {
        "injected_failure": True,
        "objective_met": objective_met,
        "unsupported_tuple_served": unsupported_served,
        "predecessor_preserved": predecessor_preserved,
        "functional_correctness": functional_correctness,
        "evidence_identity_preserved": identity_preserved,
        "recovery_ms": recovery_ms,
        "lost_requests": lost,
        "duplicated_requests": duplicated,
        "operator_actions": operator_actions,
        "final_route": final["final_route"],
        "rollback_classification": rollback,
    }


def _verify_h3_raw_artifact(
    record: dict[str, Any], artifact_root: Path, campaign_spec: dict[str, Any]
) -> None:
    root = artifact_root.resolve()
    binding = record["artifacts"].get("raw_recovery")
    if not isinstance(binding, dict):
        raise ValueError(f"{record['start_id']} lacks raw H3 recovery evidence")
    path = (root / binding["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{record['start_id']} raw H3 recovery evidence is missing")
    if _digest_bytes(path) != binding["sha256"]:
        raise ValueError(f"{record['start_id']} raw H3 recovery digest differs")
    raw = _load_object(path)
    errors = _schema_errors(raw, "h3-raw-artifact.schema.json")
    if errors:
        raise ValueError(f"{record['start_id']} raw H3 evidence: {errors[0].message}")
    receipt_path = (root / record["artifacts"]["deployment_receipt"]["path"]).resolve()
    receipt = _verify_h3_receipt(record, receipt_path, campaign_spec)
    authority_binding = record["artifacts"].get("authority_registration")
    if not isinstance(authority_binding, dict):
        raise ValueError(f"{record['start_id']} lacks authority registration")
    authority_path = (root / authority_binding["path"]).resolve()
    if not authority_path.is_relative_to(root) or not authority_path.is_file():
        raise ValueError(f"{record['start_id']} authority registration is missing")
    if _digest_bytes(authority_path) != authority_binding["sha256"]:
        raise ValueError(f"{record['start_id']} authority registration digest differs")
    if authority_binding["sha256"] != receipt["authority_registration_sha256"]:
        raise ValueError(
            f"{record['start_id']} authority registration is not receipt-bound"
        )
    authority = _load_object(authority_path)
    authority_errors = _schema_errors(
        authority, "h3-authority-registration.schema.json"
    )
    if authority_errors:
        message = authority_errors[0].message
        raise ValueError(f"{record['start_id']} authority registration: {message}")
    review_subject = {key: value for key, value in authority.items() if key != "review"}
    if authority["review"]["subject_sha256"] != _canonical_digest(review_subject):
        raise ValueError(f"{record['start_id']} authority review subject differs")
    starts = {row["start_id"]: row for row in authority["starts"]}
    authority_start = starts.get(record["start_id"])
    if authority_start is None:
        raise ValueError(f"{record['start_id']} is absent from authority registration")
    proxy_sha = authority_start["proxy_registration_sha256"]
    if proxy_sha != _canonical_digest(authority_start["proxy_registration"]):
        raise ValueError(f"{record['start_id']} proxy registration digest differs")
    if (
        receipt["authority"]["start_proxy_registration_digests"].get(record["start_id"])
        != proxy_sha
    ):
        raise ValueError(
            f"{record['start_id']} proxy registration is not receipt-bound"
        )
    if (
        raw["authority_registration_sha256"] != authority_binding["sha256"]
        or raw["proxy_registration_sha256"] != proxy_sha
    ):
        raise ValueError(f"{record['start_id']} raw H3 authority identity differs")
    request_document = _load_object(
        (root / record["artifacts"]["request_results"]["path"]).resolve()
    )
    process_document = _load_object(
        (root / record["artifacts"]["process_snapshot"]["path"]).resolve()
    )
    cleanup_document = _load_object(
        (root / record["artifacts"]["cleanup_report"]["path"]).resolve()
    )
    if request_document != raw["request_results"]:
        raise ValueError(f"{record['start_id']} request results differ from raw H3")
    if process_document != raw["process_snapshot"]:
        raise ValueError(f"{record['start_id']} process snapshot differs from raw H3")
    if cleanup_document.get("cleanup") != record["cleanup"]:
        raise ValueError(f"{record['start_id']} cleanup report differs from record")
    recomputed = _recompute_h3_metrics(record, raw, campaign_spec)
    if _canonical_digest(recomputed) != _canonical_digest(record["metrics"]):
        raise ValueError(f"{record['start_id']} H3 metrics differ from raw evidence")


def _duration_ms(interval: dict[str, int]) -> float:
    if interval["end_ns"] < interval["start_ns"]:
        raise ValueError("monotonic interval ends before it starts")
    return (interval["end_ns"] - interval["start_ns"]) / 1_000_000


def _recompute_h4_metrics(
    record: dict[str, Any], raw: dict[str, Any], campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    start_id = record["start_id"]
    bindings = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "start_id": start_id,
        "arm": record["arm"],
        "repetition": record["repetition"],
        "arm_order": record["arm_order"],
        "workload_digest": record["identity"]["workload_digest"],
        "deployment_receipt_sha256": record["deployment"]["receipt_sha256"],
    }
    for name, expected in bindings.items():
        if raw.get(name) != expected:
            raise ValueError(f"{start_id} raw artifact {name} is not bound")
    if raw["process_identity"] != record["process_identity"]:
        raise ValueError(f"{start_id} raw process identity differs")
    if record["status"] == "complete" and (
        record["process_identity"]["server_pid"] is None
        or record["process_identity"]["server_start_ticks"] is None
    ):
        raise ValueError(f"{start_id} complete start lacks server process identity")
    for label, expected in raw["artifact_sha256"].items():
        if record["artifacts"][label]["sha256"] != expected:
            raise ValueError(f"{start_id} raw artifact manifest differs for {label}")

    phases = raw["startup_phases"]
    order = [
        "discovery",
        "validation",
        "planning",
        "rendering",
        "evidence_setup",
        "worker_loading",
    ]
    cursor = raw["startup_start_ns"]
    phase_ms: dict[str, float] = {}
    for phase in order:
        interval = phases[phase]
        if interval["start_ns"] != cursor:
            raise ValueError(f"{start_id} startup phases overlap or contain a gap")
        phase_ms[phase] = _duration_ms(interval)
        cursor = interval["end_ns"]
    if cursor != raw["ready_ns"]:
        raise ValueError(f"{start_id} startup phases do not end at readiness")
    total_ms = (raw["ready_ns"] - raw["startup_start_ns"]) / 1_000_000
    if abs(sum(phase_ms.values()) - total_ms) > 1.0:
        raise ValueError(f"{start_id} startup phase sum differs from total")
    phase_ms["total"] = total_ms

    workload = campaign_spec["workload"]
    requests = raw["requests"]
    warmups = [item for item in requests if item["kind"] == "warmup"]
    measured = [item for item in requests if item["kind"] == "measured"]
    if len(warmups) != workload["warmup_requests"]:
        raise ValueError(f"{start_id} warmup request count differs")
    if len(measured) != workload["measured_requests"]:
        raise ValueError(f"{start_id} measured request count differs")
    ids = [item["request_id"] for item in requests]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{start_id} request IDs are not unique")
    for item in requests:
        if item["complete_ns"] < item["dispatch_ns"]:
            raise ValueError(f"{start_id} request has negative latency")
    successful = [
        item
        for item in measured
        if item["status_code"] == workload["success_status"]
        and (item["response_nonempty"] or not workload["require_nonempty_completion"])
    ]
    if len(successful) < workload["min_successful_measured_requests"]:
        raise ValueError(f"{start_id} has too few successful measured requests")
    first_dispatch = min(item["dispatch_ns"] for item in measured)
    last_complete = max(item["complete_ns"] for item in measured)
    elapsed_seconds = (last_complete - first_dispatch) / 1_000_000_000
    if elapsed_seconds <= 0:
        raise ValueError(f"{start_id} measured window is not positive")
    latencies = [
        (item["complete_ns"] - item["dispatch_ns"]) / 1_000_000 for item in successful
    ]
    resources = raw["resources"]
    return {
        "startup_phases_ms": phase_ms,
        "throughput": len(successful) / elapsed_seconds,
        "latency_median_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "latency_p99_ms": _percentile(latencies, 0.99),
        "cpu_ms": resources["cpu_ms"],
        "host_memory_bytes": resources["peak_host_rss_bytes"],
        "device_memory_bytes": resources["peak_device_memory_bytes"],
        "process_messages": resources["process_messages"],
        "evidence_bytes": resources["evidence_bytes"],
        "gate_open_ms": resources.get("gate_open_ms"),
        "failure_detection_ms": resources.get("failure_detection_ms"),
        "rollback_ms": resources.get("rollback_ms"),
        "recovery_ms": resources.get("recovery_ms"),
    }


def _verify_h4_raw_artifact(
    record: dict[str, Any], artifact_root: Path, campaign_spec: dict[str, Any]
) -> None:
    root = artifact_root.resolve()
    binding = record["artifacts"].get("raw_measurement")
    if not isinstance(binding, dict):
        raise ValueError(f"{record['start_id']} lacks a raw H4 measurement")
    path = (root / binding["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{record['start_id']} raw H4 measurement is missing")
    if _digest_bytes(path) != binding["sha256"]:
        raise ValueError(f"{record['start_id']} raw H4 measurement digest differs")
    raw = _load_object(path)
    errors = sorted(
        jsonschema.Draft7Validator(_load_h4_raw_schema()).iter_errors(raw),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError(
            f"{record['start_id']} raw H4 measurement: {errors[0].message}"
        )
    _verify_h4_receipt(
        record,
        (root / record["artifacts"]["deployment_receipt"]["path"]).resolve(),
        campaign_spec,
    )
    request_path = (root / record["artifacts"]["request_results"]["path"]).resolve()
    process_path = (root / record["artifacts"]["process_snapshot"]["path"]).resolve()
    cleanup_path = (root / record["artifacts"]["cleanup_report"]["path"]).resolve()
    request_document = _load_object(request_path)
    if (
        request_document.get("start_id") != record["start_id"]
        or request_document.get("requests") != raw["requests"]
    ):
        raise ValueError(f"{record['start_id']} request artifact differs from raw")
    process_document = _load_object(process_path)
    if (
        process_document.get("start_id") != record["start_id"]
        or process_document.get("process_identity") != raw["process_identity"]
    ):
        raise ValueError(f"{record['start_id']} process snapshot differs from raw")
    cleanup_document = _load_object(cleanup_path)
    if (
        cleanup_document.get("start_id") != record["start_id"]
        or cleanup_document.get("cleanup") != record["cleanup"]
    ):
        raise ValueError(f"{record['start_id']} cleanup report differs from record")
    if record["status"] == "complete":
        recomputed = _recompute_h4_metrics(record, raw, campaign_spec)
        if _canonical_digest(recomputed) != _canonical_digest(record["metrics"]):
            raise ValueError(f"{record['start_id']} metrics differ from raw evidence")


def _validate_intake(
    protocol: dict[str, Any],
    campaign: str,
    records: list[dict[str, Any]],
    artifact_root: Path,
    campaign_spec: dict[str, Any] | None = None,
) -> tuple[list[str], dict[tuple[str, int, str], dict[str, Any]]]:
    definition = protocol[campaign]
    expected_campaign = definition["campaign_id"]
    records = [row for row in records if row["campaign_id"] == expected_campaign]
    start_ids = [row["start_id"] for row in records]
    if len(start_ids) != len(set(start_ids)):
        raise ValueError("start_id values must be unique")

    indexed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in records:
        if row["cell_id"] not in definition["required_cells"]:
            raise ValueError(f"{row['start_id']} uses an unregistered cell")
        expected_order = (
            protocol["schedule"][row["repetition"] - 1].index(row["arm"]) + 1
        )
        if row["arm_order"] != expected_order:
            raise ValueError(f"{row['start_id']} differs from the frozen arm order")
        key = (row["cell_id"], row["repetition"], row["arm"])
        if key in indexed:
            raise ValueError(f"duplicate formal start for {key}")
        _verify_artifacts(row, artifact_root)
        if campaign == "h3":
            if campaign_spec is None:
                raise ValueError("H3 intake requires the frozen campaign spec")
            if row["campaign_id"] != campaign_spec["campaign_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen campaign")
            if row["cell_id"] != campaign_spec["cell_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen H3 cell")
            if row["identity"] != campaign_spec["fixed_identity"]:
                raise ValueError(f"{row['start_id']} differs from frozen H3 identity")
            _verify_h3_raw_artifact(row, artifact_root, campaign_spec)
        elif campaign == "h4":
            if campaign_spec is None:
                raise ValueError("H4 intake requires the frozen campaign spec")
            if row["campaign_id"] != campaign_spec["campaign_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen campaign")
            if row["cell_id"] != campaign_spec["cell_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen cell")
            _verify_h4_raw_artifact(row, artifact_root, campaign_spec)
        indexed[key] = row

    missing = [
        f"{cell}/r{repetition}/{arm}"
        for cell in definition["required_cells"]
        for repetition in range(1, protocol["minimum_starts"] + 1)
        for arm in protocol["arms"]
        if (cell, repetition, arm) not in indexed
    ]

    for cell in definition["required_cells"]:
        cell_rows = [row for row in records if row["cell_id"] == cell]
        if not cell_rows:
            continue
        reference = cell_rows[0]["identity"]
        if any(row["identity"] != reference for row in cell_rows[1:]):
            raise ValueError(f"{cell} has mixed cross-arm or cross-start identity")
        receipts = {row["deployment"]["receipt_sha256"] for row in cell_rows}
        if len(receipts) != 1:
            raise ValueError(f"{cell} has mixed deployment registration receipts")
    if campaign in {"h3", "h4"}:
        raw_label = "raw_recovery" if campaign == "h3" else "raw_measurement"
        for label in (
            raw_label,
            "raw_log",
            "request_results",
            "process_snapshot",
            "cleanup_report",
        ):
            digests = [row["artifacts"][label]["sha256"] for row in records]
            if len(digests) != len(set(digests)):
                raise ValueError(
                    f"{campaign.upper()} {label} artifacts are reused across starts"
                )
    return missing, indexed


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _paired_summary(
    values: list[float], *, seed: int, resamples: int, level: float
) -> dict[str, Any]:
    rng = random.Random(seed)
    bootstrapped = [
        statistics.median(rng.choices(values, k=len(values))) for _ in range(resamples)
    ]
    tail = (1 - level) / 2
    return {
        "pairs": len(values),
        "median": statistics.median(values),
        "confidence_level": level,
        "confidence_interval": [
            _percentile(bootstrapped, tail),
            _percentile(bootstrapped, 1 - tail),
        ],
    }


def _effect(
    indexed: dict[tuple[str, int, str], dict[str, Any]],
    cells: list[str],
    candidate: str,
    baseline: str,
    extractor: Callable[[dict[str, Any]], float],
    direction: str,
) -> list[float]:
    values = []
    for cell in cells:
        for repetition in range(1, 4):
            left = extractor(indexed[(cell, repetition, candidate)])
            right = extractor(indexed[(cell, repetition, baseline)])
            if right <= 0:
                raise ValueError(f"{cell}/r{repetition} baseline must be positive")
            numerator = left - right if direction == "increase" else right - left
            values.append(100 * numerator / right)
    return values


def _summarize_h4_cells(
    protocol: dict[str, Any],
    indexed: dict[tuple[str, int, str], dict[str, Any]],
    cells: list[str],
    rows: list[dict[str, Any]],
    *,
    overall_complete: bool,
) -> dict[str, Any]:
    definition = protocol["h4"]
    confidence = definition["confidence"]

    def summarize(values: list[float]) -> dict[str, Any]:
        return _paired_summary(
            values,
            seed=confidence["seed"],
            resamples=confidence["resamples"],
            level=confidence["level"],
        )

    failed = [row["start_id"] for row in rows if row["status"] == "failed"]
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    if failed or cleanup_failures:
        return {
            "status": "falsified",
            "formal_result": True,
            "campaign_complete": overall_complete,
            "starts": len(rows),
            "failed_starts": failed,
            "cleanup_failures": cleanup_failures,
            "metrics": None,
        }
    thresholds = definition["thresholds"]
    summaries: dict[str, Any] = {}
    violated = False
    for cell in cells:
        startup_percent = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        startup_absolute = [
            indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
            - indexed[(cell, repetition, "manual-integration")]["metrics"][
                "startup_phases_ms"
            ]["total"]
            for repetition in range(1, 4)
        ]
        throughput = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        p99 = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        values = {
            "ecpa_vs_manual_startup_percent": summarize(startup_percent),
            "ecpa_vs_manual_startup_absolute_ms": summarize(startup_absolute),
            "ecpa_vs_manual_throughput_regression_percent": summarize(throughput),
            "ecpa_vs_manual_p99_regression_percent": summarize(p99),
        }
        values["threshold_violation"] = (
            (
                values["ecpa_vs_manual_startup_percent"]["median"]
                > thresholds["startup_percent"]
                and values["ecpa_vs_manual_startup_absolute_ms"]["median"]
                > thresholds["startup_absolute_ms"]
            )
            or (
                values["ecpa_vs_manual_throughput_regression_percent"]["median"]
                > thresholds["throughput_regression_percent"]
            )
            or (
                values["ecpa_vs_manual_p99_regression_percent"]["median"]
                > thresholds["latency_p99_regression_percent"]
            )
        )
        violated = violated or values["threshold_violation"]
        summaries[cell] = values
    return {
        "status": "falsified" if violated else "supported",
        "formal_result": True,
        "campaign_complete": overall_complete,
        "starts": len(rows),
        "failed_starts": [],
        "cleanup_failures": [],
        "metrics": {"cells": summaries},
    }


def analyze_h3(
    protocol: dict[str, Any],
    records: list[dict[str, Any]],
    artifact_root: Path,
    campaign_spec: dict[str, Any],
) -> dict[str, Any]:
    missing, indexed = _validate_intake(
        protocol, "h3", records, artifact_root, campaign_spec
    )
    completed_cell: dict[str, Any] = {}
    cell = campaign_spec["cell_id"]
    if not any(item.startswith(f"{cell}/") for item in missing):
        cell_rows = [row for row in indexed.values() if row["cell_id"] == cell]
        injected = [row for row in cell_rows if row["metrics"]["injected_failure"]]
        violations = any(
            row["metrics"]["unsupported_tuple_served"]
            or not row["metrics"]["predecessor_preserved"]
            or not row["metrics"]["functional_correctness"]
            or not row["metrics"]["evidence_identity_preserved"]
            for row in cell_rows
        )
        cleanup_failures = [
            row["start_id"] for row in cell_rows if not all(row["cleanup"].values())
        ]
        objective_rate = (
            sum(row["metrics"]["objective_met"] for row in injected) / len(injected)
            if injected
            else 0.0
        )
        supported = (
            bool(injected)
            and not violations
            and not cleanup_failures
            and objective_rate >= protocol["h3"]["objective_rate_minimum"]
        )
        completed_cell[cell] = {
            "status": "supported" if supported else "falsified",
            "formal_result": True,
            "campaign_complete": False,
            "starts": len(cell_rows),
            "injected_failures": len(injected),
            "objective_rate": objective_rate,
            "direct_safety_violation": violations,
            "cleanup_failures": cleanup_failures,
        }
    if missing:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": protocol["h3"]["campaign_id"],
            "status": "incomplete",
            "formal_result": False,
            "received_starts": len(indexed),
            "required_starts": len(protocol["h3"]["required_cells"]) * 9,
            "missing": missing,
            "metrics": None,
            "completed_cells": completed_cell,
        }
    rows = list(indexed.values())
    injected = [row for row in rows if row["metrics"]["injected_failure"]]
    if not injected:
        raise ValueError("H3 contains no injected failures")
    objective_rate = sum(row["metrics"]["objective_met"] for row in injected) / len(
        injected
    )
    direct_violation = any(
        row["metrics"]["unsupported_tuple_served"]
        or not row["metrics"]["predecessor_preserved"]
        or not row["metrics"]["functional_correctness"]
        or not row["metrics"]["evidence_identity_preserved"]
        for row in rows
    )
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    cells = {}
    for cell in protocol["h3"]["required_cells"]:
        cell_rows = [row for row in rows if row["cell_id"] == cell]
        cell_injected = [row for row in cell_rows if row["metrics"]["injected_failure"]]
        cells[cell] = {
            "starts": len(cell_rows),
            "injected_failures": len(cell_injected),
            "objective_rate": (
                sum(row["metrics"]["objective_met"] for row in cell_injected)
                / len(cell_injected)
                if cell_injected
                else None
            ),
            "direct_safety_violation": any(
                row["metrics"]["unsupported_tuple_served"]
                or not row["metrics"]["predecessor_preserved"]
                or not row["metrics"]["functional_correctness"]
                or not row["metrics"]["evidence_identity_preserved"]
                for row in cell_rows
            ),
            "failed_starts": sum(row["status"] == "failed" for row in cell_rows),
            "cleanup_failures": [
                row["start_id"] for row in cell_rows if not all(row["cleanup"].values())
            ],
        }
    supported = (
        not direct_violation
        and not cleanup_failures
        and objective_rate >= protocol["h3"]["objective_rate_minimum"]
    )
    return {
        "schema": "ecpa-formal-campaign-summary/v1",
        "campaign_id": protocol["h3"]["campaign_id"],
        "status": "supported" if supported else "falsified",
        "formal_result": True,
        "received_starts": len(rows),
        "required_starts": len(rows),
        "missing": [],
        "metrics": {
            "injected_failures": len(injected),
            "objective_rate": objective_rate,
            "direct_safety_violation": direct_violation,
            "failed_starts": sum(row["status"] == "failed" for row in rows),
            "cleanup_failures": cleanup_failures,
            "lost_requests": sum(row["metrics"]["lost_requests"] for row in rows),
            "duplicated_requests": sum(
                row["metrics"]["duplicated_requests"] for row in rows
            ),
            "cells": cells,
        },
    }


def analyze_h4(
    protocol: dict[str, Any],
    records: list[dict[str, Any]],
    artifact_root: Path,
    campaign_spec: dict[str, Any],
) -> dict[str, Any]:
    missing, indexed = _validate_intake(
        protocol, "h4", records, artifact_root, campaign_spec
    )
    definition = protocol["h4"]
    cell = campaign_spec["cell_id"]
    cell_missing = [item for item in missing if item.startswith(f"{cell}/")]
    if not cell_missing:
        cell_rows = [row for row in indexed.values() if row["cell_id"] == cell]
        cell_result = _summarize_h4_cells(
            protocol, indexed, [cell], cell_rows, overall_complete=False
        )
    else:
        cell_result = None
    if missing:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": definition["campaign_id"],
            "status": "incomplete",
            "formal_result": False,
            "received_starts": len(indexed),
            "required_starts": len(definition["required_cells"]) * 9,
            "missing": missing,
            "metrics": None,
            "completed_cells": ({cell: cell_result} if cell_result else {}),
        }
    rows = list(indexed.values())
    failed_starts = [row["start_id"] for row in rows if row["status"] == "failed"]
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    if failed_starts:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": definition["campaign_id"],
            "status": "falsified",
            "formal_result": True,
            "received_starts": len(rows),
            "required_starts": len(rows),
            "missing": [],
            "metrics": None,
            "failed_starts": failed_starts,
            "cleanup_failures": cleanup_failures,
        }

    cells = definition["required_cells"]
    confidence = definition["confidence"]
    startup_ms = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["startup_phases_ms"]["total"],
        "increase",
    )
    startup_absolute_ms = [
        indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
        - indexed[(cell, repetition, "manual-integration")]["metrics"][
            "startup_phases_ms"
        ]["total"]
        for cell in cells
        for repetition in range(1, 4)
    ]
    throughput = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["throughput"],
        "regression",
    )
    p99 = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["latency_p99_ms"],
        "increase",
    )

    def summarize(values: list[float]) -> dict[str, Any]:
        return _paired_summary(
            values,
            seed=confidence["seed"],
            resamples=confidence["resamples"],
            level=confidence["level"],
        )

    summaries = {
        "ecpa_vs_manual_startup_percent": summarize(startup_ms),
        "ecpa_vs_manual_startup_absolute_ms": summarize(startup_absolute_ms),
        "ecpa_vs_manual_throughput_regression_percent": summarize(throughput),
        "ecpa_vs_manual_p99_regression_percent": summarize(p99),
    }
    thresholds = definition["thresholds"]
    cell_summaries = {}
    for cell in cells:
        ecpa_startup_percent = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        ecpa_startup_absolute = [
            indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
            - indexed[(cell, repetition, "manual-integration")]["metrics"][
                "startup_phases_ms"
            ]["total"]
            for repetition in range(1, 4)
        ]
        ecpa_throughput = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        ecpa_p99 = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        vanilla_startup = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        vanilla_throughput = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        vanilla_p99 = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        cell_summary = {
            "ecpa_vs_manual_startup_percent": summarize(ecpa_startup_percent),
            "ecpa_vs_manual_startup_absolute_ms": summarize(ecpa_startup_absolute),
            "ecpa_vs_manual_throughput_regression_percent": summarize(ecpa_throughput),
            "ecpa_vs_manual_p99_regression_percent": summarize(ecpa_p99),
            "vanilla_vs_manual_startup_percent": summarize(vanilla_startup),
            "vanilla_vs_manual_throughput_regression_percent": summarize(
                vanilla_throughput
            ),
            "vanilla_vs_manual_p99_regression_percent": summarize(vanilla_p99),
        }
        cell_summary["threshold_violation"] = (
            (
                cell_summary["ecpa_vs_manual_startup_percent"]["median"]
                > thresholds["startup_percent"]
                and cell_summary["ecpa_vs_manual_startup_absolute_ms"]["median"]
                > thresholds["startup_absolute_ms"]
            )
            or (
                cell_summary["ecpa_vs_manual_throughput_regression_percent"]["median"]
                > thresholds["throughput_regression_percent"]
            )
            or (
                cell_summary["ecpa_vs_manual_p99_regression_percent"]["median"]
                > thresholds["latency_p99_regression_percent"]
            )
        )
        cell_summaries[cell] = cell_summary
    supported = (
        not any(row["threshold_violation"] for row in cell_summaries.values())
        and not cleanup_failures
    )
    return {
        "schema": "ecpa-formal-campaign-summary/v1",
        "campaign_id": definition["campaign_id"],
        "status": "supported" if supported else "falsified",
        "formal_result": True,
        "received_starts": len(rows),
        "required_starts": len(rows),
        "missing": [],
        "manual_baseline": "manual-integration",
        "vanilla_reported_separately": True,
        "failed_starts": [],
        "cleanup_failures": cleanup_failures,
        "metrics": {"overall": summaries, "cells": cell_summaries},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", choices=("h3", "h4"), required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--campaign-spec", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    protocol = load_protocol()
    records = load_records(args.records)
    if args.campaign_spec is None:
        parser.error("--campaign-spec is required for H3 and H4")
    if args.campaign == "h3":
        summary = analyze_h3(
            protocol, records, args.artifact_root, load_h3_campaign(args.campaign_spec)
        )
    else:
        summary = analyze_h4(
            protocol, records, args.artifact_root, load_h4_campaign(args.campaign_spec)
        )
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
