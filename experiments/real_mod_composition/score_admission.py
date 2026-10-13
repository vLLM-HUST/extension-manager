#!/usr/bin/env python3
"""Fail closed before real-MOD evidence enters the H2 score."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
EXP = ROOT / "experiments/real_mod_composition"
DEFAULT_CAMPAIGN = EXP / "runtime_campaign.json"
DEFAULT_PREFLIGHTS = tuple(
    EXP / "artifacts" / name
    for name in (
        "kvcompress-knorm-install-order-preflight.json",
        "kvcompress-knorm-legacy-0.23.0-runtime-preflight.json",
        "kvcompress-knorm-documented-legacy-source-pair-preflight.json",
    )
)
FORMAL_RECORD_CLASS = "formal-real-host-composition"
LEGACY_CAMPAIGN_SCHEMA = "ecpa-h2-real-mod-runtime-campaign/0.1"
SOURCE_BOUND_CAMPAIGN_SCHEMA = "ecpa-h2-real-mod-runtime-campaign/v1"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact(directory: Path, declared_path: str) -> Path:
    """Relocate a captured absolute path without permitting directory traversal."""
    name = Path(declared_path).name
    if not name or name in {".", ".."}:
        raise ValueError(f"unsafe captured artifact path: {declared_path!r}")
    path = directory / name
    if not path.is_file():
        raise ValueError(f"captured artifact is missing: {path}")
    return path


def _expected_orders(campaign: dict[str, Any]) -> set[str]:
    orders = campaign.get("installation_orders")
    if not isinstance(orders, list):
        raise ValueError("campaign installation_orders must be a list")
    result: set[str] = set()
    for item in orders:
        if not isinstance(item, dict) or not isinstance(item.get("order_id"), str):
            raise ValueError("campaign contains an invalid installation order")
        order_id = item["order_id"]
        if order_id in result:
            raise ValueError(f"campaign duplicates installation order {order_id}")
        members = item.get("pip_order", item.get("members"))
        if not isinstance(members, list) or not members:
            raise ValueError(f"campaign order {order_id} has no member order")
        result.add(order_id)
    if not result:
        raise ValueError("campaign must freeze at least one installation order")
    return result


def _validate_source_campaign(campaign: dict[str, Any]) -> None:
    if (
        campaign.get("classification")
        != "frozen-before-formal-real-host-composition-runs"
    ):
        raise ValueError("source-bound campaign was not frozen before formal runs")
    if campaign.get("formal_runs") != []:
        raise ValueError("source-bound campaign must not embed post-freeze runs")
    host = campaign.get("host", {})
    if host.get("tensor_parallel_size") != 2:
        raise ValueError("formal H2 campaign must freeze TP2")
    for component in ("core", "ascend"):
        frozen = host.get(component, {})
        if not re.fullmatch(r"[0-9a-f]{40}", str(frozen.get("commit", ""))):
            raise ValueError(f"campaign host {component} commit is not frozen")
        if not re.fullmatch(r"[0-9a-f]{64}", str(frozen.get("wheel_sha256", ""))):
            raise ValueError(f"campaign host {component} wheel is not frozen")
    members = campaign.get("members")
    if not isinstance(members, list) or len(members) < 2:
        raise ValueError("source-bound campaign must freeze at least two members")
    for member in members:
        for key, size in (("commit", 40), ("tree", 40), ("wheel_sha256", 64)):
            if not re.fullmatch(rf"[0-9a-f]{{{size}}}", str(member.get(key, ""))):
                raise ValueError(f"campaign member has invalid {key}")


def _validate_planner(
    path: Path, campaign: dict[str, Any], campaign_digest: str
) -> tuple[dict[str, Any], str]:
    planner = _load(path)
    if (
        planner.get("schema") != "ecpa-h2-manager-planner-receipt/v1"
        or planner.get("classification")
        != "source-and-command-bound-static-planner-decision-before-formal-launch"
        or planner.get("planner_decision") not in {"admit", "reject"}
        or not re.fullmatch(r"[0-9a-f]{40}", str(planner.get("manager_commit", "")))
    ):
        raise ValueError("invalid source-bound planner receipt")
    if planner.get("campaign_sha256") != campaign_digest:
        raise ValueError("planner receipt does not bind the frozen campaign")
    commands = planner.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("planner receipt has no captured commands")
    all_zero = True
    for command in commands:
        if not isinstance(command.get("args"), list) or not isinstance(
            command.get("exit_code"), int
        ):
            raise ValueError("planner receipt contains an invalid command")
        all_zero = all_zero and command["exit_code"] == 0
        for stream in ("stdout", "stderr"):
            artifact = _artifact(path.parent, command[f"{stream}_path"])
            if _sha256(artifact) != command[f"{stream}_sha256"]:
                raise ValueError(f"planner {stream} artifact digest mismatch")
    config = _artifact(path.parent, planner["config_path"])
    if _sha256(config) != planner.get("config_sha256"):
        raise ValueError("planner configuration digest mismatch")
    if planner.get("all_exit_zero") is not all_zero or not all_zero:
        raise ValueError("planner commands did not all exit zero")
    dry_runs = [
        item for item in commands if item.get("args", [])[:2] == ["run", "--dry-run"]
    ]
    if len(dry_runs) != 1:
        raise ValueError("planner receipt must contain exactly one dry run")
    dry_run = json.loads(_artifact(path.parent, dry_runs[0]["stdout_path"]).read_text())
    plugins = set(dry_run.get("environment", {}).get("VLLM_PLUGINS", "").split(","))
    if not {item["entry_point"] for item in campaign["members"]} <= plugins:
        raise ValueError("planner dry run does not activate every frozen member")
    return planner, _sha256(path)


def _validate_manifest(run_dir: Path, receipt: dict[str, Any]) -> dict[str, str]:
    path = run_dir / "sha256.json"
    if _sha256(path) != receipt.get("raw_manifest_sha256"):
        raise ValueError("raw manifest digest mismatch")
    manifest = _load(path)
    required = {
        "result.json",
        "request.json",
        "response.json",
        "stdout.bin",
        "stderr.bin",
        "npu-after.txt",
        "kvcompress-config.json",
    }
    if not required <= set(manifest):
        raise ValueError("raw manifest omits required runtime artifacts")
    for name, digest in manifest.items():
        if Path(name).name != name or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise ValueError("raw manifest contains an unsafe entry")
        if _sha256(_artifact(run_dir, name)) != f"sha256:{digest}":
            raise ValueError(f"raw artifact digest mismatch: {name}")
    return manifest


def _jsonl(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{number}: invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: expected JSON object")
        result.append(value)
    return result


def _validate_runtime(
    record_path: Path,
    receipt_path: Path,
    *,
    campaign: dict[str, Any],
    campaign_digest: str,
    oracle_digest: str,
    planner_digest: str,
    planner_decision: str,
) -> dict[str, Any]:
    record, receipt = _load(record_path), _load(receipt_path)
    for document, schema_name, path in (
        (record, "formal-runtime-record.schema.json", record_path),
        (receipt, "formal-runtime-receipt.schema.json", receipt_path),
    ):
        schema = _load(EXP / schema_name)
        errors = sorted(
            jsonschema.Draft7Validator(schema).iter_errors(document),
            key=lambda item: list(item.path),
        )
        if errors:
            raise ValueError(f"{path}: {errors[0].message}")
    run_dir = receipt_path.parent
    if record_path.parent != run_dir:
        raise ValueError("record and receipt must share one captured run directory")
    if record["runtime_evidence"]["receipt_sha256"] != _sha256(receipt_path):
        raise ValueError("record does not bind the runtime receipt bytes")
    expected = {
        "campaign_sha256": campaign_digest,
        "oracle_sha256": oracle_digest,
        "case_id": campaign["case_id"],
        "order_id": record["order_id"],
    }
    for key, expected_value in expected.items():
        if record.get(key) != expected_value or receipt.get(key) != expected_value:
            raise ValueError(f"record/receipt does not bind {key}")
    if record["planner_decision"] != planner_decision:
        raise ValueError("record disagrees with the frozen planner decision")
    if receipt.get("planner_receipt_sha256") != planner_digest:
        raise ValueError("runtime receipt does not bind the planner receipt")

    manifest = _validate_manifest(run_dir, receipt)
    result_path = run_dir / "result.json"
    if _sha256(result_path) != receipt.get("raw_result_sha256"):
        raise ValueError("runtime receipt does not bind the raw result")
    result = _load(result_path)
    for key, expected_digest in (
        ("campaign_sha256", campaign_digest),
        ("oracle_sha256", oracle_digest),
        ("planner_receipt_sha256", planner_digest),
    ):
        if result.get("formal_inputs", {}).get(key) != expected_digest:
            raise ValueError(f"raw result does not bind {key}")
    if result.get("order") != record["order_id"] or result.get("failure") is not None:
        raise ValueError("raw result order or outcome is invalid")

    request_path, response_path = run_dir / "request.json", run_dir / "response.json"
    if _sha256(request_path) != receipt.get("request_sha256") or _sha256(
        response_path
    ) != receipt.get("response_sha256"):
        raise ValueError("runtime receipt does not bind request/response bytes")
    request, response = _load(request_path), _load(response_path)
    workload = campaign.get("workload", {})
    for key in ("prompt", "max_tokens", "temperature", "seed"):
        if request.get(key) != workload.get(key):
            raise ValueError(f"raw request does not bind frozen workload {key}")
    served_template = campaign.get("model", {}).get("served_name_template")
    if not isinstance(served_template, str):
        raise ValueError("campaign does not freeze a served-name template")
    try:
        expected_model = served_template.format(order_id=record["order_id"])
    except (KeyError, ValueError) as exc:
        raise ValueError("campaign served-name template is invalid") from exc
    if request.get("model") != expected_model:
        raise ValueError("raw request does not bind the frozen served model")
    choices = response.get("choices")
    completed = (
        result.get("health_status") == 200
        and result.get("completion_status") == 200
        and isinstance(choices, list)
        and bool(choices)
        and isinstance(choices[0].get("text"), str)
        and bool(choices[0]["text"])
        and response.get("model") == request.get("model")
    )
    if (
        not completed
        or receipt.get("health_status") != 200
        or receipt.get("completion_status") != 200
    ):
        raise ValueError("raw request/response does not prove a completed workload")

    engines = [
        item
        for item in result.get("process_identities", [])
        if item.get("argv") == ["VLLM::EngineCore"]
    ]
    if len(engines) != 1 or engines[0] != receipt.get("engine_identity"):
        raise ValueError("runtime receipt does not bind the unique EngineCore identity")
    engine_pid = engines[0]["pid"]
    observed = receipt["process_owned_observation"]
    trace_path = _artifact(run_dir, observed["path"])
    if _sha256(trace_path) != observed["sha256"] or manifest.get(
        trace_path.name
    ) != observed["sha256"].removeprefix("sha256:"):
        raise ValueError("runtime receipt does not bind the profiler trace")
    trace = _jsonl(trace_path)
    starts = [item for item in trace if item.get("record_type") == "process_start"]
    events = [
        item for item in trace if item.get("event_name") == "request_finished_observed"
    ]
    host = campaign["host"]
    profiler = next(
        item for item in campaign["members"] if item["id"] == "lifecycle_profiler"
    )
    trace_valid = (
        len(starts) == 1
        and starts[0].get("pid") == engine_pid == observed.get("pid")
        and starts[0].get("process_uuid") == observed.get("process_uuid")
        and starts[0].get("runtime_core_commit") == host["core"]["commit"]
        and starts[0].get("device_plugin_commit") == host["ascend"]["commit"]
        and starts[0].get("profiler_parent_commit") == profiler["commit"]
        and any(
            item.get("process_uuid") == observed.get("process_uuid") for item in events
        )
    )
    if not trace_valid:
        raise ValueError("profiler trace is not process-owned by the frozen EngineCore")

    stdout = (run_dir / "stdout.bin").read_text(errors="replace")
    pattern = re.compile(
        rf"\(EngineCore pid={engine_pid}\).*Ascend KV compression scheduler bound"
    )
    if receipt.get("kvcompress_bind_engine_pid") != engine_pid or not pattern.search(
        stdout
    ):
        raise ValueError("KVCompress binding is not owned by the observed EngineCore")
    npu_after = (run_dir / "npu-after.txt").read_text(errors="replace")
    devices = campaign["host"].get("physical_devices", [])
    npu_clean = bool(devices) and all(
        f"No running processes found in NPU {device}" in npu_after for device in devices
    )
    shutdown = (
        f"(EngineCore pid={engine_pid}) INFO" in stdout
        and "[shutdown] EngineCore: exiting busy loop" in stdout
    )
    raw_cleanup = (
        result.get("port_refused_after_stop") is True
        and result.get("surviving_owned_processes") == []
        and result.get("allocated_npu_process_tables_empty") is True
        and result.get("cleanup_proven") is True
        and receipt.get("port_refused_after_stop") is True
    )
    if (
        _sha256(run_dir / "npu-after.txt") != receipt.get("npu_after_sha256")
        or not raw_cleanup
        or not (npu_clean and shutdown)
    ):
        raise ValueError("raw artifacts do not prove EngineCore/NPU cleanup")

    recomputed = dict.fromkeys(
        (
            "host_started",
            "model_loaded",
            "workload_completed",
            "process_owned_observation",
            "cleanup_complete",
        ),
        True,
    )
    for key, recomputed_value in recomputed.items():
        if record["runtime_evidence"].get(key) is not recomputed_value:
            raise ValueError(f"record declaration disagrees with recomputed {key}")
    if receipt.get("cleanup_complete") is not True:
        raise ValueError("receipt declaration disagrees with recomputed cleanup")
    if (
        receipt.get("performance_result") is not False
        or receipt.get("compression_transaction_observed") is not False
    ):
        raise ValueError(
            "compatible binding run must not claim performance or compression"
        )
    return {
        "path": str(record_path),
        "sha256": _sha256(record_path),
        "receipt_path": str(receipt_path),
        "receipt_sha256": _sha256(receipt_path),
        "order_id": record["order_id"],
        "planner_decision": record["planner_decision"],
        "engine_pid": engine_pid,
        "runtime_evidence_recomputed": recomputed,
        "compression_transaction_observed": False,
        "performance_result": False,
    }


def assess(
    campaign_path: Path,
    preflight_paths: tuple[Path, ...],
    *,
    oracle_path: Path | None = None,
    planner_path: Path | None = None,
    record_paths: tuple[Path, ...] = (),
    receipt_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    campaign = _load(campaign_path)
    schema_name = campaign.get("schema")
    if schema_name not in {LEGACY_CAMPAIGN_SCHEMA, SOURCE_BOUND_CAMPAIGN_SCHEMA}:
        raise ValueError("unsupported H2 campaign schema")
    expected_orders = _expected_orders(campaign)
    if schema_name == SOURCE_BOUND_CAMPAIGN_SCHEMA:
        _validate_source_campaign(campaign)
    campaign_digest = _sha256(campaign_path)
    inputs = {
        "campaign": {"path": str(campaign_path), "sha256": campaign_digest},
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

    oracle = None
    oracle_digest = None
    if oracle_path is None:
        blockers.add("independent-oracle-missing")
    else:
        oracle, oracle_digest = _load(oracle_path), _sha256(oracle_path)
        if (
            oracle.get("schema") != "ecpa-h2-real-mod-oracle/v1"
            or oracle.get("status") != "automated-independent-reviewed"
            or oracle.get("campaign_sha256") != campaign_digest
            or oracle.get("review", {}).get("verdict") != "PASS"
            or oracle.get("review", {}).get("kind") != "automated-independent"
        ):
            blockers.add("independent-oracle-invalid")
    planner = None
    planner_digest = None
    if schema_name == SOURCE_BOUND_CAMPAIGN_SCHEMA:
        if planner_path is None:
            blockers.add("source-bound-planner-receipt-missing")
        else:
            planner, planner_digest = _validate_planner(
                planner_path, campaign, campaign_digest
            )
    oracle_decision = None
    if oracle is not None and "independent-oracle-invalid" not in blockers:
        labels = [
            item
            for item in oracle.get("labels", [])
            if item.get("case_id") == campaign["case_id"]
        ]
        if len(labels) != 1 or labels[0].get("decision") not in {"admit", "reject"}:
            blockers.add("oracle-case-label-missing")
        else:
            oracle_decision = labels[0]["decision"]

    if len(record_paths) != len(receipt_paths) and (record_paths or receipt_paths):
        raise ValueError("each formal record requires one explicit runtime receipt")
    accepted: list[dict[str, Any]] = []
    observed_orders: set[str] = set()
    if record_paths and (
        oracle_digest is None or planner is None or planner_digest is None
    ):
        raise ValueError("formal records require bound oracle and planner receipts")
    if record_paths:
        assert oracle_digest is not None
        assert planner is not None
        assert planner_digest is not None
    for record_path, receipt_path in zip(record_paths, receipt_paths, strict=True):
        assert oracle_digest is not None
        assert planner is not None
        assert planner_digest is not None
        accepted_record = _validate_runtime(
            record_path,
            receipt_path,
            campaign=campaign,
            campaign_digest=campaign_digest,
            oracle_digest=oracle_digest,
            planner_digest=planner_digest,
            planner_decision=planner["planner_decision"],
        )
        order_id = accepted_record["order_id"]
        if order_id not in expected_orders:
            raise ValueError(f"{record_path} names an unregistered installation order")
        if order_id in observed_orders:
            raise ValueError(f"{record_path} duplicates an installation order")
        accepted.append(accepted_record)
        observed_orders.add(order_id)
    if not accepted:
        blockers.add("formal-real-runtime-records-missing")
    if observed_orders != expected_orders:
        blockers.add("installation-order-coverage-incomplete")
    planner_decision = planner.get("planner_decision") if planner else None
    if (
        oracle_decision is not None
        and planner_decision is not None
        and oracle_decision != planner_decision
    ):
        blockers.add("planner-oracle-disagreement")
    eligible = not blockers
    return {
        "schema": "ecpa-h2-score-admission/v2",
        "classification": "formal-real-score-admission-status",
        "status": "ADMITTED" if eligible else "INCOMPLETE",
        "score_eligible": eligible,
        "inputs": inputs,
        "oracle_sha256": oracle_digest,
        "planner_receipt_sha256": planner_digest,
        "oracle_decision": oracle_decision,
        "planner_decision": planner_decision,
        "accepted_records": accepted,
        "excluded_preflights": excluded,
        "blockers": sorted(blockers),
        "scope": {
            "compatible_host_execution": eligible and oracle_decision == "admit",
            "compression_transaction": False,
            "performance": False,
        },
        "metrics": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--preflight", type=Path, action="append")
    parser.add_argument("--oracle", type=Path)
    parser.add_argument("--planner-receipt", type=Path)
    parser.add_argument("--record", type=Path, action="append", default=[])
    parser.add_argument("--receipt", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = assess(
        args.campaign,
        tuple(args.preflight or DEFAULT_PREFLIGHTS),
        oracle_path=args.oracle,
        planner_path=args.planner_receipt,
        record_paths=tuple(args.record),
        receipt_paths=tuple(args.receipt),
    )
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    return 0 if result["score_eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
