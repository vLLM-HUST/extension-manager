#!/usr/bin/env python3
"""Fail-closed verifier for a real TP2 KV compression transaction pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

COMMIT_RE = re.compile(
    r"\(EngineCore pid=(\d+)\).*KV compression scheduler commit "
    r"request_id=(\S+) semantic_tokens=(\d+) "
    r"physical_tokens=(\d+) source_blocks=(\d+) destination_blocks=(\d+) "
    r"released_blocks=(\d+)"
)
ACK_RE = re.compile(
    r"\(Worker_(TP[01]) pid=(\d+)\).*KV compression worker commit acknowledged "
    r"request_id=(\S+) "
    r"semantic_tokens=(\d+) physical_tokens=(\d+) destination_blocks=(\d+)"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_hash_manifest(run: Path) -> None:
    manifest = read_json(run / "sha256.json")
    require(isinstance(manifest, dict) and bool(manifest), "missing SHA-256 manifest")
    for relative, expected in manifest.items():
        path = run / relative
        require(path.is_file(), f"manifest member missing: {relative}")
        require(digest(path) == expected, f"manifest digest mismatch: {relative}")


def verify_npu_empty(path: Path) -> None:
    text = path.read_text()
    require(
        text.count("No running processes found") == 2,
        f"allocated NPU process table is not empty: {path.name}",
    )
    require("| 3     910B2" in text and "| 6     910B2" in text, "wrong NPU pair")


def verify_run(
    root: Path, run: Path, campaign: dict[str, Any], order: str
) -> dict[str, Any]:
    verify_hash_manifest(run)
    result = read_json(run / "result.json")
    request = read_json(run / "request.json")
    response = read_json(run / "response.json")
    config = read_json(run / "kvcompress-config.json")
    require(
        result["schema"] == "ecpa-h2-compression-transaction-raw-run/v1",
        "wrong raw schema",
    )
    require(result["order"] == order, "run order mismatch")
    require(
        result["campaign_sha256"] == digest(root / "campaign.json"),
        "campaign binding mismatch",
    )
    require(
        result["oracle_sha256"] == digest(root / "oracle.json"),
        "oracle binding mismatch",
    )
    require(
        result["runner_sha256"] == digest(root / "runner.snapshot"),
        "runner binding mismatch",
    )

    frozen = campaign["workload"]
    prompt = str(frozen["prompt_unit"]) * int(frozen["prompt_repeat"])
    require(
        hashlib.sha256(prompt.encode()).hexdigest()
        == frozen["prompt_sha256"].removeprefix("sha256:"),
        "frozen prompt digest mismatch",
    )
    require(request["prompt"] == prompt, "request prompt mismatch")
    require(
        request["max_tokens"] == frozen["max_tokens"], "request max_tokens mismatch"
    )
    require(
        request["temperature"] == frozen["temperature"], "request temperature mismatch"
    )
    require(request["seed"] == frozen["seed"], "request seed mismatch")
    served = campaign["model"]["served_name_template"].format(order_id=order)
    require(
        request["model"] == served == result["served_model"], "served model mismatch"
    )

    method = config["method_config"]
    frozen_method = campaign["kvcompress"]["method_config"]
    for key, value in frozen_method.items():
        require(method.get(key) == value, f"method config mismatch: {key}")
    threshold = int(method["kv_budget"]) + int(method["recompute_window"])
    require(
        frozen["prompt_unit"] == "Evidence-bound compression transaction sentence. ",
        "unexpected token-count fixture",
    )
    # The checked Qwen2.5 token decomposition is one initial token, six
    # tokens per repeated sentence, and one final trailing-space token.
    expected_tokens = 1 + 6 * int(frozen["prompt_repeat"])
    require(
        expected_tokens == int(frozen["expected_prompt_tokens"]),
        "frozen prompt token count mismatch",
    )
    require(
        threshold == 1152 and expected_tokens == 1201, "unexpected threshold fixture"
    )
    require(expected_tokens >= threshold, "workload does not cross threshold")
    require(result["prompt_tokens"] == expected_tokens, "runner prompt count mismatch")
    require(
        response["usage"]["prompt_tokens"] == expected_tokens,
        "response prompt count mismatch",
    )
    require(
        response["usage"]["completion_tokens"] == frozen["max_tokens"],
        "response token count mismatch",
    )
    require(response["choices"][0]["text"].strip(), "empty response")

    verify_npu_empty(run / "npu-before.txt")
    verify_npu_empty(run / "npu-after.txt")
    identities = result["process_identities"]
    engine = [x for x in identities if x.get("argv") == ["VLLM::EngineCore"]]
    workers = [
        x
        for x in identities
        if x.get("argv") in (["VLLM::Worker_TP0"], ["VLLM::Worker_TP1"])
    ]
    require(len(engine) == 1, "EngineCore identity is not unique")
    require(len(workers) == 2, "TP2 worker identities are incomplete")
    require(
        len({x["pid"] for x in identities}) == len(identities),
        "duplicate process identity",
    )
    require(len({x["boot_id"] for x in identities}) == 1, "mixed boot epochs")
    require(
        all(
            isinstance(x["start_ticks"], int) and x["start_ticks"] > 0
            for x in identities
        ),
        "invalid process start ticks",
    )

    logs = (
        (run / "stderr.bin").read_text(errors="replace")
        + "\n"
        + (run / "stdout.bin").read_text(errors="replace")
    )
    commits = COMMIT_RE.findall(logs)
    acks = ACK_RE.findall(logs)
    require(
        logs.count('"GET /health HTTP/1.1" 200 OK') == 1,
        "health HTTP 200 access record missing",
    )
    require(
        logs.count('"POST /v1/completions HTTP/1.1" 200 OK') == 1,
        "completion HTTP 200 access record missing",
    )
    require(len(commits) == 1, "expected exactly one scheduler commit")
    require(len(acks) == 2, "expected exactly one worker acknowledgement per TP rank")
    commit = commits[0]
    require(int(commit[0]) == engine[0]["pid"], "scheduler log PID is not EngineCore")
    require(int(commit[2]) == expected_tokens, "scheduler semantic anchor mismatch")
    require(
        int(commit[3]) == int(method["kv_budget"]), "scheduler physical anchor mismatch"
    )
    require(
        int(commit[5]) == int(method["kv_budget"]) // 128,
        "scheduler destination size mismatch",
    )
    require(commit[4] == commit[6], "scheduler source/release count mismatch")
    ack_ranks = {ack[0]: int(ack[1]) for ack in acks}
    require(set(ack_ranks) == {"TP0", "TP1"}, "TP worker ranks are incomplete")
    expected_worker_pids = {
        item["argv"][0].removeprefix("VLLM::Worker_"): item["pid"] for item in workers
    }
    require(ack_ranks == expected_worker_pids, "worker log PID identity mismatch")
    ack_payloads = {(ack[2], ack[3], ack[4], ack[5]) for ack in acks}
    require(len(ack_payloads) == 1, "worker acknowledgements disagree")
    ack = next(iter(ack_payloads))
    require(
        (commit[1], commit[2], commit[3], commit[5]) == ack,
        "worker/scheduler transaction mismatch",
    )

    traces: list[dict[str, Any]] = []
    trace_paths = sorted(run.glob("profiler-trace*.jsonl"))
    require(bool(trace_paths), "missing profiler traces")
    for path in trace_paths:
        traces.extend(
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        )
    engine_starts = [
        x
        for x in traces
        if x.get("record_type") == "process_start" and x.get("pid") == engine[0]["pid"]
    ]
    require(len(engine_starts) == 1, "EngineCore profiler epoch is not unique")
    process_uuid = engine_starts[0]["process_uuid"]
    finished = [
        x
        for x in traces
        if x.get("event_name") == "request_finished_observed"
        and x.get("process_uuid") == process_uuid
        and x.get("metadata", {}).get("runtime_request_id") == commit[1]
    ]
    require(len(finished) == 1, "missing process-owned request completion")
    require(
        finished[0]["metadata"]["prompt_tokens"] == expected_tokens,
        "trace prompt count mismatch",
    )
    require(
        finished[0]["metadata"]["output_tokens"] == frozen["max_tokens"],
        "trace output count mismatch",
    )
    require(
        commit[1].startswith(response["id"] + "-"),
        "response/transaction request mismatch",
    )
    require(result["failure"] is None, "runner reported failure")
    require(result["server_exit_code"] == 0, "server did not shut down cleanly")
    require(result["surviving_owned_processes"] == [], "owned process survived")
    require(result["port_refused_after_stop"] is True, "port remained open")
    require(
        result["allocated_npu_process_tables_empty"] is True, "NPU cleanup claim failed"
    )
    return {
        "order": order,
        "request_id": commit[1],
        "semantic_tokens": int(commit[2]),
        "physical_tokens": int(commit[3]),
        "destination_blocks": int(commit[5]),
        "worker_ack_count": len(acks),
        "engine_core": engine[0],
        "profiler_process_uuid": process_uuid,
        "response_sha256": digest(run / "response.json"),
        "result_sha256": digest(run / "result.json"),
        "manifest_sha256": digest(run / "sha256.json"),
    }


def verify(root: Path) -> dict[str, Any]:
    campaign = read_json(root / "campaign.json")
    oracle = read_json(root / "oracle.json")
    require(
        campaign["schema"] == "ecpa-h2-compression-transaction-campaign/v1",
        "wrong campaign schema",
    )
    require(campaign["formal_runs"] == [], "campaign was not frozen before launch")
    require(
        campaign["oracle_sha256"] == "sha256:" + digest(root / "oracle.json"),
        "oracle digest mismatch",
    )
    require(
        campaign["runner"]["sha256"] == digest(root / "runner.snapshot"),
        "runner digest mismatch",
    )
    require(
        oracle["schema"] == "ecpa-h2-compression-transaction-oracle/v1",
        "wrong oracle schema",
    )
    require(oracle["planner_runtime_blind"] is True, "oracle is not blind")
    require(
        oracle["label"] == "compatible-compression-transaction-expected",
        "oracle label mismatch",
    )
    orders = [x["order_id"] for x in campaign["installation_orders"]]
    require(
        orders == ["profiler-then-kvcompress", "kvcompress-then-profiler"],
        "installation orders mismatch",
    )
    records = [verify_run(root, root / order, campaign, order) for order in orders]
    require(
        records[0]["request_id"] != records[1]["request_id"],
        "runtime artifact replay detected",
    )
    require(
        records[0]["engine_core"]["pid"] != records[1]["engine_core"]["pid"],
        "process artifact replay detected",
    )
    require(
        records[0]["profiler_process_uuid"] != records[1]["profiler_process_uuid"],
        "profiler artifact replay detected",
    )
    return {
        "schema": "ecpa-h2-compression-transaction-admission/v1",
        "classification": "real-compatible-pair-compression-transaction",
        "status": "QUALIFIED_NONFORMAL",
        "score_eligible": False,
        "performance_result": False,
        "campaign_sha256": digest(root / "campaign.json"),
        "oracle_sha256": digest(root / "oracle.json"),
        "runner_sha256": digest(root / "runner.snapshot"),
        "runs": records,
        "claims": [
            "both installation orders completed a real TP2 compression transaction",
            "scheduler commit and both TP worker acknowledgements agree on "
            "the transaction",
            "the same request is bound to an EngineCore-owned lifecycle trace "
            "and clean shutdown",
        ],
        "nonclaims": ["performance benefit", "compression quality parity", "H3", "H4"],
        "qualification_boundary": {
            "formal_h2_result": False,
            "preregistered_timestamp_claim": False,
            "reason": (
                "campaign frozen_utc is later than the observed first launch; "
                "the field is inaccurate and is not admission evidence"
            ),
            "retained_prelaunch_binding": (
                "the immutable runner reads and validates the exact campaign, "
                "oracle, and runner digests before spawning the server"
            ),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        admission = verify(args.root.resolve())
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "REJECTED", "reason": str(error)}, indent=2))
        return 1
    rendered = json.dumps(admission, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
