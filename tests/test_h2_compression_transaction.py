from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from experiments.real_mod_composition.verify_h2_compression_transaction import verify

ROOT = Path(__file__).parents[1]
ARTIFACT = (
    ROOT
    / "experiments"
    / "real_mod_composition"
    / "artifacts"
    / "h2-compression-transaction-20261013"
)


def portable_copy(tmp_path: Path) -> Path:
    target = tmp_path / "transaction"
    shutil.copytree(ARTIFACT, target)
    return target


def rehash(run: Path, relative: str) -> None:
    import hashlib

    manifest_path = run / "sha256.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[relative] = hashlib.sha256((run / relative).read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def test_committed_transaction_pair_is_portably_qualified(tmp_path: Path) -> None:
    result = verify(portable_copy(tmp_path))
    assert result["status"] == "QUALIFIED_NONFORMAL"
    assert result["score_eligible"] is False
    assert [run["worker_ack_count"] for run in result["runs"]] == [2, 2]
    assert {
        (run["semantic_tokens"], run["physical_tokens"]) for run in result["runs"]
    } == {(1201, 1024)}


def test_missing_tp_worker_ack_is_rejected_even_if_result_claims_success(
    tmp_path: Path,
) -> None:
    root = portable_copy(tmp_path)
    run = root / "profiler-then-kvcompress"
    marker = "KV compression worker commit acknowledged"
    log_path = next(
        path
        for path in (run / "stderr.bin", run / "stdout.bin")
        if path.read_text(errors="replace").count(marker) == 2
    )
    log = log_path.read_text(errors="replace")
    first = log.index(marker)
    second = log.index(marker, first + 1)
    end = log.index("\n", second)
    log_path.write_text(log[:second] + log[end + 1 :])
    rehash(run, log_path.name)
    with pytest.raises(ValueError, match="one worker acknowledgement per TP rank"):
        verify(root)


def test_duplicate_ack_from_one_rank_is_rejected(tmp_path: Path) -> None:
    root = portable_copy(tmp_path)
    run = root / "profiler-then-kvcompress"
    path = run / "stdout.bin"
    log = path.read_text(errors="replace")
    result = json.loads((run / "result.json").read_text())
    worker_pids = {
        item["argv"][0].removeprefix("VLLM::Worker_"): item["pid"]
        for item in result["process_identities"]
        if item["argv"] in (["VLLM::Worker_TP0"], ["VLLM::Worker_TP1"])
    }
    log = re.sub(
        rf"\(Worker_TP1 pid={worker_pids['TP1']}\)"
        r"(?=[^\n]*KV compression worker commit acknowledged)",
        f"(Worker_TP0 pid={worker_pids['TP0']})",
        log,
        count=1,
    )
    path.write_text(log)
    rehash(run, path.name)
    with pytest.raises(ValueError, match="TP worker ranks are incomplete"):
        verify(root)


def test_scheduler_commit_from_wrong_pid_is_rejected(tmp_path: Path) -> None:
    root = portable_copy(tmp_path)
    run = root / "kvcompress-then-profiler"
    path = run / "stdout.bin"
    log = path.read_text(errors="replace")
    result = json.loads((run / "result.json").read_text())
    engine_pid = next(
        item["pid"]
        for item in result["process_identities"]
        if item["argv"] == ["VLLM::EngineCore"]
    )
    log = re.sub(
        rf"\(EngineCore pid={engine_pid}\)"
        r"(?=[^\n]*KV compression scheduler commit)",
        f"(EngineCore pid={result['server_identity']['pid']})",
        log,
        count=1,
    )
    path.write_text(log)
    rehash(run, path.name)
    with pytest.raises(ValueError, match="scheduler log PID is not EngineCore"):
        verify(root)


def test_profiler_event_from_another_epoch_is_rejected(tmp_path: Path) -> None:
    root = portable_copy(tmp_path)
    run = root / "kvcompress-then-profiler"
    result = json.loads((run / "result.json").read_text())
    engine_pid = next(
        item["pid"]
        for item in result["process_identities"]
        if item["argv"] == ["VLLM::EngineCore"]
    )
    trace = next(
        path
        for path in run.glob("profiler-trace*.jsonl")
        if any(
            json.loads(line).get("record_type") == "process_start"
            and json.loads(line).get("pid") == engine_pid
            for line in path.read_text().splitlines()
        )
    )
    rows = [json.loads(line) for line in trace.read_text().splitlines()]
    for row in rows:
        if row.get("record_type") == "process_start":
            row["process_uuid"] = "substituted-epoch"
            break
    trace.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    rehash(run, trace.name)
    with pytest.raises(ValueError, match="process-owned request completion"):
        verify(root)


def test_replayed_process_identity_is_rejected(tmp_path: Path) -> None:
    root = portable_copy(tmp_path)
    first = json.loads((root / "profiler-then-kvcompress" / "result.json").read_text())
    second_path = root / "kvcompress-then-profiler" / "result.json"
    second = json.loads(second_path.read_text())
    first_engine = next(
        item
        for item in first["process_identities"]
        if item["argv"] == ["VLLM::EngineCore"]
    )
    second_engine = next(
        item
        for item in second["process_identities"]
        if item["argv"] == ["VLLM::EngineCore"]
    )
    second_engine["pid"] = first_engine["pid"]
    second_path.write_text(json.dumps(second, indent=2, sort_keys=True) + "\n")
    rehash(root / "kvcompress-then-profiler", "result.json")
    with pytest.raises(ValueError):
        verify(root)
