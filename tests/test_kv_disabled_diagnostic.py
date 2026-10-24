"""Rehashed diagnostic counterexamples cannot upgrade failed source observations."""

import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_kv_disabled_diagnostic as verifier
from scripts.benchmark_inputs import resolve_original

ROOT = resolve_original(
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/kv-disabled-counterfactual-20261014"
)


@pytest.fixture(scope="module")
def originals():
    return verifier.load_archive(ROOT / "manifest.json", ROOT / "raw.tar.gz")


def change(files, name, mutation):
    value = json.loads(files[name])
    mutation(value)
    files[name] = verifier.canonical(value)


def test_real_diagnostic_is_failed_and_noncausal(originals):
    result = verifier.inspect(originals)
    assert result["both_strict_tasks_failed"] is True
    assert result["disabled_attempts"]["r4"]["HTTP_status"] == 200
    assert result["disabled_attempts"]["r4"]["strict_task_passed"] is False
    assert result["enabled_result"]["model_task_passed"] is False
    assert result["single_pair_causal_attribution"] is None
    assert result["formal_result"] is False
    assert result["disabled_attempts"]["r2"]["HTTP_response"] is None


@pytest.mark.parametrize(
    "case",
    [
        "HTTP503",
        "fake_pass",
        "foreign_peer",
        "foreign_session",
        "live_NPU",
        "missing_pre_request_failure",
        "native_mint",
        "platform_not_filtered",
        "wrong_source",
        "wrong_window",
        "missing_enabled",
    ],
)
def test_fully_rehashed_semantic_counterexamples(originals, tmp_path, case):
    files = dict(originals)
    if case == "HTTP503":
        for name in ("response-metadata.json", "result.json"):
            change(files, "r4/run/probe/" + name, lambda v: v.update(status=503))
    elif case == "fake_pass":
        change(files, "r4/run/result.json", lambda v: v.update(passed=True))
    elif case == "foreign_peer":
        change(
            files,
            "r4/run/actual-owned-source-peers.json",
            lambda v: v[1]["process"].update(pid=1999999999),
        )
    elif case == "foreign_session":
        change(
            files,
            "r4/run/terminal-process-audit.json",
            lambda v: v["remaining_sessions"][0]["owner"].update(pid=1999999999),
        )
    elif case == "live_NPU":
        files["r4/run/terminal-npu-smi.txt"] += b"| 3 0 | 12345 | python | 3000 |\n"
    elif case == "missing_pre_request_failure":
        del files["r2/run/terminal-process-audit.json"]
    elif case == "native_mint":
        change(
            files,
            "r4/run/baseline-fixed-binding.json",
            lambda v: v.update(native_Manager_handoff_qualified=True),
        )
    elif case == "platform_not_filtered":
        rows = [
            json.loads(x) for x in files["r3/baseline-host-evidence.jsonl"].splitlines()
        ]
        for row in rows:
            if row["event"] == "skipped" and row["entry_point"]["name"] == "ascend":
                row["event"] = "resolved"
        files["r3/baseline-host-evidence.jsonl"] = b"".join(
            verifier.canonical(x) + b"\n" for x in rows
        )
    elif case == "wrong_source":
        cfg = json.loads(files["r4/owner-config.json"])
        files["snapshots/" + cfg["sources"][0]["sha256"]] += b"\n"
    elif case == "wrong_window":
        change(
            files,
            "r4/run/probe/response-metadata.json",
            lambda v: v.update(
                received_monotonic_ns=v["sent_monotonic_ns"] + 181_000_000_000
            ),
        )
    else:
        del files["enabled-r3/raw.tar.gz"]
    archive = tmp_path / "raw.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, raw in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))
    manifest = json.loads((ROOT / "manifest.json").read_bytes())
    manifest["archive_sha256"] = verifier.sha(archive.read_bytes())
    manifest["inventory"] = {
        name: {"sha256": verifier.sha(raw), "bytes": len(raw)}
        for name, raw in files.items()
    }
    path = tmp_path / "manifest.json"
    path.write_bytes(verifier.canonical(manifest))
    with pytest.raises(ValueError):
        verifier.verify_archive(path, archive)
