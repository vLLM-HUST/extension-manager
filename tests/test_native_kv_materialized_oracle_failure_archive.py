"""Actual frozen oracle-failure archive; no forged summary can qualify it."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_native_kv_materialized_partial_archive import rechain

from experiments.formal_campaign import verify_kv_materialized_oracle_failure as r3
from experiments.formal_campaign import verify_kv_materialized_partial as common

ARTIFACT = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts"
    / "native-kv-materialized-oracle-failure-r3-20261014"
)


def files():
    return common.load_archive(
        ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz", oracle_failure=True
    )


def rewrite(content, name, obj):
    content[name] = common.canonical(obj)


def repack(tmp_path, content):
    import io
    import tarfile

    archive = tmp_path / "changed.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        for name, raw in content.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            handle.addfile(member, io.BytesIO(raw))
    manifest = json.loads((ARTIFACT / "manifest.json").read_bytes())
    manifest["files"] = {
        n: {"sha256": common.sha(b), "bytes": len(b)} for n, b in content.items()
    }
    manifest["archive_sha256"] = common.sha(archive.read_bytes())
    path = tmp_path / "changed-manifest.json"
    path.write_bytes(common.canonical(manifest))
    return path, archive


def test_actual_200_stop_response_is_still_a_failed_frozen_task():
    result = r3.verify_archive(ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz")
    assert result["HTTP_response"] == 200 and result["HTTP_prompt_tokens"] == 1201
    assert (
        result["HTTP_completion_tokens"] == 81
        and result["HTTP_finish_reason"] == "stop"
    )
    assert result["observed_HTTP_elapsed_s"] == 32.01909209
    assert result["model_task_passed"] is False and result["runner_success"] is False
    assert [p["later_same_row_prefix_count"] for p in result["ranks"]] == [81, 81]
    assert len(result["native_acceptances_after_HTTP_completed_read"]) == 2
    assert result["collector_terminal_identity_independently_verified"] is True
    assert (
        result["final_durable_ACK"] is None
        and result["full_objective_satisfied"] is None
    )
    assert (
        result["formal_result"] is False
        and result["compression_causality_established"] is False
    )


@pytest.mark.parametrize(
    "change",
    [
        "response",
        "oracle",
        "budget",
        "phase-clock",
        "source",
        "fake-ACK",
        "fake-success",
    ],
)
def test_r3_fully_rehashed_counterfactual_remains_rejected(tmp_path, change):
    content = copy.deepcopy(files())
    metadata = json.loads(content["original/run/probe/response-metadata.json"])
    recipe = json.loads(content["original/recipe.json"])
    if change == "response":
        body = json.loads(content["original/run/probe/response.bin"])
        body["choices"][0]["message"]["content"] = recipe["phases"][0][
            "response_oracle"
        ]["expected"]
        rewrite(content, "original/run/probe/response.bin", body)
        metadata["response_sha256"] = common.sha(
            content["original/run/probe/response.bin"]
        )
        rewrite(content, "original/run/probe/response-metadata.json", metadata)
        probe = json.loads(content["original/run/probe/result.json"])
        probe["response_sha256"] = metadata["response_sha256"]
        rewrite(content, "original/run/probe/result.json", probe)
        result = json.loads(content["original/run/result.json"])
        result["probe"]["response_sha256"] = metadata["response_sha256"]
        rewrite(content, "original/run/result.json", result)
    elif change == "oracle":
        recipe["phases"][0]["response_oracle"]["expected"] = "single-nonce-task"
        rewrite(content, "original/recipe.json", recipe)
        cfg = json.loads(content["original/owner-config.json"])
        cfg["recipe_sha256"] = common.sha(content["original/recipe.json"])
        for name in ["original/owner-config.json", "original/run/owner-config.json"]:
            rewrite(content, name, cfg)
        freeze = json.loads(content["original/freeze-summary.json"])
        freeze["owner_config_sha256"] = common.sha(
            content["original/owner-config.json"]
        )
        freeze["recipe"]["sha256"] = cfg["recipe_sha256"]
        rewrite(content, "original/freeze-summary.json", freeze)
        probe = json.loads(content["original/run/probe/result.json"])
        probe["recipe_sha256"] = cfg["recipe_sha256"]
        rewrite(content, "original/run/probe/result.json", probe)
        result = json.loads(content["original/run/result.json"])
        result["probe"]["recipe_sha256"] = cfg["recipe_sha256"]
        rewrite(content, "original/run/result.json", result)
    elif change == "budget":
        metadata["rpc_budget_s"] = 600
        rewrite(content, "original/run/probe/response-metadata.json", metadata)
    elif change == "phase-clock":
        phase = json.loads(content["original/run/phase-total-elapsed.json"])
        phase["probe_completed_monotonic_ns"] = metadata["received_monotonic_ns"] - 1
        rewrite(content, "original/run/phase-total-elapsed.json", phase)
    elif change == "source":
        content["source/0"] += b"\n# substituted client\n"
        digest = common.sha(content["source/0"])
        cfg = json.loads(content["original/owner-config.json"])
        source_path = cfg["sources"][0]["path"]
        cfg["sources"][0]["sha256"] = digest
        for row in cfg["native_source_files"]:
            if row["path"] == source_path:
                row["sha256"] = digest
        for name in ["original/owner-config.json", "original/run/owner-config.json"]:
            rewrite(content, name, cfg)
        freeze = json.loads(content["original/freeze-summary.json"])
        freeze["owner_config_sha256"] = common.sha(
            content["original/owner-config.json"]
        )
        rewrite(content, "original/freeze-summary.json", freeze)
        source_map = json.loads(content["source-map.json"])
        source_map["sources"][0]["sha256"] = digest
        rewrite(content, "source-map.json", source_map)
        metadata["client_source_sha256"] = digest
        rewrite(content, "original/run/probe/response-metadata.json", metadata)

    elif change == "fake-ACK":
        content["original/run/probe/collector-after.json"] = content[
            "original/run/probe/collector-before.json"
        ]
    elif change == "fake-success":
        result = json.loads(content["original/run/result.json"])
        result["passed"] = True
        rewrite(content, "original/run/result.json", result)
    # Chain canonical self hashes are regenerated too; this cannot create a seal.
    events = [
        json.loads(line)
        for line in content["original/run/native-raw.jsonl"].splitlines()
    ]
    content["original/run/native-raw.jsonl"] = rechain(events)
    manifest, archive = repack(tmp_path, content)
    with pytest.raises(ValueError):
        r3.verify_archive(manifest, archive)
