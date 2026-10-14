"""Sealed partial raw replay and semantic counterfactuals after all hashes change."""

from __future__ import annotations

import base64
import copy
import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_kv_materialized_partial as verifier

ARTIFACT = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/native-kv-materialized-partial-r1-20261014"
)


def files():
    return verifier.load_archive(ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz")


def repack(tmp_path, content):
    """Recompute every member, outer inventory, tar digest, raw body and chain."""
    path = tmp_path / "changed.tar.gz"
    with tarfile.open(path, "w:gz") as handle:
        for name, raw in content.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            handle.addfile(member, io.BytesIO(raw))
    manifest = json.loads((ARTIFACT / "manifest.json").read_bytes())
    manifest["files"] = {
        n: {"sha256": verifier.sha(r), "bytes": len(r)} for n, r in content.items()
    }
    manifest["archive_sha256"] = verifier.sha(path.read_bytes())
    output = tmp_path / "changed-manifest.json"
    output.write_bytes(verifier.canonical(manifest))
    return output, path


def rechain(events):
    previous = "0" * 64
    for event in events:
        event["previous_sha256"] = previous
        previous = verifier.sha(
            verifier.canonical({k: v for k, v in event.items() if k != "event_sha256"})
        )
        event["event_sha256"] = previous
    return b"".join(verifier.canonical(e) + b"\n" for e in events)


def test_actual_partial_archive_cannot_become_a_success():
    result = verifier.inspect(files())
    assert result["raw_records"] == 100 and result["upload_facts"] == 96
    assert [r["later_same_row_prefix_count"] for r in result["ranks"]] == [47, 47]
    assert result["runner_success"] is False and result["formal_result"] is False
    assert all(
        result[k] is None
        for k in [
            "HTTP_response",
            "final_durable_ACK",
            "durable_join",
            "collector_terminal_identity_independently_verified",
            "full_objective_satisfied",
        ]
    )


@pytest.mark.parametrize(
    "change",
    [
        "cpu-row",
        "scheduled-suffix",
        "metadata-row",
        "effect-clock",
        "producer-source",
        "fake-success",
        "invent-response",
    ],
)
def test_rehashed_semantic_counterfactual_rejected(tmp_path, change):
    content = copy.deepcopy(files())
    name = "original/run/native-raw.jsonl"
    events = [json.loads(line) for line in content[name].splitlines()]
    target = next(
        e
        for e in events[1:]
        if json.loads(base64.b64decode(e["raw_base64"]))["schema"].endswith(
            "projection/v2"
        )
    )
    fact = json.loads(base64.b64decode(target["raw_base64"]))
    if change == "cpu-row":
        fact["host_cpu_block_ids"][0] = 99
    elif change == "scheduled-suffix":
        fact["scheduled_appended_block_ids"] = [20]
    elif change == "metadata-row":
        fact["metadata_row"] = 1
    elif change == "effect-clock":
        fact["metadata_effect_monotonic_ns"] = 1
    elif change == "producer-source":
        content["source/20"] += b"\n# substituted source\n"
        changed_sha = verifier.sha(content["source/20"])
        cfg = json.loads(content["original/owner-config.json"])
        source_path = cfg["sources"][20]["path"]
        for row in cfg["sources"] + cfg["native_source_files"]:
            if row["path"] == source_path:
                row["sha256"] = changed_sha
        content["original/owner-config.json"] = verifier.canonical(cfg)
        content["original/run/owner-config.json"] = verifier.canonical(cfg)
        freeze = json.loads(content["original/freeze-summary.json"])
        freeze["owner_config_sha256"] = verifier.sha(
            content["original/owner-config.json"]
        )
        content["original/freeze-summary.json"] = verifier.canonical(freeze)
        source_map = json.loads(content["source-map.json"])
        source_map["sources"][20]["sha256"] = changed_sha
        content["source-map.json"] = verifier.canonical(source_map)

    elif change == "fake-success":
        result = json.loads(content["original/run/result.json"])
        result["passed"] = True
        content["original/run/result.json"] = verifier.canonical(result)
    elif change == "invent-response":
        content["original/run/probe/response.bin"] = b"{}"
    if change in {"cpu-row", "scheduled-suffix", "metadata-row", "effect-clock"}:
        keys = [
            "runtime_request_id",
            "attention_group",
            "semantic_anchor",
            "physical_anchor",
            "destination_block_ids",
            "host_cpu_block_ids",
            "allocation_block_size",
            "compression_threshold_tokens",
            "scheduled_appended_block_ids",
            "metadata_effect_monotonic_ns",
        ]
        fact["transaction_id"] = verifier.sha(
            verifier.canonical({k: fact[k] for k in keys})
        )
        raw = verifier.canonical(fact)
        target["raw_base64"] = base64.b64encode(raw).decode()
        target["raw_sha256"] = verifier.sha(raw)
        content[name] = rechain(events)
    manifest, archive = repack(tmp_path, content)
    with pytest.raises(ValueError):
        verifier.verify_archive(manifest, archive)
