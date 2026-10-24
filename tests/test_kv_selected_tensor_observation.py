"""Exact corpus replay and rehashed nested scientific/protocol counterexamples."""

import base64
import json
from pathlib import Path

import pytest

from experiments.formal_campaign import (
    verify_kv_selected_tensor_observation as verifier,
)
from scripts.benchmark_inputs import resolve_original

ROOT = resolve_original(
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts/kv-selected-tensor-observation-20261014"
)


@pytest.fixture(scope="module")
def originals():
    return verifier.load_archive(ROOT / "manifest.json", ROOT)


def test_complete_real_corpus(originals):
    result = verifier.inspect(originals)
    assert result["mixed_typed_HTTP_ACK_join"] is True
    assert result["tensor_receipts"] == 56
    assert result["whole_mixed_journal_rows"] == 201
    assert result["formal_result"] is False
    assert result["attention_consumption"] is None
    assert result["all_physical_storage_equivalence"] is None


def update(files, name, mutation):
    value = json.loads(files[name])
    mutation(value)
    files[name] = verifier.canonical(value)


def rechain(files, rows):
    previous = "0" * 64
    for row in rows:
        row["previous_sha256"] = previous
        row.pop("event_sha256")
        row["event_sha256"] = verifier.sha(verifier.canonical(row))
        previous = row["event_sha256"]
    files["runtime/run/native-raw.jsonl"] = b"".join(
        verifier.canonical(row) + b"\n" for row in rows
    )
    status = json.loads(files["runtime/run/probe/collector-after.json"])
    status["status"]["acknowledged_prefix"] = {
        "next_sequence": len(rows),
        "last_event_sha256": rows[-1]["event_sha256"],
    }
    raw = verifier.canonical(status["status"])
    status["status_raw_base64"] = base64.b64encode(raw).decode()
    status["status_raw_sha256"] = verifier.sha(raw)
    files["runtime/run/probe/collector-after.json"] = verifier.canonical(status)


def rewrite_tensor(files, event, fact):
    raw = verifier.canonical(fact)
    envelope = json.loads(base64.b64decode(event["raw_base64"]))
    for descriptor in (
        event["artifact"],
        envelope["artifact"],
        event["source_artifact"],
    ):
        descriptor["size"] = len(raw)
        descriptor["sha256"] = verifier.sha(raw)
    files["runtime/run/" + event["artifact"]["basename"]] = raw
    raw_envelope = verifier.canonical(envelope)
    event["raw_base64"] = base64.b64encode(raw_envelope).decode()
    event["raw_sha256"] = verifier.sha(raw_envelope)


@pytest.mark.parametrize(
    "case",
    [
        "HTTP503_same_body",
        "missing_payload",
        "layer_name_fork",
        "same_rank_pointer_alias",
        "destination_corruption",
        "missing_ACK",
        "foreign_cleanup_session",
        "live_NPU",
    ],
)
def test_nested_rehashed_semantic_counterexamples(originals, case):
    files = dict(originals)
    rows = [json.loads(x) for x in files["runtime/run/native-raw.jsonl"].splitlines()]
    typed = [row for row in rows if row["kind"] == "tensor.artifact.accepted"]
    if case == "HTTP503_same_body":
        for name in ("response-metadata.json", "result.json"):
            update(files, "runtime/run/probe/" + name, lambda x: x.update(status=503))
    elif case == "missing_payload":
        del files["runtime/run/" + typed[0]["artifact"]["basename"]]
    elif case in {
        "layer_name_fork",
        "same_rank_pointer_alias",
        "destination_corruption",
    }:
        event = typed[0]
        fact = json.loads(files["runtime/run/" + event["artifact"]["basename"]])
        if case == "layer_name_fork":
            fact["binding"]["layer_name"] = "model.layers.999.self_attn.attn"
        elif case == "same_rank_pointer_alias":
            rank = fact["binding"]["rank"]
            other = next(
                json.loads(files["runtime/run/" + e["artifact"]["basename"]])
                for e in typed[1:]
                if json.loads(files["runtime/run/" + e["artifact"]["basename"]])[
                    "binding"
                ]["rank"]
                == rank
            )
            for stage in ("before", "after"):
                for field in ("data_ptr", "storage_ptr"):
                    fact["cache_views"]["K"][stage][field] = other["cache_views"]["K"][
                        stage
                    ][field]
        else:
            data = bytearray(base64.b64decode(fact["destination_readback_bytes"]["K"]))
            data[0] ^= 1
            fact["destination_readback_bytes"]["K"] = base64.b64encode(data).decode()
            fact["destination_readback_sha256"]["K"] = verifier.sha(data)
        rewrite_tensor(files, event, fact)
        rechain(files, rows)
    elif case == "missing_ACK":
        update(
            files,
            "runtime/run/probe/collector-after.json",
            lambda x: x["status"].update(acknowledged_prefix={}),
        )
        value = json.loads(files["runtime/run/probe/collector-after.json"])
        raw = verifier.canonical(value["status"])
        value["status_raw_base64"] = base64.b64encode(raw).decode()
        value["status_raw_sha256"] = verifier.sha(raw)
        files["runtime/run/probe/collector-after.json"] = verifier.canonical(value)
    elif case == "foreign_cleanup_session":
        update(
            files,
            "runtime/outer-independent-terminal-audit.json",
            lambda x: x["remaining_sessions"][-1]["owner"].update(pid=1999999999),
        )
    else:
        files["runtime/run/terminal-npu-smi.txt"] += (
            b"| 3 0 | 12345 | python | 3000 |\n"
        )
    # The semantic oracle sees new payload, envelope, full chain and final ACK
    # digests; it cannot rely on the originally published digest mismatch.
    with pytest.raises((ValueError, KeyError)):
        verifier.inspect(files)
