"""Real corpus and forged completeness claims use the original frozen predicate."""

import base64
import json
from pathlib import Path

import pytest

from experiments.formal_campaign import verify_attention_source_drained_observation as v

ARCHIVE = (
    Path(__file__).parents[1]
    / "experiments/formal_campaign/artifacts"
    / "attention-source-drained-observation-20261014-r4"
)


@pytest.fixture(scope="module")
def corpus():
    return v.load_archive(ARCHIVE / "manifest.json", ARCHIVE)


def test_real_complete_prefix_with_original_host_access_denied(corpus):
    result = v.inspect(corpus)
    assert result["observed_typed_HTTP_ACK_join"] is True
    assert result["model_task_passed"] is True
    assert result["operator_receipt_count"] == 56
    assert result["formal_result"] is False
    assert result["formal_H3_starts"] == result["formal_H4_starts"] == 0
    assert result["full_model_quality"] is result["performance_result"] is None


def rewrite_status(files, mutate):
    name = "runtime/run/probe/collector-after.json"
    receipt = json.loads(files[name])
    mutate(receipt["status"])
    raw = json.dumps(receipt["status"], sort_keys=True, separators=(",", ":")).encode()
    receipt["status_raw_base64"] = base64.b64encode(raw).decode()
    receipt["status_raw_sha256"] = v.sha(raw)
    files[name] = json.dumps(receipt).encode()


def test_partial_ack_is_rejected_even_with_intact_task_and_operator_records(corpus):
    files = dict(corpus)
    rewrite_status(
        files,
        lambda s: s["acknowledged_prefix"].update(next_sequence=259),
    )
    with pytest.raises(ValueError, match="frozen replay failed"):
        v.inspect(files)


def test_forged_sealed_status_cannot_replace_second_worker_closure(corpus):
    files = dict(corpus)
    name = "runtime/run/native-raw.jsonl"
    rows = files[name].splitlines()
    assert json.loads(rows[-1])["kind"] == "attention.worker.drained"
    rows.pop()
    files[name] = b"\n".join(rows) + b"\n"
    prefix = dict(
        next_sequence=len(rows), last_event_sha256=json.loads(rows[-1])["event_sha256"]
    )

    def mutate(status):
        status["acknowledged_prefix"] = prefix
        for state in status["source_drain"]["runtimes"].values():
            state["sealed_prefix"] = prefix

    rewrite_status(files, mutate)
    with pytest.raises(ValueError, match="frozen replay failed"):
        v.inspect(files)


def test_corrupt_selected_tensor_bytes_are_rejected(corpus):
    files = dict(corpus)
    rows = [json.loads(x) for x in files["runtime/run/native-raw.jsonl"].splitlines()]
    event = next(x for x in rows if x["kind"] == "tensor.artifact.accepted")
    name = "runtime/run/" + event["artifact"]["basename"]
    raw = files[name]
    files[name] = bytes([raw[0] ^ 1]) + raw[1:]
    with pytest.raises(ValueError, match="frozen replay failed"):
        v.inspect(files)


def test_live_source_peer_in_original_cleanup_is_rejected(corpus):
    files = dict(corpus)
    name = "runtime/run/terminal-process-audit.json"
    terminal = json.loads(files[name])
    terminal["source_peers"][0]["same_identity_live"] = True
    files[name] = json.dumps(terminal).encode()
    with pytest.raises(ValueError, match="source peer epoch cleanup differs"):
        v.inspect(files)


def test_peer_epoch_cannot_be_substituted_in_original_host_evidence(corpus):
    files = dict(corpus)
    binding = json.loads(files["runtime/run/native-binding.json"])
    name = "runtime/" + Path(binding["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
    rows = [json.loads(x) for x in files[name].splitlines()]
    row = next(
        r
        for r in rows
        if r["event"] == "invoked" and r["entry_point"]["name"] == "ascend_kvcompress"
    )
    prefix, ticks = row["process"]["start_identity"].rsplit(":", 1)
    row["process"]["start_identity"] = prefix + ":" + str(int(ticks) + 1)
    files[name] = b"".join(json.dumps(r).encode() + b"\n" for r in rows)
    with pytest.raises(ValueError, match="actual Host process epoch or launch differs"):
        v.inspect(files)
