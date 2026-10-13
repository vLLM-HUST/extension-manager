"""Retained real inference and independent authority cannot be promoted or replayed."""

import json
from pathlib import Path

import pytest

from experiments.exposure_gate.qualification_verify import (
    QualificationError,
    unpack_qualification,
    verify_qualification,
)

PACKAGE = Path(__file__).resolve().parents[1] / (
    "experiments/exposure_gate/artifacts/real-invocation-gate-qualification-20261013"
)


@pytest.fixture
def retained(tmp_path):
    unpack_qualification(PACKAGE, tmp_path)
    return tmp_path


def rewrite(root, name, change):
    path = root / name
    value = json.loads(path.read_bytes())
    change(value)
    path.write_text(json.dumps(value))


def wrong_model(value):
    body = json.loads(value["body"])
    body["model"] = "other-model"
    value["body"] = json.dumps(body)


def test_retained_real_gate_has_only_invocation_qualification(retained):
    verified = verify_qualification(retained)
    assert verified["classification"] == "QUALIFIED_NONFORMAL"
    assert verified["formal_result"] is False
    assert verified["effective_semantics_result"] is False
    assert verified["worker_invocation_coverage_partial"] == 0.5
    assert verified["real_model_completions"] == 1
    assert verified["blocked_requests"] == 2


@pytest.mark.parametrize(
    "filename,change",
    [
        ("result.json", lambda v: v.update(formal_result=True)),
        ("result.json", lambda v: v.update(performance_result=True)),
        ("result.json", lambda v: v.update(launch_id="launch:replayed")),
        ("authorization.json", lambda v: v.update(launch_id="launch:replayed")),
        ("authorization.json", lambda v: v["bindings"][0].update(name="other")),
        ("cleanup-ports.json", lambda v: v.update({"8187": 0})),
        ("proxy-completion.json", wrong_model),
        ("after-open-blocked-http.json", lambda v: v.update(status=200)),
        ("after-open-route.json", lambda v: v.update(generation=1)),
        ("authorization.json.claim", lambda v: v.update(authority_pid=1)),
    ],
)
def test_tampered_result_cannot_qualify(retained, filename, change):
    rewrite(retained, filename, change)
    with pytest.raises((QualificationError, KeyError)):
        verify_qualification(retained)


def test_changing_effect_record_cannot_replace_original_host_journal(retained):
    def change(value):
        obligation = next(iter(value["obligations"].values()))
        obligation["effect_records"][0]["line_number"] = 1

    rewrite(retained, "complete-observation.json", change)
    with pytest.raises(QualificationError, match="retained Host journal"):
        verify_qualification(retained)


def test_replayed_authority_line_invalidates_hash_chain(retained):
    path = retained / "authority.jsonl"
    rows = path.read_bytes().splitlines(keepends=True)
    rows[4] = rows[3]
    path.write_bytes(b"".join(rows))
    with pytest.raises(ValueError):
        verify_qualification(retained)


def test_missing_npu_cleanup_never_qualifies(retained):
    (retained / "cleanup-npu.txt").write_text("device process still running\n")
    with pytest.raises(QualificationError, match="NPU cleanup"):
        verify_qualification(retained)
