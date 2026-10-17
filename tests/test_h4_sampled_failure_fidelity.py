"""SOURCE-ONLY candidate cases. Never device qualification or formal results."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments.formal_campaign import h4_sampled_intake as intake
from experiments.formal_campaign.analyze import (
    h4_body_binding,
    h4_request_identity_observation,
    h4_response_summary,
)
from experiments.formal_campaign.run_h4_sampled import source_admission


def traffic():
    body = json.dumps(
        dict(model="selected-model", prompt="frozen", max_tokens=64)
    ).encode()
    schedule, rows = {"requests": []}, []
    selected = set(range(16)) | {16 + 16 * i for i in range(16)}
    for i in range(272):
        rid = f"actual-start/request-{i:04d}"
        response = json.dumps(
            dict(
                id="cmpl-" + rid,
                model="selected-model",
                choices=[dict(index=0, text="output", finish_reason="length")],
                usage=dict(prompt_tokens=1195, completion_tokens=16, total_tokens=1211),
            )
        ).encode()
        evidence = dict(status_code=200, headers=[], **h4_body_binding(response))
        headers = [["X-Request-Id", rid]]
        schedule["requests"].append(
            dict(
                all_index=i,
                request_id=rid,
                selected=i in selected,
                body_sha256=hashlib.sha256(body).hexdigest(),
            )
        )
        row = dict(
            all_index=i,
            request_id=rid,
            selected=i in selected,
            kind="warmup" if i < 16 else "measured",
            dispatch_ns=1 + i * 10,
            complete_ns=2 + i * 10,
            http_request=h4_body_binding(body),
            http_response=evidence,
            request_headers=headers,
            request_identity=h4_request_identity_observation(rid, headers, evidence),
            native_clock=dict(
                sent_ns=100 + i,
                backend_sent_ns=101 + i,
                received_ns=102 + i,
                deadline_ns=120_000_000_100 + i,
                http_deadline_met=True,
            ),
            native_verified=i in selected,
            native_error=None,
            error=None,
        )
        row.update(h4_response_summary(evidence))
        rows.append(row)
    return rows, schedule, body


def test_partial_traffic_preserves_exact_observed_count_and_strict_default():
    rows, schedule, body = traffic()
    with pytest.raises(ValueError, match="coverage"):
        intake.verify_traffic(rows[:7], schedule, body)
    assert (
        len(intake.verify_traffic(rows[:7], schedule, body, allow_incomplete=True)) == 7
    )
    assert intake.verify_traffic([], schedule, body, allow_incomplete=True) == []


@pytest.mark.parametrize(
    "case", ["duplicate", "body", "deadline", "unknown", "warmup-gap"]
)
def test_partial_does_not_excuse_corrupt_existing_rows(case):
    rows, schedule, body = traffic()
    rows = copy.deepcopy(rows[:17])
    if case == "duplicate":
        rows[-1] = copy.deepcopy(rows[-2])
    elif case == "body":
        rows[-1]["http_request"]["body_sha256"] = "sha256:" + "0" * 64
    elif case == "deadline":
        rows[-1]["native_clock"]["deadline_ns"] += 1
    elif case == "unknown":
        rows[-1]["request_id"] = "not-registered"
    else:
        rows.pop(0)
    with pytest.raises(ValueError):
        intake.verify_traffic(rows, schedule, body, allow_incomplete=True)


def test_real_503_error_body_is_observed_failure_not_fabricated_completion():
    rows, schedule, body = traffic()
    row = rows[0]
    evidence = dict(
        status_code=503,
        headers=[],
        **h4_body_binding(b'{"error":{"message":"not ready"}}'),
    )
    row.update(
        http_response=evidence,
        native_verified=False,
        native_error="ValueError: non200",
        request_identity=h4_request_identity_observation(
            row["request_id"], row["request_headers"], evidence
        ),
    )
    row.update(h4_response_summary(evidence))
    assert (
        intake.verify_traffic(rows, schedule, body, allow_incomplete=True)[0][
            "status_code"
        ]
        == 503
    )
    observation = intake.failed_observation(
        dict(cell_id="original-cell"),
        dict(start_id="registered-1", arm="ecpa", repetition=1, arm_order=2),
        dict(path="/root/checked-cleanup", sha256="a" * 64),
        rows=rows,
        verified=[],
        reason=dict(kind="observed-native-failure"),
    )
    assert observation["status"] == "failed"
    assert observation["formal_start_validated"] is True
    assert observation["all_http_request_count"] == 272
    assert observation["resources"] is observation["successful_measured"] is None
    assert observation["performance_eligible"] is observation["formal_result"] is False
    assert observation["source_native_complete"] is False


def test_admission_binds_receipt_epoch_phase_and_exact_numeric_types():
    campaign = dict(_raw_sha256="sha256:" + "a" * 64)
    start = dict(
        start_id="original-1", phase=dict(path="/root/new-phase", sha256="b" * 64)
    )
    receipt, phase, closure = (
        dict(source="fresh"),
        dict(argv=["/exact/python"]),
        dict(version="actual"),
    )
    timing = dict(before_ns=10, after_ns=11, before_monotonic_ns=20)
    owner = dict(pid=42, start_ticks=3, session=42, boot_id="boot")
    first = source_admission(
        campaign,
        start,
        receipt,
        phase,
        closure,
        dict(candidate_generation=1),
        owner,
        timing,
    )
    changed = source_admission(
        campaign,
        start,
        receipt,
        phase,
        closure,
        dict(candidate_generation=True),
        owner,
        timing,
    )
    assert first["semantic_launch_sha256"] != changed["semantic_launch_sha256"]
    assert (
        source_admission(
            campaign,
            start,
            dict(source="other"),
            phase,
            closure,
            dict(candidate_generation=1),
            owner,
            timing,
        )["receipt_sha256"]
        != first["receipt_sha256"]
    )


def test_root_terminal_file_pin_detects_substitution_and_missing_file(tmp_path):
    path = tmp_path / "source-admission.json"
    path.write_text('{"observed":"one"}')
    root = dict(
        terminal_artifacts={str(path): hashlib.sha256(path.read_bytes()).hexdigest()}
    )
    intake.pinned_terminal(root, tmp_path)
    path.write_text('{"observed":"two"}')
    with pytest.raises(ValueError):
        intake.pinned_terminal(root, tmp_path)
    path.unlink()
    with pytest.raises(ValueError):
        intake.pinned_terminal(root, tmp_path)


@pytest.mark.parametrize("cleanup_ok", [True, False])
def test_queue_retains_failed_slot_and_only_continues_after_independent_release(
    tmp_path, monkeypatch, cleanup_ok
):
    """Transport is mocked here; this is queue behavior, never native proof."""
    import sys
    from types import SimpleNamespace

    from experiments.formal_campaign import h4_sampled_queue as queue

    output = tmp_path / "queue"
    starts = [
        dict(
            start_id=f"original-{i}",
            phase=dict(path="/root/frozen-phase", sha256="a" * 64),
        )
        for i in range(9)
    ]
    phase = dict(argv=[sys.executable], cwd=str(tmp_path), environment={"LANG": "C"})
    monkeypatch.setattr(queue.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        queue,
        "validate_inputs",
        lambda *a: (dict(cell_id="original-cell"), None, None, dict(starts=starts)),
    )
    monkeypatch.setattr(queue, "checked", lambda ref: json.dumps(phase).encode())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "queue",
            "--campaign",
            str(tmp_path / "campaign"),
            "--launch-spec",
            str(tmp_path / "launch"),
            "--deployment-receipt",
            str(tmp_path / "receipt"),
            "--output",
            str(output),
        ],
    )
    calls = []

    def transport(argv, **kwargs):
        calls.append(argv)
        target = Path(argv[argv.index("--output") + 1])
        if "experiments.formal_campaign.h4_sampled_root_observer" in argv:
            if not cleanup_ok:
                return SimpleNamespace(returncode=2)
            target.mkdir()
            (target / "independent-root-terminal.json").write_text('{"released":true}')
        else:
            target.write_text(
                json.dumps(
                    dict(
                        formal_start_validated=True,
                        performance_eligible=False,
                        status="failed",
                        coverage="incomplete-observed",
                        observed_failure=dict(kind="actual-timeout"),
                    )
                )
            )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(queue.subprocess, "run", transport)
    assert queue.main() == (0 if cleanup_ok else 2)
    terminal = json.loads((output / "queue-terminal.json").read_bytes())
    if cleanup_ok:
        assert len(terminal["rows"]) == 9
        assert [r["start_id"] for r in terminal["rows"]] == [
            s["start_id"] for s in starts
        ]
        assert all(
            r["status"] == "failed" and not r["performance_eligible"]
            for r in terminal["rows"]
        )
        assert len(calls) == 18  # one observer + one intake; no retries
    else:
        assert terminal["rows"] == []
        assert len(calls) == 1
        assert terminal["error"] is not None
