"""Source declaration scope and original Host framing bounds; no runtime claim."""

import copy
import hashlib
from pathlib import Path

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.formal_campaign import h3_native_source_scope as scope


@pytest.fixture
def declared(tmp_path):
    rows = []
    for suffix in scope.API_SOURCE_SUFFIXES + scope.WORKER_RECEIVER_SUFFIXES:
        path = tmp_path / suffix.removeprefix("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"# CPU fixture source\n")
        rows.append(
            {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        )
    extra = tmp_path / "unfiltered_additional_source.py"
    extra.write_bytes(b"# must remain in worker/context closure\n")
    rows.append(
        {"path": str(extra), "sha256": hashlib.sha256(extra.read_bytes()).hexdigest()}
    )
    senders = [
        {
            "process": {"role": role, "ordinal": ordinal},
            "source_files": copy.deepcopy(rows),
        }
        for role, ordinal in [("api-server", 0), ("worker", 0), ("worker", 1)]
    ]
    return senders, rows


def test_role_scope_preserves_every_original_worker_and_context_source(declared):
    senders, rows = declared
    original = copy.deepcopy(senders)
    result, union = scope.scope_native_senders(senders, rows)
    assert len(result[0]["source_files"]) == len(scope.API_SOURCE_SUFFIXES)
    assert result[1]["source_files"] == result[2]["source_files"] == union
    assert {r["path"]: r["sha256"] for r in union} == {
        r["path"]: r["sha256"] for r in rows
    }
    result[0]["source_files"].clear()
    result[1]["source_files"][0]["sha256"] = "0" * 64
    assert senders == original and union[0]["sha256"] != "0" * 64


@pytest.mark.parametrize("change", ["missing", "mutated", "duplicate", "sender-extra"])
def test_missing_producer_receiver_or_mutated_declarations_reject(declared, change):
    senders, rows = declared
    if change == "missing":
        rows.pop(0)
    elif change == "mutated":
        Path(rows[0]["path"]).write_bytes(b"# changed actual source\n")
    elif change == "duplicate":
        rows.append(dict(rows[0]))
    else:
        senders[0]["source_files"].append(
            {"path": "/not/in/source/union", "sha256": "0" * 64}
        )
    with pytest.raises(ValueError):
        scope.scope_native_senders(senders, rows)


def test_actual_original_host_private_reader_and_new_preflight_have_same_bound(
    tmp_path,
):
    spec = {"fixture": "x" * 64000}
    raw = scope.checked_spec_bytes(spec)
    path = tmp_path / "native-spec.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    assert native.read_private(path, 0o600)[0] == raw
    with pytest.raises(ValueError, match="Host64KiB"):
        scope.checked_spec_bytes({"fixture": "x" * 65536})


def planned_spec(declared):
    senders, rows = declared
    scoped, _ = scope.scope_native_senders(senders, rows)
    for sender in scoped:
        sender["process"].update(
            host="CPU_FIXTURE_ONLY",
            pid=1,
            session=1,
            start_ticks=1,
            process_epoch=1,
            start_identity="pid:1:start_ticks:1",
            boot_id="00000000-0000-0000-0000-000000000000",
        )
        sender["cmdline_sha256"] = "0" * 64
    phases = []
    for i in range(60):
        rid = f"worker-replacement-r3-vanilla-vllm-entry-points/request-{i:05d}"
        phases.append(
            {
                "phase_id": f"h3-{i:05d}",
                "client_request_id": rid,
                "external_request_id": "cmpl-" + rid + "-0",
                "challenge_nonce": hashlib.sha256(rid.encode()).hexdigest()[:32],
                "expected_ranks": [0, 1],
            }
        )
    return {
        "senders": scoped,
        "phases": phases,
        "kv_requirements": {p["phase_id"]: {} for p in phases},
        "native_launch_id": "00000000-0000-4000-8000-000000000000",
        "frozen_monotonic_ns": 1,
    }


def test_prelaunch_size_upper_bound_preserves_real_RIDs_and_rejects_unknown(declared):
    spec = planned_spec(declared)
    before = copy.deepcopy(spec)
    report = scope.native_spec_size_upper_bound(spec)
    assert report["classification"] == "PRELAUNCH_DECLARATION_SIZE_UPPER_BOUND_ONLY"
    assert report["conservative_spec_bytes"] > report["actual_declared_spec_bytes"]
    assert report["native_or_kernel_authentication_performed"] is False
    assert spec == before
    spec["phases"][0]["challenge_nonce"] = None
    with pytest.raises(ValueError, match="IDs/nonces"):
        scope.native_spec_size_upper_bound(spec)


def test_prelaunch_rejects_oversize_real_declarations_without_launching(declared):
    spec = planned_spec(declared)
    for phase in spec["phases"]:
        phase["client_request_id"] += "x" * 1000
        phase["external_request_id"] = "cmpl-" + phase["client_request_id"] + "-0"
    with pytest.raises(ValueError, match="Host64KiB"):
        scope.native_spec_size_upper_bound(spec)
