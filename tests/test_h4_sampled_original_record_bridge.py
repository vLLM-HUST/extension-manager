"""Unrun source cases; projection mocks do not establish native qualification."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments.formal_campaign import analyze
from experiments.formal_campaign import h4_sampled_record_bridge as bridge


def inputs():
    fixed = dict(
        manager_commit="a" * 40,
        host_commit="b" * 40,
        accelerator_commit="c" * 40,
        plugins={
            "actual-KV": dict(commit="d" * 40),
            "actual-profiler": dict(commit="e" * 40),
        },
        host_version="actual-host-version",
        accelerator_version="actual-accelerator-version",
        model_digest="sha256:" + "f" * 64,
        hardware="actual-hardware",
        topology="TP2",
        warm_state="warm",
    )
    campaign = dict(
        campaign_id="H4-matched-cost-v1",
        cell_id=bridge.CELL,
        fixed_identity=fixed,
        workload=dict(sha256="sha256:" + "1" * 64),
    )
    launch = dict(container_digest="sha256:" + "2" * 64)
    start = dict(
        start_id="actual-registered-slot", arm="ecpa", repetition=1, arm_order=3
    )
    observation = dict(
        status="failed",
        source_native_complete=False,
        full_native_sample_count=0,
        all_http_request_count=7,
        performance_eligible=False,
    )
    process = dict(
        launcher_pid=100,
        launcher_start_ticks=20,
        server_pid=None,
        server_start_ticks=None,
        boot_id="actual-boot",
    )
    artifacts = {
        key: dict(path=key, sha256="sha256:" + str(i) * 64)
        for i, key in enumerate(
            (
                "deployment_receipt",
                "raw_log",
                "request_results",
                "process_snapshot",
                "cleanup_report",
                "raw_measurement",
            )
        )
    }
    return campaign, launch, start, observation, process, artifacts


def test_failed_record_projection_preserves_actual_identity_and_unknown_metrics(
    tmp_path,
):
    campaign, launch, start, observation, process, artifacts = inputs()
    metrics = bridge.observed_metrics(observation, tmp_path)
    record = bridge.project(
        campaign, launch, start, observation, process, metrics, artifacts
    )
    assert record["status"] == "failed"
    assert record["cell_id"] == "compatible-resource-pair.sampled-invocation"
    assert record["identity"]["plugin_commits"] == {
        "actual-KV": "d" * 40,
        "actual-profiler": "e" * 40,
    }
    assert record["identity"]["container_digest"] == launch["container_digest"]
    assert all(value is None for value in record["metrics"].values())
    assert record["failure"] == {
        "phase": "runtime-observation",
        "class": "AuthenticatedSourceAdmittedFailure",
    }
    assert record["process_identity"]["server_pid"] is None


@pytest.mark.parametrize("mutate", ["missing-proof", "partial-traffic", "not-eligible"])
def test_success_projection_cannot_invent_original32_positive_proofs(tmp_path, mutate):
    observation = dict(
        status="succeeded",
        source_native_complete=True,
        full_native_sample_count=32,
        all_http_request_count=272,
        performance_eligible=True,
    )
    if mutate == "missing-proof":
        observation["full_native_sample_count"] = 31
    elif mutate == "partial-traffic":
        observation["all_http_request_count"] = 271
    else:
        observation["performance_eligible"] = False
    with pytest.raises(ValueError, match="original32"):
        bridge.observed_metrics(observation, tmp_path)


@pytest.mark.parametrize(
    "kind", ["preflight", "corrupt-native", "cleanup-not-released"]
)
def test_export_does_not_catch_or_promote_strict_admission_rejection(
    tmp_path, monkeypatch, kind
):
    def reject(*args, **kwargs):
        raise ValueError(kind)

    monkeypatch.setattr(bridge, "derive", reject)
    target = tmp_path / "new-record"
    for name in ("campaign", "launch", "receipt", "root-cleanup"):
        (tmp_path / name).write_text("{}")
    root = tmp_path / "root-cleanup"
    root_ref = dict(
        path=str(root), sha256=hashlib.sha256(root.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match=kind):
        bridge.export(
            tmp_path / "campaign",
            tmp_path / "launch",
            tmp_path / "receipt",
            "actual-slot",
            root_ref,
            target,
            tmp_path,
        )
    assert not target.exists()


def test_verified_witness_rejects_observation_only_flag_domain(tmp_path):
    campaign, launch, start, observation, process, artifacts = inputs()
    record = bridge.project(
        campaign,
        launch,
        start,
        observation,
        process,
        bridge.observed_metrics(observation, tmp_path),
        artifacts,
    )
    with pytest.raises(ValueError, match="witness domain"):
        bridge.verify_record(
            record,
            dict(schema=bridge.WITNESS, formal_start_validated=True),
            tmp_path,
            {},
        )


def indexed_record(status="failed"):
    return dict(
        start_id="source-admitted-actual-slot",
        status=status,
        cell_id=bridge.CELL,
        cleanup=dict(
            processes_reclaimed=True, ports_reclaimed=True, devices_reclaimed=True
        ),
        metrics={},
    )


def test_original_failed_start_policy_falsifies_without_claiming_all36(
    tmp_path, monkeypatch
):
    protocol = analyze.load_protocol()
    record = indexed_record()
    missing = [
        f"{cell}/r{rep}/{arm}"
        for cell in protocol["h4"]["required_cells"]
        for rep in range(1, 4)
        for arm in protocol["arms"]
    ][1:]
    # Intake is replaced only to exercise aggregation after admission; this unit
    # test cannot make unverified records pass the production raw verifier.
    monkeypatch.setattr(
        analyze,
        "_validate_intake",
        lambda *args: (missing, {(bridge.CELL, 1, "ecpa"): record}),
    )
    summary = analyze.analyze_h4(
        protocol, [record], tmp_path, dict(cell_id=bridge.CELL)
    )
    assert summary["status"] == "falsified"
    assert summary["formal_result"] is True
    assert summary["campaign_complete"] is False
    assert summary["received_starts"] == 1 and summary["required_starts"] == 36
    assert summary["missing"] == missing
    assert summary["metrics"] is None
    assert summary["failed_starts"] == [record["start_id"]]


def test_positive_partial_population_remains_incomplete_not_hypothesis_pass(
    tmp_path, monkeypatch
):
    protocol = analyze.load_protocol()
    record = indexed_record("complete")
    record["metrics"] = dict(measurement_scope=bridge.SCOPE)
    monkeypatch.setattr(
        analyze,
        "_validate_intake",
        lambda *args: (["missing-original-slots"], {(bridge.CELL, 1, "ecpa"): record}),
    )
    summary = analyze.analyze_h4(
        protocol, [record], tmp_path, dict(cell_id=bridge.CELL)
    )
    assert summary["status"] == "incomplete" and summary["formal_result"] is False
    assert any("product-phase-bins-unobserved" in value for value in summary["missing"])


def test_four_cell_registry_refuses_cell_relabel_and_modified_campaign(
    tmp_path, monkeypatch
):
    protocol = analyze.load_protocol()
    refs = {}
    for i, cell in enumerate(protocol["h4"]["required_cells"]):
        path = tmp_path / f"campaign-{i}.json"
        path.write_text(json.dumps(dict(cell_id=cell)))
        refs[cell] = dict(
            path=str(path),
            sha256="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    registry = tmp_path / "campaigns.json"
    registry.write_text(
        json.dumps(
            dict(schema="ecpa-h4-original-cell-campaign-registry/v1", campaigns=refs)
        )
    )
    # The real campaign schema/receipt/source validation is exercised separately;
    # here only the explicit registry path/SHA and cell-join boundary is isolated.
    monkeypatch.setattr(
        analyze, "load_h4_campaign", lambda path: json.loads(path.read_bytes())
    )
    assert len(analyze.load_h4_campaign_registry(registry)["_h4_cell_campaigns"]) == 4
    first = next(iter(refs))
    wrong = copy.deepcopy(refs)
    wrong[first] = refs[protocol["h4"]["required_cells"][1]]
    registry.write_text(
        json.dumps(
            dict(schema="ecpa-h4-original-cell-campaign-registry/v1", campaigns=wrong)
        )
    )
    with pytest.raises(ValueError, match="relabels"):
        analyze.load_h4_campaign_registry(registry)
    registry.write_text(
        json.dumps(
            dict(schema="ecpa-h4-original-cell-campaign-registry/v1", campaigns=refs)
        )
    )
    Path(refs[first]["path"]).write_text('{"cell_id":"tampered"}')
    with pytest.raises(ValueError, match="bytes changed"):
        analyze.load_h4_campaign_registry(registry)


@pytest.mark.parametrize(
    "mutation",
    [None, "status", "identity", "metric", "observation-bytes", "cleanup-role"],
)
def test_analyzer_bridge_replays_then_rejects_any_changed_projection(
    tmp_path, monkeypatch, mutation
):
    """Isolate bridge joins after a stubbed strict intake; never a native pass."""
    campaign, launch, start, observation, process, _ = inputs()
    run = tmp_path / "original-run"
    run.mkdir()
    start["run_directory"] = str(run)
    observation.update(
        coverage="incomplete-observed", observed_failure=dict(kind="actual-timeout")
    )
    (run / "source-admission.json").write_text("{}")
    for name in ("campaign", "launch", "receipt", "cleanup"):
        (tmp_path / name).write_text("{}")
    metrics = bridge.observed_metrics(observation, run)
    calls = []
    expected = copy.deepcopy((campaign, launch, start, observation, process, metrics))

    def strict_intake(*args):
        calls.append(args)
        return copy.deepcopy(expected)

    monkeypatch.setattr(bridge, "derive", strict_intake)
    (tmp_path / "observation").write_bytes(bridge.canonical(observation))
    requests, snapshot = bridge.auxiliary(run, observation, process, tmp_path)
    (tmp_path / "requests").write_bytes(bridge.canonical(requests))
    (tmp_path / "process").write_bytes(bridge.canonical(snapshot))
    witness = dict(
        schema=bridge.WITNESS,
        **{
            key: bridge.binding(tmp_path / filename, tmp_path)
            for key, filename in (
                ("campaign", "campaign"),
                ("launch", "launch"),
                ("receipt", "receipt"),
                ("root_cleanup", "cleanup"),
                ("observation", "observation"),
            )
        },
        start_id=start["start_id"],
    )
    (tmp_path / "witness").write_bytes(bridge.canonical(witness))
    artifacts = {
        key: bridge.binding(tmp_path / filename, tmp_path)
        for key, filename in (
            ("deployment_receipt", "receipt"),
            ("request_results", "requests"),
            ("process_snapshot", "process"),
            ("cleanup_report", "cleanup"),
            ("raw_measurement", "witness"),
        )
    }
    artifacts["raw_log"] = bridge.binding(run / "source-admission.json", tmp_path)
    record = bridge.project(
        campaign, launch, start, observation, process, metrics, artifacts
    )
    spec = dict(
        _path=str(tmp_path / "campaign"),
        _sha256=bridge.binding(tmp_path / "campaign", tmp_path)["sha256"],
    )
    if mutation == "status":
        record["status"] = "complete"
    elif mutation == "identity":
        record["identity"]["host_commit"] = "0" * 40
    elif mutation == "metric":
        record["metrics"]["throughput"] = 999
    elif mutation == "observation-bytes":
        (tmp_path / "observation").write_text('{"formal_start_validated":true}')
    elif mutation == "cleanup-role":
        record["artifacts"]["cleanup_report"] = bridge.binding(
            tmp_path / "process", tmp_path
        )
    if mutation is None:
        bridge.verify_record(record, witness, tmp_path, spec)
    else:
        with pytest.raises(ValueError):
            bridge.verify_record(record, witness, tmp_path, spec)
    assert len(calls) == 1  # no caller observation flag avoids strict re-intake


def test_original_record_schema_keeps_unknowns_null_only_in_named_sampled_domain():
    import jsonschema

    schema = json.loads(
        Path(bridge.__file__).with_name("record.schema.json").read_bytes()
    )
    validator = jsonschema.Draft7Validator(schema)
    campaign, launch, start, observation, process, artifacts = inputs()
    failed = bridge.project(
        campaign,
        launch,
        start,
        observation,
        process,
        bridge.observed_metrics(observation, Path("/unused")),
        artifacts,
    )
    validator.validate(failed)
    # Schema-only representative metrics, not native qualification. Actual bridge
    # publication still requires derive()->strict intake before any complete row.
    complete = copy.deepcopy(failed)
    complete.update(status="complete", failure=None)
    complete["metrics"] = dict(
        startup_phases_ms=dict.fromkeys(
            (
                "discovery",
                "validation",
                "planning",
                "rendering",
                "worker_loading",
                "evidence_setup",
            )
        )
        | dict(total=1),
        throughput=1,
        latency_median_ms=1,
        latency_p95_ms=1,
        latency_p99_ms=1,
        cpu_ms=1,
        host_memory_bytes=1,
        device_memory_bytes=1,
        process_messages=None,
        evidence_bytes=None,
        gate_open_ms=None,
        failure_detection_ms=None,
        rollback_ms=None,
        recovery_ms=None,
        measurement_scope=bridge.SCOPE,
    )
    complete["process_identity"].update(server_pid=100, server_start_ticks=20)
    validator.validate(complete)
    del complete["measurement_domain"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(complete)
