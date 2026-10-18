"""Distinct conditional original-record bridge; every projection replays raw facts."""

from __future__ import annotations

import json
from pathlib import Path

from .conditional_common import (
    DOMAIN,
    canonical,
    private_directory,
    reference,
    require,
    write,
)
from .conditional_intake import replay
from .conditional_registration import validate_inputs
from .h4_sampled_record_bridge import binding, record_identity, resolve

WITNESS = "ecpa-h4-conditional-formal-record-witness/v1"
SCOPE = "actual-product-Popen-to-health200; conditional-control-costs-unobserved"


def derive(campaign_ref, launch_ref, receipt_ref, start_id, root_ref):
    campaign, launch, _, inputs = validate_inputs(
        campaign_ref, launch_ref, allow_used_paths=True
    )
    selected = [s for s in inputs["starts"] if s["start_id"] == start_id]
    require(len(selected) == 1, "exact original slot required")
    start = selected[0]
    observed = replay(
        campaign_ref, launch_ref, start_id, root_ref, receipt_ref=receipt_ref
    )
    require(
        observed["formal_start_validated"] is True
        and all(v is True for v in observed["cleanup"].values()),
        "unverified source/cleanup cannot become original record",
    )
    run = Path(start["run_directory"])
    admission = json.loads((run / "source-admission.json").read_bytes())
    epoch_path = run / "conditional-epoch.json"
    epoch = json.loads(epoch_path.read_bytes()) if epoch_path.exists() else None
    server = None if epoch is None else epoch["kernels"]["api-server/0"]
    owner = admission["owner"]
    process = dict(
        launcher_pid=owner["pid"],
        launcher_start_ticks=owner["start_ticks"],
        server_pid=None if server is None else server["pid"],
        server_start_ticks=None if server is None else server["start_ticks"],
        boot_id=owner["boot_id"],
    )
    fields = (
        "startup_phases_ms",
        "throughput",
        "latency_median_ms",
        "latency_p95_ms",
        "latency_p99_ms",
        "cpu_ms",
        "host_memory_bytes",
        "device_memory_bytes",
        "process_messages",
        "evidence_bytes",
        "gate_open_ms",
        "failure_detection_ms",
        "rollback_ms",
        "recovery_ms",
    )
    metrics = dict.fromkeys(fields)
    if observed["performance_eligible"]:
        from .analyze import _percentile

        measured = [r for r in observed["trace"]["rows"] if r["kind"] == "measured"]
        require(len(measured) == 256, "original measured256 missing")
        elapsed = (
            max(r["complete_ns"] for r in measured)
            - min(r["dispatch_ns"] for r in measured)
        ) / 1e9
        require(elapsed > 0, "actual finite measured window invalid")
        latencies = [(r["complete_ns"] - r["dispatch_ns"]) / 1e6 for r in measured]
        timing = json.loads((run / "phase0.product-popen-timing.json").read_bytes())
        health = observed["startup_readiness"]["first_health"]
        total = (health["observed_ns"] - timing["before_ns"]) / 1e6
        require(total > 0, "first original health200 predates product Popen")
        metrics.update(
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
            | dict(total=total),
            throughput=256 / elapsed,
            latency_median_ms=_percentile(latencies, 0.5),
            latency_p95_ms=_percentile(latencies, 0.95),
            latency_p99_ms=_percentile(latencies, 0.99),
            cpu_ms=observed["resources"]["cpu_ms"],
            host_memory_bytes=observed["resources"]["peak_host_rss_bytes"],
            device_memory_bytes=observed["resources"]["peak_device_memory_bytes"],
            measurement_scope=SCOPE,
        )
    # Internal control IPC/phase costs were not exhaustively observed. Null is
    # intentional; no sum of public journal lines claims every process message.
    return campaign, launch, start, observed, process, metrics


def auxiliary(observed, process):
    trace = observed["trace"]
    return dict(
        schema="ecpa-h4-conditional-derived-request-coverage/v1",
        expected=272,
        observed_started=0 if trace is None else len(trace["started"]),
        observed_completed=0 if trace is None else len(trace["rows"]),
        coverage=observed["coverage"],
        effect_coverage=observed["effect_coverage"],
    ), dict(
        schema="ecpa-h4-conditional-derived-process-binding/v1",
        process_identity=process,
    )


def project(campaign, launch, start, observed, process, metrics, artifacts):
    return dict(
        schema="ecpa-formal-campaign-record/v1",
        measurement_domain=DOMAIN,
        campaign_id=campaign["campaign_id"],
        evidence_class="formal-real",
        deployment=dict(
            registration_state="registered",
            receipt_sha256=artifacts["deployment_receipt"]["sha256"],
        ),
        cell_id=campaign["cell_id"],
        start_id=start["start_id"],
        status=observed["status"],
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        process_identity=process,
        identity=record_identity(campaign, launch),
        artifacts=artifacts,
        cleanup=observed["cleanup"],
        metrics=metrics,
        failure=None
        if observed["status"] == "complete"
        else dict(
            phase="runtime-observation",
            **{"class": "AuthenticatedConditionalFailureOrUnknown"},
        ),
    )


def export(
    campaign_path, launch_path, receipt_path, start_id, root_ref, output, artifact_root
):
    root = Path(artifact_root).resolve()
    output = Path(output)
    for path in (campaign_path, launch_path, receipt_path, root_ref["path"]):
        binding(Path(path), root)
    c, launch_value, s, o, p, m = derive(
        reference(campaign_path),
        reference(launch_path),
        reference(receipt_path),
        start_id,
        root_ref,
    )
    require(output.is_relative_to(root), "record output escapes artifact root")
    private_directory(output)
    write(output / "independent-start-observation.json", o)
    requests, snapshot = auxiliary(o, p)
    write(output / "derived-request-coverage.json", requests)
    write(output / "derived-process-binding.json", snapshot)
    witness = dict(
        schema=WITNESS,
        campaign=binding(campaign_path, root),
        launch=binding(launch_path, root),
        receipt=binding(receipt_path, root),
        root_cleanup=binding(root_ref["path"], root),
        observation=binding(output / "independent-start-observation.json", root),
        start_id=start_id,
    )
    write(output / "record-witness.json", witness)
    artifacts = dict(
        deployment_receipt=binding(receipt_path, root),
        raw_log=binding(
            Path(s["run_directory"]) / "conditional-source-result.json", root
        ),
        request_results=binding(output / "derived-request-coverage.json", root),
        process_snapshot=binding(output / "derived-process-binding.json", root),
        cleanup_report=binding(root_ref["path"], root),
        raw_measurement=binding(output / "record-witness.json", root),
    )
    record = project(c, launch_value, s, o, p, m, artifacts)
    import jsonschema

    jsonschema.Draft7Validator(
        json.loads(Path(__file__).with_name("record.schema.json").read_bytes())
    ).validate(record)
    write(output / "record.json", record)
    return record


def verify_record(record, witness, artifact_root, campaign_spec):
    root = Path(artifact_root).resolve()
    require(
        record.get("measurement_domain") == DOMAIN
        and witness["schema"] == WITNESS
        and witness["start_id"] == record["start_id"],
        "wrong original conditional witness domain",
    )
    paths = {
        k: resolve(root, witness[k])
        for k in ("campaign", "launch", "receipt", "root_cleanup", "observation")
    }
    require(
        paths["campaign"] == Path(campaign_spec["_path"])
        and witness["campaign"]["sha256"] == campaign_spec["_sha256"],
        "frozen original campaign changed",
    )
    c, launch_value, s, o, p, m = derive(
        reference(paths["campaign"]),
        reference(paths["launch"]),
        reference(paths["receipt"]),
        record["start_id"],
        reference(paths["root_cleanup"]),
    )
    require(
        canonical(json.loads(paths["observation"].read_bytes())) == canonical(o),
        "record observation is not current strict raw replay",
    )
    requests, snapshot = auxiliary(o, p)
    require(
        json.loads(resolve(root, record["artifacts"]["request_results"]).read_bytes())
        == requests
        and json.loads(
            resolve(root, record["artifacts"]["process_snapshot"]).read_bytes()
        )
        == snapshot,
        "derived coverage/process binding changed",
    )
    require(
        record["artifacts"]["deployment_receipt"] == binding(paths["receipt"], root)
        and record["artifacts"]["cleanup_report"]
        == binding(paths["root_cleanup"], root)
        and record["artifacts"]["raw_log"]
        == binding(Path(s["run_directory"]) / "conditional-source-result.json", root),
        "record artifact roles changed",
    )
    require(
        canonical(record)
        == canonical(project(c, launch_value, s, o, p, m, record["artifacts"])),
        "original conditional record differs from raw facts",
    )
