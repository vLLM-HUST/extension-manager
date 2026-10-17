"""Original H4 record bridge: independently replayed starts, never receipt promotion.

This prospective adapter retains authenticated failed original slots. Successful
starts still need all32 strict native proofs. Unobserved product phase/control
metrics stay null; this adapter cannot turn them into an H4 performance PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import jsonschema

from .analyze import _percentile, load_protocol
from .h4_sampled_intake import intake
from .h4_sampled_native_replay import check_ref
from .h4_sampled_registration import CELL, validate_inputs
from .run_h4_sampled import write_new

DOMAIN = "ecpa-h4-sampled-native-record/v1"
WITNESS = "ecpa-h4-sampled-formal-record-witness/v1"
SCOPE = "actual-product-Popen-to-health200; native-sampled-control-costs-unobserved"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def binding(path, root):
    path, root = Path(path), Path(root).resolve()
    require(
        path.is_absolute()
        and path.resolve() == path
        and not path.is_symlink()
        and path.is_relative_to(root)
        and path.is_file(),
        "unsafe original36 artifact path",
    )
    return dict(
        path=path.relative_to(root).as_posix(),
        sha256="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def resolve(root, ref):
    require(
        type(ref) is dict and set(ref) == {"path", "sha256"},
        "strict record artifact reference required",
    )
    path = Path(root) / ref["path"]
    require(
        path.resolve().is_relative_to(Path(root).resolve()),
        "record artifact escapes root",
    )
    return check_ref(dict(path=str(path), sha256=ref["sha256"]))


def record_identity(campaign, launch):
    fixed = campaign["fixed_identity"]
    return dict(
        manager_commit=fixed["manager_commit"],
        host_commit=fixed["host_commit"],
        accelerator_commit=fixed["accelerator_commit"],
        plugin_commits={
            name: item["commit"] for name, item in fixed["plugins"].items()
        },
        provider_versions=dict(
            host=fixed["host_version"], accelerator=fixed["accelerator_version"]
        ),
        model_digest=fixed["model_digest"],
        workload_digest=campaign["workload"]["sha256"],
        hardware=fixed["hardware"],
        topology=fixed["topology"],
        warm_state=fixed["warm_state"],
        container_digest=launch["container_digest"],
    )


def observed_metrics(observation, run):
    """Only derive measured values after the strict original32 positive intake."""
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
    if observation["status"] == "failed":
        return dict.fromkeys(fields)
    require(
        observation["source_native_complete"] is True
        and observation["full_native_sample_count"] == 32
        and observation["all_http_request_count"] == 272
        and observation["performance_eligible"] is True,
        (
            "complete record requires all original32 proofs "
            "and256 successful measured responses"
        ),
    )
    result = json.loads((run / "sampled-source-result.json").read_bytes())
    timing = json.loads((run / "phase0.product-popen-timing.json").read_bytes())
    requests = [
        json.loads(line)
        for line in (run / "request-results.jsonl").read_bytes().splitlines()
    ]
    measured = [row for row in requests if row["kind"] == "measured"]
    require(len(measured) == 256, "complete record lost measured requests")
    elapsed = (
        max(r["complete_ns"] for r in measured)
        - min(r["dispatch_ns"] for r in measured)
    ) / 1e9
    require(elapsed > 0, "invalid actual measured interval")
    readiness = observation["startup_readiness"]
    require(
        readiness["API_epoch_status"] == "verified"
        and readiness["original_terminal"] is not None,
        "record lacks original first-health kernel/terminal replay",
    )
    health = readiness["first_health"]
    require(
        canonical(health) == canonical(result["health_observation"]),
        "record first-health differs from strict intake",
    )
    total = (health["observed_ns"] - timing["before_ns"]) / 1e6
    require(
        total > 0 and health["status_code"] == 200,
        "invalid actual product readiness interval",
    )
    latencies = [(r["complete_ns"] - r["dispatch_ns"]) / 1e6 for r in measured]
    resources = observation["resources"]
    return dict(
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
        cpu_ms=resources["cpu_ms"],
        host_memory_bytes=resources["peak_host_rss_bytes"],
        device_memory_bytes=resources["peak_device_memory_bytes"],
        process_messages=None,
        evidence_bytes=None,
        gate_open_ms=None,
        failure_detection_ms=None,
        rollback_ms=None,
        recovery_ms=None,
        measurement_scope=SCOPE,
    )


def derive(campaign_path, launch_path, receipt_path, start_id, root_ref):
    """No observation argument: admission is freshly established by strict intake."""
    campaign, launch, _, native = validate_inputs(
        campaign_path, launch_path, require_fresh_paths=False
    )
    protocol = load_protocol()
    require(
        campaign["campaign_id"] == protocol["h4"]["campaign_id"]
        and campaign["cell_id"] == CELL
        and CELL in protocol["h4"]["required_cells"],
        "not this original sampled pair cell",
    )
    require(
        [row["order"] for row in campaign["schedule"]] == protocol["schedule"],
        "original Latin9 changed",
    )
    starts = [s for s in native["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "one original registered slot required")
    start = starts[0]
    observation = intake(campaign_path, launch_path, receipt_path, start_id, root_ref)
    require(
        observation["formal_start_validated"] is True
        and observation["start_validation"] == "source-admitted-actual-sampled-start"
        and observation["status"] in {"failed", "succeeded"},
        "no authenticated runtime outcome",
    )
    run = Path(start["run_directory"])
    admission = json.loads((run / "source-admission.json").read_bytes())
    epoch_path = run / "sampled-epoch-archive.json"
    epoch = json.loads(epoch_path.read_bytes()) if epoch_path.exists() else None
    owner = admission["owner"]
    server = epoch["kernels"]["api-server/0"] if epoch is not None else None
    require(
        server is None or server["boot_id"] == owner["boot_id"],
        "actual process boot differs",
    )
    process = dict(
        launcher_pid=owner["pid"],
        launcher_start_ticks=owner["start_ticks"],
        server_pid=server["pid"] if server else None,
        server_start_ticks=server["start_ticks"] if server else None,
        boot_id=owner["boot_id"],
    )
    return (
        campaign,
        launch,
        start,
        observation,
        process,
        observed_metrics(observation, run),
    )


def project(campaign, launch, start, observation, process, metrics, artifacts):
    require(
        observation["status"] in {"failed", "succeeded"}, "unknown admitted outcome"
    )
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
        status="failed" if observation["status"] == "failed" else "complete",
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        process_identity=process,
        identity=record_identity(campaign, launch),
        artifacts=artifacts,
        cleanup=dict(
            processes_reclaimed=True, ports_reclaimed=True, devices_reclaimed=True
        ),
        metrics=metrics,
        failure=dict(
            phase="runtime-observation",
            **{"class": "AuthenticatedSourceAdmittedFailure"},
        )
        if observation["status"] == "failed"
        else None,
    )


def auxiliary(run, observation, process, root):
    """Derived documents retain absence; these are not fabricated original traces."""
    trace = run / "request-results.jsonl"
    epoch = run / "sampled-epoch-archive.json"
    return (
        dict(
            schema="ecpa-h4-sampled-derived-request-coverage/v1",
            original_trace=binding(trace, root) if trace.exists() else None,
            observed_requests=observation["all_http_request_count"],
            expected_requests=272,
            coverage=observation["coverage"],
            observed_failure=observation["observed_failure"],
        ),
        dict(
            schema="ecpa-h4-sampled-derived-process-binding/v1",
            process_identity=process,
            original_admission=binding(run / "source-admission.json", root),
            original_epoch=binding(epoch, root) if epoch.exists() else None,
        ),
    )


def export(
    campaign_path, launch_path, receipt_path, start_id, root_ref, output, artifact_root
):
    output, root = Path(output), Path(artifact_root).resolve()
    require(
        output.is_absolute()
        and output.resolve() == output
        and output.is_relative_to(root)
        and not output.exists(),
        "fresh contained bridge output required",
    )
    for path in (campaign_path, launch_path, receipt_path):
        binding(
            path, root
        )  # fail before fresh qualification if export paths cannot be represented
    cleanup_path = check_ref(root_ref)
    root_ref = dict(
        path=str(cleanup_path),
        sha256="sha256:" + root_ref["sha256"].removeprefix("sha256:"),
    )
    campaign, launch, start, observation, process, metrics = derive(
        campaign_path, launch_path, receipt_path, start_id, root_ref
    )
    output.mkdir(mode=0o700)
    run = Path(start["run_directory"])
    write_new(output / "independent-start-observation.json", observation)
    requests, snapshot = auxiliary(run, observation, process, root)
    write_new(output / "derived-request-coverage.json", requests)
    write_new(output / "derived-process-binding.json", snapshot)
    witness = dict(
        schema=WITNESS,
        campaign=binding(campaign_path, root),
        launch=binding(launch_path, root),
        receipt=binding(receipt_path, root),
        root_cleanup=binding(check_ref(root_ref), root),
        observation=binding(output / "independent-start-observation.json", root),
        start_id=start_id,
    )
    write_new(output / "record-witness.json", witness)
    source_result = run / "sampled-source-result.json"
    artifacts = dict(
        deployment_receipt=binding(receipt_path, root),
        raw_log=binding(
            source_result if source_result.exists() else run / "source-admission.json",
            root,
        ),
        request_results=binding(output / "derived-request-coverage.json", root),
        process_snapshot=binding(output / "derived-process-binding.json", root),
        cleanup_report=binding(check_ref(root_ref), root),
        raw_measurement=binding(output / "record-witness.json", root),
    )
    record = project(campaign, launch, start, observation, process, metrics, artifacts)
    jsonschema.Draft7Validator(
        json.loads(Path(__file__).with_name("record.schema.json").read_bytes())
    ).validate(record)
    write_new(output / "record.json", record)
    return record


def verify_record(record, witness, artifact_root, campaign_spec):
    """Analyzer entry: full strict replay, not a receipt/observation flag gate."""
    root = Path(artifact_root).resolve()
    require(
        record.get("measurement_domain") == DOMAIN
        and set(witness)
        == {
            "schema",
            "campaign",
            "launch",
            "receipt",
            "root_cleanup",
            "observation",
            "start_id",
        }
        and witness["schema"] == WITNESS
        and witness["start_id"] == record["start_id"],
        "wrong sampled record witness domain",
    )
    campaign_path, launch_path, receipt_path = (
        resolve(root, witness[k]) for k in ("campaign", "launch", "receipt")
    )
    require(
        campaign_path == Path(campaign_spec["_path"])
        and binding(campaign_path, root)["sha256"] == campaign_spec["_sha256"],
        "record uses another frozen campaign",
    )
    cleanup = resolve(root, witness["root_cleanup"])
    root_ref = dict(path=str(cleanup), sha256=witness["root_cleanup"]["sha256"])
    campaign, launch, start, observation, process, metrics = derive(
        campaign_path, launch_path, receipt_path, record["start_id"], root_ref
    )
    require(
        canonical(json.loads(resolve(root, witness["observation"]).read_bytes()))
        == canonical(observation),
        "independent observation differs from strict replay",
    )
    run = Path(start["run_directory"])
    requests, snapshot = auxiliary(run, observation, process, root)
    require(
        canonical(
            json.loads(
                resolve(root, record["artifacts"]["request_results"]).read_bytes()
            )
        )
        == canonical(requests),
        "derived request coverage differs",
    )
    require(
        canonical(
            json.loads(
                resolve(root, record["artifacts"]["process_snapshot"]).read_bytes()
            )
        )
        == canonical(snapshot),
        "derived process binding differs",
    )
    source_result = run / "sampled-source-result.json"
    require(
        record["artifacts"]["deployment_receipt"] == binding(receipt_path, root)
        and record["artifacts"]["cleanup_report"] == binding(cleanup, root)
        and record["artifacts"]["raw_log"]
        == binding(
            source_result if source_result.exists() else run / "source-admission.json",
            root,
        ),
        "record raw artifact roles differ",
    )
    require(
        canonical(record)
        == canonical(
            project(
                campaign,
                launch,
                start,
                observation,
                process,
                metrics,
                record["artifacts"],
            )
        ),
        "record projection differs from original strict source outcome",
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in (
        "campaign",
        "launch-spec",
        "deployment-receipt",
        "root-cleanup",
        "output",
        "artifact-root",
    ):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--root-cleanup-sha256", required=True)
    p.add_argument("--start-id", required=True)
    a = p.parse_args()
    export(
        a.campaign,
        a.launch_spec,
        a.deployment_receipt,
        a.start_id,
        dict(path=str(a.root_cleanup), sha256=a.root_cleanup_sha256),
        a.output,
        a.artifact_root,
    )


if __name__ == "__main__":
    main()
