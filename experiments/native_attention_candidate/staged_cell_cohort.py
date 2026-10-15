"""New owner integration for staged cached-cell verification; never launch NPU here.

The owner already launched Manager/Host and owns cleanup/watchdog. This starts
only the existing independent producer subprocess, then an owner-local private
staged controller. It preserves actual SIGTERM/lease exclusion checks. No
legacy source gate, compiler flag, full-KV, quality or H3/H4 result is changed.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from vllm_hust_ext.runtime_phase_handoff import accept_native_binding, process_identity

from . import drain_consumer
from . import live_route_reader as routes
from . import live_semantic_producer as producer
from . import semantic_producer_registry as registry
from . import staged_cell_controller as staged
from .live_cohort import public_request_headers, signal_registered_worker, start, write


def capture_owner_handoff(
    issuer, permit, *, listener, path, manager, launched_wall_ns, raw_record_path
):
    """Capture actual wire bytes once, retain original record, and seal its binding.

    Replaces both the old owner's direct accept and registry.accept_handoff. This
    calls the unchanged real Manager protocol and never reconstructs wire bytes.
    The caller stores returned body.record as native-binding.json and uses its
    environment unchanged, plus stores this envelope separately.
    """
    value = issuer._permit(permit)
    raw_path = routes._path(raw_record_path)
    parent = raw_path.parent.stat()
    registry.require(
        parent.st_uid == os.geteuid() and not parent.st_mode & 0o077,
        "raw handoff directory is not private",
    )
    descriptor = os.open(
        raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    os.close(descriptor)
    record = accept_native_binding(
        listener,
        Path(path),
        manager,
        launched_wall_ns,
        value["cell"]["manager_handoff_sources"],
        raw_path,
    )
    with raw_path.open("rb") as captured:
        os.fsync(captured.fileno())
    registry.require(
        registry.sha(raw_path.read_bytes()) == record["binding_sha256"],
        "captured original Manager wire digest differs",
    )
    return issuer._seal(
        {
            "schema": registry.HANDOFF,
            "permit_sha256": permit["sha256"],
            "record": record,
            "formal_result": False,
        }
    )


def execute(
    config,
    recipe,
    *,
    native_env,
    peers,
    manager,
    descriptor,
    spec_path,
    journal_path,
    policy_path,
    drain_policy_path,
    issuer,
    permit,
    sealed_handoff,
    inputs,
    trusted_input_audits,
):
    out = Path(config["output"])
    launch_path = Path(config["semantic_launch_spec_path"])
    launch = json.loads(launch_path.read_bytes())
    r = {
        "schema": producer.REGISTRATION,
        "formal_result": False,
        "execution_plan_id": launch["execution_plan_id"],
        "native_plan_id": native_env["VLLM_ECPA_PLAN_ID"],
        "native_launch_id": native_env["VLLM_ECPA_LAUNCH_ID"],
        "controller_instance": launch["controller_instance"],
        "candidate_generation": launch["candidate_generation"],
        "membership_epoch": launch["membership_epoch"],
        "plan_path": launch["plan"]["path"],
        "binding_path": launch["binding"]["path"],
        "semantic_launch_spec_path": str(launch_path),
        "recipe_path": config["recipe"],
        "phase_id": recipe["phases"][0]["phase_id"],
        "probe_output": str(out / "probe"),
        "spec_path": str(spec_path),
        "journal_path": str(journal_path),
        "policy_path": str(policy_path),
        "drain_policy_path": str(drain_policy_path),
        "collector_source": config["attention_collector_source"],
        "collector_descriptor": descriptor,
        "collector_socket_path": descriptor["socket_path"],
        "manager_identity": manager,
        "owner_identity": process_identity(os.getpid()),
        "source_peers": peers,
        "producer_socket": str(out / "live-producer.sock"),
        "producer_source_path": str(Path(producer.__file__).resolve()),
        "producer_source_sha256": hashlib.sha256(
            Path(producer.__file__).read_bytes()
        ).hexdigest(),
        "max_validity_ns": 30_000_000_000,
    }
    registration = out / "live-registration.json"
    write(registration, r)
    pp = controller = None
    identities = []
    http_rows = []

    def request(method="GET", path="/__semantic_status", body=None, headers=None):
        entry = time.monotonic_ns()
        connection = http.client.HTTPConnection(
            "127.0.0.1", config["public_port"], timeout=30
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            raw = response.read()
            status = response.status
        finally:
            connection.close()
        row = {
            "method": method,
            "path": path,
            "status": status,
            "request_monotonic_ns": entry,
            "response_monotonic_ns": time.monotonic_ns(),
            "response_sha256": hashlib.sha256(raw).hexdigest(),
            "response_body_path": f"live-client-{len(http_rows) + 1:04}.response.bin",
        }
        with (out / row["response_body_path"]).open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        http_rows.append(row)
        write(out / f"live-client-{len(http_rows):04}.json", row)
        return status, raw

    try:
        pp, ready = start(
            [
                config["python"],
                "-m",
                "experiments.native_attention_candidate.live_semantic_producer",
                "--registration",
                str(registration),
            ],
            config,
            out,
            "producer",
        )
        identities.append(process_identity(pp.pid))
        write(out / "live-producer-owned-kernel.json", identities[-1])
        if ready["producer"] != identities[-1]:
            raise ValueError("producer descriptor differs from actual kernel")
        pd = out / "live-producer-descriptor.json"
        write(pd, ready)
        scope = {key: r[key] for key in producer.SCOPE_FIELDS}
        expected_cell = routes.controller_cell_binding(
            issuer,
            permit,
            sealed_handoff,
            inputs,
            trusted_input_audits=trusted_input_audits,
        )
        controller = staged.StagedCellController(
            issuer=issuer,
            permit=permit,
            expected_cell=expected_cell,
            scope=scope,
            control_path=out / "staged-controller.sock",
            phase=recipe["phases"][0],
            journal_path=out / "staged-controller-raw.jsonl",
            public_port=config["public_port"],
        )
        identities.append(process_identity(os.getpid()))
        write(out / "live-authority-owned-kernel.json", identities[-1])
        if request()[0] != 503:
            raise ValueError("public response open before prepared verification")
        artifacts = {
            name: {"path": str(path), "sha256": routes._hash(path)}
            for name, path in {
                "recipe": Path(config["recipe"]),
                "spec": Path(spec_path),
                "policy": Path(policy_path),
                "drain_policy": Path(drain_policy_path),
                "registration": registration,
            }.items()
        }
        source_pins = {
            str(Path(module.__file__).resolve()): routes._hash(module.__file__)
            for module in (routes, staged, registry)
        }
        kernel_peers = {
            f"{p['process']['role']}/{p['process']['ordinal']}": {
                key: p["process"][key] for key in registry.KERNEL
            }
            for p in peers
        }
        prepared = staged.bind_and_commit_cached(
            controller,
            handoff=sealed_handoff,
            manager=manager,
            peers=kernel_peers,
            producer=identities[0],
            producer_socket=r["producer_socket"],
            artifacts=artifacts,
            inputs=inputs,
            authority_sources=source_pins,
            observation_verifier=drain_consumer.verify_observation,
            observation_arguments={
                "recipe": recipe,
                "phase_id": r["phase_id"],
                "output": Path(r["probe_output"]),
                "descriptor": descriptor,
                "spec_path": Path(spec_path),
                "journal_path": Path(journal_path),
                "policy_path": Path(policy_path),
                "drain_policy_path": Path(drain_policy_path),
            },
            producer_wait_s=config["rpc_watchdog_s"],
        )
        write(out / "cell-deployment.json", prepared["deployment"])
        write(out / "cell-verification-ticket.json", prepared["ticket"])
        phase = recipe["phases"][0]
        headers = public_request_headers(phase)
        path = urlsplit(phase["url"]).path
        expected = (out / "probe/response.bin").read_bytes()
        status, raw = request(
            "POST", path, producer.canonical(phase["payload"]), headers
        )
        if status != 200 or raw != expected:
            raise ValueError("authority did not release exact verified model response")
        mismatch, _ = request("POST", path, b"{}", headers)
        if mismatch != 503:
            raise ValueError("different request escaped finite semantic scope")
        # Actual source failure, never a synthetic epoch substitution.
        worker = next(
            p["process"]
            for p in peers
            if p["process"]["role"] == "worker" and p["process"]["ordinal"] == 1
        )
        before = process_identity(worker["pid"])
        write(
            out / "actual-worker-fault-intent.json",
            {
                "fault": "SIGTERM",
                "worker": before,
                "at_monotonic_ns": time.monotonic_ns(),
                "formal_result": False,
            },
        )
        signal_registered_worker(worker)
        end = time.monotonic() + 10
        gone = False
        while time.monotonic() < end:
            try:
                process_identity(worker["pid"])
            except (OSError, ValueError):
                gone = True
                break
            time.sleep(0.05)
        if not gone:
            raise ValueError("faulted registered worker did not terminate")
        closed, _ = request("POST", path, producer.canonical(phase["payload"]), headers)
        if closed != 503:
            raise ValueError("source epoch loss did not close response release")
        completion = json.loads((out / "producer-completion.json").read_bytes())
        if (
            http_rows[-1]["response_monotonic_ns"]
            >= completion["proof"]["expires_monotonic_ns"]
        ):
            raise ValueError("fault response arrived after proof expiry")
        write(
            out / "actual-worker-fault-observed.json",
            {
                "registered_worker": before,
                "same_registered_epoch_gone": gone,
                "response_monotonic_ns": http_rows[-1]["response_monotonic_ns"],
                "fixed_lease_expires_monotonic_ns": completion["proof"][
                    "expires_monotonic_ns"
                ],
                "formal_result": False,
            },
        )
        rpc = json.loads((out / "probe/result.json").read_bytes())
        rpc.update(
            live_semantic_producer=True,
            independent_response_authority=True,
            actual_scope_mismatch_status=mismatch,
            actual_source_epoch_loss_status=closed,
            public_response_sha256=hashlib.sha256(raw).hexdigest(),
            classification="REAL_STAGED_CELL_CACHED_RESPONSE_NONFORMAL",
            staged_cell_deployment=True,
            independent_typed_ticket=True,
            formal_result=False,
        )
        write(
            out / "live-cohort-result.json",
            {
                "passed": True,
                "producer": identities[0],
                "authority": identities[1],
                "http_observations": http_rows,
                "scope": {k: r[k] for k in producer.SCOPE_FIELDS},
                "formal_result": False,
                "deployment_sha256": prepared["deployment"]["sha256"],
                "ticket_sha256": prepared["ticket"]["sha256"],
                "classification": "bounded-cached-response-cell-only",
            },
        )
        return rpc
    finally:
        controller_cleanup_error = None
        if controller is not None:
            try:
                controller.close()
            except Exception as exc:
                controller_cleanup_error = str(exc)
        for process, identity in [(pp, identities[0] if identities else None)]:
            if process is None:
                continue
            try:
                if process_identity(process.pid) == identity:
                    os.killpg(identity["session"], signal.SIGTERM)
                process.wait(timeout=10)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
        write(
            out / "live-process-terminal.json",
            {
                "identities": identities,
                "returncodes": [pp.returncode if pp else None],
                "controller_cleanup_error": controller_cleanup_error,
                "controller_in_owner_closed": controller is None
                or controller.state == "REVOKED",
                "formal_result": False,
            },
        )
        if controller_cleanup_error is not None:
            raise ValueError(
                "staged controller cleanup failed: " + controller_cleanup_error
            )
