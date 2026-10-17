"""Candidate H4 full traffic/native sample runner; no legacy row promotion.

All272 HTTP outcomes are retained. Selected32 proofs use independent full native
verification. A source result is not a formal H4 row until independent archived
source/native/resource intake accepts it; no new positive-response launch gate.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from experiments.formal_campaign.analyze import (
    h4_body_binding,
    h4_request_identity_observation,
    h4_request_payload,
    h4_response_summary,
    load_h4_campaign,
)
from experiments.formal_campaign.h3_dynamic_authority import accepted_api_socket
from experiments.formal_campaign.h3_runtime_source_closure import (
    verify_runtime_source_closure,
)
from experiments.formal_campaign.h3_worker_relaunch import cleanup, identity, live
from experiments.formal_campaign.h4_owned_resources import OwnedTreeResourceSampler
from experiments.formal_campaign.h4_sampled_native_bootstrap import start_native_epoch
from experiments.formal_campaign.h4_sampled_native_verifier import H4NativeEpochVerifier

from .h4_sampled_pair_epoch import observe_native_epoch, verify_h4_request_current
from .h4_sampled_registration import (
    build_plan_guard,
    checked,
    read_registered_schedule,
    validate_inputs,
    verify_sampled_protocol_sources,
)
from .h4_sampled_registration import (
    validate_original_receipt as validate_receipt,
)

RAW_CLOCK = time.CLOCK_MONOTONIC_RAW


def raw_ns():
    return time.clock_gettime_ns(RAW_CLOCK)


def write_new(path, value):
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class ObservedHTTPDeadlineExceeded(TimeoutError):
    """Keep actual late HTTP bytes/clocks, but never call them on-time success."""

    def __init__(self, observation):
        super().__init__(
            "original absolute HTTP120 deadline exceeded after response read"
        )
        self.observation = observation


class _AbsoluteSocketDeadline:
    """Cancel only the captured connected socket, including response file IO.

    HTTPConnection.sock may become None for Connection: close. Keep the actual
    socket object: never use a bare fd number that could be recycled. The stop
    event/lock makes completion cancellation race-safe and the thread is joined.
    """

    def __init__(self, owned_socket, deadline_ns):
        self.socket = owned_socket
        self.deadline_ns = deadline_ns
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.fired_ns = None
        self.thread = threading.Thread(
            target=self._wait, name="h4-http-absolute-deadline", daemon=True
        )

    def _wait(self):
        remaining = max(0, (self.deadline_ns - time.monotonic_ns()) / 1e9)
        if self.stop_event.wait(remaining):
            return
        with self.lock:
            if self.stop_event.is_set():
                return
            self.fired_ns = time.monotonic_ns()
            # The response may close this exact object concurrently.
            # No descriptor-number close, SUT signal or retry.
            with contextlib.suppress(OSError):
                self.socket.shutdown(socket.SHUT_RDWR)

    def start(self):
        self.thread.start()

    def cancel_and_join(self):
        with self.lock:
            self.stop_event.set()
        self.thread.join()
        return self.fired_ns


def exchange(
    url, method, payload, request_id, epoch, deadline_ns, *, clock_observation=None
):
    """Absolute-deadline IO on one actual accepted API connection, no retry."""
    endpoint = urlparse(url)
    if endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1":
        raise ValueError("registered actual IPv4 loopback HTTP endpoint required")
    remaining = (deadline_ns - time.monotonic_ns()) / 1e9
    if remaining <= 0:
        raise TimeoutError("original request deadline elapsed before connect")
    observed = clock_observation if clock_observation is not None else {}
    connection = http.client.HTTPConnection(
        endpoint.hostname, endpoint.port, timeout=remaining
    )
    watchdog = None
    response = None
    try:
        connection.connect()  # numeric IPv4, connect bounded by original remaining
        owned_socket = connection.sock
        if owned_socket is None:
            raise ConnectionError("actual connected socket unavailable")
        watchdog = _AbsoluteSocketDeadline(owned_socket, deadline_ns)
        watchdog.start()  # before peer check, request, response headers or body IO
        peer_inode = accepted_api_socket(owned_socket, epoch["kernels"]["api-server/0"])
        epoch["bound"].validate_current(epoch["enrollment"], epoch["host_journal"])
        remaining = (deadline_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise TimeoutError("original request deadline elapsed before delivery")
        owned_socket.settimeout(remaining)
        headers = [["Host", endpoint.netloc], ["Accept-Encoding", "identity"]]
        if payload is not None:
            headers += [
                ["Content-Type", "application/json"],
                ["Content-Length", str(len(payload))],
            ]
        if request_id is not None:
            headers.append(["X-Request-Id", request_id])
        connection.putrequest(
            method, endpoint.path or "/", skip_host=True, skip_accept_encoding=True
        )
        for name, value in headers:
            connection.putheader(name, value)
        backend_sent_ns = time.monotonic_ns()
        observed["backend_sent_ns"] = backend_sent_ns
        connection.endheaders(payload)
        response = connection.getresponse()
        body = response.read()
        # This clock is the HTTP boundary, before any evidence consumption.
        completed_raw_ns, received_ns = raw_ns(), time.monotonic_ns()
        observed.update(
            received_ns=received_ns, http_deadline_met=received_ns <= deadline_ns
        )
        evidence = dict(
            status_code=response.status,
            headers=list(response.getheaders()),
            **h4_body_binding(body),
        )
        observation = (
            headers,
            evidence,
            body,
            backend_sent_ns,
            received_ns,
            completed_raw_ns,
            peer_inode,
        )
        if received_ns > deadline_ns:
            raise ObservedHTTPDeadlineExceeded(observation)
        return observation
    except Exception as error:
        observed["failure_observed_ns"] = time.monotonic_ns()
        if response is not None and isinstance(error, http.client.IncompleteRead):
            observed["interrupted_response"] = dict(
                status_code=response.status,
                headers=list(response.getheaders()),
                **h4_body_binding(error.partial),
                body_complete=False,
            )
        if (
            not isinstance(error, ObservedHTTPDeadlineExceeded)
            and time.monotonic_ns() >= deadline_ns
        ):
            raise TimeoutError(
                "original absolute HTTP120 deadline interrupted owned socket IO"
            ) from error
        raise
    finally:
        if watchdog is not None:
            observed["deadline_cancellation_ns"] = watchdog.cancel_and_join()
        if response is not None:
            response.close()
        connection.close()


def drive_requests(
    epoch, verifier, endpoint, workload, schedule, raw_path, *, calibration_one=False
):
    payload = h4_request_payload(workload, workload["served_model"])
    payload_sha = hashlib.sha256(payload).hexdigest()
    rows, lock = [], threading.Lock()
    log = raw_path.open("xb")

    def request_once(declaration):
        row = dict(
            request_id=declaration["request_id"],
            all_index=declaration["all_index"],
            kind="warmup" if declaration["all_index"] < 16 else "measured",
            selected=declaration["selected"],
            dispatch_ns=raw_ns(),
            http_request=h4_body_binding(payload),
            http_response=None,
            native_verified=False,
            native_error=None,
            error=None,
        )
        # Native/source clocks are MONOTONIC; original H4 latency is RAW. Retain
        # both actual observations and never compare their numeric epochs.
        sent_ns = time.monotonic_ns()
        deadline_ns = sent_ns + 120_000_000_000
        row["native_clock"] = dict(
            sent_ns=sent_ns,
            deadline_ns=deadline_ns,
            raw_dispatch_observed_ns=row["dispatch_ns"],
            backend_sent_ns=None,
            received_ns=None,
            http_deadline_met=None,
        )
        try:
            if declaration["body_sha256"] != payload_sha:
                raise ValueError("frozen request body does not match full schedule")
            if declaration["selected"]:
                verifier.begin_request(row["request_id"])
            try:
                result = exchange(
                    endpoint,
                    "POST",
                    payload,
                    row["request_id"],
                    epoch,
                    deadline_ns,
                    clock_observation=row["native_clock"],
                )
            except ObservedHTTPDeadlineExceeded as late:
                result = late.observation
                row["error"] = type(late).__name__ + ": " + str(late)
            headers, evidence, body, backend_sent, received, completed_raw, peer = (
                result
            )
            row.update(
                request_headers=headers,
                http_response=evidence,
                complete_ns=completed_raw,
                accepted_api_socket_inode=peer,
                request_identity=h4_request_identity_observation(
                    row["request_id"], headers, evidence
                ),
            )
            row["native_clock"].update(
                backend_sent_ns=backend_sent,
                received_ns=received,
                http_deadline_met=received <= deadline_ns,
            )
            row.update(h4_response_summary(evidence))
            if declaration["selected"]:
                try:
                    proof = verifier.verify_request(
                        request_id=row["request_id"],
                        request_body=payload,
                        response_status=evidence["status_code"],
                        response_body=body,
                        sent_ns=sent_ns,
                        received_ns=received,
                        backend_sent_ns=backend_sent,
                        deadline_ns=deadline_ns,
                        response_expectation={
                            "min_completion_tokens": 16,
                            "max_completion_tokens": 64,
                        },
                    )
                    consumed = verifier.consume(
                        proof,
                        request_id=row["request_id"],
                        response_body=body,
                        deadline_ns=deadline_ns,
                    )
                    verify_h4_request_current(
                        epoch,
                        consumed,
                        runtime_request_id=consumed.runtime_request_id,
                        transaction_id=consumed.transaction_id,
                    )
                    if time.monotonic_ns() > deadline_ns:
                        raise TimeoutError(
                            "original deadline expired after complete source/"
                            "native checks"
                        )
                    row["native_clock"].update(
                        backend_sent_ns=backend_sent,
                        received_ns=received,
                        consumed_ns=time.monotonic_ns(),
                    )
                    row.update(
                        native_verified=True,
                        native_report=dict(
                            path=consumed.snapshot_report_path,
                            sha256=consumed.snapshot_report_sha256,
                            runtime_request_id=consumed.runtime_request_id,
                            transaction_id=consumed.transaction_id,
                            profiler_snapshot_path=consumed.profiler_snapshot_path,
                            profiler_snapshot_sha256=consumed.profiler_snapshot_sha256,
                        ),
                    )
                except Exception as error:
                    row["native_error"] = type(error).__name__ + ": " + str(error)
        except Exception as error:
            row["error"] = type(error).__name__ + ": " + str(error)
        finally:
            row["native_clock"]["outcome_observed_ns"] = time.monotonic_ns()
            row.setdefault("complete_ns", raw_ns())
            if row["http_response"] is None:
                row.update(h4_response_summary(None))
            with lock:
                rows.append(row)
                log.write(json.dumps(row, sort_keys=True).encode() + b"\n")
                log.flush()
                os.fsync(log.fileno())
        return row

    try:
        batches = (
            ([schedule["requests"][0]],)
            if calibration_one
            else (schedule["requests"][:16], schedule["requests"][16:])
        )
        for declarations in batches:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(request_once, row) for row in declarations]
                for future in futures:
                    future.result()
    finally:
        log.close()
    return sorted(rows, key=lambda row: row["all_index"])


def source_admission(campaign, start, receipt, phase, closure, launch, owner, timing):
    """Recomputed by intake; minted only by the actual product Popen callback."""

    def digest(value):
        return hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()

    return dict(
        schema="ecpa-h4-sampled-product-source-admission/v1",
        campaign_sha256=campaign["_raw_sha256"],
        start_id=start["start_id"],
        phase=start["phase"],
        receipt_sha256=digest(receipt),
        runtime_closure_sha256=digest(closure),
        semantic_launch_sha256=digest(launch),
        owner=owner,
        argv=phase["argv"],
        before_ns=timing["before_ns"],
        after_ns=timing["after_ns"],
        before_monotonic_ns=timing["before_monotonic_ns"],
    )


def run_start(
    campaign, launch, workload, native, start, receipt, *, calibration_guard=None
):
    phase = json.loads(checked(start["phase"]))
    output = Path(start["run_directory"])
    # All complete source/wheel audits are qualification before measured Popen.
    qualification_begin = raw_ns()
    closure = verify_runtime_source_closure(
        phase,
        campaign["fixed_identity"],
        native["repositories"],
        native["runtime_wheels"],
    )
    if calibration_guard is not None:
        from .h3_native_plan_guard import NativePlanGuard

        if type(calibration_guard) is not NativePlanGuard or receipt is not None:
            raise ValueError(
                "unregistered calibration requires exact source-derived guard "
                "and no receipt"
            )
        guard = calibration_guard
    else:
        guard = build_plan_guard(campaign, native, start, receipt)
    qualification_end = raw_ns()
    sampler, epoch, collector = None, None, None
    result = dict(
        schema="ecpa-h4-sampled-live-source-observation/v1",
        cell_id=campaign["cell_id"],
        start_id=start["start_id"],
        formal_start_validated=False,
        formal_result=False,
        qualification_begin_ns=qualification_begin,
        qualification_end_ns=qualification_end,
        failure=None,
        source_native_complete=False,
        execution_domain="unregistered-calibration"
        if calibration_guard is not None
        else "registered-original-start",
    )

    def on_popen(process):
        nonlocal sampler
        owner = identity(process.pid)
        timing = json.loads((output / "phase0.product-popen-timing.json").read_bytes())
        if (
            timing["actual_kernel"] != owner
            or timing["argv"] != phase["argv"]
            or not (0 < timing["before_ns"] <= timing["after_ns"] <= raw_ns())
        ):
            raise ValueError("actual product Popen callback identity/clock mismatch")
        write_new(output / "actual-runtime-closure.json", closure)
        write_new(
            output / "source-admission.json",
            source_admission(
                campaign, start, receipt, phase, closure, guard.launch, owner, timing
            ),
        )
        result["product_owner"] = owner
        sampler = OwnedTreeResourceSampler(
            process.pid,
            launch["npu_memory_command"],
            archive=output / "owned-resources.json",
            expected_root=owner,
        )
        sampler.start()

    try:
        epoch = observe_native_epoch(
            phase, start["arm"], output, guard, on_popen=on_popen
        )
        boot = phase["native_bootstrap"]
        read_registered_schedule(start["schedule"], boot["phases"])
        collector, descriptor = start_native_epoch(
            output=Path(boot["output"]),
            senders=epoch["peers"],
            phases=boot["phases"],
            native_plan_id=epoch["enrollment"]["native_plan_id"],
            native_launch_id=epoch["enrollment"]["native_launch_id"],
            kv_requirements=boot["kv_requirements"],
            tensor_requirements=boot["tensor_requirements"],
            native_context_path=boot["native_context_path"],
            tensor_context_path=boot["tensor_context_path"],
            source_files=boot["source_files"],
            schedule_path=start["schedule"]["path"],
        )
        root = Path(boot["output"])
        verifier = H4NativeEpochVerifier(
            native_spec=root / "native-spec.json",
            tensor_policy=root / "tensor-policy.json",
            drain_policy=root / "drain-policy.json",
            descriptor=descriptor,
            socket_path=root / "native.sock",
            journal_path=root / "native.jsonl",
            snapshots=root / "snapshots",
            schedule_path=start["schedule"]["path"],
            profiler_host_journal=epoch["host_journal"],
            profiler_roster=epoch["roster"],
            profiler_kernels=epoch["kernels"],
        )
        popen_timing = json.loads(
            (output / "phase0.product-popen-timing.json").read_bytes()
        )
        health_deadline = popen_timing["before_monotonic_ns"] + int(
            launch["startup_timeout_seconds"] * 1000000000.0
        )
        health_attempts = []
        while True:
            if time.monotonic_ns() >= health_deadline:
                raise TimeoutError("original registered health readiness timeout")
            health = exchange(
                launch["health_url"], "GET", None, None, epoch, health_deadline
            )
            health_attempts.append(
                dict(
                    status_code=health[1]["status_code"],
                    observed_ns=health[5],
                    response=health[1],
                )
            )
            if health[1]["status_code"] == 200:
                break
            time.sleep(0.1)
        write_new(output / "all-health-observations.json", health_attempts)
        result["health_observation"] = dict(
            status_code=200, observed_ns=health[5], accepted_api_socket_inode=health[6]
        )
        schedule, _ = read_registered_schedule(start["schedule"], boot["phases"])
        traffic_workload = dict(
            workload, served_model=launch["arms"][start["arm"]]["served_model"]
        )
        rows = drive_requests(
            epoch,
            verifier,
            launch["endpoint_url"],
            traffic_workload,
            schedule,
            output / "request-results.jsonl",
            calibration_one=calibration_guard is not None,
        )
        write_new(
            output
            / (
                "calibration-one-request-results.json"
                if calibration_guard is not None
                else "all272-request-results.json"
            ),
            rows,
        )
        result.update(
            request_count=len(rows),
            selected_count=sum(r["selected"] for r in rows),
            native_verified_count=sum(r["native_verified"] for r in rows),
            source_native_complete=len(rows) == 272
            and sum(r["native_verified"] for r in rows) == 32,
        )
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
        result["failure_category"] = (
            "runtime-interruption"
            if isinstance(
                error, (TimeoutError, ConnectionError, subprocess.TimeoutExpired)
            )
            else "unqualified-verification-error"
        )
        result["failure_observed_monotonic_ns"] = time.monotonic_ns()
        result["failure_observed_raw_ns"] = raw_ns()
    finally:
        cleanup_errors = []
        if epoch is not None:
            try:
                host_raw = Path(epoch["host_journal"]).read_bytes()
                fd = os.open(
                    output / "final-original-Host.jsonl",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    384,
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(host_raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                write_new(
                    output / "sampled-epoch-archive.json",
                    dict(
                        schema="ecpa-h4-sampled-actual-epoch-archive/v1",
                        owner=epoch["owner"],
                        enrollment=epoch["enrollment"],
                        roster=epoch["roster"],
                        kernels=epoch["kernels"],
                        host_journal_original=str(epoch["host_journal"]),
                        host_journal_sha256=hashlib.sha256(host_raw).hexdigest(),
                        observed=epoch["observed"],
                    ),
                )
            except Exception as error:
                cleanup_errors.append("full original epoch snapshot: " + repr(error))
        if sampler is not None:
            try:
                result["resources"] = sampler.finish()
            except Exception as error:
                cleanup_errors.append("resource archive: " + repr(error))
        if collector is not None:
            try:
                if collector.stdin:
                    collector.stdin.close()
                collector.wait(timeout=15)
            except Exception as error:
                cleanup_errors.append("owned collector: " + repr(error))
        if epoch is not None:
            try:
                cleanup(epoch["process"], epoch["owner"], 15, epoch["owned"])
                expected = [*epoch["kernels"].values()]
                if sampler is not None:
                    expected += list(sampler.last_known_epochs)
                result["actual_epochs_gone"] = all(not live(item) for item in expected)
            except Exception as error:
                cleanup_errors.append("owned Host tree: " + repr(error))
        if output.exists():
            try:
                env = dict(os.environ, ECPA_H4_RUN_DIRECTORY=str(output))
                check = subprocess.run(
                    launch["device_cleanup_command"],
                    env=env,
                    capture_output=True,
                    check=False,
                )
                write_new(
                    output / "device-cleanup-command.json",
                    dict(
                        argv=launch["device_cleanup_command"],
                        exit_code=check.returncode,
                        stdout_base64=base64.b64encode(check.stdout).decode(),
                        stderr_base64=base64.b64encode(check.stderr).decode(),
                    ),
                )
                result["device_cleanup_exit_code"] = check.returncode
            except Exception as error:
                cleanup_errors.append("device observation: " + repr(error))
            port_observations = []
            for port in native["allocated_tcp_ports"]:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
                    channel.settimeout(0.5)
                    port_observations.append(
                        dict(
                            port=port,
                            closed=channel.connect_ex(("127.0.0.1", port)) != 0,
                        )
                    )
            result["actual_ports_closed"] = all(p["closed"] for p in port_observations)
            write_new(output / "terminal-port-observations.json", port_observations)
            result["cleanup_errors"] = cleanup_errors
            write_new(output / "sampled-source-result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--launch-spec", type=Path, required=True)
    parser.add_argument("--deployment-receipt", type=Path, required=True)
    parser.add_argument(
        "--start-id",
        help="One registered original slot; root queue preserves all9 order",
    )
    args = parser.parse_args()
    campaign, launch, workload, native = validate_inputs(
        args.campaign, args.launch_spec, require_fresh_paths=False
    )
    receipt = json.loads(args.deployment_receipt.read_bytes())
    validate_receipt(receipt, load_h4_campaign(args.campaign), args.deployment_receipt)
    verify_sampled_protocol_sources(
        native,
        Path(native["repositories"]["manager"]["path"]),
        campaign["fixed_identity"]["manager_commit"],
    )
    selected = [
        start
        for start in native["starts"]
        if args.start_id is None or start["start_id"] == args.start_id
    ]
    if args.start_id is not None and len(selected) != 1:
        raise ValueError("exact registered original start required")
    results = [
        run_start(campaign, launch, workload, native, start, receipt)
        for start in selected
    ]
    print(
        json.dumps(
            dict(
                starts=len(results),
                formal_start_validated=False,
                native_complete=sum(r["source_native_complete"] for r in results),
            )
        )
    )


if __name__ == "__main__":
    main()
