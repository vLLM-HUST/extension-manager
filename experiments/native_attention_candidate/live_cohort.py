"""Run independent live semantic producer/response authority before NPU cleanup."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

from vllm_hust_ext.runtime_phase_handoff import process_identity

from . import live_semantic_producer as producer


def write(path, value):
    raw = producer.canonical(value)
    with open(path, "xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def public_request_headers(phase):
    """Bind the public authority request separately from the backend request."""
    headers = dict(phase["headers"])
    if any(key.lower() == "x-ecpa-request-id" for key in headers):
        raise ValueError("public authority request ID is runner-owned")
    return {**headers, "X-ECPA-Request-ID": phase["external_request_id"]}


def signal_registered_worker(worker):
    expected = {
        key: worker[key] for key in ("pid", "start_ticks", "session", "boot_id")
    }
    if process_identity(worker["pid"]) != expected:
        raise ValueError("registered worker epoch changed before fault injection")
    os.kill(expected["pid"], signal.SIGTERM)
    return expected


def start(argv, config, out, name):
    process = subprocess.Popen(
        argv,
        cwd=config["cwd"],
        env=config["env"],
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=(out / (name + ".stderr")).open("wb"),
    )
    try:
        with selectors.DefaultSelector() as sel:
            sel.register(process.stdout, selectors.EVENT_READ)
            if not sel.select(20):
                raise ValueError(name + " startup deadline")
            raw = process.stdout.readline(131073)
        (out / (name + "-ready.bin")).write_bytes(raw)
        if not raw.endswith(b"\n"):
            raise ValueError(name + " failed before ready; inspect stderr")
        return process, json.loads(raw)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        raise


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
    pp = ap = None
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
        ap, ar = start(
            [
                config["python"],
                "-m",
                "experiments.native_attention_candidate.live_authority",
                "--registration",
                str(registration),
                "--producer-descriptor",
                str(pd),
                "--listen-port",
                str(config["public_port"]),
                "--journal",
                str(out / "live-authority-raw.jsonl"),
            ],
            config,
            out,
            "authority",
        )
        identities.append(process_identity(ap.pid))
        write(out / "live-authority-owned-kernel.json", identities[-1])
        if ar["authority"] != identities[-1]:
            raise ValueError("authority descriptor differs from actual kernel")
        first, _ = request()
        if first != 503:
            raise ValueError("candidate was not closed before proof")
        deadline = time.monotonic() + config["rpc_watchdog_s"]
        while time.monotonic() < deadline:
            if pp.poll() is not None:
                raise ValueError("producer terminated; inspect producer stderr")
            if (out / "producer-failure.txt").exists():
                raise ValueError("live producer failed; preserve producer-failure.txt")
            status, _ = request()
            if status == 200:
                break
            time.sleep(0.1)
        else:
            raise ValueError("live producer proof deadline")
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
            classification="REAL_LIVE_BOUNDED_RESPONSE_RELEASE_NONFORMAL",
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
            },
        )
        return rpc
    finally:
        for process, identity in reversed(
            list(zip((pp, ap), identities, strict=False))
        ):
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
                "returncodes": [p.returncode if p else None for p in (pp, ap)],
                "formal_result": False,
            },
        )
