#!/usr/bin/env python3
"""Execute the frozen H4 matched cell and retain recomputable raw evidence."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from analyze import (
    _canonical_digest,
    _digest_bytes,
    _recompute_h4_metrics,
    h4_body_binding,
    h4_request_payload,
    h4_response_summary,
    load_h4_campaign,
)
from jsonschema import Draft7Validator

PHASES = (
    "discovery",
    "validation",
    "planning",
    "rendering",
    "evidence_setup",
)
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
CLOCK = time.CLOCK_MONOTONIC_RAW


def now_ns() -> int:
    return time.clock_gettime_ns(CLOCK)


def canonical_digest(value: Any) -> str:
    return _canonical_digest(value)


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def validate_launch_spec(
    spec: dict[str, Any], receipt: dict[str, Any], raw: bytes | None = None
) -> None:
    schema = load_object(Path(__file__).resolve().parent / "h4-launch-spec.schema.json")
    Draft7Validator(schema).validate(spec)
    if set(spec.get("arms", {})) != set(ARMS):
        raise ValueError("launch spec must define the three frozen arms")
    served_models = set()
    for arm in ARMS:
        definition = spec["arms"][arm]
        if not isinstance(definition.get("server_command"), list):
            raise ValueError(f"{arm} lacks server_command")
        if canonical_digest(definition) != receipt["arm_command_digests"][arm]:
            raise ValueError(f"{arm} launch spec differs from registered command")
        served_model = definition.get("served_model")
        if not isinstance(served_model, str) or not served_model:
            raise ValueError(f"{arm} lacks served_model")
        served_models.add(served_model)
        commands = definition.get("phase_commands", {})
        if set(commands) - set(PHASES):
            raise ValueError(f"{arm} has an unknown prelaunch phase")
    if len(served_models) != 1:
        raise ValueError("all H4 arms must use the same served_model")
    if raw is not None and _digest_bytes(raw) != receipt["launch_spec_sha256"]:
        raise ValueError("launch spec digest differs from registered bytes")


def validate_receipt(
    receipt: dict[str, Any], campaign: dict[str, Any], receipt_path: Path
) -> None:
    schema = load_object(
        Path(__file__).resolve().parent / "h4-deployment-receipt.schema.json"
    )
    Draft7Validator(schema).validate(receipt)
    required = {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign["_sha256"],
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
    }
    for key, value in required.items():
        if receipt.get(key) != value:
            raise ValueError(f"deployment receipt {key} differs")
    fixed = campaign["fixed_identity"]
    for key in (
        "manager_commit",
        "host_commit",
        "accelerator_commit",
        "model_digest",
        "hardware",
        "topology",
    ):
        if receipt.get(key) != fixed[key]:
            raise ValueError(f"deployment receipt {key} differs from campaign")
    plugins = {name: item["commit"] for name, item in fixed["plugins"].items()}
    if receipt.get("plugin_commits") != plugins:
        raise ValueError("deployment receipt plugin commits differ")
    if receipt.get("workload_digest") != campaign["workload"]["sha256"]:
        raise ValueError("deployment receipt workload digest differs")
    admission = receipt["host_source_admission"]
    if canonical_digest(admission) != receipt["host_source_admission_sha256"]:
        raise ValueError("deployment receipt Host admission digest differs")
    if admission["candidate_commit"] != receipt["host_commit"]:
        raise ValueError("deployment receipt Host admission commit differs")
    if not receipt_path.is_file():
        raise ValueError("deployment receipt is missing")


def run_checked(command: list[str], env: dict[str, str], log: Any) -> None:
    completed = subprocess.run(
        command,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {command!r}")


def wait_ready(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    raise TimeoutError(f"health endpoint did not become ready: {url}")


def proc_stat(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    marker = raw.rfind(") ")
    if marker < 0:
        raise ValueError(f"malformed /proc/{pid}/stat")
    return raw[marker + 2 :].split()


def process_identity(process: subprocess.Popen[bytes]) -> dict[str, Any]:
    fields = proc_stat(process.pid)
    launcher_fields = proc_stat(os.getpid())
    return {
        "launcher_pid": os.getpid(),
        "launcher_start_ticks": int(launcher_fields[19]),
        "server_pid": process.pid,
        "server_start_ticks": int(fields[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def launcher_identity() -> dict[str, Any]:
    fields = proc_stat(os.getpid())
    return {
        "launcher_pid": os.getpid(),
        "launcher_start_ticks": int(fields[19]),
        "server_pid": None,
        "server_start_ticks": None,
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def request_once(
    endpoint: str, payload: bytes, timeout: float, request_id: str, kind: str
) -> dict[str, Any]:
    dispatch = now_ns()
    response_evidence = None
    error: str | None = None
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_evidence = {
                "status_code": response.status,
                "headers": list(response.headers.items()),
                **h4_body_binding(response.read()),
            }
    except urllib.error.HTTPError as exc:
        # HTTPError is a real response, not a transport status 0.
        response_evidence = {
            "status_code": exc.code,
            "headers": list(exc.headers.items()),
            **h4_body_binding(exc.read()),
        }
        error = f"HTTPError: {exc}"
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    return {
        "request_id": request_id,
        "kind": kind,
        "dispatch_ns": dispatch,
        "complete_ns": now_ns(),
        "error": error,
        "http_request": h4_body_binding(payload),
        "http_response": response_evidence,
        **h4_response_summary(response_evidence),
    }


def drive_requests(endpoint: str, workload: dict[str, Any]) -> list[dict[str, Any]]:
    payload = h4_request_payload(workload, workload["served_model"])
    timeout = float(workload["request_timeout_seconds"])
    rows: list[dict[str, Any]] = []
    for kind, count in (
        ("warmup", workload["warmup_requests"]),
        ("measured", workload["measured_requests"]),
    ):
        with ThreadPoolExecutor(max_workers=workload["concurrency"]) as pool:
            futures = [
                pool.submit(
                    request_once,
                    endpoint,
                    payload,
                    timeout,
                    f"{kind}-{index:04d}",
                    kind,
                )
                for index in range(count)
            ]
            rows.extend(future.result() for future in futures)
    return rows


def read_rss(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) * 1024
    return 0


def read_cpu_ms(pid: int) -> float:
    fields = proc_stat(pid)
    ticks = int(fields[11]) + int(fields[12]) + int(fields[13]) + int(fields[14])
    return ticks * 1000 / os.sysconf("SC_CLK_TCK")


def process_group_members(pgid: int) -> list[int]:
    members = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = proc_stat(int(entry.name))
            if int(fields[2]) == pgid and fields[0] != "Z":
                members.append(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return members


def process_group_usage(pgid: int) -> tuple[float, int]:
    cpu_ms = 0.0
    rss = 0
    for pid in process_group_members(pgid):
        try:
            cpu_ms += read_cpu_ms(pid)
            rss += read_rss(pid)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return cpu_ms, rss


class ResourceSampler:
    def __init__(self, pid: int, npu_command: list[str] | None) -> None:
        self.pid = pid
        self.npu_command = npu_command
        self.peak_rss = 0
        self.peak_device_memory = 0
        self.cpu_start, self.peak_rss = process_group_usage(pid)
        self.cpu_end = self.cpu_start
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self.stop_event.wait(0.25):
            try:
                cpu_ms, rss = process_group_usage(self.pid)
                self.cpu_end = max(self.cpu_end, cpu_ms)
                self.peak_rss = max(self.peak_rss, rss)
            except (FileNotFoundError, ProcessLookupError):
                break
            if self.npu_command:
                result = subprocess.run(
                    self.npu_command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    try:
                        used = int(result.stdout.strip())
                    except ValueError:
                        continue
                    self.peak_device_memory = max(self.peak_device_memory, used)

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> dict[str, int | float]:
        self.stop_event.set()
        self.thread.join()
        try:
            cpu_ms, rss = process_group_usage(self.pid)
            self.cpu_end = max(self.cpu_end, cpu_ms)
            self.peak_rss = max(self.peak_rss, rss)
        except (FileNotFoundError, ProcessLookupError):
            pass
        return {
            "cpu_ms": max(0.0, self.cpu_end - self.cpu_start),
            "peak_host_rss_bytes": self.peak_rss,
            "peak_device_memory_bytes": self.peak_device_memory,
        }


def evidence_counts(paths: list[str]) -> tuple[int, int]:
    messages = 0
    size = 0
    for raw_path in paths:
        path = Path(raw_path)
        if not path.is_file():
            continue
        size += path.stat().st_size
        with path.open("rb") as stream:
            messages += sum(1 for line in stream if line.strip())
    return messages, size


def port_closed(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return False
    except OSError:
        return True


def terminate(process: subprocess.Popen[bytes], timeout: float = 30) -> None:
    if process_group_members(process.pid):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=min(timeout, 5))
    deadline = time.monotonic() + timeout
    while process_group_members(process.pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    if process_group_members(process.pid):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=10)


def bind_file(path: Path, root: Path) -> dict[str, str]:
    return {"path": str(path.relative_to(root)), "sha256": _digest_bytes(path)}


def arm_environment(definition: dict[str, Any]) -> dict[str, str]:
    explicit = {
        str(key): str(value) for key, value in definition.get("environment", {}).items()
    }
    removed = definition.get("unset_environment", [])
    if set(removed) & explicit.keys():
        raise ValueError("environment variable is both assigned and unset")
    env = os.environ.copy()
    for key in removed:
        env.pop(key, None)
    return env | explicit


def execute_start(
    campaign: dict[str, Any],
    receipt_path: Path,
    launch_spec: dict[str, Any],
    output_root: Path,
    repetition: int,
    arm: str,
) -> dict[str, Any]:
    order = campaign["schedule"][repetition - 1]["order"]
    arm_order = order.index(arm) + 1
    start_id = f"{campaign['cell_id']}-r{repetition}-{arm}"
    run_dir = output_root / start_id
    run_dir.mkdir(parents=True, exist_ok=False)
    definition = launch_spec["arms"][arm]
    env = arm_environment(definition)
    phase_times: dict[str, dict[str, int]] = {}
    process: subprocess.Popen[bytes] | None = None
    sampler: ResourceSampler | None = None
    identity = launcher_identity()
    requests: list[dict[str, Any]] = []
    peak_rss = 0
    sampled_resources: dict[str, int | float] = {
        "cpu_ms": 0.0,
        "peak_host_rss_bytes": 0,
        "peak_device_memory_bytes": 0,
    }
    failure: dict[str, str] | None = None
    ready: int | None = None
    startup_start = now_ns()
    active_phase = PHASES[0]
    phase_begin = startup_start
    cursor = startup_start
    raw_log = run_dir / "raw.log"
    with raw_log.open("wb") as log:
        log.write((json.dumps({"start_id": start_id, "arm": arm}) + "\n").encode())
        try:
            for phase in PHASES:
                begin = cursor
                active_phase = phase
                phase_begin = begin
                commands = definition.get("phase_commands", {}).get(phase, [])
                for command in commands:
                    run_checked(command, env, log)
                cursor = now_ns() if commands else begin
                phase_times[phase] = {"start_ns": begin, "end_ns": cursor}
            worker_start = cursor
            active_phase = "worker_loading"
            phase_begin = worker_start
            process = subprocess.Popen(
                definition["server_command"],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            identity = process_identity(process)
            sampler = ResourceSampler(
                process.pid, launch_spec.get("npu_memory_command")
            )
            sampler.start()
            wait_ready(
                launch_spec["health_url"], launch_spec["startup_timeout_seconds"]
            )
            ready = now_ns()
            phase_times["worker_loading"] = {
                "start_ns": worker_start,
                "end_ns": ready,
            }
            workload = campaign["workload"] | {
                "served_model": definition["served_model"]
            }
            requests = drive_requests(launch_spec["endpoint_url"], workload)
            _, peak_rss = process_group_usage(process.pid)
            sampled_resources = sampler.finish()
        except Exception as exc:
            failure_time = now_ns()
            if ready is None:
                phase_times.setdefault(
                    active_phase,
                    {"start_ns": phase_begin, "end_ns": failure_time},
                )
                cursor = failure_time
                for phase in (*PHASES, "worker_loading"):
                    if phase not in phase_times:
                        phase_times[phase] = {"start_ns": cursor, "end_ns": cursor}
                ready = cursor
            failure = {"phase": active_phase, "class": type(exc).__name__}
            log.write(f"\nrunner failure: {exc}\n".encode())
        finally:
            if sampler is not None and sampler.thread.is_alive():
                sampled_resources = sampler.finish()
            if process is not None:
                terminate(process)

    receipt_copy = run_dir / "deployment-receipt.json"
    receipt_copy.write_bytes(receipt_path.read_bytes())
    process_snapshot = run_dir / "process-snapshot.json"
    process_snapshot.write_text(
        json.dumps({"start_id": start_id, "process_identity": identity}, sort_keys=True)
        + "\n"
    )
    request_results = run_dir / "request-results.json"
    request_results.write_text(
        json.dumps({"start_id": start_id, "requests": requests}, sort_keys=True) + "\n"
    )
    cleanup = {
        "processes_reclaimed": process is None
        or not process_group_members(process.pid),
        "ports_reclaimed": port_closed(launch_spec["host"], launch_spec["port"]),
        "devices_reclaimed": False,
    }
    device_check = launch_spec.get("device_cleanup_command")
    if device_check:
        cleanup["devices_reclaimed"] = (
            subprocess.run(device_check, check=False).returncode == 0
        )
    cleanup_report = run_dir / "cleanup-report.json"
    cleanup_report.write_text(
        json.dumps({"start_id": start_id, "cleanup": cleanup}, sort_keys=True) + "\n"
    )
    assert ready is not None
    messages, evidence_size = evidence_counts(definition.get("evidence_paths", []))
    child_bindings = {
        "raw_log": bind_file(raw_log, output_root),
        "request_results": bind_file(request_results, output_root),
        "process_snapshot": bind_file(process_snapshot, output_root),
        "cleanup_report": bind_file(cleanup_report, output_root),
    }
    raw = {
        "schema": "ecpa-h4-raw-measurement/v2",
        "launch_definition": definition,
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        "start_id": start_id,
        "arm": arm,
        "repetition": repetition,
        "arm_order": arm_order,
        "workload_digest": campaign["workload"]["sha256"],
        "deployment_receipt_sha256": _digest_bytes(receipt_copy),
        "artifact_sha256": {
            label: binding["sha256"] for label, binding in child_bindings.items()
        },
        "process_identity": identity,
        "clock": "CLOCK_MONOTONIC_RAW",
        "startup_start_ns": startup_start,
        "ready_ns": ready,
        "startup_phases": phase_times,
        "requests": requests,
        "resources": {
            "cpu_ms": sampled_resources["cpu_ms"],
            "peak_host_rss_bytes": max(
                peak_rss, int(sampled_resources["peak_host_rss_bytes"])
            ),
            "peak_device_memory_bytes": sampled_resources["peak_device_memory_bytes"],
            "process_messages": messages,
            "evidence_bytes": evidence_size,
            "gate_open_ms": None,
            "failure_detection_ms": None,
            "rollback_ms": None,
            "recovery_ms": None,
        },
    }
    raw_path = run_dir / "raw-measurement.json"
    raw_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    artifacts = {
        "deployment_receipt": bind_file(receipt_copy, output_root),
        **child_bindings,
        "raw_measurement": bind_file(raw_path, output_root),
    }
    fixed = campaign["fixed_identity"]
    record = {
        "schema": "ecpa-formal-campaign-record/v1",
        "campaign_id": campaign["campaign_id"],
        "evidence_class": "formal-real",
        "deployment": {
            "registration_state": "registered",
            "receipt_sha256": artifacts["deployment_receipt"]["sha256"],
        },
        "cell_id": campaign["cell_id"],
        "start_id": start_id,
        "status": "failed" if failure else "complete",
        "arm": arm,
        "repetition": repetition,
        "arm_order": arm_order,
        "process_identity": identity,
        "identity": {
            "manager_commit": fixed["manager_commit"],
            "host_commit": fixed["host_commit"],
            "accelerator_commit": fixed["accelerator_commit"],
            "plugin_commits": {
                key: value["commit"] for key, value in fixed["plugins"].items()
            },
            "provider_versions": {
                "host": fixed["host_version"],
                "accelerator": fixed["accelerator_version"],
            },
            "model_digest": fixed["model_digest"],
            "workload_digest": campaign["workload"]["sha256"],
            "hardware": fixed["hardware"],
            "topology": fixed["topology"],
            "warm_state": fixed["warm_state"],
            "container_digest": launch_spec["container_digest"],
        },
        "artifacts": artifacts,
        "cleanup": cleanup,
        "metrics": {},
        "failure": failure,
    }
    if not failure:
        try:
            record["metrics"] = _recompute_h4_metrics(record, raw, campaign)
        except ValueError as exc:
            record["status"] = "failed"
            record["failure"] = {
                "phase": "measurement_verification",
                "class": type(exc).__name__,
            }

    (run_dir / "record.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--deployment-receipt", type=Path, required=True)
    parser.add_argument("--launch-spec", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--start-id")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    campaign = load_h4_campaign(args.campaign)
    receipt = load_object(args.deployment_receipt)
    validate_receipt(receipt, campaign, args.deployment_receipt)
    launch_raw = args.launch_spec.read_bytes()
    launch_spec = json.loads(launch_raw)
    validate_launch_spec(launch_spec, receipt, launch_raw)
    if args.validate_only:
        print(json.dumps({"status": "validated", "starts": 9}, sort_keys=True))
        return 0
    args.output_root.mkdir(parents=True, exist_ok=True)
    records = []
    for repetition, row in enumerate(campaign["schedule"], 1):
        for arm in row["order"]:
            start_id = f"{campaign['cell_id']}-r{repetition}-{arm}"
            if args.start_id and start_id != args.start_id:
                continue
            records.append(
                execute_start(
                    campaign,
                    args.deployment_receipt,
                    launch_spec,
                    args.output_root,
                    repetition,
                    arm,
                )
            )
    with (args.output_root / "records.jsonl").open("a") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
    succeeded = records and all(
        row["status"] == "complete" and all(row["cleanup"].values()) for row in records
    )
    return 0 if succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
