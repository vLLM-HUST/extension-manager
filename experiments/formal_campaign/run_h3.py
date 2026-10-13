#!/usr/bin/env python3
"""Run one exact-stack H3 process-crash/recovery start and retain raw evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import jsonschema
from analyze import _recompute_h3_metrics, h3_response_correctness
from h3_registration import canonical, command_digest

ROOT = Path(__file__).resolve().parent


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: Any) -> dict[str, str]:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return {"path": path.name, "sha256": digest(path)}


def start_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    return int(fields[21])


def same_live_process(pid: int, expected_start_ticks: int) -> bool:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
    except FileNotFoundError:
        return False
    return fields[2] != "Z" and int(fields[21]) == expected_start_ticks


def process_identity(pid: int) -> dict[str, Any]:
    return {
        "pid": pid,
        "start_ticks": start_ticks(pid),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def wait_ready(url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 300:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise TimeoutError(f"health endpoint did not become ready: {url}")


def request_event(
    url: str,
    request_id: str,
    timeout: float,
    payload: dict[str, Any],
    expected: dict[str, Any],
) -> dict[str, Any]:
    request_raw = canonical(payload)
    detail = {
        "request_id": request_id,
        "request_method": "POST",
        "request_payload_sha256": "sha256:" + hashlib.sha256(request_raw).hexdigest(),
        "outcome": "lost",
        "tuple_supported": False,
        "functional_correctness": False,
        "status_code": 0,
        "response_body": "",
        "response_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
    }
    request = urllib.request.Request(
        url,
        data=request_raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ECPA-Request-ID": request_id,
        },
    )
    try:
        try:
            response = urllib.request.urlopen(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            body = response.read().decode("utf-8")
            detail.update(
                {
                    "outcome": "served" if response.status == 200 else "lost",
                    "tuple_supported": response.headers.get(
                        "x-ecpa-tuple-supported", "false"
                    ).lower()
                    == "true",
                    "status_code": response.status,
                    "response_body": body,
                    "response_sha256": "sha256:"
                    + hashlib.sha256(body.encode()).hexdigest(),
                }
            )
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            detail["functional_correctness"] = (
                response.status == 200
                and h3_response_correctness(parsed, payload, expected)
            )
    except (OSError, urllib.error.URLError, UnicodeError) as exc:
        detail["error"] = type(exc).__name__
    return detail


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-spec", type=Path, required=True)
    parser.add_argument("--deployment-receipt", type=Path, required=True)
    parser.add_argument("--authority-registration", type=Path, required=True)
    parser.add_argument("--arm", required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--arm-order", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    campaign = load(args.campaign_spec)
    schema = load(ROOT / "h3-campaign.schema.json")
    jsonschema.Draft7Validator(schema).validate(campaign)
    receipt = load(args.deployment_receipt)
    receipt_schema = load(ROOT / "h3-deployment-receipt.schema.json")
    jsonschema.Draft7Validator(receipt_schema).validate(receipt)
    campaign_sha = digest(args.campaign_spec)
    if receipt["campaign_sha256"] != campaign_sha:
        raise ValueError("deployment receipt is not bound to campaign")
    authority = load(args.authority_registration)
    authority_schema = load(ROOT / "h3-authority-registration.schema.json")
    jsonschema.Draft7Validator(authority_schema).validate(authority)
    if digest(args.authority_registration) != receipt["authority_registration_sha256"]:
        raise ValueError("authority registration differs from deployment receipt")
    if authority["campaign_sha256"] != campaign_sha:
        raise ValueError("authority registration is not bound to campaign")
    expected_arm_digests = {
        item["id"]: command_digest(item["launch_command"]) for item in campaign["arms"]
    }
    if receipt["arm_command_digests"] != expected_arm_digests:
        raise ValueError("deployment receipt arm commands differ from campaign")
    if (
        receipt["fault_command_digest"]
        != "sha256:" + hashlib.sha256(canonical(campaign["fault"])).hexdigest()
    ):
        raise ValueError("deployment receipt fault command differs from campaign")
    if receipt["state_command_digest"] != command_digest(
        campaign["probe"]["state_command"]
    ):
        raise ValueError("deployment receipt state command differs from campaign")
    if receipt["cleanup_command_digest"] != command_digest(
        campaign["probe"]["cleanup_command"]
    ):
        raise ValueError("deployment receipt cleanup command differs from campaign")
    arm = next((item for item in campaign["arms"] if item["id"] == args.arm), None)
    if arm is None:
        raise ValueError("arm is not frozen in campaign")

    out = args.output_dir.resolve()
    start_id = f"{campaign['cell_id']}-r{args.repetition}-{args.arm}"
    authority_start = next(
        (item for item in authority["starts"] if item["start_id"] == start_id), None
    )
    if authority_start is None:
        raise ValueError("authority registration lacks this start")
    if Path(authority_start["run_directory"]).resolve() != out:
        raise ValueError("authority-owned proxy run directory differs")
    if receipt["authority"]["endpoint"] != authority["authority_endpoint"]:
        raise ValueError("authority endpoint differs from deployment receipt")
    if (
        receipt["authority"]["start_proxy_registration_digests"].get(start_id)
        != authority_start["proxy_registration_sha256"]
    ):
        raise ValueError("authority-owned proxy identity differs")
    out.mkdir(parents=True, exist_ok=False)
    receipt_copy = out / "deployment-receipt.json"
    receipt_copy.write_bytes(args.deployment_receipt.read_bytes())
    authority_copy = out / "authority-registration.json"
    authority_copy.write_bytes(args.authority_registration.read_bytes())
    log_path = out / "raw.log"
    log_file = log_path.open("wb")
    launcher: subprocess.Popen[bytes] | None = None
    restarted: subprocess.Popen[bytes] | None = None
    events: list[dict[str, Any]] = []

    def event(kind: str, detail: dict[str, Any]) -> None:
        events.append(
            {
                "sequence": len(events) + 1,
                "monotonic_ns": time.monotonic_ns(),
                "kind": kind,
                "detail": detail,
            }
        )

    try:
        launcher = subprocess.Popen(
            arm["launch_command"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        launcher_identity = process_identity(launcher.pid)
        wait_ready(
            campaign["probe"]["health_url"], campaign["probe"]["ready_timeout_s"]
        )
        state_before = json.loads(
            subprocess.check_output(campaign["probe"]["state_command"], text=True)
        )
        target_pid = int(Path(arm["fault_target_pid_file"]).read_text().strip())
        if launcher.poll() is not None or os.getsid(target_pid) != launcher.pid:
            raise ValueError("fault target is not owned by this launcher session")
        target = process_identity(target_pid) | {
            "role": campaign["fault"]["target_role"]
        }
        fault_detail = {"fault_id": campaign["fault"]["id"], **target}
        event("fault-triggered", fault_detail)
        os.kill(target_pid, getattr(signal, campaign["fault"]["signal"]))
        deadline = time.monotonic() + campaign["fault"]["target_exit_timeout_s"]
        while time.monotonic() < deadline:
            if not same_live_process(target_pid, target["start_ticks"]):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("fault target identity remained alive")
        event("fault-observed", target)
        event("recovery-started", {})
        restarted = subprocess.Popen(
            arm["launch_command"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        wait_ready(
            campaign["probe"]["health_url"], campaign["probe"]["ready_timeout_s"]
        )
        request_details = []
        for index in range(campaign["probe"]["request_count"]):
            detail = request_event(
                campaign["probe"]["request_url"],
                f"request-{index:04d}",
                campaign["probe"]["request_timeout_s"],
                campaign["probe"]["request_payload"],
                campaign["probe"]["response_expectation"],
            )
            request_details.append(detail)
            event("request-result", detail)
        state_after = json.loads(
            subprocess.check_output(campaign["probe"]["state_command"], text=True)
        )
        event("recovery-complete", state_after)
    finally:
        for process in (restarted, launcher):
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
        log_file.close()

    cleanup = json.loads(
        subprocess.check_output(campaign["probe"]["cleanup_command"], text=True)
    )
    if set(cleanup) != {
        "processes_reclaimed",
        "ports_reclaimed",
        "devices_reclaimed",
    } or not all(value is True for value in cleanup.values()):
        raise RuntimeError("authority cleanup probe did not prove full reclamation")
    process_record = {
        "launcher_pid": launcher_identity["pid"],
        "launcher_start_ticks": launcher_identity["start_ticks"],
        "fault_target_pid": target["pid"],
        "fault_target_start_ticks": target["start_ticks"],
        "boot_id": target["boot_id"],
    }
    request_results = {"start_id": start_id, "requests": request_details}
    process_snapshot = {
        "start_id": start_id,
        "process_identity": process_record,
        "fault_target": target,
    }
    bindings = {
        "raw_log": {"path": log_path.name, "sha256": digest(log_path)},
        "request_results": write(out / "request-results.json", request_results),
        "process_snapshot": write(out / "process-snapshot.json", process_snapshot),
        "cleanup_report": write(
            out / "cleanup-report.json", {"start_id": start_id, "cleanup": cleanup}
        ),
    }
    raw = {
        "schema": "ecpa-h3-raw-recovery/v1",
        "evidence_class": "formal-real",
        "campaign_sha256": campaign_sha,
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        "start_id": start_id,
        "arm": args.arm,
        "repetition": args.repetition,
        "arm_order": args.arm_order,
        "deployment_receipt_sha256": digest(args.deployment_receipt),
        "authority_registration_sha256": digest(authority_copy),
        "proxy_registration_sha256": authority_start["proxy_registration_sha256"],
        "process_identity": process_record,
        "fault_target": target,
        "pre_fault": {
            "predecessor_digest": state_before["predecessor_digest"],
            "evidence_identity_sha256": state_before["evidence_identity_sha256"],
        },
        "artifact_sha256": {name: value["sha256"] for name, value in bindings.items()},
        "events": events,
        "request_results": request_results,
        "process_snapshot": process_snapshot,
    }
    raw_binding = write(out / "raw-recovery.json", raw)
    artifacts = {
        "deployment_receipt": {
            "path": receipt_copy.name,
            "sha256": digest(receipt_copy),
        },
        "authority_registration": {
            "path": authority_copy.name,
            "sha256": digest(authority_copy),
        },
        **bindings,
        "raw_recovery": raw_binding,
    }
    record = {
        "schema": "ecpa-formal-campaign-record/v1",
        "campaign_id": campaign["campaign_id"],
        "evidence_class": "formal-real",
        "deployment": {
            "registration_state": "registered",
            "receipt_sha256": digest(receipt_copy),
        },
        "cell_id": campaign["cell_id"],
        "start_id": start_id,
        "process_identity": process_record,
        "status": "complete",
        "arm": args.arm,
        "repetition": args.repetition,
        "arm_order": args.arm_order,
        "identity": campaign["fixed_identity"],
        "artifacts": artifacts,
        "cleanup": cleanup,
        "metrics": {},
    }
    record["metrics"] = _recompute_h3_metrics(
        record, raw, campaign | {"_sha256": campaign_sha}
    )
    record_binding = write(out / "record.json", record)
    write(
        out / "run-manifest.json",
        {
            "start_id": start_id,
            "campaign_sha256": campaign_sha,
            "deployment_receipt_sha256": digest(args.deployment_receipt),
            "artifacts": artifacts,
            "record": record_binding,
            "cleanup": cleanup,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
