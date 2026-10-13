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
from h3_authority_chain import (
    snapshot_digest,
    verify_native_recovery,
    verify_recovery_events,
)
from h3_phase_barrier import read_native_recovery, wait_native_prepare
from h3_registration import canonical, command_digest

from experiments.exposure_gate.loopback_traffic import read_traffic_journal

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


def terminate_owned_session(
    process: subprocess.Popen[bytes], owner: dict[str, Any]
) -> None:
    """Reclaim descendants even when SIGKILL already removed the leader."""
    leader = Path(f"/proc/{owner['pid']}/stat")
    if leader.exists() and start_ticks(owner["pid"]) != owner["start_ticks"]:
        raise RuntimeError("launcher PID reused; refuse group cleanup")
    if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != owner["boot_id"]:
        raise RuntimeError("boot identity changed; refuse group cleanup")

    def members() -> list[int]:
        result = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                if (
                    fields[0] != "Z"
                    and int(fields[2]) == owner["pid"]
                    and int(fields[3]) == owner["pid"]
                ):
                    if int(fields[19]) < owner["start_ticks"]:
                        raise RuntimeError("session member predates launcher")
                    result.append(int(entry.name))
            except FileNotFoundError:
                continue
        return result

    for sig in (signal.SIGTERM, signal.SIGKILL):
        if members():
            os.killpg(owner["pid"], sig)
        deadline = time.monotonic() + 5
        while members() and time.monotonic() < deadline:
            time.sleep(0.05)
    process.wait(timeout=5)
    if members():
        raise RuntimeError("owned launcher session survived cleanup")


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

    owned_launches: list[tuple[subprocess.Popen[bytes], dict[str, Any]]] = []

    def retain_failure() -> None:
        failure = load(out / "failure.json")
        try:
            report = json.loads(
                subprocess.check_output(
                    campaign["probe"]["cleanup_command"], text=True, timeout=30
                )
            )
        except Exception as cleanup_exc:
            report = {"error": str(cleanup_exc)}
        cleanup_binding = write(out / "cleanup-report.json", report)
        snapshot_binding = write(
            out / "process-snapshot.json",
            {
                "start_id": start_id,
                "failure": failure,
                "owned_launches": [p for _, p in owned_launches],
            },
        )
        request_binding = write(
            out / "request-results.json",
            {
                "start_id": start_id,
                "requests": [
                    e["detail"] for e in events if e["kind"] == "request-result"
                ],
            },
        )
        write(
            out / "record.json",
            {
                "schema": "ecpa-formal-campaign-record/v1",
                "campaign_id": campaign["campaign_id"],
                "evidence_class": "formal-real",
                "cell_id": campaign["cell_id"],
                "start_id": start_id,
                "status": "failed",
                "arm": args.arm,
                "repetition": args.repetition,
                "arm_order": args.arm_order,
                "identity": campaign["fixed_identity"],
                "metrics": {},
                "deployment": {
                    "registration_state": "registered",
                    "receipt_sha256": digest(receipt_copy),
                },
                "artifacts": {
                    "deployment_receipt": {
                        "path": receipt_copy.name,
                        "sha256": digest(receipt_copy),
                    },
                    "authority_registration": {
                        "path": authority_copy.name,
                        "sha256": digest(authority_copy),
                    },
                    "raw_log": {"path": log_path.name, "sha256": digest(log_path)},
                    "request_results": request_binding,
                    "process_snapshot": snapshot_binding,
                    "cleanup_report": cleanup_binding,
                },
                "cleanup": {
                    k: report.get(k) is True
                    for k in (
                        "processes_reclaimed",
                        "ports_reclaimed",
                        "devices_reclaimed",
                    )
                },
                "failure": {
                    "phase": "prepare-fault-recovery",
                    "class": failure["error"],
                },
            },
        )

    try:
        phase = arm.get("phase_barrier")
        if "prepare" in campaign["cell_id"] and (
            not phase or phase["support"] != "supported"
        ):
            raise ValueError(
                "arm lacks its own durable prepare protocol; no fault injected"
            )
        authority_journal = out / "authority-journal.jsonl"
        authority_events = read_traffic_journal(authority_journal)
        proxy_identity = process_identity(authority_events[0]["proxy_pid"])
        if proxy_identity["start_ticks"] != authority_events[0]["proxy_start_ticks"]:
            raise ValueError("authority process identity changed")
        if proxy_identity["pid"] == os.getpid():
            raise ValueError("authority is not independently owned")
        launched_ns = time.monotonic_ns()
        launcher = subprocess.Popen(
            arm["launch_command"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        launcher_identity = process_identity(launcher.pid)
        owned_launches.append((launcher, launcher_identity))
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
        if phase and phase["support"] == "supported":
            if args.arm != "ecpa":
                raise ValueError(
                    "ECPA native prepare/recovery cannot be injected into a baseline"
                )
            proof = wait_native_prepare(
                phase,
                target=target,
                launcher_pid=launcher.pid,
                launch_id=start_id,
                launched_ns=launched_ns,
                state_before=state_before,
            )
            write(out / "prepare-proof.json", proof)
            fault_detail["prepare_proof"] = proof
            fault_detail["prepare_proof_sha256"] = digest(out / "prepare-proof.json")
        if not same_live_process(target_pid, target["start_ticks"]):
            raise ValueError("fault target changed after prepare validation")
        os.kill(target_pid, getattr(signal, campaign["fault"]["signal"]))
        event("fault-triggered", fault_detail)
        deadline = time.monotonic() + campaign["fault"]["target_exit_timeout_s"]
        while time.monotonic() < deadline:
            if not same_live_process(target_pid, target["start_ticks"]):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("fault target identity remained alive")
        event("fault-observed", target)
        restart_ns = time.monotonic_ns()
        event("recovery-started", {"monotonic_ns": restart_ns})
        restarted = subprocess.Popen(
            arm["launch_command"],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        restarted_identity = process_identity(restarted.pid)
        owned_launches.append((restarted, restarted_identity))
        events[-1]["detail"]["manager"] = restarted_identity
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
        completion_ns = time.monotonic_ns()
        if not phase or phase["support"] != "supported":
            raise ValueError("arm lacks an independent native recovery adapter")
        native_recovery = read_native_recovery(Path(phase["journal_path"]))
        verify_native_recovery(proof, native_recovery)
        prepared = proof["native_state"]
        prepared_route = {
            "generation": prepared["predecessor_generation"],
            "fence": f"fence-{prepared['predecessor_generation']}",
            "snapshot_sha256": snapshot_digest(
                json.loads(prepared["predecessor_json"])
            ),
        }
        authority_events = read_traffic_journal(authority_journal)
        authority_facts = verify_recovery_events(
            authority_events,
            expected_proxy=proxy_identity,
            registration_sha256=authority_start["proxy_registration_sha256"],
            launch_id=start_id,
            prepared_route=prepared_route,
            fault_ns=next(
                e["monotonic_ns"] for e in events if e["kind"] == "fault-triggered"
            ),
            restart_ns=restart_ns,
            completion_ns=completion_ns,
        )
        event(
            "recovery-complete",
            {"authority_facts": authority_facts, "state_probe": state_after},
        )
    except Exception as exc:
        write(
            out / "failure.json",
            {
                "schema": "ecpa-h3-incomplete-start/v1",
                "start_id": start_id,
                "arm": args.arm,
                "status": "failed",
                "formal_result": False,
                "error": str(exc),
                "fault_injected": any(e["kind"] == "fault-triggered" for e in events),
                "events": events,
                "phase_barrier": arm.get("phase_barrier"),
            },
        )
        raise
    finally:
        for process, owner in reversed(owned_launches):
            try:
                terminate_owned_session(process, owner)
            except Exception as exc:
                write(
                    out / "failure.json",
                    {
                        "start_id": start_id,
                        "error": "owned-session-cleanup: " + str(exc),
                        "events": events,
                        "owner": owner,
                    },
                )
        log_file.close()
        if (out / "failure.json").exists():
            retain_failure()

    if (out / "failure.json").exists():
        raise RuntimeError("H3 cleanup failed; failed record retained")

    try:
        cleanup = json.loads(
            subprocess.check_output(campaign["probe"]["cleanup_command"], text=True)
        )
        if set(cleanup) != {
            "processes_reclaimed",
            "ports_reclaimed",
            "devices_reclaimed",
        } or not all(value is True for value in cleanup.values()):
            raise RuntimeError("authority cleanup probe did not prove full reclamation")
    except Exception as exc:
        write(
            out / "failure.json",
            {"start_id": start_id, "error": str(exc), "events": events},
        )
        retain_failure()
        raise
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
    authority_binding = write(
        out / "authority-chain.json",
        {
            "events": authority_events,
            "proxy_identity": proxy_identity,
            "prepared_route": prepared_route,
            "native_recovery": native_recovery,
        },
    )
    bindings["authority_chain"] = authority_binding
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
        "authority_chain": {
            "events": authority_events,
            "proxy_identity": proxy_identity,
            "prepared_route": prepared_route,
            "native_recovery": native_recovery,
        },
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
