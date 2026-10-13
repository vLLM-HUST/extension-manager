"""Execute a separately frozen common worker-crash/full-relaunch qualification.

This never enters the original manager-crash/native-prepare campaign.
"""

from __future__ import annotations

import argparse
import contextlib
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

from vllm_hust_ext.host_evidence import parse_host_event

ARMS = {
    "vanilla-vllm-entry-points": "entry-points-unmanaged",
    "manual-integration": "explicit-manual-hooks",
    "ecpa": "manager-controlled-activation",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(pid: int) -> dict[str, Any]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ValueError("process is a zombie")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "session": int(fields[3]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def live(expected: dict[str, Any]) -> bool:
    try:
        return identity(expected["pid"]) == expected
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return False


def members(owner: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                item = identity(int(entry.name))
            except (FileNotFoundError, ProcessLookupError, ValueError):
                continue
            if item["session"] == owner["pid"]:
                if item["start_ticks"] < owner["start_ticks"]:
                    raise ValueError("session member predates launcher")
                found.append(item)
    return found


def owned_sessions(owner):
    """Capture nested supervisor sessions while their ancestry is live."""
    if not live(owner):
        raise ValueError("launcher is not live for ownership capture")
    table = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            item = identity(int(entry.name))
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            table[item["pid"]] = (item, int(fields[1]))
        except (FileNotFoundError, ProcessLookupError, ValueError):
            continue
    reachable = {owner["pid"]}
    while True:
        added = {pid for pid, (_, ppid) in table.items() if ppid in reachable}
        if added <= reachable:
            break
        reachable |= added
    sessions = {table[pid][0]["session"] for pid in reachable if pid in table}
    captured = []
    for sid in sessions:
        if sid not in reachable or sid not in table:
            raise ValueError("descendant session lacks live owned leader")
        leader = table[sid][0]
        if leader["start_ticks"] < owner["start_ticks"] or not live(leader):
            raise ValueError("nested session leader changed")
        captured.append(leader)
    return captured, {pid: table[pid][0] for pid in reachable if pid in table}


def signal_exact(expected: dict[str, Any], sig: int) -> None:
    fd = os.pidfd_open(expected["pid"])
    try:
        if not live(expected):
            raise ValueError("fault target identity changed")
        signal.pidfd_send_signal(fd, sig)
    finally:
        os.close(fd)


def cleanup(process, owner, timeout, captured=None):
    sessions = {item["pid"]: item for item in (captured or [owner])}
    sessions[owner["pid"]] = owner
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if live(owner):
            try:
                new, _ = owned_sessions(owner)
            except ValueError:
                if live(owner):
                    raise
            else:
                sessions.update({item["pid"]: item for item in new})
        for session_owner in sessions.values():
            leader = Path(f"/proc/{session_owner['pid']}/stat")
            if leader.exists():
                fields = leader.read_text().rsplit(")", 1)[1].split()
                if int(fields[19]) != session_owner["start_ticks"]:
                    raise ValueError("launcher PID reused; refuse cleanup")
            for item in members(session_owner):
                if live(item):
                    with contextlib.suppress(FileNotFoundError, ProcessLookupError):
                        signal_exact(item, sig)
        deadline = time.monotonic() + timeout
        while (
            any(members(s) for s in sessions.values()) and time.monotonic() < deadline
        ):
            time.sleep(0.01)
    process.wait(timeout=timeout)
    if any(members(s) for s in sessions.values()):
        raise ValueError("owned processes survived terminal cleanup")


def validate(campaign: dict[str, Any]) -> None:
    if (
        campaign["schema"] != "ecpa-h3-worker-relaunch-qualification/v1"
        or campaign["classification"]
        not in {"QUALIFIED_NONFORMAL", "CPU_PREFLIGHT_ONLY"}
        or campaign["formal_result"] is not False
        or campaign["recovery_action"] != "common-external-full-relaunch"
        or campaign["original_manager_cell_completed"] is not False
    ):
        raise ValueError("common worker qualification scope changed")
    policy = campaign["policy"]
    if policy["signal"] != "SIGKILL" or policy["relaunches"] != 1:
        raise ValueError("one common SIGKILL/full relaunch required")
    for name in (
        "ready_timeout_s",
        "exit_timeout_s",
        "cleanup_timeout_s",
        "probe_poll_s",
        "request_timeout_s",
    ):
        if isinstance(policy[name], bool) or not 0 < policy[name] <= 300:
            raise ValueError("invalid bounded common policy")
    arms = campaign["arms"]
    if len(arms) != 3 or {a["id"] for a in arms} != set(ARMS):
        raise ValueError("retain all three original arms")
    for arm in arms:
        if not Path(arm["cwd"]).is_absolute() or not Path(arm["cwd"]).is_dir():
            raise ValueError("concrete launch cwd required")
        if arm["activation_contract"] != ARMS[arm["id"]]:
            raise ValueError("arm activation contract differs")
        if not arm["argv"] or any(not isinstance(v, str) or not v for v in arm["argv"]):
            raise ValueError("concrete launch command required")
        if len(arm["phases"]) != 2:
            raise ValueError("two fresh launch phases required")
        if len({p["launch_id"] for p in arm["phases"]}) != 2:
            raise ValueError("relaunch requires a fresh launch identity")
        if len({p["evidence_path"] for p in arm["phases"]}) != 2:
            raise ValueError("relaunch requires fresh evidence path")
        if arm["evidence_protocol"] != (
            "cpu-fixture-worker/v1"
            if campaign["classification"] == "CPU_PREFLIGHT_ONLY"
            else "vllm-host-worker-event/v1"
        ):
            raise ValueError("fixture evidence cannot qualify real Host")
        if len(arm["sources"]) != 3 or {s["role"] for s in arm["sources"]} != {
            "launcher",
            "host",
            "mod",
        }:
            raise ValueError("exact launcher/Host/MOD source bindings required")
        for source in arm["sources"]:
            if sha(Path(source["path"])) != source["sha256"]:
                raise ValueError("frozen launch source bytes differ")
        if not any(
            str(Path(s["path"]).resolve())
            in {str(Path(v).resolve()) for v in arm["argv"][:2]}
            for s in arm["sources"]
            if s["role"] == "launcher"
        ):
            raise ValueError("launcher source does not bind executed argv")
        if campaign["classification"] == "QUALIFIED_NONFORMAL":
            if not arm["probe"]["url"].startswith("http://127.0.0.1:"):
                raise ValueError("direct loopback model completion probe required")
            for source in arm["sources"]:
                if len(source["revision"]) != 40 or any(
                    c not in "0123456789abcdef" for c in source["revision"]
                ):
                    raise ValueError("exact source revision required")
            flags = set(arm["argv"])
            required = {
                "--disable-ecpa-manager",
                (
                    "--manual-hooks"
                    if arm["id"] == "manual-integration"
                    else "--enable-entrypoints"
                ),
            }
            activation_flags = flags & {
                "--disable-ecpa-manager",
                "--manual-hooks",
                "--enable-entrypoints",
            }
            if arm["id"] != "ecpa" and activation_flags != required:
                raise ValueError("baseline native activation options missing")
            if arm["id"] == "ecpa" and activation_flags:
                raise ValueError("ECPA cannot disable Manager")
    phases = [p for a in arms for p in a["phases"]]
    if (
        len({p["launch_id"] for p in phases}) != 6
        or len({p["evidence_path"] for p in phases}) != 6
    ):
        raise ValueError("launch/evidence paths must be start-owned across arms")


def worker(arm, phase, owner, launched_wall_ns):
    path = Path(phase["evidence_path"])
    content = path.read_text()
    if not content.endswith("\n"):
        return None
    records = [json.loads(line) for line in content.splitlines() if line]
    ownership, descendants = owned_sessions(owner)
    candidates = []
    for row in records:
        if arm["evidence_protocol"] == "vllm-host-worker-event/v1":
            row = parse_host_event(json.dumps(row).encode())
            proc = row["process"]
            if row["event"] != "invoked" or proc["role"] != "worker":
                continue
            if proc["assignment_source"] != "host":
                raise ValueError("worker role is not Host assigned")
            ticks = int(proc["start_identity"].rsplit(":", 1)[1])
        else:
            if row["schema"] != "cpu-fixture-worker/v1":
                raise ValueError("fixture worker protocol differs")
            proc = row["process"]
            ticks = proc["start_ticks"]
        if proc["ordinal"] != arm["target_ordinal"]:
            continue
        if row["launch_id"] != phase["launch_id"] or row["plan_id"] != arm["plan_id"]:
            raise ValueError("stale worker launch/plan identity")
        if row["observed_at_ns"] < launched_wall_ns:
            raise ValueError("worker record predates current launch")
        current = identity(proc["pid"])
        if (
            current["pid"] == owner["pid"]
            or current["start_ticks"] != ticks
            or descendants.get(current["pid"]) != current
            or current["session"] not in {s["pid"] for s in ownership}
            or current["start_ticks"] < owner["start_ticks"]
        ):
            raise ValueError("worker is outside owned launch epoch/session")
        candidates.append(
            {
                "identity": current,
                "ownership_sessions": ownership,
                "process_epoch": proc["process_epoch"],
                "ordinal": proc["ordinal"],
                "raw": row,
            }
        )
    unique = {
        json.dumps([c["identity"], c["process_epoch"]], sort_keys=True)
        for c in candidates
    }
    if not unique:
        return None
    if len(unique) != 1:
        raise ValueError("one unambiguous owned worker required")
    return candidates[-1]


def probe(arm, classification, output, phase_index, timeout):
    """Retain actual direct-backend completion bytes; no authority claim."""
    if classification == "CPU_PREFLIGHT_ONLY":
        result = subprocess.run(
            arm["probe_command"],
            capture_output=True,
            timeout=timeout,
            check=False,
            cwd=arm["cwd"],
            env=arm["env"],
        )
        (output / f"phase{phase_index}.probe.stdout").write_bytes(result.stdout)
        (output / f"phase{phase_index}.probe.stderr").write_bytes(result.stderr)
        (output / f"phase{phase_index}.probe.status").write_text(str(result.returncode))
        if result.returncode:
            raise ValueError("CPU fixture probe command failed")
        return
    spec = arm["probe"]
    raw_request = json.dumps(spec["payload"]).encode()
    (output / f"phase{phase_index}.request.json").write_bytes(raw_request)
    attempts = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            spec["url"], data=raw_request, headers={"Content-Type": "application/json"}
        )
        item = {"attempt": len(attempts), "monotonic_ns": time.monotonic_ns()}
        try:
            with urllib.request.urlopen(
                request,
                timeout=min(
                    arm["request_timeout_s"], max(0.01, deadline - time.monotonic())
                ),
            ) as response:
                body, status = response.read(), response.status
            item["status"] = status
            name = f"phase{phase_index}.response{len(attempts)}.bin"
            (output / name).write_bytes(body)
            item["response_path"] = name
            data = json.loads(body)
            accepted = (
                status == 200
                and data["model"] == spec["payload"]["model"]
                and data["usage"]["completion_tokens"] > 0
                and bool(data["choices"])
            )
        except urllib.error.HTTPError as exc:
            item["status"] = exc.code
            name = f"phase{phase_index}.response{len(attempts)}.bin"
            (output / name).write_bytes(exc.read())
            item["response_path"] = name
            item["failure"] = str(exc)
            accepted = False
        except (OSError, ValueError, KeyError, urllib.error.URLError) as exc:
            item["failure"] = str(exc)
            accepted = False
        item["accepted"] = accepted
        attempts.append(item)
        (output / f"phase{phase_index}.probe-attempts.json").write_text(
            json.dumps(attempts, indent=2) + "\n"
        )
        if accepted:
            return
        time.sleep(arm["probe_poll_s"])
    raise ValueError("actual model completion readiness timeout")


def run_arm(campaign, arm_id, output: Path):
    validate(campaign)
    arm = next(a for a in campaign["arms"] if a["id"] == arm_id)
    policy = campaign["policy"]
    output.mkdir(parents=True, exist_ok=False)
    frozen_campaign = output / "campaign.json"
    frozen_campaign.write_text(json.dumps(campaign, indent=2) + "\n")
    events, processes = [], []
    result = {
        "campaign_sha256": sha(frozen_campaign),
        "classification": campaign["classification"],
        "formal_result": False,
        "original_manager_cell_completed": False,
        "arm": arm_id,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "passed": False,
    }
    try:
        observed = []
        for source in arm["sources"]:
            (output / (source["role"] + ".source")).write_bytes(
                Path(source["path"]).read_bytes()
            )
        for index, phase in enumerate(arm["phases"]):
            validate(campaign)
            evidence = Path(phase["evidence_path"])
            if evidence.exists():
                raise ValueError("fresh evidence path already exists")
            env = dict(arm["env"])
            env.update(
                ECPA_ACTIVATION_CONTRACT=arm["activation_contract"],
                VLLM_ECPA_PLAN_ID=arm["plan_id"],
                VLLM_ECPA_LAUNCH_ID=phase["launch_id"],
                VLLM_HUST_EXT_EVIDENCE_PATH=str(evidence),
            )
            launched = time.time_ns()
            with (
                (output / f"phase{index}.stdout").open("wb") as stdout,
                (output / f"phase{index}.stderr").open("wb") as stderr,
            ):
                process = subprocess.Popen(
                    arm["argv"],
                    cwd=arm["cwd"],
                    env=env,
                    start_new_session=True,
                    stdout=stdout,
                    stderr=stderr,
                )
            owner = identity(process.pid)
            captured = [owner]
            processes.append((process, owner, captured))
            deadline = time.monotonic() + policy["ready_timeout_s"]
            while not evidence.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ValueError("launcher exited before worker evidence")
                time.sleep(0.01)
            target = None
            while target is None and time.monotonic() < deadline:
                if evidence.exists():
                    target = worker(arm, phase, owner, launched)
                if target is None:
                    time.sleep(0.01)
            if target is None:
                raise ValueError("owned worker readiness timeout")
            captured.extend(target["ownership_sessions"])
            (output / f"phase{index}.evidence.jsonl").write_bytes(evidence.read_bytes())
            probe(
                {
                    **arm,
                    "request_timeout_s": policy["request_timeout_s"],
                    "probe_poll_s": policy["probe_poll_s"],
                },
                campaign["classification"],
                output,
                index,
                policy["ready_timeout_s"],
            )
            if not live(target["identity"]):
                raise ValueError("worker died before completed probe")
            observed.append(target)
            events.append(
                {
                    "kind": "worker-observed",
                    "phase": index,
                    "monotonic_ns": time.monotonic_ns(),
                    **target,
                }
            )
            if index == 0:
                signal_exact(target["identity"], signal.SIGKILL)
                events.append(
                    {
                        "kind": "signal-delivered",
                        "monotonic_ns": time.monotonic_ns(),
                        **target,
                    }
                )
                deadline = time.monotonic() + policy["exit_timeout_s"]
                while live(target["identity"]) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if live(target["identity"]):
                    raise ValueError("fault target survived signal")
                events.append(
                    {"kind": "target-exited", "monotonic_ns": time.monotonic_ns()}
                )
                cleanup(process, owner, policy["cleanup_timeout_s"], captured)
            elif (
                target["identity"] == observed[0]["identity"]
                or target["process_epoch"] == observed[0]["process_epoch"]
            ):
                raise ValueError("relaunch did not produce fresh worker identity/epoch")
        result["passed"] = True
    except Exception as exc:
        result["failure"] = str(exc)
    finally:
        errors = []
        for process, owner, captured in processes:
            try:
                cleanup(process, owner, policy["cleanup_timeout_s"], captured)
            except Exception as exc:
                errors.append(str(exc))
        result["cleanup_errors"] = errors
        if errors:
            result["passed"] = False
        result["events"] = events
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        if sha(frozen_campaign) != result["campaign_sha256"]:
            raise ValueError("frozen campaign bytes changed during execution")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--arm", choices=ARMS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sha(args.campaign) != args.expected_sha256:
        parser.error("campaign differs from independently frozen digest")
    result = run_arm(json.loads(args.campaign.read_text()), args.arm, args.output)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
