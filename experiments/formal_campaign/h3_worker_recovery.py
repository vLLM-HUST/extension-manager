"""Source-pinned worker carrier interface and independent recovery intake.

The independent runner owns the exact fault; the carrier owns native relaunch.
This module never pretends
that a baseline has ECPA durable prepare. Host events are unsigned raw inputs,
so source admission, independent authority registration and kernel observations
remain mandatory. No caller-supplied objective verdict is consumed.
"""
from __future__ import annotations

import hashlib
import json
import signal
from pathlib import Path
import subprocess
import sys
import time

from jsonschema import Draft7Validator
from experiments.formal_campaign.h3_client_trace import verify_window, read_client_trace
from experiments.exposure_gate.loopback_traffic import read_traffic_journal
from vllm_hust_ext.host_evidence import parse_host_event

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
RAW_SCHEMA = "ecpa-h3-worker-raw-recovery/v1"


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_carrier(campaign: dict, *, check_sources: bool = False) -> dict:
    carrier = campaign.get("cell_execution")
    require(isinstance(carrier, dict), "worker cell lacks source-owned carrier; no launch or fault")
    Draft7Validator(json.loads((HERE / "h3-worker-carrier.schema.json").read_text())).validate(carrier)
    require(carrier["kind"] == "worker-recovery", "worker cell carrier kind differs")
    require(campaign["fault"]["target_role"] == "worker",
            "worker cell cannot target a Manager or caller-selected unrelated role")
    require(campaign["probe"]["request_count"] == 60
            and campaign["probe"]["request_timeout_s"] == 10,
            "original H3 client workload changed")
    expected = {f"{campaign['cell_id']}-r{r}-{a}" for r in (1, 2, 3) for a in ARMS}
    require(set(carrier["starts"]) == expected, "worker carrier must bind nine original starts")
    for start_id, row in carrier["starts"].items():
        require(row["client_window"]["request_count"] == 60
                and row["client_window"]["concurrency"] == 8
                and row["client_window"]["interval_s"] == .2
                and row["client_window"]["timeout_s"] == 10,
                "original H3 client workload changed")
        require(row["client_window"]["start_id"] == start_id, "worker client start differs")
        from experiments.formal_campaign.h3_client_trace import validate_spec
        validate_spec(row["client_window"])
        require(row["client_window"]["payload"] == campaign["probe"]["request_payload"]
                and row["client_window"]["response_expectation"] == campaign["probe"]["response_expectation"],
                "worker client oracle/workload differs from frozen campaign")
    source = carrier["source"]
    relative = Path(source["repository_path"])
    require(not relative.is_absolute() and ".." not in relative.parts
            and relative.parts[:2] == ("experiments", "formal_campaign"),
            "worker carrier source must be admitted formal_campaign code")
    require(str(Path(carrier["command"][0]).resolve()) == str(Path(sys.executable).resolve())
            and carrier["command"][1] == str((ROOT / relative).resolve()),
            "worker carrier argv is not the pinned source and runtime Python")
    if check_sources:
        raw = (ROOT / relative).read_bytes()
        require(digest(raw) == source["sha256"], "worker carrier source bytes differ")
        require(b"ecpa-h3-owned-worker-handshake/v1" in raw,
                "worker carrier lacks the independent kernel observer handshake")
        historical = subprocess.check_output(["git", "-C", str(ROOT), "show",
                                              f"{campaign['fixed_identity']['manager_commit']}:{relative}"])
        require(raw == historical, "worker carrier is absent from admitted Manager commit")
    return carrier


def _artifact(root: Path, ref: dict) -> Path:
    path = (root / ref["path"]).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file(), "worker raw artifact escapes or is missing")
    require(digest(path.read_bytes()) == ref["sha256"], "worker raw artifact digest differs")
    return path


def _event(value: dict, expected: dict, role: str) -> dict:
    event = parse_host_event(canonical(value))
    proc = event["process"]
    require(proc["assignment_source"] == "host" and proc["role"] == role,
            "worker recovery requires source-owned Host role assignment")
    require(event["event"] == "invoked", "worker carrier cannot use a loader-only record")
    ticks = int(proc["start_identity"].rsplit(":", 1)[1])
    require((proc["pid"], ticks) == (expected["pid"], expected["start_ticks"]),
            "Host event differs from independently observed kernel identity")
    require(event["launch_id"] == expected["launch_id"], "Host event launch epoch differs")
    return event


def capture_parent_worker_ancestry(parent: dict, worker: dict) -> list[dict]:
    """Observe the actual API-to-worker subtree, including engine intermediates.

    Sharing an adapter session or launch label does not establish this link.
    Re-read every kernel after walking PPIDs to reject exit/reparent/PID reuse.
    """
    from experiments.formal_campaign.h3_worker_relaunch import identity
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    chain = []
    pid = worker["pid"]
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        kernel = identity(pid)
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        require(int(fields[19]) == kernel["start_ticks"], "ancestry kernel changed")
        chain.append(kernel | {"ppid": int(fields[1])})
        if pid == parent["pid"]:
            break
        pid = int(fields[1])
    chain.reverse()
    phase = {"parent": parent, "worker": worker, "parent_worker_ancestry": chain}
    verify_parent_worker_ancestry(phase)
    for item in chain:
        require(item["boot_id"] == boot and identity(item["pid"]) ==
                {k: item[k] for k in ("pid", "start_ticks", "session", "boot_id")},
                "ancestry kernel changed after observation")
        fields = Path(f"/proc/{item['pid']}/stat").read_text().rsplit(")", 1)[1].split()
        require(int(fields[1]) == item["ppid"], "ancestry was reparented during observation")
    return chain


def verify_parent_worker_ancestry(phase: dict) -> None:
    chain = phase["parent_worker_ancestry"]
    require(len(chain) >= 2 and len({p["pid"] for p in chain}) == len(chain),
            "worker lacks a distinct API-parent ancestry chain")
    for endpoint, field in ((chain[0], "parent"), (chain[-1], "worker")):
        require(all(endpoint[k] == phase[field][k]
                    for k in ("pid", "start_ticks", "boot_id", "session")),
                "worker is not in this phase API-parent subtree")
    for parent, child in zip(chain, chain[1:]):
        require(child["ppid"] == parent["pid"]
                and child["boot_id"] == parent["boot_id"]
                and child["start_ticks"] >= parent["start_ticks"],
                "API-parent to worker ancestry edge differs")


def verify_worker_raw(raw: dict, campaign: dict, artifact_root: Path) -> dict:
    Draft7Validator(json.loads((HERE / "h3-worker-raw-recovery.schema.json").read_text())).validate(raw)
    carrier = validate_carrier(campaign)
    require(raw["cell_id"] == campaign["cell_id"] and raw["arm"] in ARMS,
            "worker raw cell/arm differs")
    require(raw["start_id"] == f"{raw['cell_id']}-r{raw['repetition']}-{raw['arm']}",
            "worker raw start differs")
    start = carrier["starts"][raw["start_id"]]
    require(raw["carrier_source_sha256"] == carrier["source"]["sha256"], "worker carrier source differs")
    before, after = raw["before"], raw["after"]
    require(before["worker"]["boot_id"] == after["worker"]["boot_id"], "worker boot changed")
    require((before["worker"]["pid"], before["worker"]["start_ticks"]) !=
            (after["worker"]["pid"], after["worker"]["start_ticks"]), "replacement kernel was replayed")
    require(before["worker"]["launch_id"] != after["worker"]["launch_id"], "worker launch epoch reused")
    for phase in (before, after):
        parent = _event(phase["parent_event"], phase["parent"], "api-server")
        worker = _event(phase["worker_event"], phase["worker"], "worker")
        require(parent["launch_id"] == worker["launch_id"], "parent/worker cross-launch evidence")
        require(phase["parent"]["boot_id"] == phase["worker"]["boot_id"], "parent/worker boot differs")
        require(phase["worker"]["start_ticks"] >= phase["parent"]["start_ticks"], "worker predates parent")
        require(phase["worker"]["session"] in phase["owned_sessions"], "worker outside captured owned sessions")
        verify_parent_worker_ancestry(phase)
    require(before["worker_event"]["process"]["process_epoch"] != after["worker_event"]["process"]["process_epoch"],
            "worker process epoch reused")
    require(raw["fault"]["target"] == before["worker"], "fault not bound to original actual worker")
    fault_ns, dead_ns, recovery_ns = raw["fault"]["triggered_ns"], raw["fault"]["observed_dead_ns"], raw["recovery_ns"]
    require(0 < fault_ns < dead_ns < after["observed_ns"] <= recovery_ns, "worker fault/recovery order differs")
    require(before["observed_ns"] < fault_ns and raw["fault"]["signal"] == campaign["fault"]["signal"],
            "worker fault is not frozen and observed before injection")
    require(raw["recovery_action"] == carrier["recovery_action"], "recovery action differs from preregistration")
    require(raw["operator_actions"] == (1 if raw["recovery_action"] == "bounded-operator-full-relaunch" else 0),
            "external relaunch must count its bounded operator action")
    paths = {key: _artifact(artifact_root, value) for key, value in raw["carrier_artifacts"].items()}
    kernels = json.loads(paths["kernel_observations"].read_bytes())
    require(kernels["before"] == before and kernels["after"] == after
            and kernels["observed_dead_ns"] == dead_ns
            and kernels["fault_triggered_ns"] == fault_ns,
            "worker raw differs from independent runner kernel observations")
    window = verify_window(start["client_window"], paths["client_trace"], paths["authority_journal"],
                           expected_client=raw["client_identity"], fault_ns=fault_ns, recovery_ns=recovery_ns)
    require(window["coverage"] == "complete-finite-delivery-window", "worker recovery lacks original continuous client window")
    require(window["backend_generation_coverage"] == "frozen-live-process-and-response-bound",
            "worker HTTP has no independently registered backend epoch")
    backend = start["client_window"]["backend_registration"]
    require(any(binding["generation"] == after["route_generation"]
                and binding["process_identity"] == {k: after["parent"][k]
                     for k in ("pid", "start_ticks", "boot_id")}
                for binding in backend.values()),
            "replacement authority backend is not the actual new Host parent kernel")
    client_events = read_client_trace(paths["client_trace"])
    sends = {e["detail"]["request_id"]: e["detail"] for e in client_events if e["kind"] == "request.start"}
    delivered = [sends[e["detail"]["request_id"]]["sent_ns"]
                 for e in client_events if e["kind"] == "request.finish"
                 and e["detail"]["status"] == 200
                 and e["detail"]["finished_ns"] <= sends[e["detail"]["request_id"]]["deadline_ns"]]
    require(any(t < fault_ns for t in delivered) and any(t > recovery_ns for t in delivered),
            "worker recovery lacks real successful HTTP before and after the fault window")
    authority = read_traffic_journal(paths["authority_journal"])
    require(authority[0]["detail"]["authorization"]["registration_sha256"] == raw["proxy_registration_sha256"],
            "worker authority is not start registered")
    final = authority[-1]["route"]
    require(final == raw["final_route_snapshot"], "worker final route differs from independent authority")
    require(after["route_generation"] != before["route_generation"], "replacement reused old authority generation")
    require(final["generation"] == after["route_generation"], "authority final generation differs from replacement")
    # Delivery and admission counts cannot prove backend exactly-once. Keep the
    # original hypothesis unknown until its execution-duplication oracle exists.
    return {"injected_failure": True, "objective_met": None, "unsupported_tuple_served": False,
            "predecessor_preserved": False, "functional_correctness": True,
            "evidence_identity_preserved": True, "recovery_ms": (recovery_ns-fault_ns)/1e6,
            "lost_requests": window["lost_requests"], "duplicated_requests": None,
            "crash_window_coverage": "complete-finite-delivery-window",
            "operator_actions": raw["operator_actions"], "final_route": "candidate",
            "rollback_classification": "bounded-operator-action" if raw["operator_actions"] else "not-applicable"}


def execute_carrier(campaign: dict, arm: str, repetition: int, arm_order: int, output: Path,
                    receipt: Path, authority: Path) -> int:
    """Invoke an exact admitted source-owned adapter, then independently intake.

    The adapter must retain every failed start; success exit alone is never a
    formal result. Missing adapter/source/registration fails before any spawn.
    """
    carrier = validate_carrier(campaign, check_sources=True)
    require(not output.exists(), "worker output must be a fresh start directory")
    output.mkdir(parents=True, exist_ok=False)
    command = carrier["command"] + ["--campaign-spec", campaign["_path"], "--arm", arm,
        "--repetition", str(repetition), "--arm-order", str(arm_order), "--output-dir", str(output),
        "--deployment-receipt", str(receipt), "--authority-registration", str(authority),
        "--kernel-observer-handshake", "ecpa-h3-owned-worker-handshake/v1"]
    # The admitted carrier must pause at each real Host phase until this
    # independent runner checks /proc ancestry, PID/start/boot and Host events.
    # It must ask this runner to fault the observed owned worker, then relaunch
    # only after the runner has independently observed that kernel's death.
    from experiments.formal_campaign.h3_worker_relaunch import identity, owned_sessions, live, cleanup, signal_exact
    process = subprocess.Popen(command, start_new_session=True)
    owner = identity(process.pid)
    captured = {}
    cleanup_sessions = {owner["pid"]: owner}
    observed_dead = None
    triggered = None
    deadline = time.monotonic() + 2 * campaign["probe"]["ready_timeout_s"] + 30
    try:
        while time.monotonic() < deadline:
            for name in ("before", "after"):
                ready = output / f"carrier-{name}.json"
                if name in captured or not ready.exists():
                    continue
                require(name == "before" or observed_dead is not None,
                        "replacement phase arrived before independently observed worker death")
                phase = json.loads(ready.read_bytes())
                sessions, descendants = owned_sessions(owner)
                cleanup_sessions.update({s["pid"]: s for s in sessions})
                for role, field in (("api-server", "parent"), ("worker", "worker")):
                    expected = phase[field]
                    kernel = identity(expected["pid"])
                    require(descendants.get(kernel["pid"]) == kernel,
                            "carrier advertised a process outside its owned descendants")
                    require(all(kernel[k] == expected[k] for k in kernel),
                            "carrier kernel identity changed before observation")
                    _event(phase[field + "_event"], expected, role)
                phase["parent_worker_ancestry"] = capture_parent_worker_ancestry(
                    phase["parent"], phase["worker"])
                phase["owned_sessions"] = [s["pid"] for s in sessions]
                phase["observed_ns"] = time.monotonic_ns()
                captured[name] = phase
                if name == "after":
                    with (output / "kernel-observations.json").open("x") as stream:
                        json.dump(captured | {"observed_dead_ns": observed_dead,
                                              "fault_triggered_ns": triggered}, stream, sort_keys=True)
                with (output / f"runner-{name}-ack.json").open("x") as stream:
                    json.dump(phase, stream, sort_keys=True)
            fault_ready = output / "carrier-fault-ready.json"
            if "before" in captured and triggered is None and fault_ready.exists():
                target = captured["before"]["worker"]
                intent = json.loads(fault_ready.read_bytes())
                require(intent == {"target": target}, "worker fault target differs from independent observation")
                exact = {k: target[k] for k in ("pid", "start_ticks", "session", "boot_id")}
                triggered = time.monotonic_ns()
                signal_exact(exact, getattr(signal, campaign["fault"]["signal"]))
                with (output / "runner-fault.json").open("x") as stream:
                    json.dump({"target": target, "triggered_ns": triggered,
                               "signal": campaign["fault"]["signal"]}, stream)
            if triggered is not None and observed_dead is None:
                target = captured["before"]["worker"]
                if not live({k: target[k] for k in ("pid", "start_ticks", "session", "boot_id")}):
                    observed_dead = time.monotonic_ns()
                    with (output / "runner-worker-dead.json").open("x") as stream:
                        json.dump({"observed_dead_ns": observed_dead}, stream)
            if process.poll() is not None:
                break
            time.sleep(.01)
        require(process.poll() == 0, "source-owned worker carrier failed or timed out; no formal result")
        require(set(captured) == {"before", "after"} and observed_dead is not None and triggered is not None,
                "worker carrier omitted independent live/dead/new-epoch handshake")
    except Exception as exc:
        # The registered source-owned adapter owns cleanup. Do not signal an
        # arbitrary PID from caller JSON or claim devices/ports reclaimed.
        with (output / "carrier-incomplete.json").open("x") as stream:
            json.dump({"formal_result": False, "error": str(exc), "owned_adapter": owner}, stream)
        raise
    finally:
        cleanup(process, owner, campaign["fault"]["target_exit_timeout_s"],
                list(cleanup_sessions.values()))
    record_path = output / "record.json"
    record = json.loads(record_path.read_bytes())
    from experiments.formal_campaign.analyze import _verify_artifacts, _verify_h3_raw_artifact
    Draft7Validator(json.loads((HERE / "record.schema.json").read_text())).validate(record)
    _verify_artifacts(record, output)
    _verify_h3_raw_artifact(record, output, campaign)
    return 0
