"""Real one-slot conditional H4 runtime. Original controls, no retry/replacement.

Source candidate only until root executes a fresh published/admitted tuple.
Outer independent root observer owns release; this producer never claims it.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .absolute_http import request_once
from .conditional_binding import activation_command
from .conditional_common import (
    checked,
    load,
    private_directory,
    reference,
    require,
    write,
)
from .conditional_registration import (
    recompute_start,
    validate_for_start,
    validate_inputs,
)
from .conditional_request_trace import RequestTrace
from .conditional_selection_authority import SelectionAuthority


def product_epochs(samples, owner):
    """Derive actual product descendants, excluding client/control/NPU samplers."""
    from .h4_owned_resources import kernel

    known = {(owner["pid"], owner["start_ticks"]): owner}
    sessions = {owner["session"]}
    for sample in samples:
        rows = {r["pid"]: r for r in sample["members"]}
        live = {
            pid
            for (pid, ticks) in known
            if pid in rows and rows[pid]["start_ticks"] == ticks
        }
        while True:
            more = {
                pid
                for pid, row in rows.items()
                if row["ppid"] in live or row["session"] in sessions
            } - live
            if not more:
                break
            live |= more
        for pid in live:
            row = rows[pid]
            value = kernel(row, owner["boot_id"])
            known[(pid, value["start_ticks"])] = value
            if pid == row["session"]:
                sessions.add(row["session"])
    return list(known.values())


def observe_roster(journal, sampler, owner, plan_id, launch_id):
    from vllm_hust_ext.host_evidence import parse_host_event

    sampler._append_sample()
    known = list(sampler.last_known_epochs)
    roster = {}
    kernels = {}
    for line in journal.read_bytes().splitlines():
        event = parse_host_event(line)
        require(
            event["plan_id"] == plan_id and event["launch_id"] == launch_id,
            "Host journal mixed actual Plan/launch",
        )
        p = event["process"]
        slot = f"{p['role']}/{p['ordinal']}"
        if slot not in (
            "api-server/0",
            "engine-core-scheduler/0",
            "worker/0",
            "worker/1",
        ):
            continue
        require(
            p["assignment_source"] == "host",
            "environment role cannot qualify actual Host",
        )
        matches = [
            k
            for k in known
            if k["pid"] == p["pid"]
            and k["start_ticks"] == int(p["start_identity"].rsplit(":", 1)[1])
            and k["boot_id"] == owner["boot_id"]
        ]
        require(
            len(matches) == 1,
            "original Host publisher not independently captured in actual owned tree",
        )
        require(
            slot not in roster or roster[slot] == p,
            "actual Host role epoch replacement",
        )
        roster[slot] = p
        kernels[slot] = matches[0]
    require(
        set(roster)
        == {"api-server/0", "engine-core-scheduler/0", "worker/0", "worker/1"},
        "actual full PP2TP1 Host roster absent",
    )
    require(
        len({(k["pid"], k["start_ticks"]) for k in kernels.values()}) == 4,
        "actual Host roles alias kernels",
    )
    return roster, kernels


def execute(
    campaign_ref, launch_ref, start_id, receipt_ref=None, *, qualification=False
):
    require(
        sys.flags.optimize == 0,
        "original assertion guards require nonoptimized interpreter",
    )
    from vllm_hust_ext.runtime_phase_handoff import (
        accept_native_binding,
        bind_receiver,
        manager_source_digests,
    )

    from .analyze import h4_request_payload
    from .conditional_input_audit import audit_actual, recheck_actual
    from .h3_worker_relaunch import cleanup, identity
    from .h4_npu_observation import decode_observation
    from .h4_owned_resources import OwnedTreeResourceSampler
    from .h4_sampled_health import HealthObserver, verify_health

    if qualification:
        require(receipt_ref is None, "qualification cannot consume deployment receipt")
        campaign, launch, workload, inputs = validate_inputs(
            campaign_ref, launch_ref, allow_used_paths=True
        )
        require(
            campaign.get("execution_domain") == "unregistered-conditional-qualification"
            and start_id.startswith("unregistered-conditional-"),
            "distinct real qualification namespace required",
        )
        selected = [s for s in inputs["starts"] if s["start_id"] == start_id]
        require(len(selected) == 1, "one exact qualification slot")
        start = selected[0]
        require(
            start["arm"] == "vanilla-vllm-entry-points",
            "bootstrap is genuine baseline only; no unqualified Manager",
        )
        material = recompute_start(
            campaign, workload, inputs, start, require_qualified=False
        )
    else:
        require(receipt_ref is not None, "actual conditional registration mandatory")
        value = load(receipt_ref)
        require(
            value["campaign"] == campaign_ref and value["launch"] == launch_ref,
            "actual command campaign/launch differs from original conditional receipt",
        )
        campaign, launch, workload, inputs, start, material = validate_for_start(
            receipt_ref, start_id
        )
        require(
            campaign.get("execution_domain") == "registered-original-starts",
            "original formal namespace required",
        )
    phase = load(start["phase"])
    require(
        Path(__file__).resolve().parent
        == Path(phase["cwd"]) / "experiments/formal_campaign",
        "actual runtime entry is not selected published source",
    )
    require(
        sys.executable == phase["python"] and Path.cwd() == Path(phase["cwd"]),
        "actual selected runtime interpreter/SDK required",
    )
    run = private_directory(start["run_directory"])
    self_kernel = identity(os.getpid())
    write(
        run / "root-invocation.json",
        dict(
            argv=sys.argv,
            kernel=self_kernel,
            campaign=campaign_ref,
            launch=launch_ref,
            receipt=receipt_ref,
            start_id=start_id,
            phase=start["phase"],
        ),
    )
    write(run / "actual-runtime-closure.json", material["runtime_closure"])
    (run / "conditional-plan.json").write_bytes(checked(start["plan"]))
    # Model14/whole8 and exact original Host1195 tokenizer checks are actual CPU
    # prelaunch reads. No external status flag can substitute for this invocation.
    audit = audit_actual(inputs, campaign, workload, phase, run)
    write(run / "source-guard-material.json", material)
    env = dict(phase["environment"])
    require(
        env["ECPA_H4_RUN_DIRECTORY"] == str(run), "actual source-owned output differs"
    )
    schedule = load(start["schedule"])
    body = h4_request_payload(workload, phase["served_model"])
    context_path = run / "selection-context.json"
    listener = None
    authority = server = process = owner = sampler = health = trace = None
    errors = []
    transport_errors = []
    rows = []
    epoch = None
    health_result = None
    cleanup_value = None
    owned = []
    failure = None
    failure_category = None
    interruption = None
    failure_mono = None
    failure_raw = None
    stop = threading.Event()
    journal = run / "original-baseline-Host.events.jsonl"
    native = None
    plan_id = material["plan_id"].rsplit(":", 1)[-1]
    if start["arm"] == "ecpa":
        for key in (
            "VLLM_ECPA_PLAN_ID",
            "VLLM_ECPA_LAUNCH_ID",
            "VLLM_ECPA_EVIDENCE_SINK",
            "VLLM_ECPA_EVIDENCE_STRICT",
            "VLLM_HUST_EXT_EVIDENCE_PATH",
        ):
            require(key not in env, "Manager owns actual native evidence environment")
        env["VLLM_HUST_EXT_CONFIG"] = phase["manager_config"]["path"]
        spec = write(
            run / "conditional-manager-launch.json",
            dict(
                schema="ecpa-h4-conditional-live-manager-launch/v1",
                receipt=receipt_ref,
                start_id=start_id,
                actual_parent=self_kernel,
                phase=start["phase"],
                plan=start["plan"],
            ),
        )
        listener = bind_receiver(
            run / "manager.sock", launch["startup_timeout_seconds"]
        )
        command = [
            phase["python"],
            "-B",
            str(Path(sys.prefix) / "bin/vllm-hust-ext"),
            "run",
            "--conditional-launch-spec",
            spec["path"],
            "--phase-binding-socket",
            str(run / "manager.sock"),
            "--",
            *activation_command(start["phase"], phase),
        ]
    else:
        env.update(
            VLLM_ECPA_PLAN_ID=plan_id,
            VLLM_ECPA_LAUNCH_ID=str(uuid.uuid4()),
            VLLM_ECPA_EVIDENCE_SINK="vllm_hust_ext.runtime_evidence:record_event",
            VLLM_ECPA_EVIDENCE_STRICT="1",
            VLLM_HUST_EXT_EVIDENCE_PATH=str(journal),
        )
        command = activation_command(start["phase"], phase)

    def serve():
        while not stop.is_set():
            try:
                authority.serve_one(0.25)
            except TimeoutError:
                continue
            except Exception as exc:
                transport_errors.append(dict(type=type(exc).__name__, message=str(exc)))
                break

    started_wall = time.time_ns()
    timing = None
    try:
        # Full runner-owned accounting includes actual client and selection
        # authority CPU, not only the product subtree. Outer root witness is
        # separately declared observational overhead, never reported as zero.
        sampler = OwnedTreeResourceSampler(
            os.getpid(),
            launch["npu_memory_command"],
            archive=run / "owned-resources.json",
            expected_root=self_kernel,
        )
        sampler.start()
        with (
            (run / "Host.stdout").open("xb") as out,
            (run / "Host.stderr").open("xb") as err,
        ):
            before_mono = time.monotonic_ns()
            before = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
            process = subprocess.Popen(
                command,
                cwd=phase["cwd"],
                env=env,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            after = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        owner = identity(process.pid)
        owned = [owner]
        timing = dict(
            schema="ecpa-h4-conditional-real-product-popen/v1",
            before_ns=before,
            after_ns=after,
            before_monotonic_ns=before_mono,
            actual_kernel=owner,
            argv=command,
        )
        write(run / "phase0.product-popen-timing.json", timing)
        write(
            run / "source-admission.json",
            dict(
                schema="ecpa-h4-conditional-source-admission/v1",
                owner=owner,
                runner=self_kernel,
                phase=start["phase"],
                campaign=campaign_ref,
                receipt=receipt_ref,
                plan=start["plan"],
                material=reference(run / "source-guard-material.json"),
                start_id=start_id,
                native_plan_id=plan_id,
                native_launch_id=env.get("VLLM_ECPA_LAUNCH_ID"),
            ),
        )
        health = HealthObserver(
            run,
            launch["health_url"],
            launch["startup_timeout_seconds"],
            owner,
            run / "phase0.product-popen-timing.json",
        )
        health.start()
        if listener is not None:
            native = accept_native_binding(
                listener,
                run / "manager.sock",
                owner,
                started_wall,
                manager_source_digests(),
                run / "actual-Manager-native-handoff.json",
            )
            require(
                native["environment"]["VLLM_ECPA_PLAN_ID"] == plan_id,
                "actual Manager native Plan differs from independent registered Plan",
            )
            env.update(native["environment"])
            journal = Path(native["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"])
        health.finish()
        preliminary = verify_health(
            run,
            launch["health_url"],
            launch["startup_timeout_seconds"],
            timing,
            epoch=None,
            require_terminal=True,
        )
        if preliminary["completion_status"] == "deadline":
            raise TimeoutError("original health readiness budget expired")
        if preliminary["completion_status"] in ("owner-exited", "accepted-peer-exited"):
            raise ConnectionError(
                "exact original owner/accepted peer exited before "
                "authenticated readiness"
            )
        roster, kernels = observe_roster(
            journal, sampler, owner, plan_id, env["VLLM_ECPA_LAUNCH_ID"]
        )
        epoch = dict(
            schema="ecpa-h4-conditional-actual-epoch/v1",
            owner=owner,
            runner=self_kernel,
            roster=roster,
            kernels=kernels,
            plan_id=plan_id,
            launch_id=env["VLLM_ECPA_LAUNCH_ID"],
            phase=start["phase"],
            manager_handoff=reference(run / "actual-Manager-native-handoff.json")
            if native
            else None,
        )
        write(run / "conditional-epoch.json", epoch)
        health_result = verify_health(
            run,
            launch["health_url"],
            launch["startup_timeout_seconds"],
            timing,
            epoch=epoch,
            require_terminal=True,
        )
        require(
            health_result["first_health"] is not None,
            "first original authenticated health200 not established",
        )
        write(
            run / "conditional-launch.json",
            dict(
                plan_id=plan_id,
                launch_id=env["VLLM_ECPA_LAUNCH_ID"],
                journal=str(journal),
                actual_command=command,
            ),
        )
        if inputs["evidence_mode"] == "sampled-invocation":
            require(
                env["ECPA_H4_CONDITIONAL_SELECTION_CONTEXT"] == str(context_path),
                "source selection declaration differs",
            )
            authority = SelectionAuthority(
                socket_path=run / "selection.sock",
                start_id=start_id,
                plan_id=plan_id,
                launch_id=env["VLLM_ECPA_LAUNCH_ID"],
                nonce=secrets.token_hex(32),
                api_kernel=kernels["api-server/0"],
                scheduler_kernel=kernels["engine-core-scheduler/0"],
                original_schedule=schedule,
                output=run / "selection-control.jsonl",
            )
            write(context_path, authority.grants())
            server = threading.Thread(target=serve, daemon=True)
            server.start()
        trace = RequestTrace(
            run / "requests.jsonl",
            schedule,
            body,
            start_id=start_id,
            plan_id=plan_id,
            launch_id=env["VLLM_ECPA_LAUNCH_ID"],
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            for group in (schedule[:16], schedule[16:]):
                futures = [
                    (
                        declaration,
                        executor.submit(
                            request_once,
                            launch["endpoint_url"],
                            body,
                            120,
                            declaration["request_id"],
                            declaration["kind"],
                            trace,
                        ),
                    )
                    for declaration in group
                ]
                for declaration, future in futures:
                    rows.append(dict(declaration, **future.result()))
        trace.close(complete=True)
        trace = None
        write(run / "actual-requests.json", rows)
        require(not transport_errors, "actual source-side selection authority failed")
        recheck_actual(audit)
    except BaseException as exc:
        from .run_h4_sampled import runtime_interruption

        errors.append(dict(stage="runtime", type=type(exc).__name__, message=str(exc)))
        failure = type(exc).__name__ + ": " + str(exc)
        interruption = runtime_interruption(exc)
        failure_category = (
            "runtime-interruption"
            if interruption is not None
            else "unqualified-verification-error"
        )
        failure_mono = time.monotonic_ns()
        failure_raw = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    finally:
        if trace is not None:
            try:
                trace.close(complete=False)
            except BaseException as exc:
                errors.append(
                    dict(stage="trace-close", type=type(exc).__name__, message=str(exc))
                )
        stop.set()
        try:
            try:
                if server is not None:
                    server.join(1)
                    require(
                        not server.is_alive(), "selection authority thread did not stop"
                    )
            finally:
                if authority is not None:
                    authority.close()
        except BaseException as exc:
            errors.append(
                dict(stage="selection-close", type=type(exc).__name__, message=str(exc))
            )
        if listener is not None:
            try:
                listener.close()
            except BaseException as exc:
                errors.append(
                    dict(
                        stage="manager-listener-close",
                        type=type(exc).__name__,
                        message=str(exc),
                    )
                )
        if health is not None:
            try:
                health.finish(cancel=True)
            except BaseException as exc:
                errors.append(
                    dict(
                        stage="health-close", type=type(exc).__name__, message=str(exc)
                    )
                )
        try:
            if sampler is not None and owner is not None:
                sampler._append_sample()
                owned = product_epochs(sampler.samples, owner)
            if process is not None:
                require(
                    owner is not None,
                    "actual Popen epoch unavailable; independent root cleanup required",
                )
                cleanup(process, owner, 10, owned)
        except BaseException as exc:
            errors.append(
                dict(stage="owned-cleanup", type=type(exc).__name__, message=str(exc))
            )
        try:
            if sampler is not None:
                resources = sampler.finish()
                sampler.require_coverage()
                write(
                    run / "conditional-resource-scope.json",
                    dict(
                        runner_root=self_kernel,
                        resources=resources,
                        scope=(
                            "entire-runner-owned-tree-including-original"
                            "-client-and-selection-authority"
                        ),
                        outer_root_observer="separately retained; not zero",
                    ),
                )
        except BaseException as exc:
            errors.append(
                dict(
                    stage="resource-finalize", type=type(exc).__name__, message=str(exc)
                )
            )
        try:
            witnesses = []
            for original in owned:
                try:
                    raw = Path(f"/proc/{original['pid']}/stat").read_text()
                    fields = raw.rsplit(")", 1)[1].split()
                    gone = (
                        int(fields[19]) != original["start_ticks"] or fields[0] == "Z"
                    )
                    witnesses.append(
                        dict(original=original, stat_raw=raw, original_gone=gone)
                    )
                except (FileNotFoundError, ProcessLookupError) as exc:
                    witnesses.append(
                        dict(
                            original=original,
                            stat_raw=None,
                            original_gone=True,
                            missing_type=type(exc).__name__,
                        )
                    )
            write(
                run / "terminal-owned-kernel-witness.json",
                dict(
                    kernels=witnesses,
                    boot_raw=Path("/proc/sys/kernel/random/boot_id").read_text(),
                    observed_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                ),
            )
            result = subprocess.run(
                launch["device_cleanup_command"],
                cwd=phase["cwd"],
                env=env,
                capture_output=True,
                timeout=30,
            )
            (run / "cleanup.stdout").write_bytes(result.stdout)
            (run / "cleanup.stderr").write_bytes(result.stderr)
            device = json.loads(result.stdout)
            raw, _ = decode_observation(device["original_command"])
            from .run_h4 import port_closed

            cleanup_value = dict(
                processes_reclaimed=bool(owner)
                and all(w["original_gone"] is True for w in witnesses),
                ports_reclaimed=port_closed(launch["host"], launch["port"]),
                devices_reclaimed=result.returncode == 0
                and device["devices_reclaimed"] is True
                and all(
                    f"No running processes found in NPU {d}".encode() in raw
                    for d in (0, 3)
                ),
                observed_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
                owned_epochs=owned,
            )
            write(run / "cleanup-observation.json", cleanup_value)
            require(
                all(
                    cleanup_value[k] is True
                    for k in (
                        "processes_reclaimed",
                        "ports_reclaimed",
                        "devices_reclaimed",
                    )
                ),
                "actual product cleanup failed; no release",
            )
        except BaseException as exc:
            errors.append(
                dict(
                    stage="terminal-cleanup", type=type(exc).__name__, message=str(exc)
                )
            )
        if journal.exists():
            try:
                (run / "final-Host.jsonl").write_bytes(journal.read_bytes())
            except BaseException as exc:
                errors.append(
                    dict(
                        stage="Host-journal-finalize",
                        type=type(exc).__name__,
                        message=str(exc),
                    )
                )
        write(
            run / "conditional-source-result.json",
            dict(
                schema="ecpa-h4-conditional-source-result/v1",
                start_id=start_id,
                execution_domain=campaign["execution_domain"],
                actual_phase=start["phase"],
                actual_plan=start["plan"],
                errors=errors,
                transport_errors=transport_errors,
                cleanup=cleanup_value,
                formal_result=False,
                failure=failure,
                failure_category=failure_category,
                runtime_interruption=interruption,
                failure_observed_monotonic_ns=failure_mono,
                failure_observed_raw_ns=failure_raw,
                actual_request_rows=len(rows),
                end_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
            ),
        )
    return 1 if errors or transport_errors else 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--campaign", type=Path, required=True)
    p.add_argument("--launch-spec", type=Path, required=True)
    p.add_argument("--start-id", required=True)
    p.add_argument("--receipt", type=Path)
    p.add_argument("--qualification", action="store_true")
    a = p.parse_args()
    require(os.geteuid() == 0, "real root-owned conditional runtime required")
    raise SystemExit(
        execute(
            reference(a.campaign),
            reference(a.launch_spec),
            a.start_id,
            None if a.receipt is None else reference(a.receipt),
            qualification=a.qualification,
        )
    )


if __name__ == "__main__":
    main()
