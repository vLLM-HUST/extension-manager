#!/usr/bin/env python3
"""Source-admitted H3 dynamic-domain runner and independent kernel observer.

No old static backend spec is changed. This owns the new authority and carrier,
observes actual Host epochs, then faults only the observed descendant worker.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_dynamic_registration import (
    materialize_recipe,
)
from experiments.formal_campaign.h3_owned_worker_carrier import (
    RegisteredAuthority,
    load,
    reference,
    save_new,
)
from experiments.formal_campaign.h3_worker_recovery import (
    _event,
    capture_parent_worker_ancestry,
)
from experiments.formal_campaign.h3_worker_relaunch import (
    cleanup,
    identity,
    live,
    owned_sessions,
    signal_exact,
)

HERE = Path(__file__).resolve().parent


def observe_phase(phase, owner):
    sessions, descendants = owned_sessions(owner)
    for role, key in (("api-server", "parent"), ("worker", "worker")):
        expected = phase[key]
        actual = identity(expected["pid"])
        require(
            descendants.get(actual["pid"]) == actual
            and all(actual[k] == expected[k] for k in actual),
            "phase kernel is not this carrier descendant",
        )
        _event(phase[key + "_event"], expected, role)
    result = dict(
        phase,
        parent_worker_ancestry=capture_parent_worker_ancestry(
            phase["parent"], phase["worker"]
        ),
        owned_sessions=[s["pid"] for s in sessions],
        observed_ns=time.monotonic_ns(),
    )
    return result, sessions


def prepare_native_paths(template, start, output):
    # Binding receivers do not create directories. These are registered
    # per-start control/evidence paths, never future process identities.
    for phase in template["arms"][start["arm"]]["phases"]:
        paths = [phase["evidence_path"], phase.get("handoff_path")]
        paths.extend(
            phase["native_bootstrap"][key]
            for key in ("native_context_path", "tensor_context_path")
        )
        for value in filter(None, paths):
            path = Path(value)
            require(
                path.is_absolute()
                and path.is_relative_to(output.resolve())
                and path.parent.resolve().is_relative_to(output.resolve()),
                "native phase path escapes this actual start",
            )
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            require(
                not path.exists()
                and path.parent.resolve().is_relative_to(output.resolve())
                and path.parent.stat().st_uid == os.getuid()
                and not path.parent.stat().st_mode & 0o077,
                "native phase requires fresh private paths",
            )


def authority_readiness_deadline(original, *, native, launched_monotonic):
    """Control-plane startup only; original client request deadlines are separate."""
    return launched_monotonic + (original["probe"]["ready_timeout_s"] if native else 10)


def execute(
    spec_path, receipt_path, start_id, output, *, check_remote=True, native=False
):
    if native:
        from experiments.formal_campaign.h3_native_registration import validate_receipt
        from experiments.formal_campaign.h3_owned_worker_carrier import (
            NativeRegisteredAuthority as Authority,
        )
    else:
        from experiments.formal_campaign.h3_dynamic_registration import validate_receipt

        Authority = RegisteredAuthority
    require(not output.exists(), "start output must be fresh")
    output.mkdir(parents=True, mode=0o700)
    authority_process = carrier_process = None
    authority_owner = carrier_owner = None
    sessions = {}
    captured = {}
    observed_launches = []
    fault = None
    dead = None
    error = None
    result = None
    try:
        spec, original, receipt = validate_receipt(
            spec_path, receipt_path, check_remote=check_remote
        )
        start = next(s for s in spec["starts"] if s["start_id"] == start_id)
        template = load(start["recipe_template"]["path"])
        for value in (start["authority"]["journal"], template["authority"]["socket"]):
            path = Path(value)
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            require(
                not path.exists()
                and path.parent.stat().st_uid == os.getuid()
                and not path.parent.stat().st_mode & 0o077,
                "authority requires fresh private source-owned paths",
            )
        if native:
            prepare_native_paths(template, start, output)
        with (output / "authority.stdout.log").open("xb") as log:
            authority_launched_monotonic = time.monotonic()
            authority_process = subprocess.Popen(
                start["authority"]["command"],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        authority_owner = identity(authority_process.pid)
        save_new(
            output / "runner-authority-observation.json",
            {
                "kernel": authority_owner,
                "command": start["authority"]["command"],
                "observed_ns": time.monotonic_ns(),
                "policy": start["policy"],
                "receipt": reference(receipt_path),
            },
        )
        deadline = authority_readiness_deadline(
            original, native=native, launched_monotonic=authority_launched_monotonic
        )
        while not Path(template["authority"]["socket"]).exists():
            require(
                authority_process.poll() is None,
                "actual authority exited before capabilities",
            )
            require(time.monotonic() < deadline, "authority readiness deadline")
            time.sleep(0.01)
        runtime_recipe = materialize_recipe(template, authority_owner)
        recipe_ref = save_new(output / "runtime-recipe.json", runtime_recipe)
        authority = Authority(runtime_recipe, receipt, start_id)
        authority.preflight()
        save_new(
            output / "runner-authority-peer-observation.json",
            {
                "kernel": authority_owner,
                "socket_fence": list(authority.socket_fence),
                "uid": authority.uid,
                "gid": authority.gid,
                "argv": authority.argv,
            },
        )
        command = [
            sys.executable,
            str(HERE / "h3_owned_worker_carrier.py"),
            "--recipe",
            str(output / "runtime-recipe.json"),
            "--recipe-sha256",
            recipe_ref["sha256"],
            "--campaign-spec",
            str(spec_path),
            "--arm",
            start["arm"],
            "--repetition",
            str(start["repetition"]),
            "--arm-order",
            str(start["arm_order"]),
            "--output-dir",
            str(output),
            "--deployment-receipt",
            str(receipt_path),
            "--authority-registration",
            str(receipt_path),
            "--kernel-observer-handshake",
            "ecpa-h3-owned-worker-handshake/v1",
        ]
        if native:
            command.append("--native-domain")
        with (output / "carrier.stdout.log").open("xb") as log:
            carrier_process = subprocess.Popen(
                command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
            )
        carrier_owner = identity(carrier_process.pid)
        sessions[carrier_owner["pid"]] = carrier_owner
        save_new(
            output / "runner-carrier-observation.json",
            {
                "kernel": carrier_owner,
                "argv": command,
                "observed_ns": time.monotonic_ns(),
            },
        )
        deadline = time.monotonic() + 2 * original["probe"]["ready_timeout_s"] + 60
        while time.monotonic() < deadline:
            for path in sorted(output.glob("phase*.launch-observation.json")):
                marker = load(path)
                if any(item["marker"] == path.name for item in observed_launches):
                    continue
                try:
                    current = identity(marker["pid"])
                    owned, descendants = owned_sessions(carrier_owner)
                    require(
                        descendants.get(current["pid"]) == current,
                        "Host launch not carrier-owned",
                    )
                    sessions.update({s["pid"]: s for s in owned})
                    observed_launches.append(
                        {
                            "marker": path.name,
                            "marker_sha256": reference(path)["sha256"],
                            "kernel": current,
                            "observed_ns": time.monotonic_ns(),
                        }
                    )
                except (FileNotFoundError, ProcessLookupError, ValueError):
                    pass
            for label in ("before", "after"):
                ready = output / f"carrier-{label}.json"
                if label in captured or not ready.exists():
                    continue
                require(
                    label == "before" or dead is not None,
                    "new phase preceded independent death observation",
                )
                phase, owned = observe_phase(load(ready), carrier_owner)
                sessions.update({s["pid"]: s for s in owned})
                captured[label] = phase
                save_new(output / f"runner-{label}-ack.json", phase)
            ready = output / "carrier-fault-ready.json"
            if "before" in captured and fault is None and ready.exists():
                target = captured["before"]["worker"]
                require(
                    load(ready) == {"target": target},
                    "fault ready changed actual target",
                )
                # Re-observe the complete API->worker ancestry immediately before
                # the only permitted injection; JSON cannot choose another PID.
                capture_parent_worker_ancestry(captured["before"]["parent"], target)
                exact = {
                    k: target[k] for k in ("pid", "start_ticks", "session", "boot_id")
                }
                triggered = time.monotonic_ns()
                signal_exact(exact, getattr(signal, original["fault"]["signal"]))
                fault = {
                    "target": target,
                    "triggered_ns": triggered,
                    "signal": original["fault"]["signal"],
                }
                save_new(output / "runner-fault.json", fault)
            if fault is not None and dead is None:
                target = {
                    k: fault["target"][k]
                    for k in ("pid", "start_ticks", "session", "boot_id")
                }
                if not live(target):
                    dead = time.monotonic_ns()
                    save_new(
                        output / "runner-worker-dead.json", {"observed_dead_ns": dead}
                    )
                elif (
                    time.monotonic_ns() - fault["triggered_ns"]
                    > original["fault"]["target_exit_timeout_s"] * 1e9
                ):
                    raise TimeoutError(
                        "observed worker did not exit within original fault bound"
                    )
            if carrier_process.poll() is not None:
                break
            time.sleep(0.01)
        require(
            carrier_process.poll() is not None,
            "owned carrier exceeded frozen readiness/terminal bound",
        )
        if carrier_process.returncode != 0:
            error = "source-owned carrier exited " + str(carrier_process.returncode)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        errors = []
        if carrier_process is not None:
            try:
                cleanup(carrier_process, carrier_owner, 10, list(sessions.values()))
            except Exception as exc:
                errors.append(str(exc))
        if authority_process is not None:
            try:
                authority_process.stdin.close()
                authority_process.wait(timeout=10)
                require(
                    authority_process.returncode == 0,
                    "authority graceful lifetime failed",
                )
            except Exception as exc:
                errors.append(str(exc))
                try:
                    cleanup(authority_process, authority_owner, 5, [authority_owner])
                except Exception as cleanup_exc:
                    errors.append(str(cleanup_exc))
        save_new(
            output / "runner-observations.json",
            {
                "schema": "ecpa-h3-dynamic-runner-observations/v1",
                "start_id": start_id,
                "host_launches": observed_launches,
                "phases": captured,
                "fault": fault,
                "observed_dead_ns": dead,
                "error": error,
                "cleanup_errors": errors,
                "formal_result": False,
            },
        )
    # No automatically qualified failure: the new intake must independently
    # validate source admission, actual observations and all raw joins.
    from experiments.formal_campaign.h3_dynamic_intake import intake

    try:
        result = intake(spec_path, receipt_path, start_id, output, native=native)
        save_new(output / "dynamic-start-observation.json", result)
    except Exception as exc:
        save_new(
            output / "intake-rejection.json",
            {
                "formal_result": False,
                "start_validation": "unverified",
                "error": str(exc),
                "retained_actual_launch_markers": len(
                    list(output.glob("phase*.launch-observation.json"))
                ),
            },
        )
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--start-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--native-domain", action="store_true")
    args = parser.parse_args()
    result = execute(
        args.campaign.resolve(),
        args.receipt.resolve(),
        args.start_id,
        args.output_dir.resolve(),
        native=args.native_domain,
    )
    print(
        json.dumps(
            result or {"start_validation": "unverified", "formal_result": False},
            sort_keys=True,
        )
    )
    return 0 if result is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
