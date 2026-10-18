#!/usr/bin/env python3
"""Source-admitted H3 dynamic-domain runner and independent kernel observer.

No old static backend spec is changed. This owns the new authority and carrier,
observes actual Host epochs, then faults only the observed descendant worker.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import require
from experiments.formal_campaign.h3_observer_carrier import (
    RegisteredAuthority,
    load,
    reference,
    save_new,
)
from experiments.formal_campaign.h3_observer_common_registration import (
    materialize_recipe,
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
            from experiments.formal_campaign.h3_observer_paths import (
                require_or_create_private_directory,
            )

            require_or_create_private_directory(path.parent)
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


def _admit_native_start(spec_path, receipt_path, start_id, *, check_remote, live_scope):
    from experiments.formal_campaign.h3_observer_live_registration import (
        ValidatedLiveStart,
    )
    from experiments.formal_campaign.h3_observer_registration import (
        validate_receipt_for_start,
    )

    if live_scope is None:
        return validate_receipt_for_start(
            spec_path, receipt_path, start_id, check_remote=check_remote
        )
    require(type(live_scope) is ValidatedLiveStart, "unissued live native admission")
    value = live_scope.value()
    require(
        value["base_campaign"]["path"] == str(Path(spec_path).resolve())
        and value["base_receipt"]["path"] == str(Path(receipt_path).resolve()),
        "live native admission belongs to another original admission",
    )
    return live_scope.native_admission(start_id)


def execute(
    spec_path,
    receipt_path,
    start_id,
    output,
    *,
    check_remote=True,
    native=False,
    live_intent=None,
    live_receipt=None,
):
    if native:
        from experiments.formal_campaign.h3_observer_carrier import (
            NativeRegisteredAuthority as Authority,
        )
    else:
        from experiments.formal_campaign.h3_observer_common_registration import (
            validate_receipt,
        )

        Authority = RegisteredAuthority
    require(native, "observer-loss runner requires its distinct native receipt domain")
    live_environment = None
    live_scope = None
    require(
        bool(live_intent) == bool(live_receipt), "both v2 intent and receipt required"
    )
    if live_intent:
        from experiments.formal_campaign.h3_observer_live_registration import (
            validate_for_start,
        )

        scope = validate_for_start(
            live_intent, live_receipt, start_id, check_remote=check_remote
        )
        live_scope = scope
        require(
            scope.value()["base_campaign"]["path"] == str(Path(spec_path).resolve())
            and scope.value()["base_receipt"]["path"]
            == str(Path(receipt_path).resolve()),
            "live extension cannot substitute original source admission",
        )
        live_environment = dict(
            os.environ,
            ECPA_H3_OBSERVER_LIVE_INTENT=str(Path(live_intent).resolve()),
            ECPA_H3_OBSERVER_LIVE_RECEIPT=str(Path(live_receipt).resolve()),
        )
    else:
        require(
            not os.environ.get("ECPA_H3_OBSERVER_LIVE_INTENT")
            and not os.environ.get("ECPA_H3_OBSERVER_LIVE_RECEIPT"),
            "v1 runner cannot inherit a live extension implicitly",
        )

    require(not output.exists(), "start output must be fresh")
    from experiments.formal_campaign.h3_observer_paths import create_private_directory

    create_private_directory(output, parents=True)
    authority_process = carrier_process = None
    authority_owner = carrier_owner = None
    sessions = {}
    captured = {}
    observed_launches = []
    fault = None
    dead = None
    error = None
    result = None
    cleanup_before = None
    cleanup_context = None
    cleanup_epochs = None
    fault_raw = None
    expected_hosts = None
    cleanup_owned = []
    observed_owned = {}
    cleanup_policy = None
    cleanup_ports = []
    try:
        if native:
            receipt = _admit_native_start(
                spec_path,
                receipt_path,
                start_id,
                check_remote=check_remote,
                live_scope=live_scope,
            )
            spec, original, start = receipt.selected(start_id)
        else:
            spec, original, receipt = validate_receipt(
                spec_path, receipt_path, check_remote=check_remote
            )
            start = next(s for s in spec["starts"] if s["start_id"] == start_id)
        from urllib.parse import urlparse

        from experiments.formal_campaign.h3_observer_cleanup import (
            observe as observe_cleanup,
        )

        cleanup_policy = spec["observer_cleanup"]
        template = load(start["recipe_template"]["path"])
        cleanup_ports = [
            start["authority"]["public_port"],
            urlparse(template["authority"]["backend_endpoint"]).port,
        ]
        from experiments.formal_campaign.h3_observer_cleanup import context_for

        cleanup_context = context_for(spec_path, receipt_path, spec, start)
        if live_intent:
            from experiments.formal_campaign.h3_observer_live_cleanup import (
                context_for as live_context,
            )
            from experiments.formal_campaign.h3_observer_live_cleanup import (
                observe as live_observe,
            )
            from experiments.formal_campaign.h3_observer_live_cleanup import scopes_for

            cleanup_context = live_context(spec_path, receipt_path, spec, start, scope)
            unix_scopes = scopes_for(scope, template)

            def observe_cleanup(*args, **kwargs):
                return live_observe(*args, unix_scopes=unix_scopes, **kwargs)

        cleanup_before = observe_cleanup(
            cleanup_policy,
            cleanup_ports,
            context=cleanup_context,
            stage="before-product",
        )
        require(
            not cleanup_before["listeners"]
            and (not live_intent or not cleanup_before["owned_unix_sockets"]),
            "registered TCP/control socket scope already externally owned",
        )
        import base64

        baseline_npu = base64.b64decode(
            cleanup_before["npu_stdout_base64"], validate=True
        )
        require(
            cleanup_before["npu_exit"] == 0
            and all(
                f"No running processes found in NPU {d}".encode() in baseline_npu
                for d in (0, 3)
            ),
            "allocated NPU baseline is not empty; no product launch",
        )
        save_new(output / "runner-cleanup-before.json", cleanup_before)
        for value in (start["authority"]["journal"], template["authority"]["socket"]):
            path = Path(value)
            from experiments.formal_campaign.h3_observer_paths import (
                require_or_create_private_directory,
            )

            require_or_create_private_directory(path.parent)
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
                env=live_environment,
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
            str(HERE / "h3_observer_carrier.py"),
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
            "ecpa-h3-owned-observer-handshake/v1",
        ]
        if native:
            command.append("--native-domain")
        with (output / "carrier.stdout.log").open("xb") as log:
            carrier_process = subprocess.Popen(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=live_environment,
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
            for owner in (authority_owner, carrier_owner):
                if owner is not None and live(owner):
                    _, actual_descendants = owned_sessions(owner)
                    for kernel in actual_descendants.values():
                        observed_owned[
                            (kernel["pid"], kernel["start_ticks"], kernel["boot_id"])
                        ] = kernel
            if cleanup_before is not None:
                external = [e["kernel"] for e in cleanup_before["external_services"]]
                require(
                    not any(k in external for k in observed_owned.values()),
                    "external service became a descendant; no owned cleanup allowed",
                )
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
                from experiments.formal_campaign.h3_dynamic_authority import (
                    read_dynamic_journal,
                )
                from experiments.formal_campaign.h3_observer_authority import JOURNAL
                from experiments.formal_campaign.h3_observer_loss import (
                    observe_and_fault,
                    observe_original_client_barrier,
                )

                events = read_dynamic_journal(
                    start["authority"]["journal"], domain=JOURNAL
                )
                bound = [
                    e["detail"]["binding"]
                    for e in events
                    if e["kind"] == "observer.actual-bound"
                    and e["detail"]["binding"]["phase_index"] == 0
                ]
                require(len(bound) == 1, "exact original observer binding missing")
                bound = bound[0]
                require(
                    load(ready)
                    == {
                        "start_id": start_id,
                        "enrollment_sha256": bound["enrollment_sha256"],
                    },
                    "observer readiness differs from source-owned original enrollment",
                )
                ready_client = load(output / "client-ready.json")["client"]
                client_kernel = identity(ready_client["pid"])
                require(
                    all(client_kernel[k] == v for k, v in ready_client.items()),
                    "original client kernel differs",
                )
                from experiments.formal_campaign.h3_observer_loss import (
                    observe_host_kernels,
                )

                original_members = load(output / "phase0.actual-membership.json")
                expected_hosts = [
                    {
                        k: m["identity"][k]
                        for k in ("pid", "start_ticks", "session", "boot_id")
                    }
                    for m in original_members
                ]
                require(
                    observe_host_kernels(expected_hosts) == expected_hosts,
                    "healthy original Host roster missing before observer injection",
                )
                raw = observe_and_fault(
                    bound,
                    authority=authority_owner,
                    source_ref=bound["source"],
                    expected_argv=bound["argv"],
                    start_id=start_id,
                    enrollment=bound["enrollment_sha256"],
                    timeout_s=original["fault"]["target_exit_timeout_s"],
                    before_signal=lambda client_kernel=client_kernel, bound=bound: (
                        observe_original_client_barrier(
                            output=output,
                            client_kernel=client_kernel,
                            start_id=start_id,
                            enrollment=bound["enrollment_sha256"],
                        )
                    ),
                )
                # Prove original API+both TP2 workers survive the observer fault
                # before the explicitly counted operator recovery retires Host.
                kernels = observe_host_kernels(expected_hosts)
                raw["host_kernels_immediately_after_observer_death"] = kernels
                raw["client_kernel"] = client_kernel
                fault_raw = raw
                save_new(output / "observer-fault-raw.json", raw)
                fault = raw["fault"]
                dead = raw["pidfd_observed_dead_ns"]
                save_new(output / "runner-fault.json", fault)
                save_new(
                    output / "runner-observer-dead.json", {"observed_dead_ns": dead}
                )
            if (
                live_intent
                and (output / "live-route-publication.json").exists()
                and not (output / "runner-live-route-observation.json").exists()
            ):
                from experiments.formal_campaign.h3_observer_live_observe import (
                    observe as observe_live_route,
                )

                observe_live_route(scope, output, authority_owner, authority)
            preservation = output / "observer-recovery-accounting.json"
            ack = output / "runner-host-preserved-ack.json"
            if preservation.exists() and not ack.exists():
                from experiments.formal_campaign.h3_client_trace import (
                    read_client_trace,
                )

                load(preservation)
                trace = read_client_trace(output / "client.jsonl")
                stopped = [e for e in trace if e["kind"] == "client.stop"]
                require(
                    len(stopped) == 1, "original finite window has no terminal event"
                )
                original_members = load(output / "phase0.actual-membership.json")
                from experiments.formal_campaign.h3_observer_loss import (
                    observe_host_kernels,
                )

                expected_hosts = [
                    {
                        k: m["identity"][k]
                        for k in ("pid", "start_ticks", "session", "boot_id")
                    }
                    for m in original_members
                ]
                actual_kernels = observe_host_kernels(expected_hosts)
                save_new(
                    ack,
                    {
                        "host_kernels": actual_kernels,
                        "client_stop_ns": stopped[0]["monotonic_ns"],
                        "host_preserved": actual_kernels == expected_hosts,
                        "observed_ns": time.monotonic_ns(),
                        "replacement_committed": bool(
                            live_intent
                            and (output / "live-route-publication.json").exists()
                        ),
                        **(
                            {"live_route_query": authority.call("query")}
                            if live_intent
                            else {}
                        ),
                    },
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
        independent_terminal_ns = time.monotonic_ns()
        cleanup_started_ns = None
        errors = []
        if cleanup_policy is not None:
            cleanup_owned.extend(observed_owned.values())
            for owner in (carrier_owner, authority_owner):
                if owner is not None and live(owner):
                    try:
                        _, table = owned_sessions(owner)
                        cleanup_owned.extend(table.values())
                    except Exception as exc:
                        errors.append("independent ownership capture: " + str(exc))
            if fault_raw is not None:
                from experiments.formal_campaign.h3_observer_cleanup import (
                    required_epochs,
                )

                cleanup_epochs = {
                    "authority": authority_owner,
                    "carrier": carrier_owner,
                    "host": expected_hosts,
                    "collector": fault_raw["binding"]["observer"],
                    "client": fault_raw["client_kernel"],
                }
                cleanup_owned.extend(required_epochs(cleanup_epochs))
            from experiments.formal_campaign.h3_observer_cleanup import ordered_kernels

            cleanup_owned = ordered_kernels(cleanup_owned)
            save_new(
                output / "runner-terminal.json",
                {
                    "schema": "ecpa-h3-observer-independent-runner-terminal/v1",
                    "start_id": start_id,
                    "context": cleanup_context,
                    "run_epochs": cleanup_epochs,
                    "fault": fault,
                    "observed_dead_ns": dead,
                    "observed_ns": independent_terminal_ns,
                    "carrier_complete": (output / "carrier-complete.json").exists(),
                    "carrier_returncode": carrier_process.poll()
                    if carrier_process is not None
                    else None,
                    "error": error,
                },
            )
            cleanup_started_ns = time.monotonic_ns()
            save_new(
                output / "runner-cleanup-ownership.json",
                {
                    "context": cleanup_context,
                    "run_epochs": cleanup_epochs,
                    "owned_kernels": cleanup_owned,
                    "captured_ns": time.monotonic_ns(),
                },
            )
            if cleanup_before is not None:
                external = [e["kernel"] for e in cleanup_before["external_services"]]
                require(
                    not any(k in external for k in cleanup_owned),
                    "externally owned service entered cleanup set; refuse signal",
                )
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
        if cleanup_before is not None:
            try:
                from experiments.formal_campaign.h3_observer_cleanup import (
                    observe as observe_cleanup,
                )

                if live_intent:
                    from experiments.formal_campaign.h3_observer_live_cleanup import (
                        observe as live_observe,
                    )

                    def observe_cleanup(*args, **kwargs):
                        return live_observe(*args, unix_scopes=unix_scopes, **kwargs)

                after = observe_cleanup(
                    cleanup_policy,
                    cleanup_ports,
                    owned=cleanup_owned,
                    context=cleanup_context,
                    stage="after-cleanup",
                    run_epochs=cleanup_epochs,
                    external_before=cleanup_before["external_services"],
                )
                save_new(output / "runner-cleanup-after.json", after)
            except Exception as exc:
                errors.append("independent cleanup observation: " + str(exc))
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
                "cleanup_owned_kernels": cleanup_owned,
                "cleanup_run_epochs": cleanup_epochs,
                "cleanup_started_ns": cleanup_started_ns,
                "recorded_ns": time.monotonic_ns(),
                "formal_result": False,
            },
        )
    if live_intent:
        # Independent actual-fault/prefix artifacts always precede intake;
        # genuine verifier errors are retained without formal promotion.
        from experiments.formal_campaign.h3_observer_live_intake import (
            intake as live_intake,
        )

        try:
            result = live_intake(
                spec_path,
                receipt_path,
                start_id,
                output,
                live_intent=live_intent,
                live_receipt=live_receipt,
            )
            save_new(output / "live-start-observation.json", result)
        except Exception as exc:
            result = {
                "schema": "ecpa-h3-observer-live-intake-rejection/v2",
                "start_id": start_id,
                "formal_start_validated": False,
                "formal_result": False,
                "objective_met": None,
                "error": type(exc).__name__ + ": " + str(exc),
                "source_attempt_retained": True,
                "cleanup_errors": errors,
            }
            save_new(output / "live-intake-rejection.json", result)
        return result
    # No automatically qualified failure: the new intake must independently
    # validate source admission, actual observations and all raw joins.
    from experiments.formal_campaign.h3_observer_intake import intake

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
