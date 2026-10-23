"""Root-owned original Manager-after-launch execution, distinct from worker recovery.

Registration must come from the future published source/wheel tuple. This module
never issues source qualification, guesses a Manager PID, or invents a baseline
actor. Its original finite client runs once, including genuine closed-route 503s.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign import h3_manager_phase_cleanup as witness
from experiments.formal_campaign import h3_manager_phase_registration as registration
from experiments.formal_campaign.h3_dynamic_runner import prepare_native_paths
from experiments.formal_campaign.h3_manager_after_launch import (
    ENV,
    ManagerCleanupFailed,
    ManagerPhaseKilled,
    callback_for_phase,
    declare,
)
from experiments.formal_campaign.h3_owned_worker_carrier import (
    HERE,
    NativeRegisteredAuthority,
    checked_reference,
    launch_phase,
    load,
    reference,
    require,
    validate_recipe,
    wait_native_health,
)
from experiments.formal_campaign.h3_runtime_source_closure import (
    verify_runtime_source_closure,
)
from experiments.formal_campaign.h3_worker_relaunch import (
    cleanup,
    identity,
    owned_sessions,
)


class ManagerRegisteredAuthority(NativeRegisteredAuthority):
    receipt_schema = registration.RECEIPT

    @classmethod
    def _registered_start(cls, capability, start_id):
        require(
            type(capability) is registration.ManagerStart,
            "Manager authority requires its independently issued start scope",
        )
        return capability.authority_binding(start_id)


def _save(path, value):
    raw = client.canonical(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _wait(path, process, deadline, *, json_file=True):
    while not Path(path).exists():
        require(process.poll() is None, "owned source process exited before its marker")
        if time.monotonic() >= deadline:
            raise TimeoutError("original registered readiness deadline")
        time.sleep(0.01)
    if not json_file:
        info = Path(path).lstat()
        require(
            stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(),
            "actual authority control path differs",
        )
        while stat.S_IMODE(Path(path).lstat().st_mode) != 0o600:
            require(process.poll() is None, "authority exited before private readiness")
            if time.monotonic() >= deadline:
                raise TimeoutError("original authority readiness deadline")
            time.sleep(0.01)
        return None
    return load(path)


def _kernels(process, expected):
    require(identity(process.pid) == expected, "owned phase root epoch changed")
    sessions, descendants = owned_sessions(expected)
    return sessions, list(descendants.values())


def execute(spec_path, receipt_path, start_id, output):
    validated = registration.validate_receipt_for_start(
        spec_path,
        receipt_path,
        start_id,
        check_remote=True,
    )
    spec, original, start = validated.selected(start_id)
    output = Path(output)
    require(not output.exists(), "fresh registered start output required")
    template = load(checked_reference(start["recipe_template"]))
    phases = template["arms"][start["arm"]]["phases"]
    require(
        all(Path(p["native_bootstrap"]["output"]).parent == output for p in phases),
        "actual start output differs from the registered native scopes",
    )
    output.mkdir(parents=True, mode=0o700)
    fd = os.open(output, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fchmod(fd, 0o700)
    finally:
        os.close(fd)
    if start["manager_phase_support"] == "unsupported-no-manager":
        _save(
            output / "unsupported.json",
            dict(
                start_id=start_id,
                reason="original baseline has no Manager actor at this phase",
                formal_start_validated=False,
                fault=None,
                measurements=None,
            ),
        )
        return 2
    require(start["arm"] == "ecpa", "baseline cannot become a fake Manager arm")
    guards = registration.build_plan_guards(
        spec,
        original,
        validated.guard_receipt(start_id),
        start,
        trusted_manager_handoffs=set(),
    )
    prepare_native_paths(template, start, output)
    # All expensive admission audits happen before the original client starts.
    for index, phase in enumerate(phases):
        closure = verify_runtime_source_closure(
            phase,
            original["fixed_identity"],
            spec["repositories"],
            spec["runtime_wheels"],
        )
        _save(output / f"phase{index}.runtime-source-closure.json", closure)
    context = witness.context_for(spec_path, receipt_path, spec, start)
    ports = [
        start["authority"]["public_port"],
        int(template["authority"]["backend_endpoint"].rsplit(":", 1)[1]),
    ]
    before = witness.observe(
        spec["manager_cleanup"], ports, context=context, stage="before-product"
    )
    _save(output / "independent-before.json", before)
    require(
        not before["listeners"] and before["npu_exit"] == 0,
        "original owned ports/devices are not independently idle",
    )
    import base64

    npu_before = base64.b64decode(before["npu_stdout_base64"], validate=True)
    require(
        all(
            f"No running processes found in NPU {d}".encode() in npu_before
            for d in (0, 3)
        ),
        "original allocated devices were not actually empty before product",
    )
    processes, captured, replacements = [], [], []
    authority_process = client_process = authority = None
    initial_manager = initial_host = client_owner = authority_owner = None
    fault = recovery_ns = client_stop_ns = None
    failure = None
    cleanup_errors = []
    product_launch_ns = time.monotonic_ns()
    _save(
        output / "root-launch.json",
        dict(
            root=identity(os.getpid()),
            source=reference(Path(__file__).resolve()),
            start_id=start_id,
            campaign=reference(Path(spec_path)),
            receipt=reference(Path(receipt_path)),
            launch_ns=product_launch_ns,
        ),
    )
    try:
        with (output / "authority.log").open("xb") as log:
            authority_process = subprocess.Popen(
                start["authority"]["command"],
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        authority_owner = identity(authority_process.pid)
        processes.append((authority_process, authority_owner, [authority_owner]))
        captured.append(authority_owner)
        _save(
            output / "authority-popen.json",
            dict(
                kernel=authority_owner,
                argv=start["authority"]["command"],
                monotonic_ns=time.monotonic_ns(),
            ),
        )
        ready = time.monotonic() + original["probe"]["ready_timeout_s"]
        _wait(
            template["authority"]["socket"], authority_process, ready, json_file=False
        )
        recipe = registration.materialize_recipe(template, authority_owner)
        _save(output / "actual-recipe.json", recipe)
        registration.validate_materialization(spec, start, recipe)
        validate_recipe(
            recipe,
            reference(output / "actual-recipe.json")["sha256"],
            output / "actual-recipe.json",
            start["arm"],
            native=True,
        )
        authority = ManagerRegisteredAuthority(recipe, validated, start_id)
        while True:
            try:
                capabilities = authority.preflight()
                break
            except ConnectionRefusedError as error:
                require(
                    authority_process.poll() is None, "authority exited before listen"
                )
                if time.monotonic() >= ready:
                    raise TimeoutError(
                        "original authority readiness deadline"
                    ) from error
                time.sleep(0.01)
        _save(output / "authority-capabilities.json", capabilities)
        config_path = Path(phases[0]["environment"][ENV])
        declaration = declare(
            config_path.parent,
            start_id=start_id,
            deadline_ns=time.monotonic_ns()
            + int(original["probe"]["ready_timeout_s"] * 1e9),
            nonce=secrets.token_hex(32),
        )
        require(
            declaration.reference()["path"] == str(config_path),
            "root declaration differs from the frozen phase environment",
        )
        _save(output / "root-barrier-reference.json", declaration.reference())
        fault_output = output / "fault"
        fault_output.mkdir(mode=0o700)
        actuator = callback_for_phase(
            phase=phases[0],
            guard=guards[0],
            declaration=declaration,
            output=fault_output,
        )
        runtime_spec = dict(
            start["client_template"],
            authority_process_identity={
                k: authority_owner[k] for k in ("pid", "start_ticks", "boot_id")
            },
            authority_domain=authority.profile,
            manager_phase_domain=registration.DOMAIN,
            dynamic_policy_sha256=client.sha(
                client.canonical(load(start["policy"]["path"]))
            ),
            dynamic_registration_sha256=authority.registration_sha,
            initial_enrollment_sha256=None,
        )
        _save(output / "runtime-client-spec.json", runtime_spec)
        with (output / "client.log").open("xb") as log:
            client_process = subprocess.Popen(
                [
                    sys.executable,
                    str(HERE / "h3_client_trace.py"),
                    "--spec",
                    str(output / "runtime-client-spec.json"),
                    "--trace",
                    str(output / "client.jsonl"),
                    "--ready",
                    str(output / "client-ready.json"),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        client_owner = identity(client_process.pid)
        processes.append((client_process, client_owner, [client_owner]))
        captured.append(client_owner)
        _save(
            output / "client-popen.json",
            dict(kernel=client_owner, monotonic_ns=time.monotonic_ns()),
        )
        _wait(output / "client-ready.json", client_process, time.monotonic() + 10)
        authority.call("bind_original_client", process_identity=client_owner)
        while not any(
            e["kind"] == "request.start"
            for e in client.read_client_trace(output / "client.jsonl")
        ):
            require(
                client_process.poll() is None,
                "original client exited before actual send",
            )
            time.sleep(0.005)
        try:
            launch_phase(
                phases[0],
                start["arm"],
                output,
                0,
                original["probe"]["ready_timeout_s"],
                after_native_binding=actuator,
            )
            raise ValueError(
                "Manager phase unexpectedly returned without its registered fault"
            )
        except ManagerPhaseKilled as actual:
            fault = actual.result
            initial_manager, initial_host = fault["manager"], fault["child"]
            captured += fault["captured_owned_kernels"]
            processes.append((actual.process, initial_manager, actual.sessions))
            if hasattr(actual, "manager_phase_cleanup_error"):
                cleanup_errors.append(actual.manager_phase_cleanup_error)
                raise ManagerCleanupFailed(
                    actual.manager_phase_cleanup_error
                ) from actual
            require(
                fault["death_observed_ns"] is not None,
                "actual Manager death was not observed",
            )
        # This is the original bounded-operator full relaunch, not an automatic
        # transaction rollback or proof of predecessor preservation/commit.
        process, owner, sessions, observed = launch_phase(
            phases[1],
            start["arm"],
            output,
            1,
            original["probe"]["ready_timeout_s"],
        )
        processes.append((process, owner, sessions))
        require(
            observed["parent"]["launch_id"]
            != load(output / "phase0.native-binding.json")["environment"][
                "VLLM_ECPA_LAUNCH_ID"
            ],
            "replacement cannot reuse the initial un-enrolled native launch UUID",
        )
        _, kernels = _kernels(process, owner)
        captured += kernels
        replacements = kernels
        wait_native_health(
            recipe["authority"]["backend_endpoint"],
            observed,
            load(output / "phase1.launch-observation.json"),
            original["probe"]["ready_timeout_s"],
        )
        generation = authority.call("query")["generation"]
        enrollment = authority.enroll(
            observed,
            load(output / "phase1.actual-membership.json"),
            phases[1]["sources"],
            generation,
        )
        _save(output / "actual-enrollment.json", enrollment)
        authority.prepare_native_epoch(
            phase_index=1,
            handoff=reference(output / "phase1.native-source-handoff.json"),
            ready_deadline_ns=load(output / "phase1.launch-observation.json")[
                "launched_monotonic_ns"
            ]
            + int(original["probe"]["ready_timeout_s"] * 1e9),
        )
        authority.call(
            "admit_generation",
            generation=enrollment["generation"],
            membership_sha256=enrollment["membership_sha256"],
        )
        recovery_ns = time.monotonic_ns()
        _save(
            output / "actual-recovery.json",
            dict(recovery_ns=recovery_ns, enrollment=enrollment),
        )
        client_process.wait(timeout=25)
    except Exception as exc:
        failure = dict(
            type=f"{type(exc).__module__}.{type(exc).__qualname__}",
            message=str(exc),
            category="runtime-interruption"
            if isinstance(
                exc,
                (
                    TimeoutError,
                    ConnectionError,
                    ProcessLookupError,
                    subprocess.TimeoutExpired,
                    ManagerCleanupFailed,
                ),
            )
            else "unqualified-verification-error",
        )
    finally:
        # Keep every actually observed session/kernel before any cleanup; no
        # invented fixed role population for the incomplete initial Host.
        for process, owner, sessions in processes:
            if process.poll() is None:
                try:
                    actual_sessions, kernels = _kernels(process, owner)
                    sessions.extend(s for s in actual_sessions if s not in sessions)
                    captured += kernels
                except Exception as exc:
                    cleanup_errors.append("ownership capture: " + str(exc))
        if client_process is not None:
            try:
                client_process.wait(timeout=25)
                traces = client.read_client_trace(output / "client.jsonl")
                stops = [e for e in traces if e["kind"] == "client.stop"]
                client_stop_ns = stops[0]["monotonic_ns"] if len(stops) == 1 else None
            except Exception as exc:
                cleanup_errors.append("original client terminal: " + str(exc))
        terminal_ns = time.monotonic_ns()
        cleanup_started_ns = time.monotonic_ns()
        if authority_process is not None and authority_process.stdin is not None:
            authority_process.stdin.close()
        for process, owner, sessions in reversed(processes):
            try:
                cleanup(process, owner, 10, sessions)
            except Exception as exc:
                cleanup_errors.append(str(exc))
        captured = witness.ordered_kernels(captured)
        run_epochs = None
        if (
            fault is not None
            and authority_owner is not None
            and client_owner is not None
        ):
            run_epochs = dict(
                authority=authority_owner,
                client=client_owner,
                manager_initial=initial_manager,
                host_initial=initial_host,
                replacement=[
                    k
                    for k in witness.ordered_kernels(replacements)
                    if k
                    not in (
                        authority_owner,
                        client_owner,
                        initial_manager,
                        initial_host,
                    )
                ],
            )
        _save(
            output / "root-terminal.json",
            dict(
                schema="ecpa-h3-manager-phase-terminal/v1",
                start_id=start_id,
                root=identity(os.getpid()),
                failure=failure,
                fault=fault,
                recovery_ns=recovery_ns,
                client_stop_ns=client_stop_ns,
                terminal_ns=terminal_ns,
                cleanup_started_ns=cleanup_started_ns,
                owned_kernels=captured,
                run_epochs=run_epochs,
                cleanup_errors=cleanup_errors,
                process_returncodes=[
                    dict(kernel=o, returncode=p.returncode) for p, o, _ in processes
                ],
                recorded_ns=time.monotonic_ns(),
                formal_result=False,
            ),
        )
        if run_epochs is not None:
            after = witness.observe(
                spec["manager_cleanup"],
                ports,
                context=context,
                stage="after-cleanup",
                owned=captured,
                run_epochs=run_epochs,
                external_before=before["external_services"],
            )
            _save(output / "independent-after.json", after)
            _save(
                output / "root-record.json",
                dict(
                    start_id=start_id,
                    root=identity(os.getpid()),
                    terminal=reference(output / "root-terminal.json"),
                    before=reference(output / "independent-before.json"),
                    after=reference(output / "independent-after.json"),
                    recorded_ns=time.monotonic_ns(),
                ),
            )
    return 0 if failure is None and not cleanup_errors else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ("campaign", "receipt", "output"):
        p.add_argument("--" + key, type=Path, required=True)
    p.add_argument("--start-id", required=True)
    a = p.parse_args()
    return execute(a.campaign, a.receipt, a.start_id, a.output)


if __name__ == "__main__":
    raise SystemExit(main())
