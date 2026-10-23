"""Replay a genuine Manager-phase fault and original finite native traffic.

Source admission, observed failure, cleanup and hypothesis proof are distinct.
Existing public native proofs are never optional, even on a failed/partial start.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign import h3_manager_phase_cleanup as cleanup
from experiments.formal_campaign import h3_manager_phase_registration as registration
from experiments.formal_campaign.h3_dynamic_intake import assess_original_objective
from experiments.formal_campaign.h3_manager_after_launch import SCHEMA
from experiments.formal_campaign.h3_manager_phase_delivery import verify_manager_window
from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    load,
    require,
)
from experiments.formal_campaign.h3_runtime_source_closure import (
    verify_runtime_source_closure,
)


def observe(spec_path, receipt_path, start_id, output):
    capability = registration.validate_receipt_for_start(
        spec_path, receipt_path, start_id
    )
    spec, original, start = capability.selected(start_id)
    output = Path(output)
    if start["manager_phase_support"] == "unsupported-no-manager":
        raw = load(output / "unsupported.json")
        require(
            raw["start_id"] == start_id
            and raw["fault"] is None
            and raw["formal_start_validated"] is False,
            "baseline invented a Manager fault",
        )
        return dict(
            schema="ecpa-h3-manager-phase-observation/v1",
            start_id=start_id,
            formal_start_validated=False,
            objective_met=None,
            start_validation="unsupported-no-manager",
            measurements=None,
        )
    root_record = load(output / "root-record.json")
    terminal = load(checked_reference(root_record["terminal"]))
    before = load(checked_reference(root_record["before"]))
    after = load(checked_reference(root_record["after"]))
    launch = load(output / "root-launch.json")
    recipe = load(checked_reference(start["recipe_template"]))
    phases = recipe["arms"]["ecpa"]["phases"]
    registration.validate_materialization(
        spec, start, load(output / "actual-recipe.json")
    )
    require(
        root_record["start_id"]
        == terminal["start_id"]
        == launch["start_id"]
        == start_id
        and root_record["root"] == terminal["root"] == launch["root"],
        "root start/kernel witness substitution",
    )
    require(
        launch["campaign"]["path"] == str(Path(spec_path))
        and checked_reference(launch["campaign"]).read_bytes()
        == Path(spec_path).read_bytes()
        and launch["receipt"]["path"] == str(Path(receipt_path))
        and checked_reference(launch["receipt"]).read_bytes()
        == Path(receipt_path).read_bytes(),
        "actual root used another campaign/receipt",
    )
    require(
        launch["source"]["path"].endswith("/h3_manager_phase_runner.py")
        and "experiments/formal_campaign/h3_manager_phase_runner.py"
        in load(receipt_path)["protocol_sources"],
        "actual root runner not source admitted",
    )
    receipt_sources = load(receipt_path)["protocol_sources"]
    require(
        client.sha(checked_reference(launch["source"]).read_bytes())
        == receipt_sources["experiments/formal_campaign/h3_manager_phase_runner.py"],
        "actual root source differs from independent receipt",
    )
    failure = terminal["failure"]
    runtime_types = {
        "builtins.TimeoutError",
        "builtins.ConnectionError",
        "builtins.ConnectionRefusedError",
        "builtins.ConnectionResetError",
        "builtins.ConnectionAbortedError",
        "builtins.BrokenPipeError",
        "builtins.ProcessLookupError",
        "subprocess.TimeoutExpired",
        "experiments.formal_campaign.h3_manager_after_launch.ManagerCleanupFailed",
    }
    require(
        failure is None
        or (
            failure["category"] == "runtime-interruption"
            and failure["type"] in runtime_types
        ),
        "schema/ABI/integrity failure is not a qualified runtime negative",
    )
    fault = terminal["fault"]
    require(
        fault is not None
        and fault == load(output / "fault/manager-after-launch.fault.json"),
        "actual Manager fault evidence missing or substituted",
    )
    event = load(output / "fault/manager-after-launch.event.json")
    declaration_ref = load(output / "root-barrier-reference.json")
    declaration_raw = checked_reference(
        dict(declaration_ref, sha256="sha256:" + declaration_ref["sha256"])
    ).read_bytes()
    declaration = json.loads(declaration_raw)
    binding = load(output / "phase0.native-binding.json")
    handoff_raw = (output / "phase0.handoff-unvalidated.json").read_bytes()
    from vllm_hust_ext.runtime_phase_handoff import manager_source_digests

    require(
        json.loads(handoff_raw)
        == {k: v for k, v in binding.items() if k != "binding_sha256"}
        and client.sha(handoff_raw).removeprefix("sha256:") == binding["binding_sha256"]
        and binding["manager_source_sha256"] == manager_source_digests(),
        "original actual Manager handoff bytes/source binding differs",
    )
    source = event["source"]
    source_map = load(checked_reference(phases[0]["native_guard"]))["source_arguments"][
        "native_sources"
    ]
    require(
        source_map.get(source["path"], "").removeprefix("sha256:") == source["sha256"]
        and client.sha(Path(source["path"]).read_bytes()).removeprefix("sha256:")
        == source["sha256"],
        "actual product hook absent from independent native source closure",
    )
    expected_native = {
        key: binding["environment"][key]
        for key in ("VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID")
    }
    launch_spec = load(checked_reference(phases[0]["semantic_launch_spec"]))
    expected_native.update(
        {
            "ECPA_SEMANTIC_" + env: str(launch_spec[key])
            for env, key in (
                ("EXECUTION_PLAN_ID", "execution_plan_id"),
                ("CONTROLLER_INSTANCE", "controller_instance"),
                ("CANDIDATE_GENERATION", "candidate_generation"),
                ("MEMBERSHIP_EPOCH", "membership_epoch"),
            )
        }
    )
    request = dict(
        schema=SCHEMA,
        operation="hold-after-launch",
        start_id=start_id,
        nonce=declaration["nonce"],
        expected_manager=event["manager"],
        expected_native=expected_native,
    )
    require(
        event["request_sha256"]
        == client.sha(client.canonical(request) + b"\n").removeprefix("sha256:"),
        "actual root challenge is not joined to source phase event",
    )
    require(
        event["schema"] == SCHEMA
        and event["phase"] == original["cell_id"]
        and event["start_id"] == declaration["start_id"] == start_id
        and event["nonce"] == declaration["nonce"]
        and event["root"] == declaration["root"] == launch["root"]
        and event["manager"] == binding["publisher"] == fault["manager"]
        and event["child"] == fault["child"]
        and event["native"] == expected_native
        and event["config_sha256"]
        == client.sha(declaration_raw).removeprefix("sha256:")
        and fault["event_sha256"]
        == client.sha(client.canonical(event)).removeprefix("sha256:")
        and fault["recovery_deadline_ns"] == fault["fault_before_ns"] + 30_000_000_000
        and event["child_popen_ns"]
        <= event["observed_monotonic_ns"]
        <= fault["fault_before_ns"]
        <= fault["fault_sent_ns"]
        < fault["death_observed_ns"]
        and event["model_request_id"] is None
        and event["commit_proved"] is event["native_completion_proved"] is False,
        "actual source Manager/phase/native/fault/clock binding differs",
    )
    # Every real launch retains the unchanged actual interpreter/wheel/source
    # closure checks. No failed-row waiver for existing native archive facts.
    for index, phase in enumerate(phases):
        expected = verify_runtime_source_closure(
            phase,
            original["fixed_identity"],
            spec["repositories"],
            spec["runtime_wheels"],
        )
        require(
            expected == load(output / f"phase{index}.runtime-source-closure.json"),
            "actual phase runtime source closure differs",
        )
    epochs = terminal["run_epochs"]
    require(
        epochs["manager_initial"] == event["manager"]
        and epochs["host_initial"] == event["child"]
        and epochs["authority"] == load(output / "authority-popen.json")["kernel"]
        and epochs["client"] == load(output / "client-popen.json")["kernel"],
        "cleanup omitted or substituted actual source role epochs",
    )
    runtime_spec = load(output / "runtime-client-spec.json")
    require(
        all(runtime_spec[k] == value for k, value in start["client_template"].items()),
        "actual client changed original registered60/body/deadlines",
    )
    from experiments.formal_campaign.h3_dynamic_authority import read_dynamic_journal
    from experiments.formal_campaign.h3_native_authority import JOURNAL

    journal = read_dynamic_journal(Path(start["authority"]["journal"]), domain=JOURNAL)
    enrolled = [
        e["detail"]["enrollment"] for e in journal if e["kind"] == "backend.enrolled"
    ]
    expected_enrollments = (
        [load(output / "actual-enrollment.json")]
        if (output / "actual-enrollment.json").exists()
        else []
    )
    require(
        enrolled == expected_enrollments,
        "actual replacement enrollment was substituted or omitted",
    )
    require(
        all(e["launch_id"] != event["native"]["VLLM_ECPA_LAUNCH_ID"] for e in enrolled),
        "replacement reused the initial un-enrolled native launch UUID",
    )

    if terminal["recovery_ns"] is not None:
        recovered = load(output / "actual-recovery.json")
        require(
            enrolled == [recovered["enrollment"]]
            and recovered["recovery_ns"] == terminal["recovery_ns"],
            "actual route-open recovery observation differs",
        )
    measurements = verify_manager_window(
        runtime_spec,
        output / "client.jsonl",
        Path(start["authority"]["journal"]),
        policy=load(checked_reference(start["policy"])),
        frozen_probe=original["probe"],
        expected_client={
            k: epochs["client"][k] for k in ("pid", "start_ticks", "boot_id")
        },
        fault_ns=fault["fault_before_ns"],
        recovery_ns=terminal["recovery_ns"],
        allow_incomplete=True,
    )
    clocks = dict(
        terminal_kind="complete-client-window"
        if terminal["client_stop_ns"] is not None
        else "independent-runner-failed-start",
        launch_ns=launch["launch_ns"],
        fault_ns=fault["fault_before_ns"],
        dead_ns=fault["death_observed_ns"],
        client_stop_ns=terminal["client_stop_ns"],
        terminal_ns=terminal["terminal_ns"],
        cleanup_started_ns=terminal["cleanup_started_ns"],
        recorded_ns=root_record["recorded_ns"],
    )
    ports = [
        start["authority"]["public_port"],
        urlparse(recipe["authority"]["backend_endpoint"]).port,
    ]
    cleaned = cleanup.verify(
        before,
        after,
        spec["manager_cleanup"],
        context=cleanup.context_for(spec_path, receipt_path, spec, start),
        run_epochs=epochs,
        owned_kernels=terminal["owned_kernels"],
        ports=ports,
        clocks=clocks,
    )
    recovery_ms = (
        None
        if terminal["recovery_ns"] is None
        else (terminal["recovery_ns"] - fault["fault_before_ns"]) / 1e6
    )
    operator_actions = int((output / "phase1.launch-observation.json").exists())
    objective = assess_original_objective(
        original["objective"], measurements, recovery_ms, operator_actions
    )
    if (
        terminal["recovery_ns"] is None
        or terminal["cleanup_errors"]
        or not all(cleaned.values())
    ):
        objective["objective_met"] = False
        objective["known_objective_violations"].append(
            "actual_recovery_or_cleanup_failed"
        )
    objective["unverified_obligations"] += [
        "predecessor_preserved_until_candidate_commit",
        "actual_transaction_commit",
        "automatic_restoration",
    ]
    return dict(
        schema="ecpa-h3-manager-phase-observation/v1",
        start_id=start_id,
        campaign_id=original["campaign_id"],
        cell_id=original["cell_id"],
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        start_validation="source-admitted-actual-start",
        formal_start_validated=True,
        measurements=measurements,
        recovery_ms=recovery_ms,
        operator_actions=operator_actions,
        cleanup=cleaned,
        raw_failure=failure,
        cleanup_errors=terminal["cleanup_errors"],
        **objective,
    )
