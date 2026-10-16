"""Explicit dynamic-domain intake; never feeds replacement identities to v1.

Source-admitted actual starts and complete delivery measurements are separate
from proving the original hypothesis. Backend execution duplication stays null.
"""

from pathlib import Path

from experiments.formal_campaign.h3_dynamic_authority import (
    canonical,
    digest,
    read_dynamic_journal,
    require,
)
from experiments.formal_campaign.h3_dynamic_client import verify_dynamic_window
from experiments.formal_campaign.h3_owned_worker_carrier import load, reference
from experiments.formal_campaign.h3_worker_recovery import (
    _event,
    verify_parent_worker_ancestry,
)


def assess_original_objective(objective, measurements, recovery_ms, operator_actions):
    """A measured violation can falsify; missing execution proof cannot pass."""
    violations = []
    if measurements is not None:
        if (
            measurements["lost_requests"] is not None
            and measurements["lost_requests"] > objective["max_lost_requests"]
        ):
            violations.append("max_lost_requests")
        if measurements["coverage"] != "complete-finite-delivery-window":
            violations.append("original_continuous_client_window")
    if recovery_ms is not None and recovery_ms > objective["max_recovery_ms"]:
        violations.append("max_recovery_ms")
    if (
        operator_actions is not None
        and operator_actions > objective["max_operator_actions"]
    ):
        violations.append("max_operator_actions")
    return {
        "objective_met": False if violations else None,
        "known_objective_violations": violations,
        "unverified_obligations": [
            "backend_execution_duplication",
            "final_route_and_predecessor_fate",
            "device_and_port_cleanup",
        ],
    }


def intake(spec_path, receipt_path, start_id, output, *, native=False):
    if native:
        from experiments.formal_campaign.h3_native_authority import JOURNAL, PROFILE
        from experiments.formal_campaign.h3_native_delivery import (
            verify_native_window as verify_window,
        )
        from experiments.formal_campaign.h3_native_registration import (
            validate_materialization,
            validate_receipt,
        )
    else:
        from experiments.formal_campaign.h3_dynamic_authority import JOURNAL, PROFILE
        from experiments.formal_campaign.h3_dynamic_registration import (
            validate_materialization,
            validate_receipt,
        )

        verify_window = verify_dynamic_window
    spec, original, receipt = validate_receipt(spec_path, receipt_path)
    start = next(s for s in spec["starts"] if s["start_id"] == start_id)
    observations = load(output / "runner-observations.json")
    require(
        observations["schema"] == "ecpa-h3-dynamic-runner-observations/v1"
        and observations["start_id"] == start_id,
        "wrong independent runner observations",
    )
    launches = observations["host_launches"]
    if not launches:
        return {
            "schema": "ecpa-h3-native-start-observation/v1"
            if native
            else "ecpa-h3-dynamic-start-observation/v1",
            "start_id": start_id,
            "start_validation": "preflight-rejection"
            if not list(output.glob("phase*.launch-observation.json"))
            else "launched-unverified",
            "formal_result": False,
            "objective_met": None,
            "error": observations["error"],
        }
    runtime_recipe = load(output / "runtime-recipe.json")
    validate_materialization(spec, start, runtime_recipe)
    authority = load(output / "runner-authority-observation.json")
    peer = load(output / "runner-authority-peer-observation.json")
    require(
        authority["command"] == start["authority"]["command"]
        and authority["receipt"] == reference(receipt_path)
        and authority["policy"] == start["policy"]
        and peer["kernel"] == authority["kernel"]
        and peer["argv"] == start["authority"]["command"],
        "authority kernel/peer/registered command differs",
    )
    require(
        runtime_recipe["authority"]["process_identity"]
        == {k: authority["kernel"][k] for k in ("pid", "start_ticks", "boot_id")},
        "runtime recipe authority differs from independent actual epoch",
    )
    adapter = load(output / "runner-carrier-observation.json")
    for launch in launches:
        path = output / launch["marker"]
        marker = load(path)
        require(
            reference(path)["sha256"] == launch["marker_sha256"]
            and marker["pid"] == launch["kernel"]["pid"]
            and adapter["observed_ns"]
            < marker["launched_monotonic_ns"]
            <= launch["observed_ns"],
            "Host launch actual observation differs",
        )
    phases = observations["phases"]
    for label, phase in phases.items():
        require(
            load(output / f"runner-{label}-ack.json") == phase,
            "phase acknowledgment differs",
        )
        verify_parent_worker_ancestry(phase)
        for role, key in (("api-server", "parent"), ("worker", "worker")):
            _event(phase[key + "_event"], phase[key], role)
    fault = observations["fault"]
    dead = observations["observed_dead_ns"]
    if fault is not None:
        require(
            "before" in phases
            and load(output / "runner-fault.json") == fault
            and fault["target"] == phases["before"]["worker"]
            and fault["signal"] == original["fault"]["signal"]
            and phases["before"]["observed_ns"] < fault["triggered_ns"],
            "actual fault/target differs",
        )
        if dead is not None:
            require(
                fault["triggered_ns"] < dead
                and load(output / "runner-worker-dead.json")["observed_dead_ns"]
                == dead,
                "actual death order differs",
            )
    policy = load(start["policy"]["path"])
    events = read_dynamic_journal(start["authority"]["journal"], domain=JOURNAL)
    require(
        events[0]["authority"] == authority["kernel"]
        and events[0]["policy_sha256"] == digest(canonical(policy)),
        "actual authority journal epoch differs",
    )
    measurements = None
    complete = output / "carrier-complete.json"
    recovery = None
    if complete.exists():
        require(
            set(phases) == {"before", "after"}
            and fault is not None
            and dead is not None,
            "complete carrier lacks actual old/dead/new phases",
        )
        before, after = phases["before"], phases["after"]
        require(
            dead < after["observed_ns"]
            and before["worker"]["launch_id"] != after["worker"]["launch_id"]
            and (before["worker"]["pid"], before["worker"]["start_ticks"])
            != (after["worker"]["pid"], after["worker"]["start_ticks"]),
            "replacement reused dead worker epoch",
        )
        recovery = load(output / "actual-recovery-observation.json")
        require(
            after["observed_ns"] <= recovery["recovery_ns"]
            and recovery["launch_id"] == after["parent"]["launch_id"],
            "recovery clock/launch differs",
        )
    if (
        fault is not None
        and (native or dead is not None)
        and (output / "client.jsonl").exists()
    ):
        client_spec = load(output / "runtime-client-spec.json")
        ready = load(output / "client-ready.json")
        expected = dict(
            start["client_template"],
            authority_process_identity={
                k: authority["kernel"][k] for k in ("pid", "start_ticks", "boot_id")
            },
            authority_domain=PROFILE,
            dynamic_policy_sha256=digest(canonical(policy)),
            dynamic_registration_sha256=policy["registration_sha256"],
            initial_enrollment_sha256=client_spec["initial_enrollment_sha256"],
        )
        require(
            client_spec == expected,
            "runtime client changed registered workload or domain",
        )
        measurements = verify_window(
            client_spec,
            output / "client.jsonl",
            Path(start["authority"]["journal"]),
            policy=policy,
            frozen_probe=original["probe"],
            expected_client=ready["client"],
            fault_ns=fault["triggered_ns"],
            recovery_ns=recovery["recovery_ns"] if recovery is not None else None,
            **({"allow_incomplete": True} if native else {}),
        )
        if complete.exists():
            require(
                load(
                    output
                    / (
                        "native-delivery-observation.json"
                        if native
                        else "dynamic-delivery-observation.json"
                    )
                )
                == measurements
                and load(complete)["delivery"] == measurements,
                "carrier measurement differs from independent intake",
            )
    recovery_ms = None
    if fault is not None and recovery is not None:
        recovery_ms = (recovery["recovery_ns"] - fault["triggered_ns"]) / 1e6
    operator_actions = (
        int(
            any(
                launch["marker"] == "phase1.launch-observation.json"
                for launch in launches
            )
        )
        if native
        else (1 if "after" in phases else None)
    )
    objective_result = assess_original_objective(
        original["objective"],
        measurements,
        recovery_ms,
        operator_actions,
    )
    formal_start_validated = bool(
        measurements is not None
        and fault is not None
        and (native or dead is not None)
        and "before" in phases
    )
    return {
        **objective_result,
        "formal_start_validated": formal_start_validated,
        "evidence_class": "formal-real"
        if formal_start_validated
        else "prospective-unverified",
        "schema": "ecpa-h3-native-start-observation/v1"
        if native
        else "ecpa-h3-dynamic-start-observation/v1",
        "start_id": start_id,
        "campaign_id": original["campaign_id"],
        "cell_id": original["cell_id"],
        "arm": start["arm"],
        "repetition": start["repetition"],
        "arm_order": start["arm_order"],
        "start_validation": "source-admitted-actual-start"
        if formal_start_validated
        else "launched-unverified",
        "delivery_validation": (
            "coverage_failed"
            if measurements
            and measurements["coverage"] != "complete-finite-delivery-window"
            else "verified"
            if measurements
            else "incomplete"
        ),
        "formal_result": False,
        "duplicated_requests": None,
        "backend_execution_duplicates": None,
        "operator_actions": operator_actions,
        "measurements": measurements,
        "failure": observations["error"],
        "cleanup_errors": observations["cleanup_errors"],
        "deployment_receipt": reference(receipt_path),
        "original_objective": original["objective"],
        "raw_artifacts": {
            p.name: reference(p)
            for p in sorted(output.iterdir())
            if p.is_file()
            and p.name
            not in ("dynamic-start-observation.json", "intake-rejection.json")
        },
    }
