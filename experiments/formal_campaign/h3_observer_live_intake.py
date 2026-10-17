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


def intake(spec_path, receipt_path, start_id, output, *, live_intent,live_receipt):
    native=True
    from experiments.formal_campaign.h3_observer_live_registration import validate_for_start
    scope=validate_for_start(live_intent,live_receipt,start_id,check_remote=True)
    require(scope.value()['base_campaign']['path']==str(Path(spec_path).resolve()) and
        scope.value()['base_receipt']['path']==str(Path(receipt_path).resolve()),
        'continuation intake original source receipt substitution')
    require(native, "observer-loss intake only admits its distinct native domain")
    if native:
        from experiments.formal_campaign.h3_observer_authority import JOURNAL, PROFILE
        from experiments.formal_campaign.h3_observer_live_delivery import (
            verify_native_window as verify_window,
        )
        from experiments.formal_campaign.h3_observer_registration import (
            validate_materialization,
            validate_receipt_for_start,
        )
    else:
        from experiments.formal_campaign.h3_dynamic_authority import JOURNAL, PROFILE
        from experiments.formal_campaign.h3_dynamic_registration import (
            validate_materialization,
            validate_receipt,
        )

        verify_window = verify_dynamic_window
    if native:
        receipt = validate_receipt_for_start(spec_path, receipt_path, start_id)
        spec, original, start = receipt.selected(start_id)
    else:
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
            "schema": "ecpa-h3-observer-live-start-observation/v2"
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
    policy = load(start["policy"]["path"])
    events = read_dynamic_journal(start["authority"]["journal"], domain=JOURNAL)
    require(events[0]["authority"] == authority["kernel"] and
            events[0]["policy_sha256"] == digest(canonical(policy)),
            "actual observer authority journal epoch differs")
    bound_events=[e for e in events if e["kind"] == "observer.actual-bound" and
                  e["detail"]["binding"]["phase_index"] == 0]
    require(len(bound_events)==1, "actual original observer binding absent")
    bound=bound_events[0]["detail"]["binding"]
    raw=load(output/"observer-fault-raw.json")
    fault=observations["fault"]
    dead=observations["observed_dead_ns"]
    require(fault == raw["fault"] == load(output/"runner-fault.json") and
            dead == raw["pidfd_observed_dead_ns"] ==
                    load(output/"runner-observer-dead.json")["observed_dead_ns"],
            "independent observer fault/death observations differ")
    require(fault["signal"] == original["fault"]["signal"] and
            phases["before"]["observed_ns"] < fault["triggered_ns"] and
            dead-fault["triggered_ns"] <= original["fault"]["target_exit_timeout_s"]*1e9,
            "observer fault signal/timing differs from original")
    require(bound_events[0]["monotonic_ns"] < fault["triggered_ns"],
            "observer journal binding occurred after injection")
    membership=load(output/"phase0.actual-membership.json")
    host_kernels=[{k:m["identity"][k] for k in ("pid","start_ticks","session","boot_id")}
                  for m in membership]
    from experiments.formal_campaign.h3_observer_loss import validate_raw
    actual_fault=validate_raw(raw,bound,authority_events=events,
                 independent_host_kernels=raw["host_kernels_immediately_after_observer_death"],
                 original_host_kernels=host_kernels)
    require(raw["client_barrier"]["first_request_started_ns"] < fault["triggered_ns"],
            "original first-request fault barrier absent")
    measurements = None
    delivery_error = None
    source_client_prefix_validated = False
    complete = output / "carrier-complete.json"
    recovery = None
    accounting=None
    terminal=None
    if complete.exists():
        require(set(phases)=={"before"} and len(launches)==1 and fault is not None and dead is not None,
                "observer-only fault cannot conceal Host relaunch/worker replacement")
        accounting=load(output/"observer-recovery-accounting.json")
        witness=load(output/"runner-host-preserved-ack.json")
        from experiments.formal_campaign.h3_client_trace import read_client_trace
        terminal=verify_live_terminal(accounting,witness,
            original_host_kernels=host_kernels,client_trace=read_client_trace(output/"client.jsonl"),
            expected_client=load(output/"client-ready.json")["client"],start_id=start_id,
            launch_ns=authority["observed_ns"],dead_ns=dead)
        terminal["kind"]="complete-client-window"
        terminal['actual_final_route_query']=witness['live_route_query']
        require(accounting['schema']=='ecpa-h3-observer-live-recovery-accounting/v2',
                'live recovery cannot borrow original v1 accounting labels')
    if (
        fault is not None
        and (native or dead is not None)
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
        from experiments.formal_campaign.h3_observer_loss import verify_first_request_prefix
        source_client_prefix_validated=verify_first_request_prefix(
            output/"runner-pre-fault-client-prefix.bin",raw["client_barrier"],
            start_id=start_id,enrollment=bound["enrollment_sha256"],
            client_spec_path=output/"runtime-client-spec.json",
            expected_client=ready["client"],fault_ns=fault["triggered_ns"])
        measurements = verify_window(
            client_spec,
            output / "client.jsonl",
            Path(start["authority"]["journal"]),
            policy=policy,
            frozen_probe=original["probe"],
            expected_client=ready["client"],
            fault_ns=fault["triggered_ns"],
            recovery_ns=recovery["recovery_ns"] if recovery is not None else None,
            allow_incomplete=True,live_receipt=scope.receipt_ref(),
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
    measured_recovery=measurements['recovery_ns'] if measurements is not None else None
    recovery_ms=(measured_recovery-fault['triggered_ns'])/1e6 if measured_recovery is not None else None
    action_path=output/'live-operator-action.json'
    operator_actions=1 if action_path.exists() else 0
    declaration=scope.value()['declaration']['operator']
    if action_path.exists():
        action=load(action_path)
        require(declaration['kind']=='explicit-original-operator' and
            action['schema']=='ecpa-h3-actual-explicit-operator-action/v2' and
            action['command']==declaration['command'] and action['operator_actions']==1 and
            action['start_id']==start_id and
            action['original_deadline_ns']==fault['triggered_ns']+30_000_000_000,
            'actual original arm operator action/source/clock differs')
    if accounting is not None:
        require(accounting['operator_actions']==operator_actions and
            accounting['recovery_ns']==measured_recovery,
            'carrier operator/recovery summary differs from actual invocation/original delivery')
    objective_result = assess_original_objective(
        original["objective"],
        measurements,
        recovery_ms,
        operator_actions,
    )
    if not actual_fault["host_preserved_after_fault"] or (terminal is not None and
            terminal["host_preserved"] is False):
        objective_result["objective_met"]=False
        objective_result["known_objective_violations"].append("predecessor_or_Host_lost_after_observer_fault")
    if terminal is not None and terminal["summary_consistent"] is False:
        objective_result["objective_met"]=False
        objective_result["known_objective_violations"].append("terminal_preservation_summary_contradicts_actual_epochs")
    from experiments.formal_campaign.h3_observer_live_cleanup import (
        verify as verify_cleanup,context_for)
    from experiments.formal_campaign.h3_observer_cleanup import ordered_kernels
    actual_client=load(output/"client-ready.json")["client"]
    require(all(raw["client_kernel"][k]==v for k,v in actual_client.items()),
            "cleanup client epoch differs from original actual client")
    epochs={"authority":authority["kernel"],"carrier":adapter["kernel"],
            "host":host_kernels,"collector":bound["observer"],"client":raw["client_kernel"]}
    expected_context=context_for(spec_path,receipt_path,spec,start,scope)
    if terminal is None:
        from experiments.formal_campaign.h3_observer_loss import verify_independent_partial_terminal
        terminal=verify_independent_partial_terminal(load(output/"runner-terminal.json"),
            context=expected_context,epochs=epochs,fault=fault,dead_ns=dead,
            cleanup_started_ns=observations["cleanup_started_ns"])
    ownership=load(output/"runner-cleanup-ownership.json")
    owned=ordered_kernels(observations["cleanup_owned_kernels"])
    require(ownership["context"]==expected_context and ownership["run_epochs"]==epochs and
            observations["cleanup_run_epochs"]==epochs and ownership["owned_kernels"]==owned and
            terminal["terminal_ns"] <= observations["cleanup_started_ns"] <= ownership["captured_ns"],
            "cleanup full owned-kernel capture differs from actual start epochs")
    from urllib.parse import urlparse
    ports=[start["authority"]["public_port"],urlparse(runtime_recipe["authority"]["backend_endpoint"]).port]
    extra_epochs=[]
    successor_root=Path(scope.value()['declaration']['successor']['output'])
    descriptor_path=successor_root/'collector-descriptor.json'
    if descriptor_path.exists():
        descriptor=load(descriptor_path)
        extra_epochs.append({k:descriptor['collector'][k] for k in
            ('pid','start_ticks','session','boot_id')})
    if action_path.exists():
        action=load(action_path)
        require(action['operator_kernel'] is not None,
            'actual explicit operator kernel unknown; cleanup cannot invent ownership')
        extra_epochs.append(action['operator_kernel'])
    route_assessment=None
    if (output/'live-route-publication.json').exists():
        publication=load(output/'live-route-publication.json')
        enrolled_transports=[e for e in events if e['kind']=='observer.transport.enrolled']
        require(len(enrolled_transports)==1 and enrolled_transports[0]['detail']['transport']==publication['transport']
            and enrolled_transports[0]['monotonic_ns']<=publication['published_ns'],
            'independent publication differs from actual authority transport enrollment')
        require(descriptor_path.exists() and publication['transport']['successor_descriptor']==load(descriptor_path)
            and publication['transport']['live_receipt']==scope.receipt_ref(),
            'published continuation receiver differs from actual immutable successor descriptor')
        if accounting is not None:
            require(accounting['replacement_committed'] is True,
                'actual successor publication contradicts carrier commit summary')
    elif accounting is not None:
        require(accounting['replacement_committed'] is False,
            'carrier claims successor commit without actual source publication')
    if (output/'runner-live-route-observation.json').exists():
        from experiments.formal_campaign.h3_observer_live_observe import verify as verify_live_route
        require(descriptor_path.exists(),'independent route observation lacks actual successor descriptor')
        route_assessment=verify_live_route(load(output/'runner-live-route-observation.json'),
            load(output/'live-route-publication.json'),scope,authority_kernel=authority['kernel'],
            host_kernels=host_kernels,terminal_ns=terminal['terminal_ns'])
        require(route_assessment['successor_kernel'] in extra_epochs,
            'route observation successor differs from actual cleanup descriptor')
    cleanup=verify_cleanup(load(output/"runner-cleanup-before.json"),
        load(output/"runner-cleanup-after.json"),spec["observer_cleanup"],
        context=expected_context,run_epochs=epochs,owned_kernels=owned,ports=ports,
        scope=scope,recipe=runtime_recipe,extra_epochs=extra_epochs,
        clocks={"terminal_kind":terminal["kind"],
                "launch_ns":authority["observed_ns"],"fault_ns":fault["triggered_ns"],
                "dead_ns":dead,"client_stop_ns":terminal["client_stop_ns"],
                "terminal_ns":terminal["terminal_ns"],
                "cleanup_started_ns":observations["cleanup_started_ns"],
                "recorded_ns":observations["recorded_ns"]})
    if not all(cleanup.values()):
        objective_result["objective_met"]=False
        objective_result["known_objective_violations"].append("original_cleanup_failure_policy")
    if route_assessment is None:
        objective_result['unverified_obligations'].append('independent_actual_successor_route_observation')
    elif not route_assessment['host_preserved'] or not route_assessment['summary_consistent']:
        objective_result['objective_met']=False
        objective_result['known_objective_violations'].append('original_Host_lost_before_independent_successor_route_observation')
    if complete.exists() and (output/'live-route-publication.json').exists():
        actual_final=terminal['actual_final_route_query']['route']
        expected_transport=load(output/'live-route-publication.json')['transport']
        if actual_final['generation']!=expected_transport['generation'] or actual_final['snapshot']!={'transport_enrollment_sha256':expected_transport['sha256']}:
            objective_result['objective_met']=False
            objective_result['known_objective_violations'].append('successor_route_lost_by_original_client_stop')
    if measured_recovery is None:
        objective_result['unverified_obligations'].append('actual_original_client_successor_delivery_recovery')
    if delivery_error is not None:
        objective_result["unverified_obligations"].append("original_delivery_and_native_proof_verification_incomplete")
    formal_start_validated = bool(
        source_client_prefix_validated
        and fault is not None
        and (native or dead is not None)
        and "before" in phases
    )
    return {
        **objective_result,
        "formal_start_validated": formal_start_validated,
        "evidence_class": "source-admitted-observer-live-actual-fault/v2"
        if formal_start_validated
        else "prospective-unverified",
        "schema": "ecpa-h3-observer-live-start-observation/v2"
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
        "cleanup":cleanup,
        "observer_recovery_accounting":accounting,
        "independent_live_route_assessment":route_assessment,
        "live_receipt":scope.receipt_ref(),
        "recovery_ns":measured_recovery,
        "independent_terminal_assessment":terminal,
        "measurements": measurements,
        "delivery_error":delivery_error,
        "source_admission_basis":"source-registered-actual-observer-fault-plus-original-request-start",
        "partial_failed_start":not complete.exists(),
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


def verify_live_terminal(accounting,witness,*,original_host_kernels,client_trace,
                         expected_client,start_id,launch_ns,dead_ns):
    starts=[e for e in client_trace if e['kind']=='client.start']
    stops=[e for e in client_trace if e['kind']=='client.stop']
    require(len(original_host_kernels)==3 and len(starts)==len(stops)==1 and
        starts[0]['detail']['start_id']==start_id and all(e['client']==expected_client for e in client_trace),
        'v2 terminal original client/Host epochs differ')
    stop=stops[0]['monotonic_ns']
    require(launch_ns<=starts[0]['monotonic_ns']<=dead_ns<=stop and
        witness['client_stop_ns']==stop and stop<=accounting['observed_ns']<=witness['observed_ns'] and
        type(accounting['replacement_committed']) is bool and
        witness['replacement_committed']==accounting['replacement_committed'],
        'v2 terminal actual chained stop/commit accounting differs')
    carrier=accounting['host_kernels_at_client_stop']==original_host_kernels
    independent=witness['host_kernels']==original_host_kernels
    return {'host_preserved':carrier and independent,'summary_consistent':
        accounting['predecessor_alive_through_client_window'] is carrier and
        witness['host_preserved'] is independent,'client_stop_ns':stop,
        'terminal_ns':witness['observed_ns']}
