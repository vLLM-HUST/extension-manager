"""Independent raw conditional start replay. Missing coverage stays unknown.

No recorded malformed fact is downgraded to an incomplete run. A real admitted
failure is retained only with actual Popen admission and independent cleanup.
"""

from __future__ import annotations

import errno
import json
from pathlib import Path

from .conditional_common import canonical, checked, load, reference, require, sha

KEYS = ("pid", "start_ticks", "session", "boot_id")


def kernel(value):
    return {k: value[k] for k in KEYS}


def key(value):
    return tuple(value[k] for k in KEYS)


def verify_terminal_epoch(row, expected):
    require(
        kernel(row["original"]) == kernel(expected)
        and row["boot_raw"].strip() == expected["boot_id"],
        "terminal witness epoch/boot substituted",
    )
    require(
        type(row["observed_raw_ns"]) is int and row["observed_raw_ns"] > 0,
        "terminal witness clock absent",
    )
    raw = row["stat_raw"]
    if raw is None:
        require(
            row["missing_type"] in ("FileNotFoundError", "ProcessLookupError"),
            "unknown proc error cannot prove death",
        )
    else:
        fields = raw.rsplit(")", 1)[1].split()
        require(
            row["missing_type"] is None
            and int(raw.split(" ", 1)[0]) == expected["pid"]
            and (int(fields[19]) != expected["start_ticks"] or fields[0] == "Z"),
            "live exact kernel cannot be released",
        )


def verify_cleanup(
    ref,
    *,
    campaign_ref,
    launch_ref,
    inputs_ref,
    start,
    receipt_ref,
    admission,
    source_result,
):
    from .h4_npu_observation import decode_observation

    root = load(ref)
    run = Path(start["run_directory"])
    require(
        root["schema"] == "ecpa-h4-conditional-independent-root-terminal/v1"
        and root["released"] is True
        and root["run_directory"] == str(run)
        and root["start_id"] == start["start_id"]
        and root["phase"] == start["phase"]
        and root["campaign"] == campaign_ref
        and root["launch"] == launch_ref
        and root["inputs"] == inputs_ref
        and root["receipt"] == receipt_ref,
        "independent cleanup belongs to a different original start",
    )
    # Original selected source bytes, never caller-provided observer code.
    expected_source = (
        Path(load(start["phase"])["cwd"])
        / "experiments/formal_campaign/conditional_root_observer.py"
    )
    require(
        root["observer_source"] == reference(expected_source),
        "independent root observer source changed",
    )
    popen = load(root["runner_popen"])
    terminal = root["runner_terminal"]
    require(
        terminal["popen"] == root["runner_popen"]
        and terminal["wait_api"] == "subprocess.Popen.poll"
        and terminal["kernel"] == kernel(popen["kernel"]) == kernel(admission["runner"])
        and terminal["returncode"] == root["runner_exit_code"],
        "actual runner terminal/Popen epoch changed",
    )
    seen = {key(e): e for e in root["all_observed_epochs"]}
    require(
        len(seen) == len(root["all_observed_epochs"])
        and key(admission["owner"]) in seen
        and key(admission["runner"]) in seen
        and root["product_root"] == admission["owner"],
        "actual product/runner never independently observed",
    )
    live = []
    for line in checked(root["live_observations"]).splitlines():
        row = json.loads(line)
        live += row["members"]
    require(
        set(seen) == {key(e) for e in live} | {key(popen["kernel"])},
        "cleanup inventory differs from independent original observations",
    )
    prior = source_result["end_raw_ns"]
    for name in ("terminal_epochs", "terminal_epochs_after_npu"):
        witnesses = root[name]
        require(
            len(witnesses) == len(seen)
            and {key(w["original"]) for w in witnesses} == set(seen),
            "cleanup omits owned kernel",
        )
        for w in witnesses:
            verify_terminal_epoch(w, seen[key(w["original"])])
            require(
                prior <= w["observed_raw_ns"] <= root["terminal_raw_ns"],
                "cleanup outside original runner terminal span",
            )
    inputs = load(inputs_ref)
    require(
        set(root["open_ports"]) == {str(p) for p in inputs["allocated_tcp_ports"]},
        "registered port set changed",
    )
    for row in root["open_ports"].values():
        require(
            row["connect_ex"] == errno.ECONNREFUSED
            and prior <= row["observed_raw_ns"] <= root["terminal_raw_ns"],
            "port closure unknown/open or wrong clock",
        )
    smi = load(root["terminal_npu_observation"])
    raw, _ = decode_observation(smi)
    require(
        all(f"No running processes found in NPU {d}".encode() in raw for d in (0, 3))
        and prior <= smi["observed_monotonic_raw_ns"] <= root["terminal_raw_ns"],
        "actual independent NPU cleanup absent",
    )
    require(not root["remaining_observed_epochs"], "independent owned survivors remain")
    return root, dict(
        processes_reclaimed=True, ports_reclaimed=True, devices_reclaimed=True
    )


def lifecycle(raw, *, epoch, phase, model):
    from vllm_hust_ext.host_evidence import parse_host_event

    from .conditional_oracle import BATCH, GROUP, PREEMPT, SCHEMA

    configured = []
    unique = set()
    for line in raw.splitlines():
        event = parse_host_event(line)
        require(
            event["plan_id"] == epoch["plan_id"]
            and event["launch_id"] == epoch["launch_id"],
            "Host history Plan/launch changed",
        )
        if event["entry_point"]["group"] != GROUP:
            continue
        require(event["event_id"] not in unique, "duplicate conditional event")
        unique.add(event["event_id"])
        fact = json.loads(event["detail"])
        p = fact["payload"]
        require(
            fact["schema"] == SCHEMA and fact["action"] == "configured",
            "lifecycle mode emitted invocation facts",
        )
        require(
            event["process"] == epoch["roster"]["engine-core-scheduler/0"]
            and event["binding_status"] == "bound"
            and event["event"] == "resolved"
            and p["activation_route"] == phase["arm"],
            "configuration publisher/route changed",
        )
        require(
            p["batch_policy"] == p["batch_option"] == BATCH
            and p["preemption_policy"] == p["preemption_option"] == PREEMPT
            and p["batch_enabled"] is True
            and p["preemption_enabled"] is True
            and p["max_num_seqs"] == 1
            and p["model"] == model
            and p["pipeline_parallel_size"] == 2
            and p["tensor_parallel_size"] == 1,
            "actual distinct conditional controllers not configured",
        )
        config = p["batch_configuration"]
        require(
            config["pipeline_parallel_size"] == 2
            and config["tensor_parallel_size"] == 1
            and type(config["microbatch_count"]) is int
            and 1 < config["microbatch_count"] <= p["max_concurrent_batches"],
            "actual Pipeline condition false",
        )
        configured.append(fact)
    require(len(configured) <= 1, "duplicate actual controller configuration")
    return dict(
        actual_source_condition_observed=len(configured) == 1,
        sampled_accepted_coverage_complete=None,
        absent_dispatch_is_unknown=True,
        runtime_effectiveness_claim=False,
    )


def functional_window_complete(trace, health, oracle):
    return bool(
        trace is not None
        and trace["complete"]
        and health is not None
        and health["first_health"] is not None
        and (oracle is None or not oracle.get("functional_failures", []))
    )


def no_epoch_cause(source, root, root_ref, expected_argv, timing):
    """Original H4 exact typed runtime taxonomy; no generic nonzero promotion."""
    from .h4_sampled_intake import independent_runner_signal

    require(
        source["schema"] == "ecpa-h4-conditional-source-result/v1",
        "wrong conditional source taxonomy domain",
    )
    require(
        source.get("failure_category") != "unqualified-verification-error",
        "explicit schema/ABI/integrity failure remains unqualified",
    )
    require(
        all(e["stage"] == "runtime" for e in source["errors"]),
        "unqualified finalization errors cannot become formal failure",
    )
    signal = independent_runner_signal(root, root_ref, expected_argv)
    if source.get("failure_category") is None:
        require(
            source.get("failure") is None
            and source.get("runtime_interruption") is None
            and signal is not None,
            "missing or untyped no-epoch runtime cause remains unqualified",
        )
        return signal
    event = source.get("runtime_interruption")
    allowed = {
        "timeout": {"builtins.TimeoutError"},
        "connection": {
            "builtins.ConnectionError",
            "builtins.ConnectionRefusedError",
            "builtins.ConnectionResetError",
            "builtins.ConnectionAbortedError",
            "builtins.BrokenPipeError",
            "http.client.RemoteDisconnected",
        },
        "process-timeout": {"subprocess.TimeoutExpired"},
    }
    require(
        source["failure_category"] == "runtime-interruption"
        and isinstance(event, dict)
        and set(event)
        == {
            "schema",
            "family",
            "exception_type",
            "observed_monotonic_ns",
            "observed_raw_ns",
        }
        and event["schema"] == "ecpa-h4-source-runtime-interruption/v1"
        and event["family"] in allowed
        and event["exception_type"] in allowed[event["family"]]
        and len(source["errors"]) == 1
        and source["errors"][0]["type"] == event["exception_type"].rsplit(".", 1)[1]
        and isinstance(source["errors"][0].get("message"), str)
        and source["failure"]
        == source["errors"][0]["type"] + ": " + source["errors"][0]["message"]
        and isinstance(source.get("failure"), str)
        and bool(source["failure"])
        and all(
            type(v) is int
            for v in (
                event["observed_monotonic_ns"],
                event["observed_raw_ns"],
                source.get("failure_observed_monotonic_ns"),
                source.get("failure_observed_raw_ns"),
            )
        )
        and timing["before_monotonic_ns"]
        <= event["observed_monotonic_ns"]
        <= source["failure_observed_monotonic_ns"]
        and timing["after_ns"]
        <= event["observed_raw_ns"]
        <= source["failure_observed_raw_ns"]
        <= source["end_raw_ns"]
        <= root["terminal_raw_ns"],
        "no-epoch runtime interruption lacks exact original typed cause/clocks",
    )
    return dict(kind="source-observed-runtime-interruption", source=event)


def replay(
    campaign_ref,
    launch_ref,
    start_id,
    root_ref,
    *,
    receipt_ref=None,
    qualification=False,
):
    from .analyze import h4_request_payload
    from .conditional_registration import (
        recompute_start,
        validate_for_start,
        validate_inputs,
        verify_protocol,
    )
    from .conditional_request_trace import replay_trace

    if qualification:
        campaign, launch, workload, inputs = validate_inputs(
            campaign_ref, launch_ref, allow_used_paths=True
        )
        require(
            campaign["execution_domain"] == "unregistered-conditional-qualification",
            "qualification domain changed",
        )
        starts = [s for s in inputs["starts"] if s["start_id"] == start_id]
        require(len(starts) == 1, "unknown original start")
        start = starts[0]
        recompute_start(
            campaign,
            workload,
            inputs,
            start,
            fresh_source=False,
            require_qualified=False,
        )
    else:
        require(receipt_ref is not None, "actual distinct receipt required")
        rv = load(receipt_ref)
        require(
            rv["campaign"] == campaign_ref and rv["launch"] == launch_ref,
            "record receipt/campaign changed",
        )
        campaign, launch, workload, inputs, start, _ = validate_for_start(
            receipt_ref, start_id, fresh_source=False
        )
    phase = load(start["phase"])
    run = Path(start["run_directory"])
    verify_protocol(
        inputs, Path(phase["cwd"]), campaign["fixed_identity"]["manager_commit"]
    )
    admission = json.loads((run / "source-admission.json").read_bytes())
    source = json.loads((run / "conditional-source-result.json").read_bytes())
    require(
        admission["start_id"] == source["start_id"] == start_id
        and admission["campaign"] == campaign_ref
        and admission["receipt"] == receipt_ref
        and admission["phase"] == source["actual_phase"] == start["phase"]
        and admission["plan"] == source["actual_plan"] == start["plan"],
        "source admission original identity changed",
    )
    timing = json.loads((run / "phase0.product-popen-timing.json").read_bytes())
    require(
        timing["actual_kernel"] == admission["owner"]
        and 0 < timing["before_ns"] <= timing["after_ns"] <= source["end_raw_ns"],
        "actual product Popen clocks changed",
    )
    root, cleanup = verify_cleanup(
        root_ref,
        campaign_ref=campaign_ref,
        launch_ref=launch_ref,
        inputs_ref=campaign["conditional_inputs"],
        start=start,
        receipt_ref=receipt_ref,
        admission=admission,
        source_result=source,
    )

    # Independently observed terminal pinning is required for EVERY input read.
    def product(name, required=True):
        path = run / name
        if not path.exists():
            require(not required, "required original raw product absent: " + name)
            return None
        require(
            root["terminal_artifacts"].get(str(path)) == sha(path.read_bytes()),
            "terminal product changed or was not independently pinned: " + name,
        )
        return path.read_bytes()

    for name in (
        "source-admission.json",
        "conditional-source-result.json",
        "phase0.product-popen-timing.json",
    ):
        product(name)
    require(
        product("conditional-plan.json") == checked(start["plan"]),
        "actual original typed Plan changed",
    )
    material = json.loads(product("source-guard-material.json"))
    from .source_provenance import validate_observation

    validate_observation(
        material["observation"],
        campaign["source_provenance_policy"],
        campaign["fixed_identity"],
    )
    require(
        admission["material"] == reference(run / "source-guard-material.json")
        and material["plan_sha256"] == sha(checked(start["plan"]))
        and material["phase_sha256"] == start["phase"]["sha256"]
        and material["source"] == inputs["protocol_sources"],
        "actual guard/Plan/source material changed",
    )
    require(
        json.loads(product("actual-runtime-closure.json"))
        == material["runtime_closure"],
        "actual prelaunch whole source/wheel guard report changed",
    )
    epoch_raw = product("conditional-epoch.json", False)
    epoch = None if epoch_raw is None else json.loads(epoch_raw)
    trace_raw = product("requests.jsonl", False)
    trace = None
    health = None
    oracle = None
    resources = None
    cause = None
    if epoch is not None:
        require(
            epoch["owner"] == admission["owner"]
            and epoch["runner"] == admission["runner"]
            and epoch["phase"] == start["phase"]
            and epoch["plan_id"] == material["plan_id"].rsplit(":", 1)[-1],
            "actual Host epoch/Plan changed",
        )
        require(
            set(epoch["kernels"])
            == set(epoch["roster"])
            == {"api-server/0", "engine-core-scheduler/0", "worker/0", "worker/1"},
            "actual PP2TP1 roles missing",
        )
        require(
            len({key(k) for k in epoch["kernels"].values()}) == 4,
            "actual Host roles alias",
        )
        independently_seen = {key(e) for e in root["all_observed_epochs"]}
        for slot, k in epoch["kernels"].items():
            p = epoch["roster"][slot]
            require(
                key(k) in independently_seen
                and p["pid"] == k["pid"]
                and int(p["start_identity"].rsplit(":", 1)[1]) == k["start_ticks"]
                and p["assignment_source"] == "host",
                "Host publisher not exact independently observed kernel",
            )
        from .h4_sampled_health import verify_health

        for name in ("health-probes.jsonl", "health-probe-terminal.json"):
            product(name)
        health = verify_health(
            run,
            launch["health_url"],
            launch["startup_timeout_seconds"],
            timing,
            epoch=epoch,
            require_terminal=True,
        )
        if trace_raw is not None:
            body = h4_request_payload(workload, phase["served_model"])
            schedule = load(start["schedule"])
            trace = replay_trace(
                trace_raw,
                schedule,
                body,
                binding=dict(
                    start_id=start_id,
                    plan_id=epoch["plan_id"],
                    launch_id=epoch["launch_id"],
                ),
                allow_incomplete=True,
                served_model=phase["served_model"],
            )
            require(
                all(
                    timing["after_ns"] <= s["dispatch_ns"] <= source["end_raw_ns"]
                    for s in trace["started"].values()
                ),
                "request outside actual original product interval",
            )
            require(
                all(r["complete_ns"] <= source["end_raw_ns"] for r in trace["rows"]),
                "response after real source terminal",
            )
            host = product("final-Host.jsonl")
            if inputs["evidence_mode"] == "sampled-invocation":
                from .conditional_oracle import evaluate

                ctx = json.loads(product("selection-context.json"))
                require(
                    ctx["start_id"] == start_id
                    and ctx["authority_kernel"] == admission["runner"]
                    and ctx["uid"] == 0
                    and ctx["plan_id"] == epoch["plan_id"]
                    and ctx["launch_id"] == epoch["launch_id"]
                    and len(ctx["nonce"]) == 64
                    and all(c in "0123456789abcdef" for c in ctx["nonce"])
                    and len(ctx["socket_identity"]) == 2
                    and all(type(n) is int and n >= 0 for n in ctx["socket_identity"])
                    and ctx["socket_path"] == str(run / "selection.sock"),
                    "control context authority/socket/epoch from another start",
                )
                require(
                    ctx["kernels"]["api"] == epoch["kernels"]["api-server/0"]
                    and ctx["kernels"]["scheduler"]
                    == epoch["kernels"]["engine-core-scheduler/0"],
                    "control peers changed",
                )
                oracle = evaluate(
                    host,
                    plan_id=epoch["plan_id"],
                    launch_id=epoch["launch_id"],
                    api_process=epoch["roster"]["api-server/0"],
                    scheduler_process=epoch["roster"]["engine-core-scheduler/0"],
                    model=campaign["fixed_identity"]["model_path"],
                    pp=2,
                    tp=1,
                    request_rows=trace["rows"],
                    selected_request_ids=[
                        r["request_id"] for r in schedule if r["selected"]
                    ],
                    control_raw=product("selection-control.jsonl"),
                    control_context=ctx,
                    request_body=body,
                    served_model=phase["served_model"],
                    schedule=schedule,
                    started=trace["started"],
                    allow_incomplete=True,
                    expected_arm=start["arm"],
                    terminal_raw_ns=source["end_raw_ns"],
                )
            else:
                oracle = lifecycle(
                    host,
                    epoch=epoch,
                    phase=phase,
                    model=campaign["fixed_identity"]["model_path"],
                )
    else:
        expected_argv = [
            phase["python"],
            "-B",
            "-m",
            "experiments.formal_campaign.conditional_runtime",
            "--campaign",
            campaign_ref["path"],
            "--launch-spec",
            launch_ref["path"],
            "--start-id",
            start_id,
        ]
        expected_argv += (
            ["--qualification"] if qualification else ["--receipt", receipt_ref["path"]]
        )
        cause = no_epoch_cause(source, root, root_ref, expected_argv, timing)
        require(
            trace_raw is None,
            "client trace cannot precede actual authenticated Host epoch",
        )
        # A missing epoch is a genuine admitted failed start, never a positive
        # health/condition/measurement. Present malformed health/raw is retained
        # and cannot produce success through this path.
        for name in ("health-probes.jsonl", "health-probe-terminal.json"):
            product(name, False)
        from .h4_sampled_health import verify_health

        health = verify_health(
            run,
            launch["health_url"],
            launch["startup_timeout_seconds"],
            timing,
            epoch=None,
            require_terminal=False,
        )
        host = product("final-Host.jsonl", False)
        if host is not None:
            from vllm_hust_ext.host_evidence import parse_host_event

            native_launch = admission["native_launch_id"]
            handoff_raw = product("actual-Manager-native-handoff.json", False)
            if handoff_raw is not None:
                handoff = json.loads(handoff_raw)
                native_launch = handoff["environment"]["VLLM_ECPA_LAUNCH_ID"]
                require(
                    handoff["environment"]["VLLM_ECPA_PLAN_ID"]
                    == admission["native_plan_id"],
                    "partial Manager Plan differs",
                )
            require(
                not host.strip() or native_launch is not None,
                "partial Host history lacks actual native handoff identity",
            )
            known = {key(k) for k in root["all_observed_epochs"]}
            ids = set()
            for line in host.splitlines():
                event = parse_host_event(line)
                publisher = event["process"]
                require(
                    event["event_id"] not in ids
                    and event["plan_id"] == admission["native_plan_id"]
                    and event["launch_id"] == native_launch
                    and any(
                        k[0] == publisher["pid"]
                        and k[1] == int(publisher["start_identity"].rsplit(":", 1)[1])
                        for k in known
                    ),
                    "partial recorded native fact identity corrupted",
                )
                ids.add(event["event_id"])
    if health is not None and health["requires_authenticated_runtime_failure"]:
        from .h4_sampled_intake import bind_health_owner_exit

        require(
            cause is not None,
            "typed health interruption lacks authenticated original runtime cause",
        )
        bind_health_owner_exit(
            health, cause, root, dict(admission, after_ns=timing["after_ns"])
        )
    scope_raw = product("conditional-resource-scope.json", False)
    if scope_raw is not None:
        scope = json.loads(scope_raw)
        require(
            scope["runner_root"] == admission["runner"],
            "resource accounting root substituted",
        )
        from .h4_owned_resources import verify_archive

        product("owned-resources.json")
        verify_archive(
            run / "owned-resources.json", admission["runner"], scope["resources"]
        )
        resources = scope["resources"]
    actual_input = json.loads(product("actual-input-audit.json"))
    # Original input auditor and original tokenizer replay are source-owned;
    # their immutable report is cross-joined below, never caller support status.
    from .conditional_input_audit import OWNERSHIP_PATH, OWNERSHIP_SHA

    require(
        actual_input["schema"] == "ecpa-h4-conditional-full-input-audit/v1"
        and actual_input["original_guard"]
        == dict(path=str(OWNERSHIP_PATH), sha256=OWNERSHIP_SHA)
        and sha(OWNERSHIP_PATH.read_bytes()) == OWNERSHIP_SHA
        and len(actual_input["model_files"]) == 14
        and "sha256:" + sha(canonical(actual_input["model_files"]))
        == campaign["fixed_identity"]["model_digest"],
        "actual model14/ownership guard changed",
    )
    token = json.loads(product("actual-tokenizer.json"))
    command = json.loads(product("actual-tokenizer-command.json"))
    require(
        actual_input["actual_tokenizer"] == reference(run / "actual-tokenizer.json")
        and command["returncode"] == 0
        and command["argv"]
        == [
            phase["python"],
            "-B",
            "-m",
            "experiments.formal_campaign.h4_sampled_calibration",
            "--tokenizer-worker",
        ]
        and command["input"]["payload"]
        == json.loads(h4_request_payload(workload, phase["served_model"]))
        and token["request_sha256"] == sha(canonical(command["input"]["payload"]))
        and token["prompt_token_count"] == len(token["input_ids"]) == 1195
        and token["input_ids_sha256"]
        == sha(canonical(token["input_ids"]))
        == inputs["prompt_input_ids_sha256"]
        and product("actual-tokenizer.stdout") == canonical(token) + b"\n",
        "actual original Host parser/tokenizer proof changed",
    )
    product("actual-tokenizer.stderr")
    functional = functional_window_complete(trace, health, oracle)
    configured = (
        oracle is not None and oracle["actual_source_condition_observed"] is True
    )
    effects = (
        oracle is not None and oracle.get("sampled_accepted_coverage_complete") is True
    )
    complete = (
        functional
        and configured
        and (inputs["evidence_mode"] == "lifecycle-only" or effects)
        and not source["errors"]
        and not source["transport_errors"]
        and resources is not None
    )
    return dict(
        schema="ecpa-h4-conditional-independent-start-observation/v1",
        start_id=start_id,
        cell_id=campaign["cell_id"],
        arm=start["arm"],
        repetition=start["repetition"],
        arm_order=start["arm_order"],
        formal_start_validated=not qualification,
        configured_and_functional_supported=functional
        and configured
        and not source["errors"]
        and not source["transport_errors"],
        effect_coverage=oracle,
        cleanup=cleanup,
        resources=resources,
        startup_readiness=health,
        trace=trace,
        status="complete" if complete else "failed",
        performance_eligible=complete,
        coverage="complete-observed" if complete else "unknown-or-failed",
        source_errors=source["errors"],
        authenticated_runtime_cause=cause,
        phase_bins=None,
        phase_bins_status="unobserved; no zero substitution",
        independent_root_cleanup=root_ref,
        formal_result=False,
        H4_hypothesis_claim=False,
    )


def replay_qualification(value):
    require(
        value["products"]["source-admission.json"]["path"]
        == str(Path(value["run_directory"]) / "source-admission.json"),
        "qualification product run changed",
    )
    result = replay(
        value["campaign"],
        value["launch"],
        value["start_id"],
        value["root_cleanup"],
        qualification=True,
    )
    for name, ref in value["products"].items():
        require(
            ref == reference(Path(value["run_directory"]) / name),
            "qualification product bytes changed",
        )
    return result
