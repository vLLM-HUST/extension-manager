"""Prospective actual-input assembler; execution performs original full guards.

Input contains REAL fresh five-source reports, official wheel/installed proofs,
full8 ownership declarations, model14, and tokenizer1195 identity. No ready flag
or draft SHA can authorize source admission. No staging or device operations.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

from .conditional_common import (
    ARMS,
    CELLS,
    IDS,
    checked,
    load,
    mode,
    private_directory,
    protocol_sources,
    reference,
    require,
    sha,
    write,
)
from .qualify_conditional import request_schedule


def qualified_config(base_ref, qualification_ref, *, fixed, workload, bundles):
    from .conditional_qualification import validate_report

    validate_report(qualification_ref, expected_fixed=fixed, expected_workload=workload)
    value = load(base_ref)
    require(
        set(value["extensions"]) == IDS,
        "exact new actual policy pair configuration required",
    )
    for bundle in bundles:
        extension = value["extensions"][bundle.bundle_id]
        require(
            extension["enabled"] is True
            and "runtime_qualification" not in extension["configuration"],
            "caller runtime qualification forbidden",
        )
        profile = dict(bundle.manifest.activation.additional_config)[
            "_manager_runtime_qualification"
        ]
        require(
            profile["host_commit"] == fixed["host_commit"]
            and profile["model"] == fixed["model_path"]
            and profile["pipeline_parallel_size"] == 2
            and profile["tensor_parallel_size"] == 1
            and profile["max_num_seqs"] == 1,
            "actual new declared profile differs",
        )
        # This is a derived original Provider input, not an acceptance predicate.
        # Every formal issuer/start also independently replays qualification_ref.
        extension["configuration"]["runtime_qualification"] = dict(
            profile, status="passed"
        )
    return value


def assemble(actual_ref, output, cell, *, qualification_ref=None):
    from vllm_hust_ext.cli import _activation_environment
    from vllm_hust_ext.config import load_config
    from vllm_hust_ext.core import plan_for
    from vllm_hust_ext.discovery import discover_bundles

    from . import h4_registration, source_provenance
    from .analyze import load_protocol
    from .conditional_binding import host_command
    from .conditional_plan import compile_actual

    require(cell in CELLS, "one genuine original conditional cell required")
    require(
        qualification_ref is not None or cell.endswith(".sampled-invocation"),
        (
            "real new-tuple bootstrap uses sampled mode; its "
            "configured/functional report can precede either original cell"
        ),
    )
    actual = load(actual_ref)
    import jsonschema

    jsonschema.Draft7Validator(
        json.loads(
            Path(__file__)
            .with_name("conditional-actual-inputs.schema.json")
            .read_bytes()
        )
    ).validate(actual)
    require(
        actual["schema"] == "ecpa-h4-conditional-actual-build-inputs/v1",
        "actual future build input required",
    )
    require(
        {
            "manager_commit",
            "host_commit",
            "accelerator_commit",
            "host_version",
            "accelerator_version",
            "model_path",
            "model_digest",
            "topology",
            "hardware",
            "warm_state",
        }
        <= set(actual["fixed_identity"]),
        "actual complete new fixed identity required",
    )
    require(
        set(actual["fixed_identity"]["plugins"]) == IDS
        and set(actual["repositories"])
        == {"manager", "host", "accelerator", *("plugin:" + i for i in IDS)},
        "actual distinct new five-source tuple required",
    )
    sdk = Path(actual["repositories"]["manager"]["path"])
    require(
        Path(__file__).resolve().parent == sdk / "experiments/formal_campaign",
        "assembler is not actual published selected source",
    )
    require(
        sys.executable == actual["python"] and Path.cwd() == sdk,
        "actual new private interpreter/selected SDK required",
    )
    # Original remote observations are performed here, then issuer and every
    # actual slot perform their own original guards. No observation reuse flag.
    source_provenance.observe_sources(
        actual["fixed_identity"],
        actual["source_provenance_policy"],
        actual["repositories"],
    )
    for ref in actual["build_and_installed_proofs"].values():
        checked(ref)
    require(
        set(actual["build_and_installed_proofs"])
        == {"manager", "host", "accelerator", *("plugin:" + i for i in IDS)},
        "new official build+fresh installed evidence required for all five",
    )
    output = private_directory(output)
    (output / "inputs").mkdir(mode=0o700)
    workload_raw = checked(actual["original_workload"])
    workload = json.loads(workload_raw)
    protocol = load_protocol()
    require(
        workload["max_tokens"] == 64
        and workload["warmup_requests"] == 16
        and workload["measured_requests"] == 256
        and workload["concurrency"] == 8
        and workload["request_timeout_seconds"] == 120,
        "original workload changed",
    )
    write(output / "inputs/workload.json", workload_raw)
    bundles = discover_bundles(tuple(sorted(IDS)))
    config_ref = actual["unqualified_manager_config"]
    load(config_ref)
    if qualification_ref is not None:
        config_ref = write(
            output / "qualified-manager-config.json",
            qualified_config(
                config_ref,
                qualification_ref,
                fixed=actual["fixed_identity"],
                workload=workload,
                bundles=bundles,
            ),
        )
    configuration = load_config(Path(config_ref["path"]))
    require(set(configuration.enabled) == IDS, "actual pair not enabled")
    env = load(actual["environment"])
    require(
        all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()),
        "exact real environment required",
    )
    for key in (
        "VLLM_ECPA_PLAN_ID",
        "VLLM_ECPA_LAUNCH_ID",
        "VLLM_ECPA_EVIDENCE_SINK",
        "VLLM_ECPA_EVIDENCE_STRICT",
        "VLLM_HUST_EXT_EVIDENCE_PATH",
        "ECPA_H4_SOURCE_OWNED_PAIR",
        "ECPA_ACTIVATION_PROFILE_PATH",
        "ECPA_ACTIVATION_CONTRACT",
    ):
        require(key not in env, "old/foreign native activation authority forbidden")
    require(
        env.get("ASCEND_RT_VISIBLE_DEVICES") == "0,1",
        "actual two-card runtime mapping differs",
    )
    env.update(
        _activation_environment(
            bundles,
            tuple(plan_for(b, configuration.extension(b.bundle_id)) for b in bundles),
        )
    )
    env["VLLM_HUST_EXT_CONFIG"] = config_ref["path"]
    # Host and model arguments come from future actual configuration, not a
    # prior KV/profiler launcher. Every fixed dimension is independently checked.
    base = [
        actual["python"],
        "-m",
        "vllm.entrypoints.cli.main",
        "serve",
        actual["fixed_identity"]["model_path"],
        "--host",
        "127.0.0.1",
        "--port",
        str(actual["port"]),
        "--served-model-name",
        actual["served_model"],
        "--pipeline-parallel-size",
        "2",
        "--tensor-parallel-size",
        "1",
        "--data-parallel-size",
        "1",
        "--max-num-seqs",
        "1",
        "--max-model-len",
        "2048",
        "--enforce-eager",
        "--disable-ecpa-manager",
        "--enable-entrypoints",
    ]
    argv = host_command(base, bundles, configuration)
    execution = (
        "registered-original-starts"
        if qualification_ref is not None
        else "unregistered-conditional-qualification"
    )
    starts = []
    launch_arms = {}
    run_parent = Path(
        actual["qualification_run_root"]
        if qualification_ref is None
        else actual["formal_run_root"]
    )
    require(
        run_parent.is_dir() and run_parent.resolve() == run_parent,
        "actual short private run parent required",
    )
    run_root = private_directory(
        run_parent
        / (
            "q"
            if qualification_ref is None
            else "l"
            if cell.endswith(".lifecycle-only")
            else "s"
        )
    )
    require(
        run_root.is_absolute() and run_root.resolve() == run_root and run_root.is_dir(),
        "root must supply an actual fresh short run parent",
    )
    for repetition, order in enumerate(protocol["schedule"], 1):
        for arm_order, arm in enumerate(order, 1):
            sid = (
                "unregistered-conditional-" if qualification_ref is None else ""
            ) + f"{cell}-r{repetition}-{arm}"
            run = run_root / f"{repetition}{arm_order}"
            require(not run.exists(), "original output already used; no retries")
            phase_env = dict(
                env,
                ECPA_H4_CONDITIONAL_EVIDENCE="1",
                ECPA_H4_CONDITIONAL_MODE=mode(cell),
                ECPA_H4_CONDITIONAL_ACTIVATION=arm,
                ECPA_H4_RUN_DIRECTORY=str(run),
            )
            if mode(cell) == "sampled-invocation":
                phase_env["ECPA_H4_CONDITIONAL_SELECTION_CONTEXT"] = str(
                    run / "selection-context.json"
                )
            phase = dict(
                arm=arm,
                evidence_mode=mode(cell),
                environment=phase_env,
                host_argv=argv,
                cwd=str(sdk),
                python=actual["python"],
                served_model=actual["served_model"],
                manager_config=config_ref,
                execution_domain=execution,
            )
            phase_ref = write(output / f"phase-{repetition}{arm_order}.json", phase)
            schedule = request_schedule(sid)
            schedule_ref = write(
                output / f"schedule-{repetition}{arm_order}.json", schedule
            )
            plan, raw = compile_actual(
                dict(argv=argv, cwd=str(sdk), environment=phase_env),
                bundles,
                configuration,
                schedule,
            )
            plan_ref = write(output / f"plan-{repetition}{arm_order}.json", raw)
            starts.append(
                dict(
                    start_id=sid,
                    arm=arm,
                    repetition=repetition,
                    arm_order=arm_order,
                    run_directory=str(run),
                    phase=phase_ref,
                    schedule=schedule_ref,
                    plan=plan_ref,
                )
            )
            # Original issuer freezes real Host/provider semantics for each arm;
            # exact per-slot wrapper/env is additionally bound by conditional refs.
            if arm not in launch_arms:
                launch_arms[arm] = dict(
                    server_command=argv,
                    environment=phase_env,
                    phase_commands={},
                    evidence_paths=[],
                    served_model=actual["served_model"],
                )
    inputs = dict(
        schema="ecpa-h4-conditional-original-inputs/v1",
        evidence_mode=mode(cell),
        topology=dict(pp=2, tp=1, dp=1, world_size=2),
        allocated_devices=[0, 3],
        allocated_tcp_ports=[actual["port"]],
        starts=starts,
        repositories=actual["repositories"],
        runtime_wheels=actual["runtime_wheels"],
        whole_runtime_payloads=actual["whole_runtime_payloads"],
        model_files=actual["model_files"],
        prompt_input_ids_sha256=actual["prompt_input_ids_sha256"],
        protocol_sources=protocol_sources(sdk),
        qualification=qualification_ref,
        actual_build_inputs=actual_ref,
    )
    inputs_ref = write(output / "conditional-inputs.json", inputs)
    fixed = copy.deepcopy(actual["fixed_identity"])
    require(
        fixed["topology"] == actual["fixed_identity"]["topology"]
        and "PP2" in fixed["topology"]
        and "TP1" in fixed["topology"],
        "new fixed PP2TP1 identity must be explicit",
    )
    campaign = dict(
        schema="ecpa-h4-minimal-matched-cell-campaign/v1",
        campaign_id=protocol["h4"]["campaign_id"],
        cell_id=cell,
        arms=[dict(id=a, manager_used=a == "ecpa") for a in ARMS],
        fixed_identity=fixed,
        workload=dict(
            path="inputs/workload.json", sha256="sha256:" + sha(workload_raw)
        ),
        planned_starts=9,
        schedule=[
            dict(repetition=i, order=o) for i, o in enumerate(protocol["schedule"], 1)
        ],
        formal_h4_result=False,
        performance_result=False,
        score_eligible=False,
        conditional_inputs=inputs_ref,
        execution_domain=execution,
        source_provenance_policy=actual["source_provenance_policy"],
        protocol_binding=dict(
            manager_commit=fixed["manager_commit"],
            **{
                label: "sha256:" + sha((sdk / relative).read_bytes())
                for label, relative in h4_registration.PROTOCOL_FILES.items()
            },
        ),
    )
    campaign_ref = write(output / "campaign.json", campaign)
    launch = dict(
        schema="ecpa-h4-launch-spec/v1",
        arms=launch_arms,
        health_url=f"http://127.0.0.1:{actual['port']}/health",
        endpoint_url=f"http://127.0.0.1:{actual['port']}/v1/completions",
        host="127.0.0.1",
        port=actual["port"],
        startup_timeout_seconds=900,
        container_digest=actual["container_digest"],
        device_cleanup_command=[
            actual["python"],
            "-B",
            "-m",
            "experiments.formal_campaign.h4_npu_observation",
            "cleanup",
        ],
        npu_memory_command=[
            actual["python"],
            "-B",
            "-m",
            "experiments.formal_campaign.h4_npu_observation",
            "memory",
        ],
    )
    launch_ref = write(output / "launch-spec.json", launch)
    from .conditional_registration import validate_inputs

    validate_inputs(campaign_ref, launch_ref)
    first = next(s for s in starts if s["arm"] == ARMS[0])
    first_phase = load(first["phase"])
    environment_ref = write(
        output / "qualification-environment.json", first_phase["environment"]
    )
    observer_output = output / "qualification-root"
    frozen = output / "actual-qualification.json"
    write(
        output / "commands.json",
        dict(
            schema="ecpa-h4-conditional-real-next-commands/v1",
            execution_domain=execution,
            campaign=campaign_ref,
            launch=launch_ref,
            qualification=qualification_ref,
            # These are exact real CLI entrypoints, never evaluated by assembly.
            issue=[
                actual["python"],
                "-B",
                "-m",
                "experiments.formal_campaign.conditional_registration",
                "--campaign",
                campaign_ref["path"],
                "--launch-spec",
                launch_ref["path"],
                "--output",
                str(output / "receipt.json"),
            ],
            run_nine=[
                actual["python"],
                "-B",
                "-m",
                "experiments.formal_campaign.conditional_queue",
                "--receipt",
                str(output / "receipt.json"),
                "--output",
                str(output / "nine"),
                "--artifact-root",
                "/",
            ],
            qualification_start=first["start_id"],
            observe_qualification=[
                actual["python"],
                "-B",
                "-m",
                "experiments.formal_campaign.conditional_root_observer",
                "--campaign",
                campaign_ref["path"],
                "--launch-spec",
                launch_ref["path"],
                "--start-id",
                first["start_id"],
                "--qualification",
                "--python",
                actual["python"],
                "--sdk",
                str(sdk),
                "--environment",
                environment_ref["path"],
                "--output",
                str(observer_output),
            ],
            freeze_qualification=[
                actual["python"],
                "-B",
                "-m",
                "experiments.formal_campaign.conditional_qualification",
                "--campaign",
                campaign_ref["path"],
                "--launch-spec",
                launch_ref["path"],
                "--start-id",
                first["start_id"],
                "--run",
                first["run_directory"],
                "--root-cleanup",
                str(observer_output / "independent-root-terminal.json"),
                "--output",
                str(frozen),
            ],
            formal_result=False,
        ),
    )
    return campaign_ref, launch_ref


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--actual-inputs", type=Path, required=True)
    p.add_argument("--actual-inputs-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--cell", choices=sorted(CELLS), required=True)
    p.add_argument("--qualification", type=Path)
    a = p.parse_args()
    assemble(
        dict(path=str(a.actual_inputs.resolve()), sha256=a.actual_inputs_sha256),
        a.output,
        a.cell,
        qualification_ref=None
        if a.qualification is None
        else reference(a.qualification),
    )


if __name__ == "__main__":
    main()
