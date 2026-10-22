"""Actual additive original conditional H4 admission; no simulation/ready flag.

The legacy H4 merged-source receipt is issued first only after independently
replayed new tuple qualification and all declared static conditional inputs.
A distinct source-owned conditional receipt binds that real base receipt. Root
must execute this source to issue anything; source/AST review issues no receipt.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from .conditional_common import (
    CELLS,
    IDS,
    canonical,
    checked,
    load,
    mode,
    protocol_sources,
    reference,
    require,
    sha,
    write,
)


def activation_semantics(phase):
    """Only original per-slot ownership/route fields may differ across arms."""
    return dict(
        python=phase["python"],
        cwd=phase["cwd"],
        served_model=phase["served_model"],
        host_argv=phase["host_argv"],
        manager_config=phase["manager_config"],
        environment={
            k: v
            for k, v in phase["environment"].items()
            if k
            not in (
                "ECPA_H4_CONDITIONAL_ACTIVATION",
                "ECPA_H4_RUN_DIRECTORY",
                "ECPA_H4_CONDITIONAL_SELECTION_CONTEXT",
            )
        },
    )


def require_same_activation(left, right):
    require(
        canonical(activation_semantics(left)) == canonical(activation_semantics(right)),
        (
            "original three arms must share exact policy configuration/Host "
            "argv/runtime environment"
        ),
    )


def validate_inputs(campaign_ref, launch_ref, *, allow_used_paths=False):
    from . import h4_registration

    campaign = load(campaign_ref)
    launch = load(launch_ref)
    workload = json.loads(
        h4_registration.validate_campaign(campaign, Path(campaign_ref["path"]))
    )
    h4_registration.validate_launch_spec(launch)
    require(
        campaign["cell_id"] in CELLS
        and set(campaign["fixed_identity"]["plugins"]) == IDS,
        "genuine original conditional cell required",
    )
    require(
        [
            workload[k]
            for k in (
                "max_tokens",
                "warmup_requests",
                "measured_requests",
                "concurrency",
                "request_timeout_seconds",
            )
        ]
        == [64, 16, 256, 8, 120]
        and workload["min_successful_measured_requests"] == 256,
        "original workload constants changed",
    )
    inputs = load(campaign["conditional_inputs"])
    require(
        inputs["schema"] == "ecpa-h4-conditional-original-inputs/v1"
        and inputs["evidence_mode"] == mode(campaign["cell_id"]),
        "wrong conditional schema/mode",
    )
    require(
        inputs["topology"] == dict(pp=2, tp=1, dp=1, world_size=2)
        and inputs["allocated_devices"] == [0, 3],
        "fresh fixed PP2TP1 two-card subject required",
    )
    require(len(inputs["starts"]) == 9, "all original nine required")
    expected = [
        (r, o, arm)
        for r, row in enumerate(campaign["schedule"], 1)
        for o, arm in enumerate(row["order"], 1)
    ]
    require(
        [(s["repetition"], s["arm_order"], s["arm"]) for s in inputs["starts"]]
        == expected,
        "original Latin9 order differs",
    )
    seen, roots = set(), set()
    first_phase = None
    for start in inputs["starts"]:
        require(
            start["start_id"]
            == (
                "unregistered-conditional-"
                if campaign.get("execution_domain")
                == "unregistered-conditional-qualification"
                else ""
            )
            + f"{campaign['cell_id']}-r{start['repetition']}-{start['arm']}"
            and start["start_id"] not in seen,
            "original start ID changed/reused",
        )
        seen.add(start["start_id"])
        phase = load(start["phase"])
        root = Path(start["run_directory"])
        require(
            root.is_absolute() and root.resolve() == root and str(root) not in roots,
            "actual independent private run root required",
        )
        roots.add(str(root))
        require(
            allow_used_paths or not root.exists(),
            "original output already exists; no retry",
        )
        require(
            phase["arm"] == start["arm"]
            and phase["evidence_mode"] == inputs["evidence_mode"]
            and phase["execution_domain"] == campaign["execution_domain"],
            "actual phase/arm/mode/domain differs",
        )
        require(
            not {
                "VLLM_ECPA_PLAN_ID",
                "VLLM_ECPA_LAUNCH_ID",
                "VLLM_ECPA_EVIDENCE_SINK",
                "VLLM_ECPA_EVIDENCE_STRICT",
                "VLLM_HUST_EXT_EVIDENCE_PATH",
            }
            & phase["environment"].keys(),
            "actual source-owned launcher alone owns native evidence environment",
        )
        expected_context = (
            str(root / "selection-context.json")
            if inputs["evidence_mode"] == "sampled-invocation"
            else None
        )
        require(
            phase["environment"].get("ECPA_H4_CONDITIONAL_SELECTION_CONTEXT")
            == expected_context,
            "source-side selection context differs from actual original run",
        )
        if first_phase is None:
            first_phase = phase
        else:
            require_same_activation(first_phase, phase)
        require(
            phase["host_argv"][4] == campaign["fixed_identity"]["model_path"]
            and phase["served_model"] == launch["arms"][start["arm"]]["served_model"],
            "actual Host/workload model differs from registered original model",
        )
        require(
            phase["environment"]["ECPA_H4_CONDITIONAL_MODE"] == inputs["evidence_mode"]
            and phase["environment"]["ECPA_H4_CONDITIONAL_EVIDENCE"] == "1",
            "source-side mode missing",
        )
        require(
            phase["environment"].get("ECPA_H4_SOURCE_OWNED_PAIR") != "1",
            "unconditional KV/profiler adapter forbidden",
        )
        require(
            phase["environment"]["ECPA_H4_RUN_DIRECTORY"] == str(root),
            "source-owned exact run path differs",
        )
        from .qualify_conditional import request_schedule

        schedule = load(start["schedule"])
        require(
            schedule == request_schedule(start["start_id"]),
            "original272/32 exact schedule changed",
        )
        require(
            len(str(root / "selection.sock").encode()) <= 107
            and len(str(root / "manager.sock").encode()) <= 107,
            "actual Unix socket bound",
        )
    campaign["_sha256"] = "sha256:" + sha(checked(campaign_ref))
    return campaign, launch, workload, inputs


def verify_protocol(inputs, sdk, commit):
    current = protocol_sources(sdk)
    require(
        inputs["protocol_sources"] == current,
        "conditional source-owned protocol inventory changed",
    )
    for relative, ref in current.items():
        raw = subprocess.check_output(
            ["git", "-C", str(sdk), "show", commit + ":" + relative]
        )
        require(
            raw == checked(ref),
            "conditional protocol file not exact published selected source",
        )


def recompute_start(
    campaign, workload, inputs, start, *, fresh_source=True, require_qualified=True
):
    from vllm_hust_ext.config import load_config
    from vllm_hust_ext.discovery import discover_bundles

    from . import source_provenance
    from .conditional_plan import compile_actual

    phase = load(start["phase"])
    if fresh_source:
        observation = source_provenance.observe_sources(
            campaign["fixed_identity"],
            campaign["source_provenance_policy"],
            inputs["repositories"],
        )
    else:
        observation = None
    sdk = Path(inputs["repositories"]["manager"]["path"])
    verify_protocol(inputs, sdk, campaign["fixed_identity"]["manager_commit"])
    # Fresh full runtime/whole-wheel guards remain inside the original readers;
    # qualification report/Plan/static refs are independently replayed too.
    from .h3_runtime_source_closure import verify_runtime_source_closure

    closure = verify_runtime_source_closure(
        dict(
            argv=phase["host_argv"], cwd=phase["cwd"], environment=phase["environment"]
        ),
        campaign["fixed_identity"],
        inputs["repositories"],
        inputs["runtime_wheels"],
    )
    if require_qualified:
        from .conditional_qualification import validate_report

        qualification = validate_report(
            inputs["qualification"],
            expected_fixed=campaign["fixed_identity"],
            expected_workload=workload,
        )
    else:
        qualification = None
    from importlib.metadata import version

    require(
        campaign["fixed_identity"]["host_version"] == version("vllm")
        and campaign["fixed_identity"]["accelerator_version"] == version("vllm-ascend"),
        "fixed reported actual Host/accelerator versions differ",
    )
    bundles = discover_bundles(tuple(sorted(IDS)))
    for bundle in bundles:
        subject = campaign["fixed_identity"]["plugins"][bundle.bundle_id]
        wheel = inputs["runtime_wheels"]["plugin:" + bundle.bundle_id]["wheel"]
        require(
            subject["version"] == bundle.manifest.bundle_version
            and subject["wheel_sha256"].removeprefix("sha256:")
            == wheel["sha256"].removeprefix("sha256:"),
            "fixed actual plugin version/wheel differs",
        )
    configuration = load_config(Path(phase["manager_config"]["path"]))
    checked(phase["manager_config"])
    require(set(configuration.enabled) == IDS, "actual two policies required")
    if not require_qualified:
        from .h4_conditional_provider_qualification import prepare_unregistered

        prepare_unregistered(
            phase=dict(
                argv=phase["host_argv"],
                cwd=phase["cwd"],
                environment=phase["environment"],
            ),
            fixed=campaign["fixed_identity"],
            repositories=inputs["repositories"],
            runtime_wheels=inputs["runtime_wheels"],
            bundles=bundles,
            configuration=configuration,
        )

    plan, raw = compile_actual(
        dict(
            argv=phase["host_argv"], cwd=phase["cwd"], environment=phase["environment"]
        ),
        bundles,
        configuration,
        load(start["schedule"]),
    )
    require(
        raw == checked(start["plan"]),
        "independent actual typed Plan differs from registered bytes",
    )
    from .conditional_activation import validate_equivalent_activation

    validate_equivalent_activation(phase, bundles, configuration)
    return dict(
        observation=observation,
        runtime_closure=closure,
        qualification=qualification,
        plan_id=plan.plan_id,
        plan_sha256=sha(raw),
        phase_sha256=start["phase"]["sha256"],
        source=inputs["protocol_sources"],
    )


def issue(campaign_ref, launch_ref, output):
    from . import h4_registration, source_provenance

    campaign, launch, workload, inputs = validate_inputs(campaign_ref, launch_ref)
    require(
        campaign.get("execution_domain") == "registered-original-starts",
        "qualification namespace cannot issue original formal receipt",
    )
    require(not Path(output).exists(), "fresh distinct conditional receipt required")
    # Original full canonical predicates on actual five repositories.
    observation = source_provenance.observe_sources(
        campaign["fixed_identity"],
        campaign["source_provenance_policy"],
        inputs["repositories"],
    )
    materials = [
        recompute_start(campaign, workload, inputs, start, fresh_source=False)
        for start in inputs["starts"]
    ]
    manager = inputs["repositories"]["manager"]
    host = inputs["repositories"]["host"]
    ms = h4_registration.observe_merged_source(
        Path(manager["path"]),
        manager["remote"],
        "vLLM-HUST/extension-manager",
        campaign["fixed_identity"]["manager_commit"],
    )
    hs = h4_registration.observe_merged_source(
        Path(host["path"]),
        host["remote"],
        "vLLM-HUST/vllm-hust",
        campaign["fixed_identity"]["host_commit"],
    )
    base = h4_registration.build_receipt(
        campaign_raw=checked(campaign_ref),
        campaign_path=Path(campaign_ref["path"]),
        launch_raw=checked(launch_ref),
        manager_repo=Path(manager["path"]),
        manager_source=ms,
        host_source=hs,
    )
    base = source_provenance.upgrade_receipt(
        base,
        campaign,
        observation,
        source_provenance.bind_protocol_source(
            Path(manager["path"]), campaign["fixed_identity"]["manager_commit"], "h4"
        ),
    )
    # No file exists before ALL real predicates above accept.
    base_path = Path(str(output) + ".original-h4.json")
    h4_registration.atomic_write_new(base_path, base)
    value = dict(
        schema="ecpa-h4-conditional-deployment-receipt/v1",
        original_registration=reference(base_path),
        campaign=campaign_ref,
        launch=launch_ref,
        conditional_inputs=campaign["conditional_inputs"],
        source_observation=observation,
        starts=[
            dict(start_id=s["start_id"], material=m)
            for s, m in zip(inputs["starts"], materials, strict=True)
        ],
        registration_state="registered",
        admissible=True,
        evidence_mode=inputs["evidence_mode"],
        qualification=inputs["qualification"],
    )
    write(Path(output), value)
    return value


def validate_receipt_static(value, campaign, inputs):
    from vllm_hust_ext.plan_artifact import parse_plan_artifact

    from .source_provenance import validate_observation

    require(
        set(value)
        == {
            "schema",
            "original_registration",
            "campaign",
            "launch",
            "conditional_inputs",
            "source_observation",
            "starts",
            "registration_state",
            "admissible",
            "evidence_mode",
            "qualification",
        }
        and value["schema"] == "ecpa-h4-conditional-deployment-receipt/v1"
        and value["registration_state"] == "registered"
        and value["admissible"] is True
        and value["evidence_mode"] == inputs["evidence_mode"],
        "strict original whole-nine conditional receipt required",
    )
    validate_observation(
        value["source_observation"],
        campaign["source_provenance_policy"],
        campaign["fixed_identity"],
    )
    require(
        type(value["starts"]) is list
        and len(value["starts"]) == 9
        and [row["start_id"] for row in value["starts"]]
        == [row["start_id"] for row in inputs["starts"]],
        "receipt original Latin9 inventory changed",
    )
    for row, start in zip(value["starts"], inputs["starts"], strict=True):
        require(
            set(row) == {"start_id", "material"},
            "unknown original registration slot fields",
        )
        material = row["material"]
        plan_raw = checked(start["plan"])
        plan = parse_plan_artifact(plan_raw)
        require(
            set(material)
            == {
                "observation",
                "runtime_closure",
                "qualification",
                "plan_id",
                "plan_sha256",
                "phase_sha256",
                "source",
            }
            and material["observation"] is None
            and material["plan_id"] == plan.plan_id
            and material["plan_sha256"] == sha(plan_raw)
            and material["phase_sha256"] == start["phase"]["sha256"]
            and material["source"] == inputs["protocol_sources"],
            "whole-nine registered Plan/phase/source material changed",
        )
    # The original registration observation stays frozen. A subsequent fresh
    # observation may have newer main tips, but must independently validate the
    # SAME fixed five subjects under the SAME preregistered provenance policy.


def validate_current_materials(value, current):
    require(
        all(
            row["material"]["qualification"] == current["qualification"]
            and row["material"]["runtime_closure"] == current["runtime_closure"]
            for row in value["starts"]
        ),
        "whole-nine original qualification/runtime material changed",
    )


def validate_for_start(receipt_ref, start_id, *, fresh_source=True):
    value = load(receipt_ref)
    require(
        value["schema"] == "ecpa-h4-conditional-deployment-receipt/v1"
        and value["admissible"] is True,
        "actual conditional receipt required",
    )
    campaign, launch, workload, inputs = validate_inputs(
        value["campaign"], value["launch"], allow_used_paths=True
    )
    validate_receipt_static(value, campaign, inputs)
    require(
        value["conditional_inputs"] == campaign["conditional_inputs"]
        and value["qualification"] == inputs["qualification"],
        "receipt roots changed",
    )
    from .run_h4 import validate_launch_spec, validate_receipt

    original = load(value["original_registration"])
    validate_receipt(original, campaign, Path(value["original_registration"]["path"]))
    validate_launch_spec(launch, original, checked(value["launch"]))
    starts = [s for s in inputs["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "one exact original slot required")
    material = recompute_start(
        campaign, workload, inputs, starts[0], fresh_source=fresh_source
    )
    validate_current_materials(value, material)
    return campaign, launch, workload, inputs, starts[0], material


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--campaign", type=Path, required=True)
    p.add_argument("--launch-spec", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    issue(reference(a.campaign), reference(a.launch_spec), a.output)


if __name__ == "__main__":
    main()
