"""First-registration candidate builder; intent is never historical qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def checked(ref):
    raw = Path(ref["path"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ref["sha256"].removeprefix("sha256:"):
        raise ValueError("source intent bytes changed")
    return raw


def save(path, value):
    raw = value if isinstance(value, bytes) else canonical(value) + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "sha256": "sha256:" + hashlib.sha256(raw).hexdigest()}


def compile_actual_pair(output, base_ref, contract_ref):
    """Future actual installed identities; no plugin imports during this draft."""
    from experiments.pair_semantic_candidate.binding import IDS, KV, compile_pair_plan
    from vllm_hust_ext import semantic_runtime_binding as runtime
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes

    base = parse_plan_artifact(checked(base_ref))
    contract = json.loads(checked(contract_ref))
    bundles = discover_bundles(tuple(sorted(IDS)))
    pair_base, plan, binding, pair = compile_pair_plan(
        base,
        bundles,
        contract,
        profiler_slots={"api-server": (0,), "engine-core-scheduler": (0,)},
    )
    base_path = save(output / "pair-base.json", plan_artifact_bytes(pair_base))
    plan_path = save(output / "full-pair-plan.json", plan_artifact_bytes(plan))
    binding_path = save(output / "full-native-binding.json", binding)
    kv_path = save(output / "original-kv-contract.json", checked(contract_ref))
    profiler_path = save(
        output / "profiler-loader-contract.json", pair["profiler_contract"]
    )
    mapping_path = save(output / "plugin-map.json", {KV: pair["plugin_identities"][KV]})
    launch = runtime.make_semantic_launch_spec(
        bundles,
        base_plan_path=Path(base_path["path"]),
        plan_path=Path(plan_path["path"]),
        binding_path=Path(binding_path["path"]),
        contract_paths=(Path(kv_path["path"]), Path(profiler_path["path"])),
        plugin_map_path=Path(mapping_path["path"]),
        controller_instance="controller:h4-sampled-" + secrets.token_hex(16),
        candidate_generation=1,
        membership_epoch=0,
    )
    launch_ref = save(output / "semantic-launch.json", launch)
    runtime.validate_semantic_launch_spec(launch_ref["path"], bundles)
    save(output / "pair-binding.json", pair)
    from .h4_sampled_registration import resource_pair_declaration

    save(
        output / "actual-manifest-resource-pair.json",
        resource_pair_declaration(bundles),
    )
    return plan_path, launch_ref


def prepare_intent(source_ref, output):
    """Derive a new long input from existing native calibration text, not receipts."""
    old = json.loads(checked(source_ref))
    payload = old["payload"]
    if not isinstance(payload.get("prompt"), str):
        raise ValueError("source must contain actual rendered completions prompt text")
    # Historical tokenizer/native counts are deliberately not copied as validity.
    workload = dict(
        schema="ecpa-h4-openai-completions-workload/v1",
        endpoint="/v1/completions",
        prompt=payload["prompt"],
        max_tokens=64,
        warmup_requests=16,
        measured_requests=256,
        min_successful_measured_requests=256,
        concurrency=8,
        temperature=0.0,
        seed=12012,
        request_timeout_seconds=120,
        success_status=200,
        require_nonempty_completion=True,
        throughput_primary="successful_requests_per_second",
        latency_clock="CLOCK_MONOTONIC_RAW",
        latency_quantiles=[0.5, 0.95, 0.99],
    )
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    workload_ref = save(output / "new-workload-intent.json", workload)
    selected = list(range(16)) + [16 + 16 * i for i in range(16)]
    save(
        output / "first-registration-intent.json",
        dict(
            schema="ecpa-h4-sampled-first-registration-intent/v1",
            cell_id="compatible-resource-pair.sampled-invocation",
            source_text_intent=source_ref,
            workload=workload_ref,
            historical_qualification_reused=False,
            tokenizer_and_native_calibration=None,
            selected_all_indices=selected,
            all_requests=272,
            selected_requests=32,
            selection_rule="all16warmup plus measured indices0,16,...240",
            provider_parameters=dict(kv_budget=1024, recompute_window=128),
            required_native_min_completion_tokens=16,
            formal_registration=None,
            ready=False,
            original36_target_unchanged=True,
        ),
    )
    schedule = [
        ["vanilla-vllm-entry-points", "manual-integration", "ecpa"],
        ["manual-integration", "ecpa", "vanilla-vllm-entry-points"],
        ["ecpa", "vanilla-vllm-entry-points", "manual-integration"],
    ]
    save(
        output / "supplementary-long-lifecycle-nine-plan.json",
        dict(
            schema="ecpa-h4-explicit-supplementary-mode-match-plan/v1",
            cohort_id="H4-long-input-lifecycle-mode-match-supplement-v1",
            workload=workload_ref,
            provider_parameters=dict(kv_budget=1024, recompute_window=128),
            evidence_mode="lifecycle-only",
            original36_eligible=False,
            replaces_original_short_lifecycle_cell=False,
            planned_starts=9,
            starts=[
                dict(repetition=r, arm_order=i, arm=arm)
                for r, arms in enumerate(schedule, 1)
                for i, arm in enumerate(arms, 1)
            ],
            registration=None,
            status="planned-unregistered",
            purpose="only matched long-input cohort may identify evidence-mode effect",
        ),
    )
    return workload_ref


def freeze_from_bindings(binding_ref, output, *, calibration_only=False):
    """Freeze complete real prepared phase/guard inputs; never fill absent refs.

    This stage follows actual installed pair Plan compilation and new tokenizer/
    NPU calibration. The binding file must supply their original exact outputs,
    fresh source/input audits and nine actual source-owned phase declarations.
    It cannot turn this draft's intent or a historic receipt into qualification.
    """
    from .h4_sampled_native_schedule import SELECTED_INDICES, validate_schedule
    from .h4_sampled_registration import checked as checked_native
    from .h4_sampled_registration import validate_inputs

    binding = json.loads(checked(binding_ref))
    if binding["schema"] != "ecpa-h4-sampled-prepared-real-bindings/v1":
        raise ValueError("complete future real binding input required")
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    workload_raw = checked_native(binding["workload"])
    workload = json.loads(workload_raw)
    if [
        workload[k]
        for k in (
            "max_tokens",
            "warmup_requests",
            "measured_requests",
            "concurrency",
            "request_timeout_seconds",
        )
    ] != [64, 16, 256, 8, 120]:
        raise ValueError("original workload dimensions cannot change")
    workload_ref = save(output / "workload.json", workload_raw)
    launch_raw = checked_native(binding["launch_spec"])
    launch = json.loads(launch_raw)
    save(output / "launch-spec.json", launch_raw)
    model_names = {arm["served_model"] for arm in launch["arms"].values()}
    if len(model_names) != 1:
        raise ValueError("all three arms require the same actual model")
    model = next(iter(model_names))
    payload = canonical(
        {
            "model": model,
            **{k: workload[k] for k in ("prompt", "max_tokens", "temperature", "seed")},
        }
    )
    body_sha = hashlib.sha256(payload).hexdigest()
    starts = []
    for start in binding["starts"]:
        phase = json.loads(checked_native(start["phase"]))
        phases = phase["native_bootstrap"]["phases"]
        by_client = {p["client_request_id"]: p for p in phases}
        declarations = []
        for index in range(272):
            kind, ordinal = (
                ("warmup", index) if index < 16 else ("measured", index - 16)
            )
            rid = f"{start['start_id']}/{kind}-{ordinal:04d}"
            selected = index in SELECTED_INDICES
            if selected and rid not in by_client:
                raise ValueError(
                    "prepared phase is missing exact selected full request ID"
                )
            declaration = by_client.get(rid)
            declarations.append(
                dict(
                    all_index=index,
                    request_id=rid,
                    external_request_id="cmpl-" + rid + "-0",
                    phase_id=declaration["phase_id"]
                    if selected
                    else f"unsampled-{index:03d}",
                    body_sha256=body_sha,
                    selected=selected,
                )
            )
        schedule = dict(
            schema="ecpa-h4-sampled-native-schedule/v1",
            request_count=272,
            warmup_count=16,
            measured_count=256,
            concurrency=8,
            timeout_s=120,
            selected_all_indices=list(SELECTED_INDICES),
            requests=declarations,
        )
        validate_schedule(schedule)
        schedule_ref = save(
            output / ("schedule-" + str(len(starts)) + ".json"), canonical(schedule)
        )
        starts.append({**start, "schedule": schedule_ref})
    # Refs below must be complete actual preparation products, not guessed
    # kernels/launch identities or fabricated input audit dictionaries.
    native = dict(
        schema="ecpa-h4-full-native-sampled-inputs/v1",
        provider_parameters=dict(kv_budget=1024, recompute_window=128),
        selected_all_indices=list(SELECTED_INDICES),
        starts=starts,
        original_native_intent=binding["original_native_intent"],
        repositories=binding["repositories"],
        runtime_wheels=binding["runtime_wheels"],
        sampled_protocol_sources=binding["sampled_protocol_sources"],
        provider_config_refs=binding["provider_config_refs"],
        resource_pair_declaration=binding["resource_pair_declaration"],
        allocated_tcp_ports=binding["allocated_tcp_ports"],
        new_tokenizer_and_native_calibration=binding[
            "new_tokenizer_and_native_calibration"
        ],
        historical_qualification_reused=False,
        independent_aftercleanup_native_intake=(
            "experiments.formal_campaign.h4_sampled_intake; a"
            "ctual independently observed root cleanup ref ma"
            "ndatory"
        ),
    )
    native_ref = save(output / "native-inputs.json", native)
    campaign = json.loads(checked_native(binding["campaign_template"]))
    campaign.update(
        cell_id="compatible-resource-pair.sampled-invocation",
        execution_domain="unregistered-calibration"
        if calibration_only
        else "registered-original-starts",
        fixed_identity=binding["fixed_identity"],
        source_provenance_policy=binding["source_provenance_policy"],
        workload=dict(path="workload.json", sha256=workload_ref["sha256"]),
        sampled_native_inputs=native_ref,
        planned_starts=9,
        formal_h4_result=False,
        performance_result=False,
        score_eligible=False,
    )
    campaign_ref = save(output / "campaign.json", campaign)
    validate_inputs(
        Path(campaign_ref["path"]),
        output / "launch-spec.json",
        _calibration_only=calibration_only,
    )
    if calibration_only:
        save(
            output / "commands.json",
            dict(
                domain="unregistered-calibration",
                formal_result=False,
                deployment_receipt=None,
                root_observer=[
                    binding["python"],
                    "-m",
                    "experiments.formal_campaign.h4_sampled_root_observer",
                    "--campaign",
                    str(output / "campaign.json"),
                    "--launch-spec",
                    str(output / "launch-spec.json"),
                    "--start-id",
                    starts[0]["start_id"],
                    "--python",
                    binding["python"],
                    "--sdk",
                    json.loads(checked_native(starts[0]["phase"]))["cwd"],
                    "--environment",
                    binding["calibration_environment_path"],
                    "--source-repositories",
                    binding["repository_locations_path"],
                    "--unregistered-calibration",
                    "--output",
                    str(output / "independent-calibration-root"),
                ],
            ),
        )
        return campaign_ref
    save(
        output / "commands.json",
        dict(
            registration=[
                binding["python"],
                "-m",
                "experiments.formal_campaign.h4_sampled_registration",
                "--campaign",
                str(output / "campaign.json"),
                "--launch-spec",
                str(output / "launch-spec.json"),
                "--source-repositories",
                binding["repository_locations_path"],
                "--output",
                binding["new_receipt_path"],
            ],
            first9=[
                binding["python"],
                "-m",
                "experiments.formal_campaign.h4_sampled_queue",
                "--campaign",
                str(output / "campaign.json"),
                "--launch-spec",
                str(output / "launch-spec.json"),
                "--deployment-receipt",
                binding["new_receipt_path"],
                "--output",
                str(output / "original-nine-root-queue"),
            ],
            formal_promotion_allowed=False,
            reason=(
                "source result must independently pass h4_sampled"
                "_intake plus real root cleanup before any per-st"
                "art admission; original36 aggregate remains sepa"
                "rate"
            ),
        ),
    )
    return campaign_ref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-native-text", type=Path)
    parser.add_argument("--source-native-text-sha256")
    parser.add_argument("--prepared-bindings", type=Path)
    parser.add_argument(
        "--calibration-only",
        action="store_true",
        help=(
            "Distinct unregistered qualification namespace; no receipt/first9 commands"
        ),
    )
    parser.add_argument("--prepared-bindings-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.prepared_bindings:
        if not args.prepared_bindings_sha256:
            parser.error("--prepared-bindings-sha256 required")
        result = freeze_from_bindings(
            dict(
                path=str(args.prepared_bindings.resolve()),
                sha256=args.prepared_bindings_sha256,
            ),
            args.output.resolve(),
            calibration_only=args.calibration_only,
        )
    else:
        if not args.source_native_text or not args.source_native_text_sha256:
            parser.error("source-native-text path/hash required for new intent")
        result = prepare_intent(
            dict(
                path=str(args.source_native_text.resolve()),
                sha256=args.source_native_text_sha256,
            ),
            args.output.resolve(),
        )
    print(json.dumps(dict(workload_intent=result, ready=False, formal_result=False)))


if __name__ == "__main__":
    main()
