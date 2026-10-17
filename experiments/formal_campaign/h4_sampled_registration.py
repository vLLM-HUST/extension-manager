"""Candidate H4 sampled original-cell input checks and actual source guard factory.

The ordinary H4 live issuer still performs the actual remote/source transition.
These checks do not mint a deployment receipt or assert runtime qualification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from experiments.formal_campaign import h4_registration, source_provenance
from experiments.formal_campaign.h3_native_plan_guard import NativePlanGuard
from experiments.native_attention_candidate import live_route_reader as routes
from experiments.pair_semantic_candidate import authority as pair
from experiments.pair_semantic_candidate.binding import IDS
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.plan_artifact import parse_plan_artifact

CELL = "compatible-resource-pair.sampled-invocation"
SELECTED = list(range(16)) + [16 + 16 * index for index in range(16)]
require, canonical = pair.require, pair.canonical


def original_h4_runner():
    """Use the exact package-owned original runner, without a global alias.

    The original runner explicitly supports its package and script import modes.
    No unrelated ``analyze`` module is read, replaced or trusted by this path.
    """
    import importlib

    return importlib.import_module("experiments.formal_campaign.run_h4")


def validate_original_receipt(receipt, campaign, receipt_path):
    return original_h4_runner().validate_receipt(receipt, campaign, receipt_path)


def checked(ref):
    raw = pair._regular(ref["path"])
    require(
        hashlib.sha256(raw).hexdigest() == ref["sha256"].removeprefix("sha256:"),
        "registered sampled input changed",
    )
    return raw


def read_registered_schedule(reference, phases):
    from .h4_sampled_native_schedule import bind_selected_phases, read_schedule

    expected = checked(reference)
    schedule, raw = read_schedule(reference["path"])
    require(
        raw == expected,
        "actual full272 schedule differs from frozen path/SHA reference",
    )
    bind_selected_phases({"phases": phases}, schedule)
    return schedule, raw


def resource_pair_declaration(bundles):
    """Actual manifest modes are preserved, independent of the fullnative Plan.

    Do not convert manifest shared into typed Plan shared-read or drop a claim.
    This covers only original unconditional compatible-resource-pair cells.
    """
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    ordered = sorted(bundles, key=lambda b: b.bundle_id)
    require(
        {b.bundle_id for b in ordered} == IDS and len(ordered) == 2,
        "actual two-MOD resource pair required",
    )
    plugins, snapshots = installed_plugin_identities(ordered)
    claims = []
    for bundle, plugin in zip(ordered, plugins, strict=True):
        for claim in bundle.manifest.resource_claims:
            claims.append(
                dict(
                    scope=claim.scope,
                    resource=claim.resource,
                    owner=plugin.id,
                    mode=claim.mode,
                )
            )
    for claim in claims:
        sharing = [
            c
            for c in claims
            if (c["scope"], c["resource"]) == (claim["scope"], claim["resource"])
        ]
        require(
            len(sharing) == 1 or all(c["mode"] == "shared" for c in sharing),
            "actual declared resource pair is not unconditionally compatible",
        )
    return dict(
        schema="ecpa-h4-actual-manifest-resource-pair/v1",
        enabled_bundles=snapshots,
        manifest_resource_claims=claims,
        scope="compatible-resource-pair",
        semantic_Plan_replaced=False,
    )


def preflight_native_spec(phase):
    """Size all registered32 phases before Host Popen; never authenticate a PID.

    Actual source paths, request IDs, nonce/requirements and full source union
    are retained. Only future kernel/UUID fields use conservative sizing values.
    Bootstrap still independently validates the observed actual spec afterward.
    """
    import os
    import socket

    from experiments.exposure_gate import native_semantic_collector as native

    from .h4_sampled_native_source_scope import (
        native_spec_size_upper_bound,
        scope_native_senders,
    )

    boot = phase["native_bootstrap"]
    phases = boot["phases"]
    ids = {p["phase_id"] for p in phases}
    require(
        len(phases) == len(ids) == 32
        and set(boot["tensor_requirements"]) == ids
        and set(boot["kv_requirements"]) == ids,
        "every original32 selected tensor/KV inventory is mandatory",
    )
    for pid, requirement in boot["tensor_requirements"].items():
        layers = requirement["layer_indices"]
        require(
            set(requirement) == {"layer_indices", "semantic_anchor", "physical_anchor"}
            and type(layers) is list
            and layers
            and all(type(i) is int and i >= 0 for i in layers)
            and len(set(layers)) == len(layers)
            and type(requirement["semantic_anchor"]) is int
            and type(requirement["physical_anchor"]) is int
            and 0 < requirement["physical_anchor"] < requirement["semantic_anchor"]
            and all(
                requirement[k] == boot["kv_requirements"][pid][k]
                for k in ("semantic_anchor", "physical_anchor")
            ),
            "full original per-phase tensor inventory/anchors differ",
        )
    sources = boot["source_files"]
    senders = [
        dict(
            process=dict(
                role=role,
                ordinal=ordinal,
                host=socket.gethostname(),
                assignment_source="host",
                pid=1,
                session=1,
                start_ticks=1,
                process_epoch=1,
                start_identity="pid:1:start_ticks:1",
                boot_id="00000000-0000-0000-0000-000000000000",
            ),
            cmdline_sha256="0" * 64,
            peer_uid=os.getuid(),
            peer_gid=os.getgid(),
            source_files=sources,
        )
        for role, ordinal in (("api-server", 0), ("worker", 0), ("worker", 1))
    ]
    scoped, retained = scope_native_senders(senders, sources)
    require(
        canonical(sorted(retained, key=lambda r: r["path"]))
        == canonical(sorted(sources, key=lambda r: r["path"])),
        "preflight lost original native source union",
    )
    semantic = json.loads(checked(phase["semantic_launch_spec"]))
    return native_spec_size_upper_bound(
        dict(
            schema=native.KV_SPEC_V2,
            classification="CPU_REVIEW_CANDIDATE_ONLY",
            formal_producer_registration=False,
            native_plan_id=semantic["native_plan_id"],
            native_launch_id="00000000-0000-4000-8000-000000000000",
            frozen_monotonic_ns=1,
            max_event_age_ns=5_000_000_000,
            max_uploads_per_rank=256,
            senders=scoped,
            phases=phases,
            kv_requirements=boot["kv_requirements"],
        )
    )


def validate_inputs(
    campaign_path, launch_path, *, require_fresh_paths=True, _calibration_only=False
):
    campaign_path, launch_path = Path(campaign_path), Path(launch_path)
    campaign_raw = campaign_path.read_bytes()
    campaign = json.loads(campaign_raw)
    campaign["_raw_sha256"] = "sha256:" + hashlib.sha256(campaign_raw).hexdigest()
    launch = json.loads(launch_path.read_bytes())
    workload = json.loads(h4_registration.validate_campaign(campaign, campaign_path))
    h4_registration.validate_launch_spec(launch)
    require(campaign["cell_id"] == CELL, "original sampled cell ID required")
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
        == [64, 16, 256, 8, 120],
        "original H4 request dimensions changed",
    )
    native = json.loads(checked(campaign["sampled_native_inputs"]))
    require(
        native["schema"] == "ecpa-h4-full-native-sampled-inputs/v1",
        "new domain required",
    )
    require(
        native["selected_all_indices"] == SELECTED, "frozen sample selection differs"
    )
    require(len(native["starts"]) == 9, "all original nine starts required")
    require(
        native["provider_parameters"] == {"kv_budget": 1024, "recompute_window": 128},
        "registered actual provider configuration differs",
    )
    if _calibration_only:
        require(
            campaign.get("execution_domain") == "unregistered-calibration",
            "qualification requires its own explicit namespace/domain",
        )
        intent = json.loads(checked(native["new_tokenizer_and_native_calibration"]))
        require(
            set(intent) == {"schema", "workload_sha256", "fixed_identity"}
            and intent["schema"] == "ecpa-h4-unregistered-calibration-intent/v1"
            and (intent["workload_sha256"] == campaign["workload"]["sha256"])
            and (
                canonical(intent["fixed_identity"])
                == canonical(campaign["fixed_identity"])
            ),
            "explicit unregistered qualification intent required",
        )
    else:
        require(
            campaign.get("execution_domain") != "unregistered-calibration",
            "qualification packet cannot become a formal deployment",
        )
        from .h4_sampled_calibration import validate_calibration

        validate_calibration(
            native["new_tokenizer_and_native_calibration"],
            campaign=campaign,
            launch=launch,
            workload=workload,
            native=native,
        )
    expected = [
        (r, order, arm)
        for r, row in enumerate(campaign["schedule"], 1)
        for order, arm in enumerate(row["order"], 1)
    ]
    require(
        [(s["repetition"], s["arm_order"], s["arm"]) for s in native["starts"]]
        == expected,
        "sampled starts do not match original balanced schedule",
    )
    actual_resources = resource_pair_declaration(discover_bundles(tuple(sorted(IDS))))
    require(
        canonical(actual_resources)
        == canonical(json.loads(checked(native["resource_pair_declaration"]))),
        "actual two manifest resource/owner/mode declaration changed",
    )
    # Preserve the complete native spec/policy and original KV contract roots.
    checked(native["original_native_intent"]["base_plan"])
    checked(native["original_native_intent"]["kv_contract"])
    manager_config = json.loads(checked(native["provider_config_refs"]["manager"]))
    baseline_profile = json.loads(checked(native["provider_config_refs"]["baseline"]))
    kv_id = "org.vllm-hust.ascend-kvcompress"
    profiler_id = "org.vllm-hust.request-lifecycle-profiler"
    require(
        manager_config["extensions"][kv_id]["enabled"] is True
        and manager_config["extensions"][profiler_id]["enabled"] is True,
        "actual Manager config must enable both real MODs",
    )
    configuration = manager_config["extensions"][kv_id]["configuration"]
    require(
        canonical(configuration) == canonical(baseline_profile["configuration"])
        and baseline_profile["extension_id"] == kv_id,
        "baseline and ECPA provider configuration bytes differ",
    )
    require(
        configuration["method"] == "triattention"
        and configuration["method_config"]["kv_budget"] == 1024
        and configuration["method_config"]["recompute_window"] == 128,
        "actual configuration must preserve1024/128",
    )
    roots, directories, contexts = set(), set(), set()
    for start in native["starts"]:
        require(start["start_id"] not in roots, "start identities alias")
        roots.add(start["start_id"])
        require(
            start["run_directory"] not in directories,
            "original independent starts cannot share run directories",
        )
        directories.add(start["run_directory"])
        phase = json.loads(checked(start["phase"]))
        boot = phase["native_bootstrap"]
        read_registered_schedule(start["schedule"], boot["phases"])
        require(
            Path(boot["output"]) == Path(start["run_directory"]) / "n",
            "native output must use the registered fresh short run root",
        )
        for key in ("native_context_path", "tensor_context_path"):
            require(boot[key] not in contexts, "start native contexts alias")
            contexts.add(boot[key])
        guard = json.loads(checked(phase["native_guard"]))
        require(set(guard["bundle_ids"]) == IDS, "actual pair must remain enabled")
        require(
            guard["native_launch_spec"] == phase["semantic_launch_spec"],
            "full Plan/semantic launch references differ",
        )
        require(
            phase["environment"].get("ECPA_H4_NATIVE_SAMPLED_SELECTION") == "1",
            "registered real source-side sampling must be explicitly enabled",
        )
        if start["arm"] != "ecpa":
            require(
                phase["environment"].get("VLLM_ECPA_EVIDENCE_SINK")
                == "vllm_hust_ext.runtime_evidence:record_event"
                and phase["environment"].get("VLLM_ECPA_EVIDENCE_STRICT") == "1",
                (
                    "baseline must preserve actual public Host eviden"
                    "ce sink and strict path"
                ),
            )
        argv = phase["argv"]
        wrapper = str(
            Path(native["repositories"]["manager"]["path"])
            / "experiments/formal_campaign/h3_dynamic_host.py"
        )
        if start["arm"] == "ecpa":
            require(
                argv[:3] == [phase["argv"][0], wrapper, "manager"]
                and argv[3] == "run"
                and "--" in argv
                and argv[argv.index("--") + 1 : argv.index("--") + 5]
                == [argv[0], wrapper, "managed-host", "serve"],
                "actual ECPA must run published Manager/managed-Host source path",
            )
        else:
            flag = (
                "--manual-hooks"
                if start["arm"] == "manual-integration"
                else "--enable-entrypoints"
            )
            require(
                argv[:6]
                == [
                    argv[0],
                    wrapper,
                    "baseline",
                    "serve",
                    "--disable-ecpa-manager",
                    flag,
                ],
                "actual baseline must run original source-owned activation contract",
            )
        require(
            "--max-num-seqs" in argv and argv[argv.index("--max-num-seqs") + 1] == "1",
            "current actual source tuple retains max-num-seqs1",
        )
        for reference in native["sampled_protocol_sources"].values():
            require(
                guard["source_arguments"]["native_sources"].get(reference["path"])
                == reference["sha256"].removeprefix("sha256:"),
                "new sampled protocol source absent from independent full source guard",
            )
        # Independent size-only preflight before any actual Host Popen.
        # Actual post-kernel bootstrap check remains mandatory and unchanged.
        preflight_native_spec(phase)
        from .h4_sampled_pair_epoch import preflight_paths

        preflight_paths(
            Path(start["run_directory"]), phase, require_fresh=require_fresh_paths
        )
    return campaign, launch, workload, native


def build_plan_guard(campaign, native, start, receipt):
    """Recompute fresh actual inputs; roots come from issued observation/intent."""
    require(
        receipt["campaign_sha256"] == campaign["_raw_sha256"]
        and receipt["cell_id"] == CELL
        and receipt["admissible"] is True,
        "actual registered original H4 receipt required",
    )
    source_provenance.receipt_schema(receipt, campaign, "h4")
    return _build_guard_from_observation(
        campaign, native, start, receipt["source_provenance_observation"]
    )


def _build_guard_from_observation(campaign, native, start, observation):
    """Shared exact fresh input/Plan predicates; no synthetic receipt object."""
    phase = json.loads(checked(start["phase"]))
    policy = json.loads(checked(phase["native_guard"]))
    args = policy["source_arguments"]
    require(
        canonical(args["observation"]) == canonical(observation),
        "per-start source observation differs from actual issuer receipt",
    )
    base_ref = native["original_native_intent"]["base_plan"]
    contract_ref = native["original_native_intent"]["kv_contract"]
    require(
        checked(args["original_kv_base"]) == checked(base_ref)
        and checked(args["kv_contract"]) == checked(contract_ref),
        "full original KV roots changed",
    )
    base = parse_plan_artifact(checked(base_ref))
    roots = set()
    for audit in args["input_audits"].values():
        current = routes.audit_cell_inputs(
            audit["config"]["path"], audit["recipe"]["path"]
        )
        require(
            canonical(current) == canonical(audit), "fresh source input audit differs"
        )
        roots.add(pair.sha(canonical(current)))
    pair_inputs = args["pair_inputs"]
    require(pair_inputs is not None, "actual two-MOD wheel/source audit required")
    current = pair.audit_pair_inputs(
        pair_inputs["native_inputs"],
        pair_inputs["wheels"],
        plugin_commits=pair_inputs["plugin_commits"],
        bundles=discover_bundles(tuple(sorted(IDS))),
    )
    require(
        canonical(current) == canonical(pair_inputs), "actual pair input audit differs"
    )
    roots.add(pair.sha(canonical(current)))
    guard = NativePlanGuard(
        policy=policy,
        trusted_source_observations={source_provenance.digest(canonical(observation))},
        trusted_input_digests=roots,
        trusted_manager_handoffs=set(),
        trusted_base_plan_ids={base.plan_id},
        trusted_contract_digests={pair.sha(checked(contract_ref))},
    )
    guard.verify_plan_current()
    return guard


def build_calibration_guard(campaign, native, start, locations):
    """Own fresh canonical source observations, never caller-provided trust roots."""
    observation = source_provenance.observe_sources(
        campaign["fixed_identity"], campaign["source_provenance_policy"], locations
    )
    verify_sampled_protocol_sources(
        native,
        Path(locations["manager"]["path"]),
        campaign["fixed_identity"]["manager_commit"],
    )
    return _build_guard_from_observation(campaign, native, start, observation)


def issue(campaign_path, launch_path, repository_locations_path, output):
    """Actual original H4 transition plus full new native-source admission.

    This is future executable source, not an offline fabricated receipt. All
    source observations and per-start input audits below are actually recomputed.
    """
    campaign, launch, _, native = validate_inputs(campaign_path, launch_path)
    locations = json.loads(Path(repository_locations_path).read_bytes())
    fixed = campaign["fixed_identity"]
    observation = source_provenance.observe_sources(
        fixed, campaign["source_provenance_policy"], locations
    )
    manager = locations["manager"]
    host = locations["host"]
    manager_source = h4_registration.observe_merged_source(
        Path(manager["path"]),
        manager["remote"],
        "vLLM-HUST/extension-manager",
        fixed["manager_commit"],
    )
    host_source = h4_registration.observe_merged_source(
        Path(host["path"]), host["remote"], "vLLM-HUST/vllm-hust", fixed["host_commit"]
    )
    receipt = h4_registration.build_receipt(
        campaign_raw=Path(campaign_path).read_bytes(),
        campaign_path=Path(campaign_path),
        launch_raw=Path(launch_path).read_bytes(),
        manager_repo=Path(manager["path"]),
        manager_source=manager_source,
        host_source=host_source,
    )
    receipt = source_provenance.upgrade_receipt(
        receipt,
        campaign,
        observation,
        source_provenance.bind_protocol_source(
            Path(manager["path"]), fixed["manager_commit"], "h4", h4_source_owned=True
        ),
    )
    verify_sampled_protocol_sources(
        native, Path(manager["path"]), fixed["manager_commit"]
    )
    # No receipt file exists until every full native source/Plan guard accepts.
    for start in native["starts"]:
        build_plan_guard(campaign, native, start, receipt)
    h4_registration.atomic_write_new(Path(output), receipt)
    return receipt


SAMPLED_PROTOCOL_FILES = (
    "h4_sampled_registration.py",
    "h4_sampled_prepare.py",
    "h4_sampled_pair_epoch.py",
    "h4_sampled_host_launch.py",
    "run_h4_sampled.py",
    "h4_sampled_native_schedule.py",
    "h4_sampled_native_collector.py",
    "h4_sampled_native_client.py",
    "h4_sampled_native_bootstrap.py",
    "h4_sampled_native_source_scope.py",
    "h4_sampled_native_verifier.py",
    "h4_sampled_native_replay.py",
    "h4_sampled_intake.py",
    "h4_sampled_root_observer.py",
    "h4_sampled_queue.py",
    "h4_sampled_calibration.py",
    "h4_sampled_record_bridge.py",
    "h4_sampled_health.py",
)


def verify_sampled_protocol_sources(native, repository, commit):
    import subprocess

    refs = native["sampled_protocol_sources"]
    required = {
        "experiments/formal_campaign/" + name for name in SAMPLED_PROTOCOL_FILES
    }
    require(
        set(refs) == required,
        "complete named H4 native protocol source inventory required",
    )
    for relative, reference in refs.items():
        original = subprocess.run(
            ["git", "-C", str(repository), "show", commit + ":" + relative],
            check=True,
            capture_output=True,
        ).stdout
        require(
            checked(reference) == original,
            "new protocol source is not exact admitted Manager Git bytes",
        )
        actual = (repository / relative).resolve()
        require(
            Path(reference["path"]).resolve() == actual,
            "new protocol source ref is not its actual selected repository path",
        )


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--launch-spec", type=Path, required=True)
    parser.add_argument("--source-repositories", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = issue(
        args.campaign, args.launch_spec, args.source_repositories, args.output
    )
    print(
        json.dumps(
            dict(
                admissible=receipt["admissible"],
                receipt=str(args.output),
                formal_starts=0,
                formal_result=False,
            )
        )
    )


if __name__ == "__main__":
    main()
