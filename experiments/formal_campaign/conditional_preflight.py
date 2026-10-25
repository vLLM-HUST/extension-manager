"""Real future source/runtime/Plan preflight for Pipeline+BidKV; no receipt mint.

All trust roots are independently recomputed with original production readers.
Old H2 static oracle explains the conditional rule but never admits a new tuple.
"""

from __future__ import annotations

import json
from pathlib import Path

IDS = {"org.vllm-hust.pipeline-microbatch", "org.vllm-hust.bidkv"}
CELLS = {
    "conditional-resource-pair.lifecycle-only",
    "conditional-resource-pair.sampled-invocation",
}


def require(value, why):
    if not value:
        raise ValueError(why)


def validate(campaign_path, launch_path, locations, runtime_wheels):
    from experiments.formal_campaign import h4_registration, source_provenance
    from experiments.formal_campaign.h3_runtime_source_closure import (
        verify_runtime_source_closure,
    )
    from vllm_hust_ext.config import load_config
    from vllm_hust_ext.discovery import discover_bundles

    campaign_path, launch_path = Path(campaign_path), Path(launch_path)
    campaign = json.loads(campaign_path.read_bytes())
    launch = json.loads(launch_path.read_bytes())
    workload = json.loads(h4_registration.validate_campaign(campaign, campaign_path))
    h4_registration.validate_launch_spec(launch)
    require(
        campaign["cell_id"] in CELLS
        and set(campaign["fixed_identity"]["plugins"]) == IDS,
        "genuine conditional pair/domain required",
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
        == [64, 16, 256, 8, 120],
        "original dimensions changed",
    )
    bundles = discover_bundles(tuple(sorted(IDS)))
    require({b.bundle_id for b in bundles} == IDS, "actual selected two bundles absent")
    observation = source_provenance.observe_sources(
        campaign["fixed_identity"], campaign["source_provenance_policy"], locations
    )
    proofs = []
    for _arm, definition in launch["arms"].items():
        require(
            definition["environment"].get("ECPA_H4_CONDITIONAL_EVIDENCE") == "1",
            "actual source producer not enabled",
        )
        # Do not run the existing unconditional KV/profiler activation adapter.
        require(
            definition["environment"].get("ECPA_H4_SOURCE_OWNED_PAIR") != "1",
            "wrong unconditional adapter",
        )
        phase = dict(
            argv=definition["server_command"],
            cwd=locations["manager"]["path"],
            environment=definition["environment"],
        )
        argv = phase["argv"]
        require(
            "--max-num-seqs" in argv and argv[argv.index("--max-num-seqs") + 1] == "1",
            "maxseq1 required",
        )
        require(
            "--pipeline-parallel-size" in argv
            and int(argv[argv.index("--pipeline-parallel-size") + 1]) > 1,
            "actual Pipeline PP>1 required",
        )
        require(
            "--tensor-parallel-size" in argv
            and int(argv[argv.index("--tensor-parallel-size") + 1]) > 0,
            "actual TP explicit; no historical TP2 assumption",
        )
        proofs.append(
            verify_runtime_source_closure(
                phase, campaign["fixed_identity"], locations, runtime_wheels
            )
        )
        # Original providers perform actual manifest version/API/config checks.
        # No provider or Manager predicate is replaced by this source oracle.
        config = load_config(Path(definition["environment"]["VLLM_HUST_EXT_CONFIG"]))
        from experiments.formal_campaign import (
            h4_conditional_provider_qualification as actual_qualification,
        )

        require(
            Path(actual_qualification.__file__).resolve()
            == Path(locations["manager"]["path"])
            / "experiments/formal_campaign/h4_conditional_provider_qualification.py",
            "qualification helper is not original selected source-owned module",
        )
        prepare_unregistered = actual_qualification.prepare_unregistered
        preparation = prepare_unregistered(
            phase=phase,
            fixed=campaign["fixed_identity"],
            repositories=locations,
            runtime_wheels=runtime_wheels,
            bundles=bundles,
            configuration=config,
        )
        for options in preparation["actual_options"].values():
            for key, value in options.items():
                require(
                    argv.count(key) == 1 and argv[argv.index(key) + 1] == value,
                    "actual CLI not original provider projection",
                )
        expected_batch = config.extension(
            "org.vllm-hust.pipeline-microbatch"
        ).configuration["launch_options"]["batch_admission_policy_config"]
        require(
            argv.count("--batch-admission-policy-config") == 1
            and json.loads(argv[argv.index("--batch-admission-policy-config") + 1])
            == expected_batch,
            "actual Pipeline configuration differs from provider intent",
        )
        proofs.append(preparation)
    return dict(
        source_observation=observation,
        actual_runtime_source_closures=proofs,
        formal_result=False,
        next_required=(
            "actual source-owned conditional registration; "
            "this helper alone never authorizes execution"
        ),
    )
