"""Actual conditional three-arm Host activation; no KV/profiler carrier reuse."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .conditional_common import ARMS, IDS, load, require


def validate_equivalent_activation(phase, bundles, configuration):
    from vllm_hust_ext.core import (
        LifecycleState,
        plan_for,
        reject_conflicting_plans,
        status_for,
    )

    require(
        phase["arm"] in ARMS
        and phase["environment"]["ECPA_H4_CONDITIONAL_ACTIVATION"] == phase["arm"],
        "actual route/arm differs",
    )
    require(
        {b.bundle_id for b in bundles} == IDS and set(configuration.enabled) == IDS,
        "genuine two policies required",
    )
    argv = phase["host_argv"]
    require(
        argv[:4] == [phase["python"], "-m", "vllm.entrypoints.cli.main", "serve"],
        "real published Host CLI required",
    )
    expected = {
        "--served-model-name": phase["served_model"],
        "--max-model-len": "2048",
        "--max-num-seqs": "1",
        "--pipeline-parallel-size": "2",
        "--tensor-parallel-size": "1",
        "--data-parallel-size": "1",
    }
    for key, value in expected.items():
        require(
            argv.count(key) == 1 and argv[argv.index(key) + 1] == value,
            "original fixed actual topology/maxseq differs",
        )
    require(
        "--model" not in argv
        and not any(a.startswith("--model=") for a in argv)
        and "--enforce-eager" in argv,
        "original direct-model/eager Host declaration required",
    )
    model_index = argv.index("--served-model-name")
    require(
        model_index + 2 == len(argv) or argv[model_index + 2].startswith("--"),
        "original single served-model name required",
    )
    plans = []
    for bundle in bundles:
        extension = configuration.extension(bundle.bundle_id)
        # All formal arms share the original provider admission checks. The
        # unregistered bootstrap explicitly uses the separate source ABI path.
        if phase.get("execution_domain") != "unregistered-conditional-qualification":
            status = status_for(bundle, extension)
            require(
                LifecycleState.COMPATIBLE in status.states
                and LifecycleState.INCOMPATIBLE not in status.states,
                "original provider refuses actual runtime qualification",
            )
        plan = plan_for(bundle, extension)
        plans.append(plan)
        for key, value in plan.generated_config.get("vllm_options", {}).items():
            require(
                argv.count(key) == 1 and argv[argv.index(key) + 1] == value,
                "three-arm actual CLI differs from provider projection",
            )
        for key, value in plan.generated_config.get("environment", {}).items():
            require(
                phase["environment"].get(key) == value,
                "three-arm actual provider environment differs",
            )
    reject_conflicting_plans(tuple(plans))
    batch = configuration.extension("org.vllm-hust.pipeline-microbatch").configuration[
        "launch_options"
    ]["batch_admission_policy_config"]
    require(
        argv.count("--batch-admission-policy-config") == 1
        and json.loads(argv[argv.index("--batch-admission-policy-config") + 1])
        == batch,
        "three-arm actual Pipeline configuration differs",
    )
    require(
        batch["pipeline_parallel_size"] == 2
        and batch["tensor_parallel_size"] == 1
        and batch["microbatch_count"] == 2,
        "real PP2TP1/microbatch2 condition required",
    )
    require(
        phase["environment"].get("ECPA_ACTIVATION_PROFILE_PATH") is None
        and phase["environment"].get("ECPA_ACTIVATION_CONTRACT") is None,
        (
            "old KV-only activation contract cannot stand in for conditional "
            "policy activation"
        ),
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--phase", type=Path, required=True)
    p.add_argument("--phase-sha256", required=True)
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    phase = load(dict(path=str(a.phase.resolve()), sha256=a.phase_sha256))
    require(
        phase["arm"] in ARMS
        and os.environ["ECPA_H4_CONDITIONAL_ACTIVATION"] == phase["arm"],
        "actual frozen arm/route required",
    )
    require(sys.executable == phase["python"], "exact selected interpreter required")
    # No fake general entry-point is claimed for these scheduler-policy MODs.
    # manual-integration triggers the actual additive Host explicit factories;
    # vanilla/ECPA retain the stock Host public policy resolver and validation.
    argv = phase["host_argv"]
    require(
        a.command and a.command[0] == "--" and a.command[1:] == argv,
        "actual Host argv changed after Manager rendering",
    )
    require(
        argv[:4] == [sys.executable, "-m", "vllm.entrypoints.cli.main", "serve"],
        "real Host command required",
    )
    sys.argv = ["vllm", *argv[3:]]
    from vllm.entrypoints.cli.main import main as actual_host_main

    actual_host_main()


if __name__ == "__main__":
    main()
