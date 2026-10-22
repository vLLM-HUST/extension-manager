"""Freeze and independently replay real new-tuple configured/functional support.

No historical PP2TP2 qualification, caller status flag or command return code is
an admission predicate. Effect coverage stays separate and may remain unknown.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .conditional_common import canonical, checked, load, reference, require, sha, write

SCHEMA = "ecpa-h4-conditional-independent-qualification/v1"
PRODUCTS = (
    "source-admission.json",
    "phase0.product-popen-timing.json",
    "actual-runtime-closure.json",
    "conditional-epoch.json",
    "final-Host.jsonl",
    "requests.jsonl",
    "actual-requests.json",
    "owned-resources.json",
    "conditional-source-result.json",
    "conditional-plan.json",
    "conditional-launch.json",
    "selection-control.jsonl",
    "selection-context.json",
    "actual-tokenizer.json",
    "actual-tokenizer-command.json",
    "actual-tokenizer.stdout",
    "actual-tokenizer.stderr",
    "health-probes.jsonl",
    "health-probe-terminal.json",
    "terminal-owned-kernel-witness.json",
    "cleanup-observation.json",
    "terminal-npu-smi.json",
    "terminal-npu-smi.stdout",
    "terminal-npu-smi.stderr",
)


def validate_report(ref, *, expected_fixed, expected_workload):
    value = load(ref)
    require(
        set(value)
        == {
            "schema",
            "scope",
            "fixed_identity",
            "workload_sha256",
            "campaign",
            "launch",
            "start_id",
            "run_directory",
            "root_cleanup",
            "products",
        },
        "exact new qualification report required",
    )
    require(
        value["schema"] == SCHEMA
        and value["scope"] == "actual-configured-pair-and-public-functional-requests",
        "old/static/caller qualification forbidden",
    )
    require(
        canonical(value["fixed_identity"]) == canonical(expected_fixed)
        and value["workload_sha256"] == sha(canonical(expected_workload)),
        "qualification tuple/workload changed",
    )
    run = Path(value["run_directory"])
    require(
        set(value["products"]) == set(PRODUCTS),
        "actual original qualification products missing",
    )
    for name, product in value["products"].items():
        require(
            Path(product["path"]) == run / name,
            "qualification product moved to another run",
        )
        checked(product)
    from .conditional_intake import replay_qualification

    summary = replay_qualification(value)
    require(
        summary["configured_and_functional_supported"] is True
        and all(
            summary["cleanup"][k] is True
            for k in ("processes_reclaimed", "ports_reclaimed", "devices_reclaimed")
        ),
        "real new tuple configuration/HTTP/health/cleanup qualification failed",
    )
    return dict(
        report=ref,
        scope=value["scope"],
        fixed_identity=value["fixed_identity"],
        configured_and_functional_supported=True,
        effect_coverage=summary["effect_coverage"],
        runtime_effectiveness_claim=False,
        performance_claim=False,
    )


def freeze(campaign_ref, launch_ref, start_id, run, root_cleanup_ref, output):
    from .conditional_registration import validate_inputs

    campaign, launch, workload, inputs = validate_inputs(
        campaign_ref, launch_ref, allow_used_paths=True
    )
    require(
        campaign.get("execution_domain") == "unregistered-conditional-qualification",
        "fresh unregistered namespace required",
    )
    starts = [s for s in inputs["starts"] if s["start_id"] == start_id]
    require(len(starts) == 1, "exact original qualification start required")
    require(
        Path(starts[0]["run_directory"]) == Path(run),
        "qualification run directory differs",
    )
    value = dict(
        schema=SCHEMA,
        scope="actual-configured-pair-and-public-functional-requests",
        fixed_identity=campaign["fixed_identity"],
        workload_sha256=sha(canonical(workload)),
        campaign=campaign_ref,
        launch=launch_ref,
        start_id=start_id,
        run_directory=str(run),
        root_cleanup=root_cleanup_ref,
        products={name: reference(Path(run) / name) for name in PRODUCTS},
    )
    # Validate a real prospective value through the SAME reader before writing
    # an accepted report; no synthetic receipt or positive shortcut is created.
    from .conditional_intake import replay_qualification

    summary = replay_qualification(value)
    require(
        summary["configured_and_functional_supported"] is True,
        "actual qualification failed; keep original raw failure",
    )
    path = Path(output)
    write(path, value)
    return validate_report(
        reference(path),
        expected_fixed=campaign["fixed_identity"],
        expected_workload=workload,
    )


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--campaign", type=Path, required=True)
    p.add_argument("--launch-spec", type=Path, required=True)
    p.add_argument("--start-id", required=True)
    p.add_argument("--run", type=Path, required=True)
    p.add_argument("--root-cleanup", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    freeze(
        reference(a.campaign),
        reference(a.launch_spec),
        a.start_id,
        a.run,
        reference(a.root_cleanup),
        a.output,
    )


if __name__ == "__main__":
    main()
