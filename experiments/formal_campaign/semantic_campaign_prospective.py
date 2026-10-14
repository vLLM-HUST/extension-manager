"""Source-bound prerequisite/matrix draft, never formal registration or execution."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = [
    "experiments/formal_campaign/protocol.json",
    "experiments/formal_campaign/h3_registration.py",
    "experiments/formal_campaign/h4_registration.py",
    "experiments/exposure_gate/loopback_traffic.py",
    "src/vllm_hust_ext/host_observer.py",
    "src/vllm_hust_ext/formal_host_observer.py",
    "src/vllm_hust_ext/contract_compiler.py",
    "experiments/native_attention_candidate/operator_observer.py",
    "experiments/native_attention_candidate/collector.py",
    "experiments/native_attention_candidate/attention_consumer.py",
    "experiments/formal_campaign/source_provenance.py",
]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def build(root=ROOT):
    protocol = json.loads((root / FILES[0]).read_bytes())
    compiler = ast.parse((root / FILES[6]).read_text())
    events = next(
        ast.literal_eval(node.value)
        for node in compiler.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_EVENTS"
            for target in node.targets
        )
    )
    proxy = (root / FILES[3]).read_text()
    if 'raise GateError("semantic obligation evidence is unverified")' not in proxy:
        raise ValueError("formal gate contract changed; source audit must be renewed")
    if events != {"loaded", "invoked", "health-observed"}:
        raise ValueError(
            "compiled event contract changed; do not invent semantic readiness"
        )
    source_checks = {}
    for study in ("h3", "h4"):
        tree = ast.parse(
            (root / f"experiments/formal_campaign/{study}_registration.py").read_text()
        )
        main = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        repos = [
            node.args[2].value
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "observe_merged_source"
            and isinstance(node.args[2], ast.Constant)
        ]
        source_checks[study] = repos
    arms, schedule = protocol["arms"], protocol["schedule"]
    planned = {}
    for study in ("h3", "h4"):
        cells = []
        for cell in protocol[study]["required_cells"]:
            rows = [
                dict(
                    start_id=f"{cell}-r{rep}-{arm}",
                    arm=arm,
                    repetition=rep,
                    order=order,
                    status="unverified",
                    executable=False,
                )
                for rep, sequence in enumerate(schedule, 1)
                for order, arm in enumerate(sequence, 1)
            ]
            cells.append(
                dict(
                    cell_id=cell,
                    starts=rows,
                    source_support="unverified",
                    formal_starts_completed=0,
                )
            )
        planned[study] = dict(
            required_cells=cells,
            planned_starts=len(cells) * 9,
            formal_starts_completed=0,
            thresholds=copy.deepcopy(protocol[study].get("thresholds")),
            objective_rate_minimum=protocol[study].get("objective_rate_minimum"),
        )
    return dict(
        schema="ecpa-semantic-prospective-campaign-readiness/v1",
        classification="SOURCE_PREREGISTRATION_DRAFT_ONLY",
        formal_result=False,
        performance_result=False,
        score_eligible=False,
        executable=False,
        source_sha256={p: sha((root / p).read_bytes()) for p in FILES},
        protocol_sha256=sha((root / FILES[0]).read_bytes()),
        compiled_events=sorted(events),
        issuer_legacy_merged_repository_checks=source_checks,
        new_issuer_full_tuple_policy="explicit-preregistered-published-commit-or-merged-main",
        full_tuple_deployment_source_observation="unverified-no-live-deployment-input",
        current_semantic_gate="fail-closed-unverified",
        old_effective_aggregation_exists=True,
        old_effective_aggregation_is_new_typed_admission=False,
        matched_arms=arms,
        independent_starts_per_arm=3,
        schedule=schedule,
        planned_campaigns=planned,
        missing_formal_edges=[
            "explicit-semantic-obligation-and-required-bounded-effect-predicate",
            "registered-source-owned-producer-to-compiled-Plan-obligation",
            "live-authority-consumption-of-typed-tensor-OP-chain-before-route-open",
            "controller-instance-generation-membership-epoch-and-lease-binding",
            "semantic-freshness-invalidation-on-worker-replacement-and-observer-loss",
            "closed-public-route-private-authority-probe-and-live-response-binding",
            "all-required-extension-classes-and-compositions-not-only-KV-single-request",
            "actual-full-runtime-provider-source-observation-for-the-future-deployment",
        ],
        prospective_identity={
            key: None
            for key in (
                "host_commit",
                "accelerator_commit",
                "plugin_commits",
                "wheel_digests",
                "model_digest",
                "workload_digest",
                "container_digest",
                "warm_state",
                "api_protocol_capabilities",
                "authority_generation_policy",
            )
        },
        invariants=[
            "no-retrofit-of-successful-Tensor-R1-or-CPU-qualification",
            "every-original-required-cell-retained-even-unsupported-unverified",
            "no-ECPA-native-prepare-recovery-in-baseline-arms",
            "same-model-workload-stack-topology-warm-state-and-source-scope-per-pair",
            "freeze-fault-objective-and-bounded-clienttrace-before-first-launch",
            "timeout-loss-not-execution-loss-and-admission-duplicate-not-sideeffect-duplicate",
            "do-not-convert-unknown-client-window-metrics-to-zero",
            "own-PID-start-boot-session-and-port-device-cleanup-per-start",
            "do-not-terminate-externally-owned-services",
            "retain-raw-failures-drift-and-threshold-violations",
        ],
        h4_startup_interpretation="violation-only-if-percent-and-absolute-both-exceed",
        h4_measurement_scope="control-plane-cost-not-MOD-performance-benefit",
        unknown_objectives={
            key: None
            for key in (
                "max_recovery_ms",
                "max_lost_requests",
                "max_execution_duplicates",
                "max_operator_actions",
                "expected_final_route",
                "allowed_rollback_classifications",
            )
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(build(), sort_keys=True, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
