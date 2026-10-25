"""Independent actual two-policy typed Plan compiler for unregistered qualification.

New source-owned domain; it neither borrows KV/profiler effect obligations nor
claims public-release or transactional safety. Actual original providers and
whole runtime/source preflight must accept before invoking this compiler.
"""

from __future__ import annotations

import hashlib
import json
from importlib.metadata import version


def compile_actual(phase, bundles, configuration, original_schedule):
    from vllm_hust_ext.core import reject_conflicting_plans
    from vllm_hust_ext.ecpa_model import (
        EvidenceObligation,
        HostCompatibility,
        Plan,
        PredecessorSnapshot,
        ResourceClaim,
    )
    from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes
    from vllm_hust_ext.providers.vllm import VllmProvider
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    ordered = sorted(bundles, key=lambda b: b.bundle_id)
    if {b.bundle_id for b in ordered} != {
        "org.vllm-hust.pipeline-microbatch",
        "org.vllm-hust.bidkv",
    }:
        raise ValueError("exact actual policy pair required")
    plugins, snapshots = installed_plugin_identities(ordered)
    projections = tuple(
        VllmProvider().plan(
            b.manifest, configuration.extension(b.bundle_id).configuration, enabled=True
        )
        for b in ordered
    )
    reject_conflicting_plans(projections)
    inputs = dict(
        schema="ecpa-h4-conditional-source-intent/v1",
        argv=phase["argv"],
        cwd=phase["cwd"],
        generated_projections={p.extension_id: p.generated_config for p in projections},
        actual_manifest_payloads=snapshots,
        original_schedule=original_schedule,
        environment_sha256=hashlib.sha256(
            json.dumps(
                {
                    k: v
                    for k, v in phase["environment"].items()
                    if k not in ("VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID")
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    )
    claims = tuple(
        ResourceClaim(
            "urn:ecpa:resource:" + claim.scope + "." + claim.resource,
            plugin.id,
            "shared-read" if claim.mode == "shared" else claim.mode,
        )
        for bundle, plugin in zip(ordered, plugins, strict=True)
        for claim in bundle.manifest.resource_claims
    )
    observed_event = (
        "resolved"
        if phase["environment"]["ECPA_H4_CONDITIONAL_MODE"] == "lifecycle-only"
        else "invoked"
    )
    obligations = tuple(
        EvidenceObligation(
            "conditional:" + bundle.bundle_id + ":actual-scheduler-" + observed_event,
            "engine-core-scheduler",
            observed_event,
            (0,),
        )
        for bundle in ordered
    )
    plan = Plan(
        tuple(plugins),
        HostCompatibility("vllm", version("vllm"), "vllm", "1.0"),
        claims,
        obligations,
        PredecessorSnapshot(0, None, inputs),
        False,
    )
    raw = plan_artifact_bytes(plan)
    if parse_plan_artifact(raw) != plan:
        raise ValueError("canonical typed Plan roundtrip failed")
    return plan, raw
