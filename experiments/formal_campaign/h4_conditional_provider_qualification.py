"""Separate UNREGISTERED source/runtime qualification preparation for two policies.

Existing VllmProvider.supports/check/plan and the Manager serving CLI are untouched.
No returned object is a ProviderCheck, deployment receipt, accepted formal Plan,
or runtime_qualification.status=passed. This entry cannot authorize Manager run.
"""

from __future__ import annotations

import inspect
from dataclasses import fields
from importlib.metadata import version

IDS = {"org.vllm-hust.pipeline-microbatch", "org.vllm-hust.bidkv"}


def require(value, why):
    if not value:
        raise ValueError(why)


def prepare_unregistered(
    *, phase, fixed, repositories, runtime_wheels, bundles, configuration
):
    from vllm.v1.core.sched import batch_admission as admission
    from vllm.v1.core.sched import preemption

    from experiments.formal_campaign.h3_runtime_source_closure import (
        verify_runtime_source_closure,
    )
    from vllm_hust_ext.capabilities import detect_vllm_capabilities
    from vllm_hust_ext.core import reject_conflicting_plans
    from vllm_hust_ext.providers.base import assess_compatibility
    from vllm_hust_ext.providers.vllm import VllmProvider

    require(
        {b.bundle_id for b in bundles} == IDS and len(bundles) == 2,
        "exact genuine two-policy pair required",
    )
    require(
        set(configuration.enabled) == IDS,
        "actual two policies must be explicitly selected",
    )
    closure = verify_runtime_source_closure(phase, fixed, repositories, runtime_wheels)
    capabilities = detect_vllm_capabilities()
    require(
        capabilities.source == "vllm.plugins.extension_capabilities"
        and capabilities.host_api_version == "1.0"
        and capabilities.protocol_versions.get("vllm.batch-admission-policy") == "1.1"
        and capabilities.protocol_versions.get("vllm.preemption-policy") == "1.0",
        "actual independently source-owned Host registry/ABI required",
    )
    require(
        admission.BATCH_ADMISSION_POLICY_API_VERSION == "1.1"
        and preemption.PREEMPTION_POLICY_API_VERSION == "1.0",
        "actual implementation API constants differ",
    )
    require(
        list(
            inspect.signature(
                admission.BatchAdmissionPolicyController.admit_batch
            ).parameters
        )
        == ["self", "context"]
        and list(
            inspect.signature(
                preemption.PreemptionPolicyController.select_victim
            ).parameters
        )
        == ["self", "context"],
        "actual dispatcher ABI differs",
    )
    require(
        {f.name for f in fields(admission.BatchAdmissionContext)}
        == {
            "requests",
            "in_flight_batch_ids",
            "max_concurrent_batches",
            "pipeline_parallel_size",
            "now",
        },
        "actual Pipeline immutable context ABI differs",
    )
    require(
        {f.name for f in fields(preemption.PreemptionContext)}
        == {
            "candidates",
            "scheduling_policy",
            "requesting_request_id",
            "kv_cache_usage",
            "now",
            "builtin_victim_id",
        },
        "actual BidKV immutable context ABI differs",
    )
    plans = []
    for bundle in bundles:
        extension = configuration.extension(bundle.bundle_id)
        require(
            not (
                {
                    "host_version",
                    "host_api_version",
                    "protocol_versions",
                    "runtime_qualification",
                }
                & extension.configuration.keys()
            ),
            "caller compatibility/qualification override forbidden",
        )
        compatible, reasons = assess_compatibility(
            bundle.manifest,
            extension.configuration,
            detected_host_version=version(bundle.manifest.host.name),
            default_api_version=capabilities.host_api_version,
            default_protocol_versions=capabilities.protocol_versions,
        )
        require(
            compatible is True,
            "new actual source declaration does not cover detected Host: "
            + repr(reasons),
        )
        # These renderable launch projections are for the explicit unregistered
        # direct-Host experiment only; normal Manager check still demands actual
        # qualification and cannot consume this preparation dictionary.
        plans.append(
            VllmProvider().plan(bundle.manifest, extension.configuration, enabled=True)
        )
    reject_conflicting_plans(tuple(plans))
    options = {
        p.extension_id: p.generated_config.get("vllm_options", {}) for p in plans
    }
    require(
        options["org.vllm-hust.pipeline-microbatch"].get("--batch-admission-policy")
        == "vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy"
        and options["org.vllm-hust.bidkv"].get("--preemption-policy")
        == "bidkv.adapters.vllm_hust.selector.BidkvPreemptionPolicy",
        "actual provider policy projections changed",
    )
    return dict(
        schema="ecpa-h4-unregistered-scheduler-pair-preparation/v1",
        actual_source_closure=closure,
        actual_options=options,
        formal_result=False,
        deployment_receipt=None,
        qualification_status=None,
    )
