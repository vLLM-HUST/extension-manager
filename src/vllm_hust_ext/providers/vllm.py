"""Provider for vLLM-owned in-process extension points."""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import asdict
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)


def _detect_protocol_versions() -> dict[str, str]:
    """Report only contracts exported by the installed vLLM host."""
    try:
        contracts = import_module("vllm.plugins.contracts")
        scheduler_policy = contracts.DomainContract.SCHEDULER_POLICY_V1
    except (AttributeError, ImportError):
        return {}
    if scheduler_policy.value != "vllm.scheduler.policy.v1":
        return {}
    return {"vllm.scheduler.policy": "1.0"}


class VllmProvider:
    name = "vllm"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        native_manifest = {
            "schema_version": "1.0",
            "bundle_id": manifest.bundle_id,
            "bundle_version": manifest.bundle_version,
            "host_api_range": manifest.host.api_range or ">=1,<2",
            "components": [
                {
                    "component_id": component.component_id,
                    "contracts": list(component.contracts),
                    "execution_planes": list(component.execution_planes),
                    "isolation": component.isolation,
                    "implementation_ref": component.implementation_ref,
                    "permissions": list(component.permissions),
                }
                for component in manifest.components
            ],
        }
        generated = {
            "environment": dict(manifest.activation.environment),
            "additional_config": dict(manifest.activation.additional_config),
            "native_extension_manifest": native_manifest,
            "user_config": configuration,
        }
        warnings = ()
        if manifest.kind == "scheduler_policy" and manifest.protocols:
            warnings = (
                "in-process scheduler activation requires explicit host and "
                "protocol compatibility evidence; run refuses unverified policies",
            )
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            (
                PlanAction(
                    "configure_launch",
                    "vllm",
                    manifest.lifecycle_owner,
                    details={"enabled": enabled},
                ),
            ),
            generated,
            warnings,
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        native_manifest = plan.generated_config.get("native_extension_manifest")
        artifacts = []
        if native_manifest is not None:
            artifacts.append(
                RenderArtifact(
                    "vllm-extension-manifest.json",
                    "application/json",
                    json.dumps(native_manifest, indent=2, sort_keys=True),
                )
            )
        artifacts.append(
            RenderArtifact(
                "vllm-launch.json",
                "application/json",
                json.dumps(asdict(plan), indent=2, sort_keys=True),
            )
        )
        return tuple(artifacts)

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        detected_version = None
        with suppress(PackageNotFoundError):
            detected_version = version("vllm")
        compatible, evidence = assess_compatibility(
            manifest,
            configuration,
            detected_host_version=detected_version,
            default_api_version="1.0",
            # A matching vLLM distribution version does not prove that a
            # fork-only or draft extension protocol is actually present.
            default_protocol_versions=_detect_protocol_versions(),
        )
        return ProviderCheck(
            compatible=compatible,
            configured=compatible is not False,
            degraded=compatible is None,
            evidence=evidence + ("vLLM launch configuration can be rendered",),
        )
