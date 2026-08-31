"""Provider for vLLM-owned in-process extension points."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
)


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
        generated = {
            "environment": dict(manifest.activation.environment),
            "additional_config": dict(manifest.activation.additional_config),
            "user_config": configuration,
        }
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
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        return (
            RenderArtifact(
                "vllm-launch.json",
                "application/json",
                json.dumps(asdict(plan), indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        compatible = self.supports(manifest)
        return ProviderCheck(
            compatible=compatible,
            configured=compatible,
            evidence=("vLLM launch configuration can be rendered",),
        )
