"""Provider for vLLM-owned in-process extension points."""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import asdict
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
            default_protocol_versions={},
        )
        return ProviderCheck(
            compatible=compatible,
            configured=compatible is not False,
            degraded=compatible is None,
            evidence=evidence + ("vLLM launch configuration can be rendered",),
        )
