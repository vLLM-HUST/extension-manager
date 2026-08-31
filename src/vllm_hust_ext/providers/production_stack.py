"""Render-only provider for vLLM Production Stack and Kubernetes resources."""

from __future__ import annotations

import json
from typing import Any

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)


class ProductionStackProvider:
    name = "production-stack"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        values = configuration.get("values", {})
        if not isinstance(values, dict):
            raise ValueError("Production Stack values must be an object")
        chart = str(configuration.get("chart", "vllm/vllm-stack"))
        release = str(configuration.get("release", "vllm"))
        namespace = str(configuration.get("namespace", "default"))
        generated = {
            "chart": chart,
            "release": release,
            "namespace": namespace,
            "values": values,
            "enabled": enabled,
        }
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            (
                PlanAction("helm_template", chart, "kubernetes"),
                PlanAction("server_dry_run", namespace, "kubernetes"),
                PlanAction("check_rollout", release, "kubernetes"),
            ),
            generated,
            (
                "Rendering is non-mutating. Applying Helm releases, CRDs, "
                "controllers, routers, autoscalers, or OCI images remains an "
                "explicit Kubernetes operator action.",
            ),
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        values = plan.generated_config["values"]
        commands = {
            "render": "helm template <release> <chart> -f values.json",
            "validate": "kubectl apply --dry-run=server -f rendered.yaml",
            "apply": None,
        }
        return (
            RenderArtifact(
                "values.json",
                "application/json",
                json.dumps(values, indent=2, sort_keys=True),
            ),
            RenderArtifact(
                "operator-plan.json",
                "application/json",
                json.dumps(commands, indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        compatible, compatibility_evidence = assess_compatibility(
            manifest, configuration
        )
        values = configuration.get("values")
        configured = isinstance(values, dict)
        reachable = configuration.get("cluster_reachable")
        healthy = configuration.get("rollout_healthy")
        if reachable is not None and not isinstance(reachable, bool):
            return ProviderCheck(
                compatible,
                False,
                evidence=compatibility_evidence
                + ("cluster_reachable must be boolean",),
            )
        if healthy is not None and not isinstance(healthy, bool):
            return ProviderCheck(
                compatible,
                False,
                evidence=compatibility_evidence + ("rollout_healthy must be boolean",),
            )
        degraded = reachable is False or healthy is False
        return ProviderCheck(
            compatible,
            configured,
            reachable=reachable,
            healthy=healthy,
            degraded=degraded,
            evidence=compatibility_evidence + ("no cluster mutation was attempted",),
        )
