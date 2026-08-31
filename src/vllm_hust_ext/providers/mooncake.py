"""Non-invasive provider for official Mooncake services and vLLM connectors."""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
)

_CONNECTORS = {"MooncakeConnector", "MooncakeStoreConnector"}


class MooncakeProvider:
    name = "mooncake"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def _connector_config(self, configuration: dict[str, Any]) -> dict[str, Any]:
        connector = configuration.get("connector", "MooncakeConnector")
        if connector not in _CONNECTORS:
            raise ValueError(f"unsupported official Mooncake connector: {connector}")
        role = configuration.get("kv_role", "kv_both")
        if role not in {"kv_producer", "kv_consumer", "kv_both"}:
            raise ValueError(f"unsupported Mooncake KV role: {role}")
        result: dict[str, Any] = {"kv_connector": connector, "kv_role": role}
        extra = configuration.get("kv_connector_extra_config", {})
        if not isinstance(extra, dict):
            raise ValueError("kv_connector_extra_config must be an object")
        if extra:
            result["kv_connector_extra_config"] = extra
        return result

    def plan(
        self,
        manifest: BundleManifest,
        configuration: dict[str, Any],
        *,
        enabled: bool,
    ) -> ProviderPlan:
        connector = self._connector_config(configuration)
        actions = [
            PlanAction(
                "render_connector_config",
                "vllm",
                "vllm",
                details={"enabled": enabled},
            )
        ]
        for service in manifest.requires_services:
            actions.append(
                PlanAction(
                    "check_service",
                    service.service_id,
                    manifest.lifecycle_owner,
                    details={"protocol": service.protocol},
                )
            )
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            tuple(actions),
            {"kv_transfer_config": connector},
            (
                "Mooncake service lifecycle remains owned by its external operator; "
                "the manager will not start, stop, upgrade, or delete it.",
            ),
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        return (
            RenderArtifact(
                "mooncake-vllm-connector.json",
                "application/json",
                json.dumps(plan.generated_config, indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        try:
            self._connector_config(configuration)
        except ValueError as error:
            return ProviderCheck(False, False, evidence=(str(error),))
        health_url = configuration.get("health_url")
        if not health_url:
            required = bool(manifest.requires_services)
            return ProviderCheck(
                True,
                not required,
                degraded=required,
                evidence=("health_url is required to verify the external service",),
            )
        try:
            request = Request(str(health_url), method="GET")
            with urlopen(request, timeout=2) as response:  # noqa: S310
                healthy = 200 <= response.status < 300
                return ProviderCheck(
                    True,
                    True,
                    reachable=True,
                    healthy=healthy,
                    degraded=not healthy,
                    evidence=(f"Mooncake health endpoint returned {response.status}",),
                )
        except HTTPError as error:
            return ProviderCheck(
                True,
                True,
                reachable=True,
                healthy=False,
                degraded=True,
                evidence=(f"Mooncake health endpoint returned {error.code}",),
            )
        except (OSError, URLError) as error:
            return ProviderCheck(
                True,
                True,
                reachable=False,
                healthy=False,
                degraded=True,
                evidence=(f"Mooncake service is unreachable: {error}",),
            )
