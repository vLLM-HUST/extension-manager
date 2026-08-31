"""Non-invasive provider for LMCache services and official vLLM connectors."""

from __future__ import annotations

import json
from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from vllm_hust_ext.manifest import BundleManifest
from vllm_hust_ext.providers.base import (
    PlanAction,
    ProviderCheck,
    ProviderPlan,
    RenderArtifact,
    assess_compatibility,
)

_CONNECTORS = {
    "LMCacheMPConnector",
    "LMCacheConnectorV1",
    "LMCacheConnectorV1Dynamic",
    "LMCacheAscendConnector",
    "LMCacheAscendConnectorV1Dynamic",
}
_DEFAULT_MODULE_PATHS = {
    "LMCacheConnectorV1Dynamic": "lmcache.integration.vllm.lmcache_connector_v1",
    "LMCacheAscendConnectorV1Dynamic": (
        "lmcache_ascend.integration.vllm.lmcache_ascend_connector_v1"
    ),
}
_ALLOWED_MODULE_PATHS = {
    "LMCacheConnectorV1Dynamic": {
        "lmcache.integration.vllm.lmcache_connector_v1",
    },
    "LMCacheAscendConnectorV1Dynamic": {
        "lmcache_ascend.integration.vllm.lmcache_ascend_connector_v1",
    },
}


class LMCacheProvider:
    name = "lmcache"

    def supports(self, manifest: BundleManifest) -> bool:
        return manifest.host.provider == self.name

    def _connector_config(self, configuration: dict[str, Any]) -> dict[str, Any]:
        connector = configuration.get("connector", "LMCacheMPConnector")
        if connector not in _CONNECTORS:
            raise ValueError(f"unsupported official LMCache connector: {connector}")
        role = configuration.get("kv_role", "kv_both")
        if role not in {"kv_producer", "kv_consumer", "kv_both"}:
            raise ValueError(f"unsupported LMCache KV role: {role}")

        result: dict[str, Any] = {"kv_connector": connector, "kv_role": role}
        extra = configuration.get("kv_connector_extra_config", {})
        if not isinstance(extra, dict):
            raise ValueError("kv_connector_extra_config must be an object")
        if extra:
            result["kv_connector_extra_config"] = extra

        module_path = configuration.get(
            "kv_connector_module_path", _DEFAULT_MODULE_PATHS.get(connector)
        )
        if module_path is not None:
            allowed_paths = _ALLOWED_MODULE_PATHS.get(connector, set())
            if not isinstance(module_path, str) or module_path not in allowed_paths:
                raise ValueError(
                    "kv_connector_module_path does not match the selected official "
                    f"LMCache connector {connector}"
                )
            result["kv_connector_module_path"] = module_path
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
        warnings = (
            (
                "LMCache service and cache-data lifecycle remain owned by the "
                "external operator; the manager will not start, stop, upgrade, "
                "clear, evict, or delete them."
            )
            if manifest.requires_services
            else (
                "LMCache runtime and platform-backend lifecycle remain owned by "
                "the host operator; the manager only renders the vLLM connector "
                "configuration and will not import or mutate the backend."
            )
        )
        return ProviderPlan(
            manifest.bundle_id,
            self.name,
            tuple(actions),
            {"kv_transfer_config": connector},
            (warnings,),
        )

    def render(self, plan: ProviderPlan) -> tuple[RenderArtifact, ...]:
        return (
            RenderArtifact(
                "lmcache-vllm-connector.json",
                "application/json",
                json.dumps(plan.generated_config, indent=2, sort_keys=True),
            ),
        )

    def check(
        self, manifest: BundleManifest, configuration: dict[str, Any]
    ) -> ProviderCheck:
        detected_version = None
        distribution = (
            "lmcache-ascend"
            if manifest.host.name.casefold() == "lmcache-ascend"
            else "lmcache"
        )
        with suppress(PackageNotFoundError):
            detected_version = version(distribution)
        compatible, compatibility_evidence = assess_compatibility(
            manifest,
            configuration,
            detected_host_version=detected_version,
            default_api_version="1.0",
            default_protocol_versions={
                "lmcache-mp-service": "1.0",
                "vllm-kv-connector": "1.0",
            },
        )
        if compatible is False:
            return ProviderCheck(False, False, evidence=compatibility_evidence)
        try:
            self._connector_config(configuration)
        except ValueError as error:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence + (str(error),),
            )

        health_url = configuration.get("health_url")
        if not health_url:
            required = bool(manifest.requires_services)
            return ProviderCheck(
                compatible,
                not required,
                degraded=required,
                evidence=compatibility_evidence
                + ("health_url is required to verify the LMCache service",),
            )
        parsed = urlparse(str(health_url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ProviderCheck(
                compatible,
                False,
                degraded=True,
                evidence=compatibility_evidence
                + ("health_url must be an absolute HTTP(S) URL",),
            )
        try:
            request = Request(str(health_url), method="GET")
            with urlopen(request, timeout=2) as response:  # noqa: S310
                healthy = 200 <= response.status < 300
                return ProviderCheck(
                    compatible,
                    True,
                    reachable=True,
                    healthy=healthy,
                    degraded=not healthy,
                    evidence=compatibility_evidence
                    + (f"LMCache health endpoint returned {response.status}",),
                )
        except HTTPError as error:
            return ProviderCheck(
                compatible,
                True,
                reachable=True,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + (f"LMCache health endpoint returned {error.code}",),
            )
        except (OSError, URLError) as error:
            return ProviderCheck(
                compatible,
                True,
                reachable=False,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + (f"LMCache service is unreachable: {error}",),
            )
