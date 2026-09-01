"""Non-invasive provider for LMCache services and official vLLM connectors."""

from __future__ import annotations

import json
from contextlib import suppress
from importlib.metadata import PackageNotFoundError, version
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
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
_ASCEND_CONNECTORS = {
    "LMCacheConnectorV1",
    "LMCacheAscendConnector",
    "LMCacheAscendConnectorV1Dynamic",
}
_REQUIRED_OPERATION_EVIDENCE = (
    "mode",
    "model",
    "backend",
    "stored_tokens",
    "hit_tokens",
    "retrieved_tokens",
    "failed_requests",
)


def _version_url(health_url: str, configured: object | None) -> str:
    value = str(configured) if configured is not None else ""
    if value:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("version_url must be an absolute HTTP(S) URL")
        return value
    parsed = urlparse(health_url)
    return urlunparse(
        parsed._replace(path="/lmc_version", params="", query="", fragment="")
    )


def _read_service_version(value: object) -> str:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict):
        for key in ("version", "lmcache_version", "lmc_version"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    raise ValueError("LMCache version endpoint returned an unsupported payload")


_DEFAULT_MODULE_PATHS = {
    "LMCacheConnectorV1": (
        "vllm_ascend.distributed.kv_transfer.kv_pool.lmcache_ascend_connector"
    ),
    "LMCacheConnectorV1Dynamic": "lmcache.integration.vllm.lmcache_connector_v1",
    "LMCacheAscendConnectorV1Dynamic": (
        "lmcache_ascend.integration.vllm.lmcache_ascend_connector_v1"
    ),
}
_ALLOWED_MODULE_PATHS = {
    "LMCacheConnectorV1": {
        "vllm_ascend.distributed.kv_transfer.kv_pool.lmcache_ascend_connector",
    },
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

    def _operation_evidence(
        self, configuration: dict[str, Any], connector: str
    ) -> tuple[bool | None, bool, tuple[str, ...]]:
        expected_mode = (
            "vllm_ascend_in_process"
            if connector in _ASCEND_CONNECTORS
            else "vllm_mp_connector"
        )
        raw = configuration.get("connector_operation_evidence")
        if raw is None:
            return (
                None,
                True,
                (
                    "connector_operation_evidence is required before this "
                    f"{expected_mode} path can be reported healthy",
                ),
            )
        if not isinstance(raw, dict):
            return False, False, ("connector_operation_evidence must be an object",)
        missing = [name for name in _REQUIRED_OPERATION_EVIDENCE if name not in raw]
        if missing:
            return (
                False,
                False,
                ("connector_operation_evidence is missing: " + ", ".join(missing),),
            )
        if raw["mode"] != expected_mode:
            return (
                False,
                False,
                (
                    "connector_operation_evidence.mode must be "
                    f"{expected_mode} for {connector}",
                ),
            )
        for name in ("model", "backend"):
            if not isinstance(raw[name], str) or not raw[name].strip():
                return (
                    False,
                    False,
                    (f"connector_operation_evidence.{name} must be non-empty",),
                )
        counts: dict[str, int] = {}
        for name in (
            "stored_tokens",
            "hit_tokens",
            "retrieved_tokens",
            "failed_requests",
        ):
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return (
                    False,
                    False,
                    (
                        f"connector_operation_evidence.{name} must be a "
                        "non-negative integer",
                    ),
                )
            counts[name] = value
        healthy = (
            counts["stored_tokens"] > 0
            and counts["hit_tokens"] > 0
            and counts["retrieved_tokens"] == counts["hit_tokens"]
            and counts["stored_tokens"] >= counts["hit_tokens"]
            and counts["failed_requests"] == 0
        )
        return (
            healthy,
            True,
            (
                "LMCache connector operations: "
                f"mode={expected_mode}, model={raw['model']}, "
                f"backend={raw['backend']}, stored={counts['stored_tokens']}, "
                f"hit={counts['hit_tokens']}, "
                f"retrieved={counts['retrieved_tokens']}, "
                f"failed_requests={counts['failed_requests']}",
            ),
        )

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
        try:
            connector_config = self._connector_config(configuration)
        except ValueError as error:
            return ProviderCheck(
                None,
                False,
                degraded=True,
                evidence=(str(error),),
            )
        connector = str(connector_config["kv_connector"])
        operations_healthy, operations_configured, operations_evidence = (
            self._operation_evidence(configuration, connector)
        )
        if not operations_configured:
            return ProviderCheck(
                None,
                False,
                degraded=True,
                evidence=operations_evidence,
            )

        if connector in _ASCEND_CONNECTORS:
            detected_versions: dict[str, str] = {}
            for distribution in ("vllm-ascend", "lmcache", "lmcache-ascend"):
                with suppress(PackageNotFoundError):
                    detected_versions[distribution] = version(distribution)
            protocol_versions = {"vllm-kv-connector": "1.0"}
            for distribution, protocol in (
                ("lmcache", "lmcache-runtime"),
                ("lmcache-ascend", "lmcache-ascend-runtime"),
            ):
                if distribution in detected_versions:
                    protocol_versions[protocol] = detected_versions[distribution]
            compatible, compatibility_evidence = assess_compatibility(
                manifest,
                configuration,
                detected_host_version=detected_versions.get("vllm-ascend"),
                default_api_version="1.0",
                default_protocol_versions=protocol_versions,
            )
            detected_evidence = tuple(
                f"detected {name} {value}"
                for name, value in sorted(detected_versions.items())
            )
            evidence = (
                detected_evidence + compatibility_evidence + operations_evidence
            )
            return ProviderCheck(
                compatible,
                True,
                healthy=operations_healthy is True and compatible is True,
                degraded=operations_healthy is not True or compatible is not True,
                evidence=evidence,
            )

        locally_detected_version = None
        if not manifest.requires_services:
            with suppress(PackageNotFoundError):
                locally_detected_version = version("lmcache")

        health_url = configuration.get("health_url")
        if not health_url:
            required = bool(manifest.requires_services)
            return ProviderCheck(
                None,
                not required,
                degraded=required or operations_healthy is not True,
                evidence=operations_evidence
                + ("health_url is required to verify the LMCache service",),
            )
        parsed = urlparse(str(health_url))
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ProviderCheck(
                None,
                False,
                degraded=True,
                evidence=("health_url must be an absolute HTTP(S) URL",),
            )
        try:
            service_version_url = _version_url(
                str(health_url), configuration.get("version_url")
            )
        except ValueError as error:
            return ProviderCheck(None, False, degraded=True, evidence=(str(error),))
        try:
            request = Request(str(health_url), method="GET")
            with urlopen(request, timeout=2) as response:  # noqa: S310
                healthy = 200 <= response.status < 300
                health_evidence = (
                    f"LMCache health endpoint returned {response.status}",
                )
                detected_version = locally_detected_version
                version_evidence: tuple[str, ...] = ()
                if healthy and "host_version" not in configuration:
                    try:
                        version_request = Request(service_version_url, method="GET")
                        with urlopen(version_request, timeout=2) as version_response:  # noqa: S310
                            if not 200 <= version_response.status < 300:
                                raise ValueError(
                                    "LMCache version endpoint returned "
                                    f"{version_response.status}"
                                )
                            detected_version = _read_service_version(
                                json.load(version_response)
                            )
                            version_evidence = (
                                "LMCache service version "
                                f"{detected_version} read from {service_version_url}",
                            )
                    except (
                        HTTPError,
                        OSError,
                        URLError,
                        ValueError,
                        json.JSONDecodeError,
                    ) as error:
                        version_evidence = (
                            f"LMCache service version is unavailable: {error}",
                        )
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
                return ProviderCheck(
                    compatible,
                    True,
                    reachable=True,
                    healthy=(
                        healthy
                        and operations_healthy is True
                        and compatible is True
                    ),
                    degraded=(
                        not healthy
                        or operations_healthy is not True
                        or compatible is not True
                    ),
                    evidence=(
                        health_evidence
                        + version_evidence
                        + compatibility_evidence
                        + operations_evidence
                    ),
                )
        except HTTPError as error:
            compatible, compatibility_evidence = assess_compatibility(
                manifest,
                configuration,
                detected_host_version=locally_detected_version,
                default_api_version="1.0",
                default_protocol_versions={
                    "lmcache-mp-service": "1.0",
                    "vllm-kv-connector": "1.0",
                },
            )
            return ProviderCheck(
                compatible,
                True,
                reachable=True,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + operations_evidence
                + (f"LMCache health endpoint returned {error.code}",),
            )
        except (OSError, URLError) as error:
            compatible, compatibility_evidence = assess_compatibility(
                manifest,
                configuration,
                detected_host_version=locally_detected_version,
                default_api_version="1.0",
                default_protocol_versions={
                    "lmcache-mp-service": "1.0",
                    "vllm-kv-connector": "1.0",
                },
            )
            return ProviderCheck(
                compatible,
                True,
                reachable=False,
                healthy=False,
                degraded=True,
                evidence=compatibility_evidence
                + operations_evidence
                + (f"LMCache service is unreachable: {error}",),
            )
