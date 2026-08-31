from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import (
    LifecycleState,
    plan_for,
    reject_conflicting_plans,
    status_for,
)
from vllm_hust_ext.manifest import BundleManifest, parse_manifest
from vllm_hust_ext.providers.base import ProviderPlan
from vllm_hust_ext.providers.lmcache import LMCacheProvider
from vllm_hust_ext.providers.mooncake import MooncakeProvider
from vllm_hust_ext.providers.production_stack import ProductionStackProvider
from vllm_hust_ext.providers.vllm import VllmProvider

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLES = Path(__file__).parents[1] / "examples"


def manifest(name: str) -> BundleManifest:
    return parse_manifest(json.loads((FIXTURES / name).read_text(encoding="utf-8")))


def bundle(value: BundleManifest) -> SimpleNamespace:
    return SimpleNamespace(bundle_id=value.bundle_id, manifest=value)


def test_bidkv_is_a_vllm_owned_scheduler_policy() -> None:
    value = manifest("bidkv-v0.2.json")
    plan = VllmProvider().plan(value, {}, enabled=True)

    assert value.kind == "scheduler_policy"
    assert value.lifecycle_owner == "vllm"
    assert all(not action.mutating for action in plan.actions)
    assert plan.generated_config["additional_config"] == {
        "victim_selector_plugin": "bidkv"
    }


def test_mooncake_plan_reuses_official_connector_without_owning_service() -> None:
    value = manifest("mooncake-v0.2.json")
    plan = MooncakeProvider().plan(
        value,
        {"connector": "MooncakeStoreConnector", "kv_role": "kv_both"},
        enabled=True,
    )

    assert value.kind == "kv_service_adapter"
    assert value.lifecycle_owner == "external_operator"
    assert plan.generated_config["kv_transfer_config"]["kv_connector"] == (
        "MooncakeStoreConnector"
    )
    assert {action.operation for action in plan.actions} == {
        "render_connector_config",
        "check_service",
    }
    assert all(not action.mutating for action in plan.actions)


def test_mooncake_unreachable_is_degraded_not_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("mooncake-v0.2.json")

    def unreachable(*args: object, **kwargs: object) -> None:
        raise URLError("connection refused")

    monkeypatch.setattr("vllm_hust_ext.providers.mooncake.urlopen", unreachable)
    status = status_for(
        bundle(value),
        ExtensionConfig(True, {"health_url": "http://127.0.0.1:1/health"}),
        include_external_providers=False,
    )

    assert LifecycleState.ENABLED in status.states
    assert LifecycleState.DEGRADED in status.states
    assert LifecycleState.REACHABLE not in status.states


def test_lmcache_plan_uses_mp_connector_without_owning_cache_data() -> None:
    value = manifest("lmcache-v0.2.json")
    plan = LMCacheProvider().plan(
        value,
        {
            "connector": "LMCacheMPConnector",
            "kv_connector_module_path": (
                "lmcache.integration.vllm.lmcache_mp_connector"
            ),
            "kv_connector_extra_config": {
                "lmcache.mp.host": "lmcache.example",
                "lmcache.mp.port": 5555,
            },
        },
        enabled=True,
    )

    connector = plan.generated_config["kv_transfer_config"]
    assert connector["kv_connector"] == "LMCacheMPConnector"
    assert connector["kv_connector_module_path"].startswith("lmcache.integration.vllm.")
    assert {action.operation for action in plan.actions} == {
        "render_connector_config",
        "check_service",
    }
    assert all(not action.mutating for action in plan.actions)


def test_lmcache_unreachable_is_degraded_and_keeps_enabled_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest("lmcache-v0.2.json")

    def unreachable(*args: object, **kwargs: object) -> None:
        raise URLError("connection refused")

    monkeypatch.setattr("vllm_hust_ext.providers.lmcache.urlopen", unreachable)
    status = status_for(
        bundle(value),
        ExtensionConfig(True, {"health_url": "http://127.0.0.1:1/healthcheck"}),
        include_external_providers=False,
    )

    assert LifecycleState.ENABLED in status.states
    assert LifecycleState.DEGRADED in status.states
    assert LifecycleState.REACHABLE not in status.states


def test_lmcache_rejects_nonofficial_dynamic_connector_module() -> None:
    value = manifest("lmcache-v0.2.json")

    with pytest.raises(ValueError, match="official"):
        LMCacheProvider().plan(
            value,
            {
                "connector": "LMCacheMPConnector",
                "kv_connector_module_path": "untrusted.connector.module",
            },
            enabled=True,
        )


def test_production_stack_renders_but_never_applies() -> None:
    value = manifest("production-stack-v0.2.json")
    provider = ProductionStackProvider()
    plan = provider.plan(
        value,
        {"values": {"routerSpec": {"enableRouter": True}}},
        enabled=True,
    )
    artifacts = provider.render(plan)

    assert value.kind == "control_plane_extension"
    assert all(not action.mutating for action in plan.actions)
    assert all("apply" not in action.operation for action in plan.actions)
    operator_plan = json.loads(artifacts[1].content)
    assert operator_plan["apply"] is None

    check = provider.check(value, {"values": {}})
    assert check.compatible is None
    assert check.degraded is True


def test_core_rejects_provider_generated_mutation() -> None:
    value = manifest("bidkv-v0.2.json")
    plan = plan_for(
        bundle(value),
        ExtensionConfig(True, {}),
        include_external_providers=False,
    )
    assert all(not action.mutating for action in plan.actions)


def test_known_host_version_projects_compatible_or_incompatible() -> None:
    value = manifest("bidkv-v0.2.json")

    compatible = status_for(
        bundle(value),
        ExtensionConfig(True, {"host_version": "0.19.0"}),
        include_external_providers=False,
    )
    incompatible = status_for(
        bundle(value),
        ExtensionConfig(True, {"host_version": "0.20.0"}),
        include_external_providers=False,
    )

    assert LifecycleState.COMPATIBLE in compatible.states
    assert LifecycleState.INCOMPATIBLE in incompatible.states


def test_conflicting_provider_plans_are_rejected() -> None:
    plans = (
        ProviderPlan("one", "vllm", (), {"additional_config": {"policy": "a"}}),
        ProviderPlan("two", "vllm", (), {"additional_config": {"policy": "b"}}),
    )

    with pytest.raises(ValueError, match="conflict"):
        reject_conflicting_plans(plans)


@pytest.mark.parametrize(
    ("directory", "provider"),
    [
        ("lmcache-provider", "lmcache"),
        ("mooncake-provider", "mooncake"),
        ("production-stack-provider", "production-stack"),
    ],
)
def test_installable_provider_profiles_use_project_owned_namespace(
    directory: str, provider: str
) -> None:
    root = EXAMPLES / directory
    manifest_path = next(root.glob("src/*/manifests/vllm-hust-extension-v0.2.json"))
    value = parse_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")

    assert value.host.provider == provider
    assert '[project.entry-points."vllm_hust.extension_bundles"]' in pyproject
    assert "vllm.extension_bundles" not in pyproject
