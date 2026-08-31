from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.error import URLError

import pytest

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import LifecycleState, plan_for, status_for
from vllm_hust_ext.manifest import BundleManifest, parse_manifest
from vllm_hust_ext.providers.mooncake import MooncakeProvider
from vllm_hust_ext.providers.production_stack import ProductionStackProvider
from vllm_hust_ext.providers.vllm import VllmProvider

FIXTURES = Path(__file__).parent / "fixtures"


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


def test_core_rejects_provider_generated_mutation() -> None:
    value = manifest("bidkv-v0.2.json")
    plan = plan_for(
        bundle(value),
        ExtensionConfig(True, {}),
        include_external_providers=False,
    )
    assert all(not action.mutating for action in plan.actions)
