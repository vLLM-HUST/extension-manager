import json
from types import SimpleNamespace

import pytest

from vllm_hust_ext.cli import (
    _activation_environment,
    _merge_command_config,
    _merge_provider_plan,
)
from vllm_hust_ext.manifest import BundleActivation
from vllm_hust_ext.providers.base import PlanAction, ProviderPlan


def test_activation_does_not_replace_vllm_plugin_allowlist() -> None:
    bundle = SimpleNamespace(
        bundle_id="org.vllm-hust.bidkv",
        manifest=SimpleNamespace(
            activation=BundleActivation(environment=(("BIDKV_UTILITY_ENABLE", "1"),))
        ),
    )

    environment = _activation_environment((bundle,))

    assert environment == {
        "BIDKV_UTILITY_ENABLE": "1",
        "VLLM_HUST_EXT_ENABLED_BUNDLES": "org.vllm-hust.bidkv",
    }
    assert "VLLM_PLUGINS" not in environment


def test_run_merges_existing_additional_config() -> None:
    command = ["vllm", "serve", "model", "--additional-config", '{"user":1}']

    merged = _merge_command_config(command, {"victim_selector_plugin": "bidkv"})

    assert merged[-1] == '{"user":1,"victim_selector_plugin":"bidkv"}'


def test_run_rejects_activation_conflict() -> None:
    command = [
        "vllm",
        "serve",
        "model",
        "--additional-config",
        '{"victim_selector_plugin":"other"}',
    ]

    with pytest.raises(ValueError, match="conflicts"):
        _merge_command_config(command, {"victim_selector_plugin": "bidkv"})


def connector_plan(provider: str, connector: str) -> ProviderPlan:
    return ProviderPlan(
        f"org.vllm-hust.{provider}-provider",
        provider,
        (
            PlanAction(
                "render_connector_config",
                "vllm",
                "vllm",
                mutating=False,
            ),
        ),
        {
            "kv_transfer_config": {
                "kv_connector": connector,
                "kv_role": "kv_both",
            }
        },
    )


@pytest.mark.parametrize(
    ("provider", "connector"),
    [
        ("lmcache", "LMCacheMPConnector"),
        ("mooncake", "MooncakeStoreConnector"),
    ],
)
def test_run_merges_any_declared_vllm_connector_capability(
    provider: str, connector: str
) -> None:
    command = _merge_provider_plan(
        ["vllm", "serve", "model"], connector_plan(provider, connector)
    )

    assert command[-2] == "--kv-transfer-config"
    assert json.loads(command[-1])["kv_connector"] == connector


def test_run_rejects_two_connectors_claiming_vllm_transfer_config() -> None:
    command = _merge_provider_plan(
        ["vllm", "serve", "model"],
        connector_plan("mooncake", "MooncakeStoreConnector"),
    )

    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(
            command,
            connector_plan("lmcache", "LMCacheMPConnector"),
        )


def test_run_rejects_connector_config_without_declared_vllm_action() -> None:
    plan = ProviderPlan(
        "org.example.invalid",
        "invalid",
        (),
        {"kv_transfer_config": {"kv_connector": "Invalid"}},
    )

    with pytest.raises(ValueError, match="render_connector_config"):
        _merge_provider_plan(["vllm", "serve", "model"], plan)
