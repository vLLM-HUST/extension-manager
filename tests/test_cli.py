from types import SimpleNamespace

import pytest

from vllmhust.cli import (
    _activation_environment,
    _merge_command_config,
)
from vllmhust.manifest import BundleActivation


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
        "VLLMHUST_ENABLED_BUNDLES": "org.vllm-hust.bidkv",
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
