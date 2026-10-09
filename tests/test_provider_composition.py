"""Joint plans must agree with the host CLI's actual merge boundaries."""

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from vllm_hust_ext.cli import _activation_config, _activation_environment
from vllm_hust_ext.core import reject_conflicting_plans
from vllm_hust_ext.manifest import BundleActivation, ResourceClaim, parse_manifest
from vllm_hust_ext.providers.base import ConfigClaim, ProviderPlan
from vllm_hust_ext.providers.vllm import VllmProvider


def make_plan(bundle_id, *, environment=(), additional_config=(), configuration=None):
    manifest = parse_manifest(
        json.loads(
            (Path(__file__).parent / "fixtures/worker-class-v0.3.json").read_text()
        )
    )
    manifest = replace(
        manifest,
        bundle_id=bundle_id,
        components=(),
        activation=BundleActivation(
            environment=environment,
            additional_config=additional_config,
        ),
    )
    bundle = SimpleNamespace(bundle_id=bundle_id, manifest=manifest)
    return bundle, VllmProvider().plan(manifest, configuration or {}, enabled=True)


def test_adapter_and_method_with_distinct_native_metadata_compose():
    adapter, first = make_plan(
        "org.example.adapter",
        environment=(("KV_ENABLED", "1"),),
        configuration={"method": "pyramidkv", "budget": 1368},
    )
    method, second = make_plan("org.example.method")
    assert (
        first.generated_config["native_extension_manifest"]
        != (second.generated_config["native_extension_manifest"])
    )
    reject_conflicting_plans((first, second))
    environment = _activation_environment((adapter, method), (first, second))
    assert environment["KV_ENABLED"] == "1"
    assert environment["VLLMHUST_EXT_ENABLED_BUNDLES"] == (
        "org.example.adapter,org.example.method"
    )


def test_disjoint_and_identical_host_keys_compose():
    adapter, first = make_plan(
        "org.example.first",
        environment=(("A", "1"), ("SAME", "yes")),
        additional_config=(("a", {"enabled": True}),),
    )
    method, second = make_plan(
        "org.example.second",
        environment=(("B", "2"), ("SAME", "yes")),
        additional_config=(("b", 2),),
    )
    reject_conflicting_plans((first, second))
    assert _activation_environment((adapter, method), (first, second))["B"] == "2"
    assert _activation_config((adapter, method)) == {
        "a": {"enabled": True},
        "b": 2,
    }


@pytest.mark.parametrize(
    "field, kwargs",
    [
        ("environment.SAME", {"environment": (("SAME", "different"),)}),
        ("additional_config.policy", {"additional_config": (("policy", {"b": 2}),)}),
    ],
)
def test_conflicting_shared_values_still_fail(field, kwargs):
    _, first = make_plan(
        "org.example.first",
        environment=(("SAME", "original"),),
        additional_config=(("policy", {"a": 1}),),
    )
    _, second = make_plan("org.example.second", **kwargs)
    with pytest.raises(ValueError, match="conflict on vllm." + field):
        reject_conflicting_plans((first, second))


def test_json_options_are_atomic_per_cli_option():
    _, first = make_plan(
        "org.example.first",
        configuration={
            "launch_options": {"speculative_config": {"method": "mtp"}},
        },
    )
    _, second = make_plan(
        "org.example.second",
        configuration={
            "launch_options": {"speculative_config": {"num_speculative_tokens": 2}},
        },
    )
    with pytest.raises(ValueError, match="vllm_json_options.--speculative-config"):
        reject_conflicting_plans((first, second))
    _, third = make_plan(
        "org.example.third",
        configuration={
            "launch_options": {"batch_admission_policy_config": {"budget": 2}},
        },
    )
    reject_conflicting_plans((first, third))


def test_projection_cannot_bypass_exclusive_resource_claim():
    claim = ResourceClaim("scheduler", "vllm-process", "exclusive")
    first = ProviderPlan("one", "vllm", (), resource_claims=(claim,), config_claims=())
    second = replace(first, extension_id="two")
    with pytest.raises(ValueError, match="exclusive versus exclusive"):
        reject_conflicting_plans((first, second))


def test_legacy_provider_keeps_whole_field_conflict_check():
    first = ProviderPlan("one", "external", (), {"settings": {"a": 1}})
    second = ProviderPlan("two", "external", (), {"settings": {"b": 2}})
    with pytest.raises(ValueError, match="external.settings"):
        reject_conflicting_plans((first, second))


def test_path_segments_do_not_conflate_dotted_environment_keys():
    first = ProviderPlan(
        "one", "vllm", (), config_claims=(ConfigClaim(("environment", "a.b"), "one"),)
    )
    second = ProviderPlan(
        "two", "vllm", (), config_claims=(ConfigClaim(("environment.a", "b"), "two"),)
    )
    reject_conflicting_plans((first, second))


def test_mixed_legacy_and_projected_plans_remain_conservative():
    _, projected = make_plan("org.example.projected", environment=(("A", "1"),))
    legacy = ProviderPlan("legacy", "vllm", (), {"environment": {"A": "2"}})
    for plans in ((legacy, projected), (projected, legacy)):
        with pytest.raises(ValueError, match="vllm.environment"):
            reject_conflicting_plans(plans)
