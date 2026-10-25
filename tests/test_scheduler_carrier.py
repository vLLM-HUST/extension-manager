"""Scheduler carriers select native classes without importing the implementation."""

import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from vllm_hust_ext.cli import _merge_provider_plan
from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_for, reject_conflicting_plans
from vllm_hust_ext.manifest import ResourceClaim, parse_manifest
from vllm_hust_ext.providers.base import ProviderPlan
from vllm_hust_ext.providers.vllm import VllmProvider

FIXTURE = Path(__file__).parent / "fixtures/scheduler-class-v0.3.json"
IMPLEMENTATION = "example_scheduler.scheduler.Scheduler"


def manifest():
    return parse_manifest(json.loads(FIXTURE.read_text()))


def test_scheduler_carrier_renders_native_selection_without_import():
    value = manifest()
    plan = VllmProvider().plan(value, {}, enabled=True)
    assert plan.generated_config["vllm_options"] == {"--scheduler-cls": IMPLEMENTATION}
    command = _merge_provider_plan(["vllm", "serve", "model"], plan)
    assert command == ["vllm", "serve", "model", "--scheduler-cls", IMPLEMENTATION]
    assert "example_scheduler" not in sys.modules
    assert all(not action.mutating for action in plan.actions)
    rendered = VllmProvider().render(plan)
    launch = next(row for row in rendered if row.name == "vllm-launch.json")
    assert json.loads(launch.content)["generated_config"]["vllm_options"] == {
        "--scheduler-cls": IMPLEMENTATION
    }


def test_multiple_scheduler_classes_fail_before_import():
    value = manifest()
    value = replace(value, components=(*value.components, value.components[0]))
    with pytest.raises(ValueError, match="exactly one vllm.scheduler-class.v1"):
        VllmProvider().plan(value, {}, enabled=True)


@pytest.mark.parametrize("planes", [(), ("worker",), ("scheduler", "worker")])
def test_scheduler_plane_is_exclusive(planes):
    value = manifest()
    value = replace(
        value, components=(replace(value.components[0], execution_planes=planes),)
    )
    with pytest.raises(ValueError, match="only the scheduler plane"):
        VllmProvider().plan(value, {}, enabled=True)


@pytest.mark.parametrize("field", ["component", "runtime", "owner"])
def test_scheduler_is_owned_by_trusted_vllm_process(field):
    value = manifest()
    if field == "component":
        value = replace(
            value,
            components=(replace(value.components[0], isolation="process_isolated"),),
        )
    elif field == "runtime":
        value = replace(
            value, runtime=replace(value.runtime, isolation="process_isolated")
        )
    else:
        value = replace(value, lifecycle_owner="external_operator")
    with pytest.raises(ValueError, match="vLLM-owned trusted_in_process"):
        VllmProvider().plan(value, {}, enabled=True)


@pytest.mark.parametrize("change", ["missing", "shared", "scope", "resource"])
def test_scheduler_requires_exact_exclusive_carrier_claim(change):
    value = manifest()
    claim = value.resource_claims[0]
    claims = {
        "missing": (),
        "shared": (replace(claim, mode="shared"),),
        "scope": (replace(claim, scope="vllm-process"),),
        "resource": (replace(claim, resource="vllm.scheduler.other"),),
    }[change]
    with pytest.raises(ValueError, match="exclusive.*resource claim"):
        VllmProvider().plan(replace(value, resource_claims=claims), {}, enabled=True)


def test_same_scheduler_class_cannot_be_owned_by_two_bundles():
    value = manifest()
    plans = tuple(
        plan_for(
            SimpleNamespace(
                bundle_id=bundle_id, manifest=replace(value, bundle_id=bundle_id)
            ),
            ExtensionConfig(True, {}),
            include_external_providers=False,
        )
        for bundle_id in ("org.example.one", "org.example.two")
    )
    with pytest.raises(ValueError, match="exclusive versus exclusive"):
        reject_conflicting_plans(plans)


def test_scheduler_and_worker_components_compose_in_one_bundle():
    value = manifest()
    worker = replace(
        value.components[0],
        component_id="worker-carrier",
        contracts=("vllm.worker-class.v1",),
        execution_planes=("worker",),
        implementation_ref="example_scheduler.worker:Worker",
    )
    value = replace(
        value,
        components=(*value.components, worker),
        resource_claims=(
            *value.resource_claims,
            ResourceClaim(
                "vllm.process-carrier.worker", "vllm-process-tree", "exclusive"
            ),
        ),
    )
    plan = VllmProvider().plan(value, {}, enabled=True)
    assert plan.generated_config["vllm_options"] == {
        "--scheduler-cls": IMPLEMENTATION,
        "--worker-cls": "example_scheduler.worker.Worker",
    }


def scalar_plan(option):
    return ProviderPlan(
        "org.example.carrier", "vllm", (), {"vllm_options": {option: IMPLEMENTATION}}
    )


@pytest.mark.parametrize(
    "option",
    [
        "--scheduler-cls",
        "--worker-cls",
        "--preemption-policy",
        "--batch-admission-policy",
    ],
)
@pytest.mark.parametrize(
    "tail",
    [
        ["FLAG", IMPLEMENTATION, "FLAG", "other.Class"],
        ["FLAG=" + IMPLEMENTATION, "FLAG=other.Class"],
        ["FLAG", IMPLEMENTATION, "FLAG=other.Class"],
        ["FLAG=" + IMPLEMENTATION, "FLAG", "other.Class"],
    ],
)
def test_later_scalar_override_cannot_escape_validation(option, tail):
    command = [
        "vllm",
        "serve",
        "model",
        *(item.replace("FLAG", option) for item in tail),
    ]
    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(command, scalar_plan(option))


@pytest.mark.parametrize(
    "tail",
    [
        ["--scheduler-cls"],
        ["--scheduler-cls="],
        ["--scheduler-cls", "--worker-cls", "worker.Class"],
        ["--scheduler-cls", IMPLEMENTATION, "--scheduler-cls"],
        ["--scheduler-cls", "--", "model"],
    ],
)
def test_missing_scalar_value_is_rejected(tail):
    with pytest.raises(ValueError, match="requires a value"):
        _merge_provider_plan(["vllm", "serve", *tail], scalar_plan("--scheduler-cls"))


def test_identical_scalar_duplicates_preserve_existing_command():
    command = [
        "vllm",
        "serve",
        "model",
        "--scheduler-cls",
        IMPLEMENTATION,
        "--scheduler-cls=" + IMPLEMENTATION,
    ]
    assert _merge_provider_plan(command, scalar_plan("--scheduler-cls")) == command


def test_generated_scalar_is_inserted_before_end_of_options():
    assert _merge_provider_plan(
        ["vllm", "serve", "--", "model"], scalar_plan("--scheduler-cls")
    ) == ["vllm", "serve", "--scheduler-cls", IMPLEMENTATION, "--", "model"]


@pytest.mark.parametrize(
    "suffix",
    [["--scheduler-cls", IMPLEMENTATION], ["--scheduler-cls=" + IMPLEMENTATION]],
)
def test_managed_scalar_after_end_of_options_cannot_count_as_activation(suffix):
    with pytest.raises(ValueError, match="cannot follow the -- separator"):
        _merge_provider_plan(
            ["vllm", "serve", "model", "--", *suffix], scalar_plan("--scheduler-cls")
        )


@pytest.mark.parametrize(
    "option",
    [
        "--scheduler-cls",
        "--worker-cls",
        "--preemption-policy",
        "--batch-admission-policy",
    ],
)
@pytest.mark.parametrize("equals", [False, True])
def test_native_underscore_alias_cannot_override_a_matching_selector(option, equals):
    alias = "--" + option[2:].replace("-", "_")
    tail = [alias + "=other.Class"] if equals else [alias, "other.Class"]
    with pytest.raises(ValueError, match="conflicts"):
        _merge_provider_plan(
            ["vllm", "serve", "model", option, IMPLEMENTATION, *tail],
            scalar_plan(option),
        )


def test_native_underscore_alias_with_matching_value_is_preserved():
    command = ["vllm", "serve", "model", "--scheduler_cls=" + IMPLEMENTATION]
    assert _merge_provider_plan(command, scalar_plan("--scheduler-cls")) == command


@pytest.mark.parametrize("suffix", [["--scheduler_cls"], ["--scheduler_cls="]])
def test_native_underscore_alias_missing_value_is_rejected(suffix):
    with pytest.raises(ValueError, match="requires a value"):
        _merge_provider_plan(["vllm", "serve", *suffix], scalar_plan("--scheduler-cls"))


def test_native_underscore_alias_after_separator_is_rejected():
    with pytest.raises(ValueError, match="cannot follow the -- separator"):
        _merge_provider_plan(
            ["vllm", "serve", "--", "--scheduler_cls=" + IMPLEMENTATION],
            scalar_plan("--scheduler-cls"),
        )


@pytest.mark.parametrize("key", ["--scheduler-cl", "--scheduler_cl", "--worker-cl"])
@pytest.mark.parametrize("equals", [False, True])
def test_native_argparse_abbreviation_is_not_an_override_escape(key, equals):
    option = "--worker-cls" if key.startswith("--worker") else "--scheduler-cls"
    tail = [key + "=other.Class"] if equals else [key, "other.Class"]
    with pytest.raises(ValueError, match="abbreviated managed option"):
        _merge_provider_plan(
            ["vllm", "serve", "model", option, IMPLEMENTATION, *tail],
            scalar_plan(option),
        )
