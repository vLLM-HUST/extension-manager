"""Portable canonical-src checks; fixtures do not establish native qualification."""

import hashlib
import json
from pathlib import Path

import pytest

from experiments.real_mod_composition.source_constraint_preflight import (
    checked_file,
    declared_topology,
    source_plans,
)
from vllm_hust_ext.core import plan_dict, reject_conflicting_plans
from vllm_hust_ext.providers.base import ConfigurationRequirement, ProviderPlan


def plans(tmp_path):
    rows = []
    for name, low, high in [("pipeline", 2, None), ("kv", 1, 1)]:
        original = Path(__file__).parent / "fixtures" / f"h2-source-{name}.json"
        manifest = tmp_path / f"{name}.json"
        manifest.write_bytes(original.read_bytes())
        data = json.loads(manifest.read_bytes())
        source = tmp_path / f"{name}.py"
        source.write_text("# tiny source binding fixture, not an implementation\n")

        def ref(p):
            return {
                "path": p.name,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }

        rows.append(
            {
                "source": ref(source),
                "manifest": ref(manifest),
                "owner": data["extension_id"],
                "version": data["extension_version"],
                "configuration_requirements": [
                    {
                        "path": ["parallel_config", "pipeline_parallel_size"],
                        "minimum": low,
                        "maximum": high,
                    }
                ],
            }
        )
    return source_plans(tmp_path, rows)


@pytest.mark.parametrize("pp", [1, 2, 3])
def test_disjoint_independent_source_predicates_reject_both_orders(tmp_path, pp):
    pair = plans(tmp_path)
    for order in [pair, tuple(reversed(pair))]:
        with pytest.raises(
            ValueError, match="CONFIGURATION_CONSTRAINT_CONFLICT"
        ) as error:
            reject_conflicting_plans(
                order,
                configuration_values={
                    ("vllm", "parallel_config", "pipeline_parallel_size"): pp
                },
            )
        assert "ascend-kvcompress requires [1, 1]" in str(error.value)
        assert "pipeline-microbatch requires [2, unbounded]" in str(error.value)


@pytest.mark.parametrize("index,pp", [(0, 2), (1, 1)])
def test_single_predicate_pass_is_not_reject_all(tmp_path, index, pp):
    reject_conflicting_plans(
        (plans(tmp_path)[index],),
        configuration_values={
            ("vllm", "parallel_config", "pipeline_parallel_size"): pp
        },
    )


@pytest.mark.parametrize("index,pp", [(0, 1), (1, 2)])
def test_single_unmet_constraint(tmp_path, index, pp):
    with pytest.raises(ValueError, match="CONFIGURATION_REQUIREMENT_UNMET"):
        reject_conflicting_plans(
            (plans(tmp_path)[index],),
            configuration_values={
                ("vllm", "parallel_config", "pipeline_parallel_size"): pp
            },
        )


def test_source_substitution_fails_binding(tmp_path):
    path = tmp_path / "source.py"
    path.write_bytes(b"original")
    ref = {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    assert checked_file(tmp_path, ref) == path
    path.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="SHA mismatch"):
        checked_file(tmp_path, ref)
    with pytest.raises(ValueError, match="beneath"):
        checked_file(tmp_path, {"path": "../source.py", "sha256": ref["sha256"]})


@pytest.mark.parametrize(
    "argv",
    [
        [
            "--pipeline-parallel-size=2",
            "--pipeline-parallel-size=1",
            "--tensor-parallel-size=1",
        ],
        ["--pipeline-parallel-size=0", "--tensor-parallel-size=1"],
        ["--tensor-parallel-size=1"],
    ],
)
def test_final_argv_rejects_ambiguous_or_missing_topology(argv):
    with pytest.raises(ValueError):
        declared_topology(argv)


def test_final_argv_no_override():
    assert (
        declared_topology(
            ["python", "--pipeline-parallel-size=2", "--tensor-parallel-size", "1"]
        )[("vllm", "parallel_config", "pipeline_parallel_size")]
        == 2
    )


def test_generic_other_setting_and_legacy_shape():
    def plan(owner, low, high):
        return ProviderPlan(
            owner,
            "vllm",
            (),
            configuration_requirements=(
                ConfigurationRequirement(("cache", "blocks"), low, high),
            ),
        )

    a, b = plan("one", 2, 4), plan("two", 3, 5)
    reject_conflicting_plans(
        (a, b), configuration_values={("vllm", "cache", "blocks"): 3}
    )
    with pytest.raises(ValueError, match="CONFIGURATION_REQUIREMENT_UNMET"):
        reject_conflicting_plans(
            (a, b), configuration_values={("vllm", "cache", "blocks"): True}
        )
    with pytest.raises(ValueError, match="CONFIGURATION_CONSTRAINT_CONFLICT"):
        reject_conflicting_plans((a, plan("other", 5, 8)))
    old = ProviderPlan("legacy", "vllm", ())
    reject_conflicting_plans((old,))
    assert "configuration_requirements" not in plan_dict(old)


def test_same_owner_duplicate_intervals_are_not_a_sorting_error():
    plan = ProviderPlan(
        "one",
        "vllm",
        (),
        configuration_requirements=(
            ConfigurationRequirement(("limit",), 2, None),
            ConfigurationRequirement(("limit",), 2, 4),
        ),
    )
    reject_conflicting_plans((plan,), configuration_values={("vllm", "limit"): 3})


@pytest.mark.parametrize("low,high", [(True, 3), (0, 1), (3, 2)])
def test_invalid_interval_is_not_an_admission(low, high):
    plan = ProviderPlan(
        "one",
        "vllm",
        (),
        configuration_requirements=(ConfigurationRequirement(("limit",), low, high),),
    )
    with pytest.raises(ValueError, match="INVALID_CONFIGURATION_REQUIREMENT"):
        reject_conflicting_plans((plan,))
