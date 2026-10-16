"""Native registration counterexamples; CPU declarations never formal evidence."""

import copy
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, ValidationError
from test_h3_dynamic_registration import candidate
from test_h3_native_source_scope import declared as declared
from test_h3_native_source_scope import planned_spec
from test_pair_semantic_binding import pair as pair

from experiments.formal_campaign import h3_native_registration as reg
from experiments.formal_campaign.h3_owned_worker_carrier import reference
from vllm_hust_ext import discovery
from vllm_hust_ext.ecpa_model import EvidenceObligation
from vllm_hust_ext.exposure_gate import GateError
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def complete_planned(declared):
    planned = planned_spec(declared)
    for req in planned["kv_requirements"].values():
        req.update(semantic_anchor=1201, physical_anchor=1024)
    return planned


def native_candidate(tmp_path, monkeypatch, declared):
    spec = candidate(tmp_path, monkeypatch)
    spec["schema"] = reg.DOMAIN
    intent = tmp_path / "CPU-intent-only.json"
    intent.write_text("{}")
    spec["original_native_intent"] = {
        "base_plan": reference(intent),
        "kv_contract": reference(intent),
    }
    campaign_path = tmp_path / "native-campaign.json"
    receipt_path = tmp_path / "native-receipt.json"
    checked = []

    def check_recipe(*args, native=False):
        assert native is True
        Draft7Validator(
            reg.load(reg.HERE / "h3-native-worker-recipe.schema.json")
        ).validate(args[0])
        checked.append(args[3])

    # This test isolates registration schema/commands/preflight. Native compiler
    # and actual runtime source admission have independent integration tests.
    monkeypatch.setattr(reg.common, "validate_recipe", check_recipe)
    original = reg.load(Path(spec["original_campaign"]["path"]))
    for start in spec["starts"]:
        root = Path(start["policy"]["path"]).parent
        recipe_path = Path(start["recipe_template"]["path"])
        recipe = reg.load(recipe_path)
        recipe["schema"] = "ecpa-h3-native-worker-recipe/v1"
        recipe["authority"]["source"] = reference(reg.HERE / reg.AUTHORITY_SOURCE)
        for index, phase in enumerate(recipe["arms"][start["arm"]]["phases"]):
            launch = root / f"semantic{index}.json"
            launch.write_bytes(
                reg.canonical(
                    {
                        "execution_plan_id": "plan:sha256:" + "1" * 64,
                        "candidate_generation": index + 1,
                        "membership_epoch": index,
                        "controller_instance": "controller:CPU-only",
                    }
                )
            )
            phase["semantic_launch_spec"] = reference(launch)
            guard = root / f"guard{index}.json"
            guard.write_bytes(
                reg.canonical(
                    {
                        "native_launch_spec": reference(launch),
                        "origin": "installed-manager"
                        if start["arm"] == "ecpa"
                        else "host-baseline",
                        "source_arguments": {
                            "fixed": original["fixed_identity"],
                            "policy": spec["source_policy"],
                        },
                    }
                )
            )
            phase["native_guard"] = reference(guard)
            planned = complete_planned(declared)
            for i, row in enumerate(planned["phases"]):
                row["client_request_id"] = f"{start['start_id']}/request-{i:05d}"
                row["external_request_id"] = "cmpl-" + row["client_request_id"] + "-0"
            phase["native_bootstrap"] = {
                "output": str(root / f"native{index}"),
                "native_context_path": str(root / f"context{index}.json"),
                "tensor_context_path": str(root / f"tensor{index}.json"),
                "source_files": declared[1],
                "phases": planned["phases"],
                "kv_requirements": planned["kv_requirements"],
                "tensor_requirements": {
                    p["phase_id"]: {
                        "layer_indices": [0],
                        "semantic_anchor": planned["kv_requirements"][p["phase_id"]][
                            "semantic_anchor"
                        ],
                        "physical_anchor": planned["kv_requirements"][p["phase_id"]][
                            "physical_anchor"
                        ],
                    }
                    for p in planned["phases"]
                },
            }
        # Other arms share equivalent structures but remain independently named.
        for arm in recipe["arms"]:
            recipe["arms"][arm]["phases"] = recipe["arms"][start["arm"]]["phases"]
        recipe_path.write_bytes(reg.canonical(recipe))
        start["recipe_template"] = reference(recipe_path)
        policy_path = Path(start["policy"]["path"])
        policy = reg.load(policy_path)
        policy["schema"] = "ecpa-h3-native-static-policy/v1"
        for alias in policy["native_plan_bindings"]:
            alias.pop("mode", None)
        for key in ("allowed_events", "bindings", "binding_artifacts"):
            del policy[key]
        policy["source_refs"] += [
            {"path": r["path"], "sha256": "sha256:" + r["sha256"]} for r in declared[1]
        ]
        policy_path.write_bytes(reg.canonical(policy))
        start["policy"] = reference(policy_path)
        policy["registration_sha256"] = reg.scope_digest(
            spec["original_campaign"], start
        )
        policy_path.write_bytes(reg.canonical(policy))
        start["policy"] = reference(policy_path)
        definition = start["authority"]
        definition["receipt_path"] = str(receipt_path)
        definition["command"] = [
            sys.executable,
            str(reg.HERE / reg.AUTHORITY_SOURCE),
            "--policy",
            str(policy_path),
            "--policy-sha256",
            start["policy"]["sha256"],
            "--journal",
            definition["journal"],
            "--socket",
            recipe["authority"]["socket"],
            "--public-port",
            str(definition["public_port"]),
            "--owned-stdin-lifetime",
        ] + reg.authority_arguments(campaign_path, start)
    return spec, campaign_path, receipt_path, checked


def test_native_nine_starts_keep_exact_workload_and_receipt_command(
    tmp_path, monkeypatch, declared
):
    spec, path, receipt, checked = native_candidate(tmp_path, monkeypatch, declared)
    reg.validate_campaign(spec, spec_path=path)
    assert len(checked) == 9
    reg.validate_receipt_destination(spec, receipt)
    with pytest.raises(GateError, match="receipt path"):
        reg.validate_receipt_destination(spec, tmp_path / "other.json")
    changed = copy.deepcopy(spec)
    changed["starts"][0]["authority"]["command"][-1] = "/other/receipt.json"
    with pytest.raises(GateError, match="authority command"):
        reg.validate_campaign(changed, spec_path=path)
    changed = copy.deepcopy(spec)
    changed["starts"].pop()
    with pytest.raises(ValidationError):
        reg.validate_campaign(changed, spec_path=path)


def test_native_and_invoked_domains_reject_each_others_schema(tmp_path, monkeypatch):
    spec = candidate(tmp_path, monkeypatch)
    with pytest.raises(ValidationError):
        reg.validate_campaign(spec, spec_path=tmp_path / "campaign.json")
    spec["schema"] = reg.DOMAIN
    with pytest.raises(ValidationError):
        reg.common.validate_campaign(spec)


def test_preflight_uses_actual_paths_and_all60_ids_before_popen(tmp_path, declared):
    launch = tmp_path / "launch.json"
    launch.write_bytes(reg.canonical({"execution_plan_id": "plan:sha256:" + "1" * 64}))
    planned = complete_planned(declared)
    phase = {
        "semantic_launch_spec": reference(launch),
        "native_bootstrap": {
            "source_files": declared[1],
            "phases": planned["phases"],
            "kv_requirements": planned["kv_requirements"],
            "tensor_requirements": {
                p["phase_id"]: {
                    "layer_indices": [0],
                    "semantic_anchor": planned["kv_requirements"][p["phase_id"]][
                        "semantic_anchor"
                    ],
                    "physical_anchor": planned["kv_requirements"][p["phase_id"]][
                        "physical_anchor"
                    ],
                }
                for p in planned["phases"]
            },
        },
    }
    result = reg.preflight_native_spec(phase)
    assert result["actual_request_count"] == 60
    assert result["native_or_kernel_authentication_performed"] is False
    phase["native_bootstrap"]["phases"][0]["external_request_id"] = "different-request"
    with pytest.raises(ValueError, match="request IDs"):
        reg.preflight_native_spec(phase)


@pytest.mark.parametrize("ordinals", [(), (0,), (0, 1)])
def test_original_native_intent_must_retain_actual_kv_and_both_workers(
    pair, monkeypatch, tmp_path, ordinals
):
    monkeypatch.setattr(
        discovery, "discover_bundles", lambda ids: tuple(pair.bundles[:1])
    )
    base = replace(
        pair.base,
        obligations=(
            EvidenceObligation("worker-invoked", "worker", "invoked", ordinals),
        ),
    )
    base_path, contract = tmp_path / "base.json", tmp_path / "contract.json"
    base_path.write_bytes(plan_artifact_bytes(base))
    contract.write_bytes(reg.canonical(pair.contract))
    spec = {
        "original_native_intent": {
            "base_plan": reference(base_path),
            "kv_contract": reference(contract),
        }
    }
    if ordinals == (0, 1):
        actual, raw = reg._intent_roots(spec)
        assert actual == base and raw == contract.read_bytes()
        contract.write_text("{}")
        with pytest.raises(ValueError, match="differ"):
            reg._intent_roots(spec)
    else:
        with pytest.raises(
            (ValueError, GateError), match="both workers|requires target ordinals"
        ):
            reg._intent_roots(spec)


def test_native_cpu_declarations_cannot_issue_without_independent_source_observation(
    tmp_path, monkeypatch, declared
):
    spec, path, receipt, _ = native_candidate(tmp_path, monkeypatch, declared)
    path.write_bytes(reg.canonical(spec))

    def refuse(*args):
        raise GateError("CPU tuple is unpublished")

    monkeypatch.setattr(reg.common.source_provenance, "observe_sources", refuse)
    with pytest.raises(GateError, match="unpublished"):
        reg.issue(path, receipt)
    assert not receipt.exists()


def test_replacement_reused_semantic_generation_rejected_before_launch(
    tmp_path, monkeypatch, declared
):
    spec, _, _, _ = native_candidate(tmp_path, monkeypatch, declared)
    start = spec["starts"][0]
    recipe = reg.load(Path(start["recipe_template"]["path"]))
    phase = recipe["arms"][start["arm"]]["phases"][1]
    path = Path(phase["semantic_launch_spec"]["path"])
    launch = reg.load(path)
    launch["candidate_generation"] = 1
    path.write_bytes(reg.canonical(launch))
    phase["semantic_launch_spec"] = reference(path)
    with pytest.raises(GateError, match="advance original semantic"):
        reg.validate_start(
            spec,
            reg.load(Path(spec["original_campaign"]["path"])),
            start,
            recipe,
            reg.load(Path(start["policy"]["path"])),
        )


def test_missing_tensor_coverage_rejected_before_kernel_or_collector_popen(
    tmp_path, declared
):
    launch = tmp_path / "launch.json"
    launch.write_bytes(reg.canonical({"execution_plan_id": "plan:sha256:" + "1" * 64}))
    planned = complete_planned(declared)
    phase = {
        "semantic_launch_spec": reference(launch),
        "native_bootstrap": {
            "source_files": declared[1],
            "phases": planned["phases"],
            "kv_requirements": planned["kv_requirements"],
            "tensor_requirements": {},
        },
    }
    with pytest.raises(GateError, match="cover every original60"):
        reg.preflight_native_spec(phase)
    assert reg.materialize_recipe is reg.common.materialize_recipe
    assert reg.validate_materialization is reg.common.validate_materialization
