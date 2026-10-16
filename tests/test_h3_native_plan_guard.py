"""CPU compiler/trust counterexamples only; no formal or NPU qualification."""

import copy
import json
from types import SimpleNamespace

import pytest
from test_pair_semantic_binding import pair as pair
from test_request_semantic_authority import source_fixture

from experiments.formal_campaign import h3_native_plan_guard as g
from vllm_hust_ext import contract_compiler, semantic_obligations
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def setup_guard(pair, tmp_path, monkeypatch):
    def save(name, value):
        path = tmp_path / name
        raw = value if type(value) is bytes else g.canonical(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return {"path": str(path), "sha256": g.sha(raw)}

    bundles = pair.bundles[:1]
    monkeypatch.setattr(g, "discover_bundles", lambda selected: bundles)
    compiled = contract_compiler.compile_contracts(
        (contract_compiler.parse_contract(pair.contract),),
        host_runtime=pair.base.host.runtime,
        host_version=pair.base.host.version,
    )
    plan, binding = semantic_obligations.compile_native_semantic_plan(
        pair.base,
        compiled,
        extension_plugin_ids={g.KV: pair.base.plugins[0].id},
        required_worker_ordinals=(0, 1),
    )
    base_ref = save("base.json", plan_artifact_bytes(pair.base))
    plan_ref = save("plan.json", plan_artifact_bytes(plan))
    native_ref = save("binding.json", binding)
    contract_ref = save("contract.json", pair.contract)
    mapping = save("map.json", {g.KV: pair.base.plugins[0].id})
    launch = g.runtime.make_semantic_launch_spec(
        bundles,
        base_plan_path=base_ref["path"],
        plan_path=plan_ref["path"],
        binding_path=native_ref["path"],
        contract_paths=[contract_ref["path"]],
        plugin_map_path=mapping["path"],
        controller_instance="controller:CPU",
        candidate_generation=1,
        membership_epoch=0,
    )
    launch_ref = save("launch.json", launch)
    fixed, policy, observation = source_fixture()
    audit = {
        "schema": g.routes.SCHEMA,
        "formal_result": False,
        "wheel_revisions": {
            "manager": fixed["manager_commit"],
            "host": fixed["host_commit"],
            "ascend": fixed["accelerator_commit"],
        },
        "wheel_sha256": {k: "a" * 64 for k in g.routes.DISTRIBUTIONS},
        "source_files": {},
        "file_state": {
            str(__file__): g.routes._state(__import__("pathlib").Path(__file__).stat())
        },
    }
    args = {
        "fixed": fixed,
        "policy": policy,
        "observation": observation,
        "input_audits": {"CPU": audit},
        "native_sources": {base_ref["path"]: base_ref["sha256"]},
        "original_kv_base": base_ref,
        "kv_contract": contract_ref,
        "pair_inputs": None,
        "publisher_argv": ["/CPU-original-publisher"],
    }
    full = {
        "schema": g.SCHEMA,
        "origin": "installed-manager",
        "native_launch_spec": launch_ref,
        "bundle_ids": [g.KV],
        "source_arguments": args,
    }
    roots = {
        "policy": full,
        "trusted_source_observations": {
            g.source_provenance.digest(g.canonical(observation))
        },
        "trusted_input_digests": {g.sha(g.canonical(audit))},
        "trusted_manager_handoffs": set(),
        "trusted_base_plan_ids": {pair.base.plan_id},
        "trusted_contract_digests": {contract_ref["sha256"]},
    }
    return SimpleNamespace(
        roots=roots, save=save, launch=launch, full=full, plan=plan, bundles=bundles
    )


def test_single_actual_kv_supported_without_forcing_second_mod(
    pair, tmp_path, monkeypatch
):
    context = setup_guard(pair, tmp_path, monkeypatch)
    guard = g.build_native_plan_guard(**context.roots)
    assert guard.paired is False
    assert guard.handoffs is context.roots["trusted_manager_handoffs"]
    assert not guard.handoffs  # Real handoff trust is added only after real Popen.
    assert (
        g.runtime.validate_semantic_launch_spec(
            context.full["native_launch_spec"]["path"], context.bundles
        )["execution_plan_id"]
        == context.plan.plan_id
    )
    context.full["source_arguments"]["native_sources"].clear()
    assert guard.policy["source_arguments"]["native_sources"]


def test_old_audit_without_guard_and_full_plan_source_coverage_rejected(
    pair, tmp_path, monkeypatch
):
    context = setup_guard(pair, tmp_path, monkeypatch)
    guard = g.build_native_plan_guard(**context.roots)
    with pytest.raises(ValueError, match="audit|source"):
        guard.verify_plan_current()


def test_untrusted_observation_rejected_before_any_actual_artifact_admission(
    pair, tmp_path, monkeypatch
):
    context = setup_guard(pair, tmp_path, monkeypatch)
    context.roots["trusted_source_observations"] = {"sha256:" + "0" * 64}
    guard = g.build_native_plan_guard(**context.roots)
    with pytest.raises(ValueError, match="not independently trusted"):
        guard.verify_plan_current()


def test_semantically_equal_contract_rewrite_cannot_replace_original_bytes(
    pair, tmp_path, monkeypatch
):
    context = setup_guard(pair, tmp_path, monkeypatch)
    changed = context.save(
        "different-contract-bytes.json", json.dumps(pair.contract, indent=2).encode()
    )
    launch = copy.deepcopy(context.launch)
    launch["contracts"] = [changed]
    context.full["native_launch_spec"] = context.save("different-launch.json", launch)
    guard = g.build_native_plan_guard(**context.roots)
    with pytest.raises(ValueError, match="original trusted KV contract bytes"):
        guard.verify_plan_current()


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-policy",
        "unknown-arguments",
        "duplicate-bundle",
        "fake-origin",
        "pair-audit-in-singleton",
    ],
)
def test_strict_factory_cannot_accept_undeclared_fields_or_tuple(
    pair, tmp_path, monkeypatch, mutation
):
    context = setup_guard(pair, tmp_path, monkeypatch)
    if mutation == "unknown-policy":
        context.full["caller_approved"] = True
    elif mutation == "unknown-arguments":
        context.full["source_arguments"]["skip_fresh_source"] = True
    elif mutation == "duplicate-bundle":
        context.full["bundle_ids"] *= 2
    elif mutation == "fake-origin":
        context.full["origin"] = "pretend-manager"
    else:
        context.full["source_arguments"]["pair_inputs"] = {}
    with pytest.raises(ValueError):
        g.build_native_plan_guard(**context.roots)


@pytest.mark.parametrize(
    "changed",
    [
        {"membership_epoch": "dynamic-membership-UUID"},
        {"membership_epoch": False},
        {"candidate_generation": True},
        {"controller_instance": "another-controller"},
    ],
)
def test_semantic_integer_scope_cannot_be_filled_from_dynamic_membership(changed):
    launch = dict(
        execution_plan_id="plan:sha256:" + "a" * 64,
        controller_instance="controller:CPU",
        candidate_generation=1,
        membership_epoch=0,
    )
    g._semantic_context(launch, launch)
    with pytest.raises(ValueError):
        g._semantic_context({**launch, **changed}, launch)


def test_caller_json_cannot_substitute_for_consumed_full_native_proof():
    bound = object.__new__(g.BoundNativePlanGuard)
    with pytest.raises(ValueError, match="detached, forged or not consumed"):
        bound.verify_request_current(
            {},
            "/CPU-no-journal",
            runtime_request_id="CPU",
            transaction_id="CPU",
            native_report={"native_complete": True},
        )


def test_even_independently_admitted_base_cannot_drop_second_worker_invocation(pair):
    from dataclasses import replace

    from vllm_hust_ext.ecpa_model import EvidenceObligation

    g._require_original_kv_invocations(pair.base)
    for obligations in ((), (EvidenceObligation("weak", "worker", "invoked", (0,)),)):
        with pytest.raises(ValueError, match="both TP2 worker"):
            g._require_original_kv_invocations(
                replace(pair.base, obligations=obligations)
            )
