import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from test_contract_compiler import manifest

from vllm_hust_ext.cli import main
from vllm_hust_ext.contract_compiler import (
    ContractPlanningError,
    compile_contracts,
    parse_contract,
)
from vllm_hust_ext.ecpa_model import (
    Attestation,
    ContractError,
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ProcessIdentity,
    ReferenceModel,
)
from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes
from vllm_hust_ext.semantic_obligations import EVENT, compile_native_semantic_plan

PLUGIN = PluginIdentity("org.example", "kv", "1.0.0", "a" * 64)
BASE = Plan(
    (PLUGIN,),
    HostCompatibility("vllm", "0.11.2", "ascend", "1"),
    (),
    (EvidenceObligation("invocation", "worker", "invoked", (0, 1)),),
    PredecessorSnapshot(0, None, {}),
)


def payload():
    raw = manifest("org.example.kv")
    raw["process_obligations"][0]["event"] = EVENT
    raw["authority"]["runtime"][0]["event"] = EVENT
    return raw


def compiled(raw=None):
    return compile_contracts(
        (parse_contract(raw or payload()),), host_runtime="vllm", host_version="0.11.2"
    )


def bind(base=BASE, contracts=None, mapping=None, ordinals=(0, 1)):
    return compile_native_semantic_plan(
        base,
        contracts or compiled(),
        extension_plugin_ids=mapping
        if mapping is not None
        else {"org.example.kv": PLUGIN.id},
        required_worker_ordinals=ordinals,
    )


def test_explicit_contract_produces_new_immutable_roundtrippable_plan():
    before = plan_artifact_bytes(BASE)
    Draft7Validator(
        json.loads(Path("spec/0.1/manifest.schema.json").read_bytes())
    ).validate(payload())
    plan, binding = bind()
    assert plan.plan_id != BASE.plan_id
    assert plan_artifact_bytes(BASE) == before
    assert parse_plan_artifact(plan_artifact_bytes(plan)) == plan
    assert plan.obligations[:-1] == BASE.obligations
    assert plan.obligations[-1].event == EVENT
    assert plan.obligations[-1].required_ordinals == (0, 1)
    assert binding["formal_producer_registration"] is False
    assert binding["execution_plan_id"] == plan.plan_id
    assert bind() == (plan, binding)


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "api-server"),
        ("completion", "optional"),
        ("completion", "quorum"),
        ("authority", "provider"),
        ("authority", "external"),
    ],
)
def test_contract_parser_and_schema_reject_wrong_semantic_authority_or_coverage(
    field, value
):
    raw = payload()
    raw["process_obligations"][0][field] = value
    if value == "quorum":
        raw["process_obligations"][0]["quorum"] = 1
    assert list(
        Draft7Validator(
            json.loads(Path("spec/0.1/manifest.schema.json").read_bytes())
        ).iter_errors(raw)
    )
    with pytest.raises(ContractPlanningError):
        compiled(raw)


@pytest.mark.parametrize("ordinals", [(0,), (0, 1, 2), (False, True), (1, 0)])
def test_partial_or_ambiguous_worker_sets_are_rejected(ordinals):
    with pytest.raises(ValueError, match="TP2"):
        bind(ordinals=ordinals)


@pytest.mark.parametrize(
    "mapping",
    [{}, {"org.example.other": PLUGIN.id}, {"org.example.kv": "plugin:unbound"}],
)
def test_mapping_must_name_exact_semantic_contract_and_artifact(mapping):
    with pytest.raises(ValueError):
        bind(mapping=mapping)


def test_no_implicit_promotion_and_no_posthoc_rebinding():
    lifecycle = manifest("org.example.kv")
    with pytest.raises(ValueError, match="no explicit"):
        bind(contracts=compiled(lifecycle))
    plan, _ = bind()
    with pytest.raises(ValueError, match="posthoc"):
        bind(base=plan)


def test_host_version_plugin_version_and_compiled_bindings_are_checked():
    with pytest.raises(ValueError, match="different hosts"):
        bind(base=replace(BASE, host=replace(BASE.host, version="0.11.3")))
    other = replace(PLUGIN, version="2.0.0")
    with pytest.raises(ValueError, match="versions differ"):
        bind(base=replace(BASE, plugins=(other,)), mapping={"org.example.kv": other.id})
    changed = replace(compiled(), obligation_bindings=())
    with pytest.raises(ValueError, match="bindings do not match"):
        bind(contracts=changed)


def test_artifact_and_contract_bytes_change_both_identities():
    plan, binding = bind()
    changed_plugin = replace(PLUGIN, artifact_sha256="b" * 64)
    other, receipt = bind(
        base=replace(BASE, plugins=(changed_plugin,)),
        mapping={"org.example.kv": changed_plugin.id},
    )
    assert other.plan_id != plan.plan_id
    assert (
        receipt["bindings"][0]["obligation_id"]
        != binding["bindings"][0]["obligation_id"]
    )
    raw = payload()
    raw["rollback"]["manager_owned"].append("extra local state")
    other, receipt = bind(contracts=compiled(raw))
    assert other.plan_id != plan.plan_id
    assert (
        receipt["bindings"][0]["obligation_id"]
        != binding["bindings"][0]["obligation_id"]
    )


def test_invocation_receipts_cannot_satisfy_bounded_effect_obligation():
    plan, _ = bind()
    model = ReferenceModel()
    model.resolve(["test"], "test")
    model.make_plan(
        plan.plugins, plan.host, plan.claims, plan.obligations, plan.predecessor
    )
    model.prepare()
    workers = tuple(
        ProcessIdentity("host", "worker", i, f"start-{i}", 1) for i in (0, 1)
    )
    model.launch("launch", workers)
    for obligation in plan.obligations:
        for worker in workers:
            model.attest(
                Attestation(
                    plan.plan_id,
                    "launch",
                    worker,
                    obligation.obligation_id,
                    "invoked",
                    f"{obligation.obligation_id}-{worker.ordinal}",
                    1,
                    10,
                    PLUGIN.id,
                ),
                now=2,
            )
    assert not model.evidence_complete()
    with pytest.raises(ContractError):
        model.commit(0)


def test_cli_compiles_fresh_private_artifacts_without_overwriting(tmp_path, capsys):
    base = tmp_path / "base.json"
    base.write_bytes(plan_artifact_bytes(BASE))
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(payload()))
    mapping = tmp_path / "map.json"
    mapping.write_text(json.dumps({"org.example.kv": PLUGIN.id}))
    output = tmp_path / "compiled"
    args = [
        "compile-semantic-plan",
        "--base-plan",
        str(base),
        "--contract",
        str(contract),
        "--plugin-map",
        str(mapping),
        "--output-directory",
        str(output),
    ]
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert (
        parse_plan_artifact((output / "plan.json").read_bytes()).plan_id
        == result["execution_plan_id"]
    )
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "plan.json").stat().st_mode & 0o777 == 0o400
    assert json.loads((output / "binding.json").read_bytes()) == result
    with pytest.raises(SystemExit):
        main(args)
    assert base.read_bytes() == plan_artifact_bytes(BASE)
    mapping.write_text('{"org.example.kv":"first","org.example.kv":"second"}')
    fresh = tmp_path / "ambiguous"
    args[-1] = str(fresh)
    with pytest.raises(SystemExit):
        main(args)
    assert not fresh.exists()


def test_legacy_invocation_observer_cannot_upgrade_semantic_plan(tmp_path):
    from vllm_hust_ext.host_evidence import EntryPointBinding
    from vllm_hust_ext.host_observer import (
        HostObservationError,
        observe_bound_invocations,
    )

    plan, _ = bind()
    metadata = tmp_path.stat()
    with pytest.raises(HostObservationError, match="every Plan obligation"):
        observe_bound_invocations(
            tmp_path,
            expected_directory_identity=(metadata.st_dev, metadata.st_ino),
            plan=plan,
            launch_id="launch",
            controller_instance="controller",
            bindings=(
                EntryPointBinding(
                    "group", "kv", "kv:register", PLUGIN.id, "invocation"
                ),
            ),
            required_processes=[
                {"host": "host", "role": "worker", "ordinal": i, "process_epoch": 1}
                for i in (0, 1)
            ],
        )
