"""CPU scope contracts with tiny fresh files; no native qualification evidence."""

import copy
import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.formal_campaign import h3_observer_live_registration as live
from vllm_hust_ext.exposure_gate import GateError


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    common, original = live.common, live.original
    calls = []
    observed = {"CPU-fixture-only": "original-source"}
    epoch_refs = {}

    def save(path, value):
        path.write_bytes(live.canonical(value))
        return live.reference(path)

    source = tmp_path / "CPU-source.py"
    source.write_text("# tiny source, never an installed native runtime\n")
    source_ref = live.reference(source)
    campaign = {
        "cell_id": "observer-loss",
        "objective": {"max_recovery_ms": 30000},
        "fixed_identity": {"manager_commit": "CPU-fixture"},
    }
    original_ref = save(tmp_path / "original.json", campaign)
    receipt_path = tmp_path / "native-receipt.json"
    starts, declarations = [], []
    protocol = json.loads((Path(live.__file__).parent / "protocol.json").read_bytes())
    for repetition, arms in enumerate(protocol["schedule"], 1):
        for arm in arms:
            sid = f"observer-loss-r{repetition}-{arm}"
            root = tmp_path / sid
            grant = root / "live-observer-control"
            host_sources = []
            for filename in live.HOST_FILES:
                path = root / "vllm/plugins" / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# CPU source " + filename)
                host_sources.append(
                    {
                        "path": str(path),
                        "sha256": live.hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
            policy = {
                "registration_sha256": "CPU-registration",
                "grant": {"holder": sid},
                "source_refs": [
                    {**row, "sha256": "sha256:" + row["sha256"]} for row in host_sources
                ],
            }
            policy_ref = save(root / "policy.json", policy)
            phase = {
                "native_bootstrap": {
                    "output": str(root / "n0"),
                    "source_files": host_sources,
                },
                "environment": {"ECPA_NATIVE_OBSERVER_REBIND_DIRECTORY": str(grant)},
            }
            recipe = {
                "authority": {"source": source_ref},
                "arms": {arm: {"phases": [phase]}},
            }
            recipe_ref = save(root / "recipe.json", recipe)
            starts.append(
                {
                    "start_id": sid,
                    "repetition": repetition,
                    "arm": arm,
                    "recipe_template": recipe_ref,
                    "policy": policy_ref,
                    "authority": {
                        "command": [sys.executable, str(source)],
                        "receipt_path": str(receipt_path),
                    },
                }
            )
            epoch_refs[sid] = []
            for epoch in range(2):
                path = root / f"epoch-{epoch}.bin"
                path.write_bytes(f"CPU current epoch {epoch}".encode())
                epoch_refs[sid].append(live.reference(path))
            successor = root / "live-observer-successor"
            operator = (
                {"kind": "source-owned-automatic", "command": []}
                if arm == "ecpa"
                else {
                    "kind": "explicit-original-operator",
                    "command": [
                        sys.executable,
                        str(
                            Path(live.__file__).with_name(
                                "h3_observer_live_operator.py"
                            )
                        ),
                        "--intent",
                        str(tmp_path / "intent.json"),
                        "--live-receipt",
                        str(tmp_path / "live.json"),
                        "--start-id",
                        sid,
                        "--runtime-recipe",
                        str(root / "runtime-recipe.json"),
                        "--output",
                        str(root / "live-operator-result.json"),
                    ],
                }
            )
            declarations.append(
                {
                    "start_id": sid,
                    "grant_directory": str(grant),
                    "operator": operator,
                    "successor": {
                        "output": str(successor),
                        "native_context_path": str(successor / "semantic-context.json"),
                        "tensor_context_path": str(successor / "tensor-context.json"),
                    },
                }
            )
    spec = {
        "schema": "CPU-static-native-fixture",
        "original_campaign": original_ref,
        "source_policy": {},
        "repositories": {},
        "starts": starts,
    }
    spec_path = tmp_path / "native.json"
    save(spec_path, spec)

    def static(value, *, profile, spec_path):
        ids = [s["start_id"] for s in value["starts"]]
        live.require(len(ids) == len(set(ids)) == 9, "ambiguous static start")
        for start in value["starts"]:
            live.check_ref(start["recipe_template"])
            live.check_ref(start["policy"])
        calls.append(("static", tuple(ids)))
        return json.loads(live.check_ref(value["original_campaign"]).read_bytes())

    def dynamic(kind):
        def verify(spec, original, *args, _starts=None, **kwargs):
            selected = spec["starts"] if _starts is None else _starts
            ids = tuple(s["start_id"] for s in selected)
            calls.append((kind, ids))
            live.check_ref(source_ref)
            for sid in ids:
                for ref in epoch_refs[sid]:
                    live.check_ref(ref)

        return verify

    def fresh(*args):
        calls.append(("remote", ()))
        return copy.deepcopy(observed)

    def binding(*args):
        live.check_ref(source_ref)
        return {"CPU-protocol-source": source_ref["sha256"]}

    monkeypatch.setattr(common, "_validate_campaign", static)
    monkeypatch.setattr(common, "_verify_deployment_sources", dynamic("deployment"))
    monkeypatch.setattr(common, "verify_runtime_closures", dynamic("runtime"))
    monkeypatch.setattr(original, "verify_native_plans", dynamic("plans"))
    monkeypatch.setattr(common, "_protocol_binding", binding)
    monkeypatch.setattr(common.source_provenance, "observe_sources", fresh)
    monkeypatch.setattr(
        common.source_provenance, "validate_observation", lambda *args: None
    )
    # Only lexical UDS bounds use our long temporary CPU fixture paths.
    monkeypatch.setattr(live, "precheck_uds_paths", lambda *args: None)
    original.issue(spec_path, receipt_path)
    assert all(
        len(ids) == 9
        for kind, ids in calls
        if kind in {"deployment", "runtime", "plans"}
    )
    intent = {
        "schema": live.INTENT,
        "domain": live.DOMAIN,
        "base_campaign": live.reference(spec_path),
        "base_receipt": live.reference(receipt_path),
        "receipt_path": str(tmp_path / "live.json"),
        "starts": declarations,
    }
    intent_path = tmp_path / "intent.json"
    save(intent_path, intent)
    live.issue(intent_path, tmp_path / "live.json")
    assert all(
        len(ids) == 9
        for kind, ids in calls
        if kind in {"deployment", "runtime", "plans"}
    )
    calls.clear()
    return dict(
        spec=spec,
        path=spec_path,
        base=receipt_path,
        intent=intent_path,
        live=tmp_path / "live.json",
        calls=calls,
        epochs=epoch_refs,
        observed=observed,
        source=source,
        source_ref=source_ref,
        save=save,
    )


def validate(f, sid=None):
    return live.validate_for_start(
        f["intent"], f["live"], sid or f["spec"]["starts"][0]["start_id"]
    )


def test_selected_scope_rebuilds_once_and_never_authorizes_other_start(
    prepared, monkeypatch
):
    f = prepared
    inputs = live._inputs
    seen = []

    def counted(*args, **kwargs):
        seen.append(kwargs.get("_selected_start_id"))
        return inputs(*args, **kwargs)

    monkeypatch.setattr(live, "_inputs", counted)
    scope = validate(f)
    sid = f["spec"]["starts"][0]["start_id"]
    assert seen == [sid]
    assert all(
        ids == (sid,)
        for kind, ids in f["calls"]
        if kind in {"deployment", "runtime", "plans"}
    )
    assert [len(ids) for kind, ids in f["calls"] if kind == "static"] == [9]
    assert len([1 for kind, _ in f["calls"] if kind == "remote"]) == 2
    assert scope.value()["start"]["start_id"] == sid and "starts" not in scope.value()
    detached = scope.value()
    detached["start"]["start_id"] = "other"
    assert scope.value()["start"]["start_id"] == sid
    with pytest.raises(AttributeError):
        scope._raw = b"{}"
    with pytest.raises(GateError, match="independently issued"):
        live.ValidatedLiveStart(scope.value(), scope.receipt_ref())


def test_default_full_reconstruction_and_issuer_remain_all_nine(prepared):
    f = prepared
    live._body(f["intent"], check_remote=True)
    assert all(
        len(ids) == 9
        for kind, ids in f["calls"]
        if kind in {"deployment", "runtime", "plans"}
    )


@pytest.mark.parametrize("sid", ["unknown", "", None, 7])
def test_invalid_start_cannot_be_scoped(prepared, sid):
    with pytest.raises((GateError, ValueError), match="start"):
        live.validate_for_start(prepared["intent"], prepared["live"], sid)


def test_ambiguous_original_start_rejected(prepared):
    f = prepared
    value = copy.deepcopy(f["spec"])
    value["starts"][-1]["start_id"] = value["starts"][0]["start_id"]
    f["save"](f["path"], value)
    intent = json.loads(f["intent"].read_bytes())
    intent["base_campaign"] = live.reference(f["path"])
    f["save"](f["intent"], intent)
    with pytest.raises(GateError, match="ambiguous"):
        validate(f)


@pytest.mark.parametrize("target", ["recipe_template", "policy"])
def test_unselected_static_reference_still_checked(prepared, target):
    path = Path(prepared["spec"]["starts"][-1][target]["path"])
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(GateError):
        validate(prepared)


def test_unselected_base_receipt_row_cannot_be_resigned(prepared):
    f = prepared
    value = json.loads(f["base"].read_bytes())
    value["starts"][-1]["authority"]["argv_sha256"] = "sha256:" + "0" * 64
    f["save"](f["base"], value)
    intent = json.loads(f["intent"].read_bytes())
    intent["base_receipt"] = live.reference(f["base"])
    f["save"](f["intent"], intent)
    with pytest.raises(GateError, match="per-start"):
        validate(f)


@pytest.mark.parametrize("field", ["declaration", "receipt", "source"])
def test_full_live_receipt_declaration_and_fresh_remote_rejected_on_change(
    prepared, field
):
    f = prepared
    if field == "declaration":
        value = json.loads(f["intent"].read_bytes())
        value["starts"][-1]["grant_directory"] += "-changed"
        f["save"](f["intent"], value)
    elif field == "receipt":
        value = json.loads(f["live"].read_bytes())
        value["starts"][-1]["declaration_sha256"] = "sha256:" + "0" * 64
        f["save"](f["live"], value)
    else:
        f["observed"]["CPU-fixture-only"] = "changed-current-source"
    with pytest.raises(GateError):
        validate(f)


def test_dynamic_epochs_and_source_are_fresh_on_every_validation(prepared):
    f = prepared
    sid = f["spec"]["starts"][0]["start_id"]
    other = f["spec"]["starts"][1]["start_id"]
    scope = validate(f)
    Path(f["epochs"][other][0]["path"]).write_bytes(b"unselected runtime changed")
    validate(f)
    assert scope.value()["start"]["start_id"] == sid
    with pytest.raises(GateError):
        validate(f, other)
    Path(f["epochs"][sid][1]["path"]).write_bytes(b"selected second epoch changed")
    with pytest.raises(GateError):
        validate(f)
    f["source"].write_bytes(b"current executable source changed")
    with pytest.raises(GateError):
        validate(f)


def test_checked_json_rejects_change_between_reference_check_and_parse(
    tmp_path, monkeypatch
):
    path = tmp_path / "checked.json"
    path.write_bytes(b'{"original":true}')
    ref = live.reference(path)
    original_check = live.check_ref

    def changed_after_check(value):
        result = original_check(value)
        path.write_bytes(b'{"replaced":true}')
        return result

    monkeypatch.setattr(live, "check_ref", changed_after_check)
    with pytest.raises(GateError, match="readback bytes changed"):
        live._checked_json(ref)


def test_input_cannot_claim_an_intent_reference_for_different_parsed_bytes(
    prepared, monkeypatch
):
    f = prepared
    original_observe = live.common.source_provenance.observe_sources
    mutated = False

    def change_during_guard(*args):
        nonlocal mutated
        result = original_observe(*args)
        if not mutated:
            f["intent"].write_bytes(f["intent"].read_bytes() + b" ")
            mutated = True
        return result

    monkeypatch.setattr(
        live.common.source_provenance, "observe_sources", change_during_guard
    )
    with pytest.raises(GateError, match="intent changed"):
        validate(f)


def test_receipt_reference_cannot_follow_different_bytes_after_comparison(
    prepared, monkeypatch
):
    f = prepared
    original_canonical = live.canonical
    changed = False

    def mutate_after_parse(value):
        nonlocal changed
        result = original_canonical(value)
        if (
            isinstance(value, dict)
            and value.get("schema") == live.RECEIPT
            and not changed
        ):
            f["live"].write_bytes(f["live"].read_bytes() + b" ")
            changed = True
        return result

    monkeypatch.setattr(live, "canonical", mutate_after_parse)
    with pytest.raises(GateError, match="receipt changed before selected scope"):
        validate(f)


@pytest.mark.parametrize("operation", ["issue", "validate"])
def test_output_path_binds_reconstructed_intent_snapshot(
    prepared, monkeypatch, operation
):
    f = prepared
    original_inputs = live._inputs

    def replaced_after_initial_path_check(*args, **kwargs):
        intent = json.loads(f["intent"].read_bytes())
        replacement = str(f["live"].with_name("other-live.json"))
        intent["receipt_path"] = replacement
        for declaration in intent["starts"]:
            command = declaration["operator"]["command"]
            if command:
                command[command.index("--live-receipt") + 1] = replacement
        f["save"](f["intent"], intent)
        return original_inputs(*args, **kwargs)

    monkeypatch.setattr(live, "_inputs", replaced_after_initial_path_check)
    with pytest.raises(GateError, match="reconstructed intent"):
        if operation == "issue":
            live.issue(f["intent"], f["live"])
        else:
            validate(f)


@pytest.mark.parametrize("entry_mode", ["script", "module"])
def test_actual_authority_cli_constructs_canonical_typed_grants(
    prepared, monkeypatch, entry_mode, tmp_path
):
    """Run the real CLI through construction, stopping before socket/Host work.

    Existing CPU source-issuer fixture supplies the typed scope. Expensive base
    Plan construction is isolated; neither an actual native proof nor runtime
    qualification is claimed by this identity/entrypoint contract.
    """
    from experiments.formal_campaign import h3_observer_authority as authority
    from experiments.formal_campaign import h3_observer_live_launcher as launcher
    from experiments.formal_campaign import h3_observer_registration as base

    tmp_path.chmod(0o700)
    scope = validate(prepared)
    original_start = scope.value()["start"]
    start = copy.deepcopy(original_start)
    journal_path = tmp_path / "entry-journal.jsonl"
    start["authority"]["journal"] = str(journal_path)
    selected = SimpleNamespace(
        selected=lambda sid: ({}, {}, start),
        guard_receipt=lambda sid: {},
    )
    monkeypatch.setattr(base, "validate_receipt_for_start", lambda *args: selected)
    monkeypatch.setattr(base, "build_plan_guards", lambda *args, **kwargs: [])
    # The fixture uses tiny CPU-only source labels. Verify its original receipt
    # bytes here; real protocol/Host source reconstruction is covered separately.
    monkeypatch.setattr(
        launcher,
        "recheck_scope",
        lambda issued: json.loads(live.check_ref(issued.receipt_ref()).read_bytes()),
    )
    reached = []

    class ConstructorReached(Exception):
        pass

    def construct(self, policy, journal, *, plan_guards):
        try:
            assert type(self) is authority.NativeAuthority
            self.start = original_start
            self.output = Path(scope.value()["declaration"]["grant_directory"]).parent
            # Original exact authority/scope checks remain enabled, not isinstance.
            grants = launcher.LiveGrants(self, scope)
            assert type(grants) is launcher.LiveGrants
            assert grants.authority is self and grants.scope is scope
            reached.append(self)
        finally:
            journal.close()
        raise ConstructorReached

    monkeypatch.setattr(authority.NativeAuthority, "__init__", construct)
    argv = [
        str(Path(authority.__file__).resolve()),
        "--policy",
        start["policy"]["path"],
        "--policy-sha256",
        start["policy"]["sha256"],
        "--journal",
        str(journal_path),
        "--socket",
        str(tmp_path / "never-bound.sock"),
        "--campaign",
        str(prepared["path"]),
        "--receipt",
        str(prepared["base"]),
        "--start-id",
        start["start_id"],
        "--public-port",
        "0",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(ConstructorReached):
        if entry_mode == "script":
            runpy.run_path(argv[0], run_name="__main__")
        else:
            with pytest.warns(RuntimeWarning, match="found in sys.modules"):
                runpy.run_module(authority.__name__, run_name="__main__")
    assert len(reached) == 1
    assert not (tmp_path / "never-bound.sock").exists()


def test_canonical_authority_still_rejects_unissued_live_scope():
    from experiments.formal_campaign import h3_observer_authority as authority
    from experiments.formal_campaign.h3_observer_live_launcher import LiveGrants

    actual_type = authority.NativeAuthority.__new__(authority.NativeAuthority)
    with pytest.raises(GateError, match="independently issued v2 scope"):
        LiveGrants(actual_type, SimpleNamespace(ready=True))
