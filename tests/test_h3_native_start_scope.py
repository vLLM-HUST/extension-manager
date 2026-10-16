"""CPU-only scoped validation boundaries; mocked qualification is never evidence."""

from pathlib import Path

import pytest
from test_h3_native_registration import native_candidate
from test_h3_native_source_scope import declared as declared

from experiments.formal_campaign import h3_native_registration as reg
from experiments.formal_campaign.h3_owned_worker_carrier import (
    NativeRegisteredAuthority,
    reference,
)
from vllm_hust_ext.exposure_gate import GateError


@pytest.fixture
def prepared(tmp_path, monkeypatch, declared):
    spec, path, receipt, checked = native_candidate(tmp_path, monkeypatch, declared)
    path.write_bytes(reg.canonical(spec))
    calls = []
    epoch_files = {}
    for start in spec["starts"]:
        epoch_files[start["start_id"]] = []
        for index in range(2):
            p = tmp_path / f"cpu-fresh-{len(epoch_files)}-{index}.bin"
            p.write_bytes(f"CPU epoch {index}".encode())
            epoch_files[start["start_id"]].append(reference(p))

    def selected(spec, starts):
        return spec["starts"] if starts is None else starts

    cpu_source = tmp_path / "CPU-current-source.py"
    cpu_source.write_bytes(b"# original CPU source bytes")
    source_ref = reference(cpu_source)
    epoch_files["CPU-source-ref"] = source_ref

    def deployment(spec, original, *, profile=None, _starts=None):
        # Static campaign validation is real above; expensive runtime boundary
        # is replaced with tiny actual file reads, scoped by the implementation.
        assert len(spec["starts"]) == 9
        reg.checked_reference(source_ref)
        calls.append(
            ("deployment", tuple(s["start_id"] for s in selected(spec, _starts)))
        )

    def runtime(spec, original, *, _starts=None):
        calls.append(("runtime", tuple(s["start_id"] for s in selected(spec, _starts))))

    def plans(spec, original, observation, *, _starts=None):
        ids = tuple(s["start_id"] for s in selected(spec, _starts))
        calls.append(("plans", ids))
        for sid in ids:
            for ref in epoch_files[sid]:
                reg.checked_reference(ref)

    protocol = tmp_path / "CPU-protocol.bin"
    protocol.write_bytes(b"CPU protocol binding")
    monkeypatch.setattr(reg.common, "_verify_deployment_sources", deployment)
    monkeypatch.setattr(reg.common, "verify_runtime_closures", runtime)
    monkeypatch.setattr(reg, "verify_native_plans", plans)
    monkeypatch.setattr(
        reg.common, "_protocol_binding", lambda *args: reference(protocol)
    )
    monkeypatch.setattr(
        reg.common.source_provenance, "observe_sources", lambda *args: {"CPU": True}
    )
    monkeypatch.setattr(
        reg.common.source_provenance, "validate_observation", lambda *args: None
    )
    reg.issue(path, receipt)
    assert all(len(ids) == 9 for _, ids in calls)
    assert len(reg.load(receipt)["starts"]) == 9
    calls.clear()
    checked.clear()
    return spec, path, receipt, checked, calls, epoch_files, protocol


def test_scoped_result_cannot_authorize_other_start_or_be_unpacked(prepared):
    spec, path, receipt, checked, calls, _, _ = prepared
    sid = spec["starts"][0]["start_id"]
    value = reg.validate_receipt_for_start(path, receipt, sid)
    assert len(checked) == 9
    assert all(ids == (sid,) for _, ids in calls)
    context, _, start = value.selected(sid)
    assert "starts" not in context and start["start_id"] == sid
    assert NativeRegisteredAuthority._registered_start(value, sid)["start_id"] == sid
    other = spec["starts"][1]["start_id"]
    for getter in (value.selected, value.authority_binding, value.guard_receipt):
        with pytest.raises((ValueError, GateError), match="scope differs"):
            getter(other)
    with pytest.raises((ValueError, GateError), match="scope differs"):
        NativeRegisteredAuthority._registered_start(value, other)
    with pytest.raises(TypeError):
        tuple(value)
    with pytest.raises(AttributeError, match="immutable"):
        value._raw = b"{}"
    with pytest.raises((ValueError, GateError), match="not issued"):
        reg._ValidatedNativeStart(spec=spec, original={}, receipt={}, start_id=sid)
    context["repositories"].clear()
    start["authority"].clear()
    fresh_context, _, fresh_start = value.selected(sid)
    assert fresh_context["repositories"] and fresh_start["authority"]


def test_full_validator_and_issuer_remain_all_nine(prepared):
    spec, path, receipt, checked, calls, _, _ = prepared
    result = reg.validate_receipt(path, receipt)
    assert len(result[0]["starts"]) == 9 and len(result[2]["starts"]) == 9
    assert len(checked) == 9
    assert all(len(ids) == 9 for _, ids in calls)
    legacy = reg.common.validate_receipt
    assert legacy is not reg.validate_receipt_for_start


@pytest.mark.parametrize("sid", ["unknown", "", None, 1])
def test_unknown_and_invalid_start_rejected(prepared, sid):
    _, path, receipt, _, calls, _, _ = prepared
    with pytest.raises((ValueError, GateError), match="start"):
        reg.validate_receipt_for_start(path, receipt, sid)
    assert not calls


def test_unselected_policy_raw_bytes_still_checked(prepared):
    spec, path, receipt, _, calls, _, _ = prepared
    sid = spec["starts"][0]["start_id"]
    other = Path(spec["starts"][-1]["policy"]["path"])
    other.write_bytes(other.read_bytes() + b" ")
    with pytest.raises((ValueError, GateError), match="digest|bytes"):
        reg.validate_receipt_for_start(path, receipt, sid)
    assert not calls


def test_unselected_receipt_row_cannot_change(prepared):
    spec, path, receipt, _, _, _, _ = prepared
    value = reg.load(receipt)
    value["starts"][-1]["authority"]["argv_sha256"] = "sha256:" + "0" * 64
    receipt.write_bytes(reg.canonical(value))
    with pytest.raises((ValueError, GateError), match="per-start"):
        reg.validate_receipt_for_start(path, receipt, spec["starts"][0]["start_id"])


def test_protocol_and_remote_conditions_preserved(prepared, monkeypatch):
    spec, path, receipt, _, _, _, protocol = prepared
    sid = spec["starts"][0]["start_id"]
    monkeypatch.setattr(
        reg.common.source_provenance, "observe_sources", lambda *args: {"changed": True}
    )
    with pytest.raises((ValueError, GateError), match="source observation changed"):
        reg.validate_receipt_for_start(path, receipt, sid, check_remote=True)
    protocol.write_bytes(b"changed CPU protocol")
    with pytest.raises((ValueError, GateError), match="protocol source"):
        reg.validate_receipt_for_start(path, receipt, sid)


def test_selected_epochs_rechecked_each_call_not_other_start_authority(prepared):
    spec, path, receipt, _, calls, epochs, _ = prepared
    sid = spec["starts"][0]["start_id"]
    other = spec["starts"][1]["start_id"]
    first = reg.validate_receipt_for_start(path, receipt, sid)
    Path(epochs[other][0]["path"]).write_bytes(b"unselected dynamic state changed")
    reg.validate_receipt_for_start(path, receipt, sid)
    assert len(calls) == 6
    with pytest.raises((ValueError, GateError), match="scope differs"):
        first.selected(other)
    with pytest.raises((ValueError, GateError), match="digest|bytes"):
        reg.validate_receipt_for_start(path, receipt, other)
    source = Path(epochs["CPU-source-ref"]["path"])
    original_source = source.read_bytes()
    source.write_bytes(b"# changed source on next validation")
    with pytest.raises((ValueError, GateError), match="digest|bytes"):
        reg.validate_receipt_for_start(path, receipt, sid)
    source.write_bytes(original_source)
    Path(epochs[sid][1]["path"]).write_bytes(b"selected second epoch changed")
    with pytest.raises((ValueError, GateError), match="digest|bytes"):
        reg.validate_receipt_for_start(path, receipt, sid)


def test_real_expensive_loops_observe_only_selected_and_repeat(tmp_path, monkeypatch):
    from experiments.formal_campaign import h3_runtime_source_closure as runtime

    declaration = tmp_path / "CPU-audit-config-and-recipe.json"
    declaration.write_text("{}")
    audit = {"config": reference(declaration), "recipe": reference(declaration)}
    guard = tmp_path / "guard.json"
    guard.write_bytes(
        reg.canonical({"source_arguments": {"input_audits": {"cpu": audit}}})
    )
    starts = []
    for index in range(9):
        recipe = tmp_path / f"recipe-{index}.json"
        recipe.write_bytes(
            reg.canonical(
                {
                    "arms": {
                        "cpu": {
                            "phases": [
                                {
                                    "tag": [index, epoch],
                                    "native_guard": reference(guard),
                                }
                                for epoch in range(2)
                            ]
                        }
                    }
                }
            )
        )
        starts.append(
            {
                "start_id": f"CPU-start-{index}",
                "arm": "cpu",
                "recipe_template": reference(recipe),
            }
        )
    spec = {"starts": starts, "repositories": {}, "runtime_wheels": {}}
    original = {"fixed_identity": {}}
    selected = (starts[4],)
    closures, wheels, plans = [], [], []

    def verify(phase, *args):
        closures.append(phase["tag"])
        return {"actual_runtime": {"distributions": {}}}

    def seven(claim):
        wheels.append(claim)
        return claim, {}

    monkeypatch.setattr(runtime, "verify_runtime_source_closure", verify)
    monkeypatch.setattr(reg, "_native_wheel_payloads", seven)
    for _ in range(2):
        reg.installed_payloads(spec, original, _starts=selected)
    assert closures == [[4, 0], [4, 1]] * 2
    assert len(wheels) == 2  # Separate full observations in separate invocations.
    closures.clear()
    reg.common.verify_runtime_closures(spec, original, _starts=selected)
    assert closures == [[4, 0], [4, 1]]
    monkeypatch.setattr(
        reg,
        "build_plan_guards",
        lambda spec, original, receipt, start, **kwargs: plans.append(
            start["start_id"]
        ),
    )
    reg.verify_native_plans(spec, original, {}, _starts=selected)
    assert plans == ["CPU-start-4"]
    plans.clear()
    reg.verify_native_plans(spec, original, {})
    assert len(plans) == 9
