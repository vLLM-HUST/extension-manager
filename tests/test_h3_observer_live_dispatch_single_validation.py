"""Tiny CPU contracts for scheduling delegation; no runtime qualification.

Reuse the existing live-scope fixture's independently rebuilding production
validator. Expensive source/native operations remain explicit tiny-file stubs.
These cases stop at the real execute admission boundary before any product IO.
"""

import copy
import json
from pathlib import Path

import pytest
from test_h3_observer_live_start_scope import prepared as _prepared

from experiments.formal_campaign import h3_observer_live_dispatch as dispatch
from experiments.formal_campaign import h3_observer_live_registration as live
from experiments.formal_campaign import h3_observer_runner as runner
from vllm_hust_ext.exposure_gate import GateError

prepared = _prepared


class AdmissionBoundaryReached(Exception):
    pass


def clean_negative():
    return {
        "formal_start_validated": True,
        "objective_met": False,
        "cleanup": {
            "processes_reclaimed": True,
            "ports_reclaimed": True,
            "devices_reclaimed": True,
            "external_services_preserved": True,
        },
        "cleanup_errors": [],
    }


def test_each_latin_slot_runs_real_live_validator_once(prepared, monkeypatch):
    f = prepared
    inputs = live._inputs
    actual_execute = runner.execute
    validated = []
    execution_calls = []

    def counted(*args, **kwargs):
        validated.append(kwargs.get("_selected_start_id"))
        return inputs(*args, **kwargs)

    # The tiny fixture creates source directories under each output. The real
    # entry's fresh-output check is the first operation after live validation.
    # Replace only that check to stop immediately and perform no process IO.
    original_require = runner.require

    def boundary(value, reason):
        if reason == "start output must be fresh":
            raise AdmissionBoundaryReached
        return original_require(value, reason)

    def through_actual_entry(*args, **kwargs):
        execution_calls.append((args, kwargs))
        with pytest.raises(AdmissionBoundaryReached):
            actual_execute(*args, **kwargs)
        return clean_negative()

    monkeypatch.setattr(live, "_inputs", counted)
    monkeypatch.setattr(runner, "require", boundary)
    monkeypatch.setattr(runner, "execute", through_actual_entry)
    rows = dispatch.run_nine(f["intent"], f["live"])
    expected = [s["start_id"] for s in f["spec"]["starts"]]
    assert validated == expected
    assert [r["start_id"] for r in rows] == expected
    assert all(r["result"]["objective_met"] is False for r in rows)
    assert len([c for c in f["calls"] if c[0] == "remote"]) == 18
    for (args, kwargs), sid in zip(execution_calls, expected, strict=True):
        assert args[:3] == (str(f["path"]), str(f["base"]), sid)
        assert args[3] == f["intent"].parent / sid
        assert kwargs == {
            "native": True,
            "check_remote": True,
            "live_intent": f["intent"],
            "live_receipt": f["live"],
        }


@pytest.mark.parametrize(
    "changed", ["source", "unselected-recipe", "live-receipt", "unknown-start"]
)
def test_actual_entry_rejects_corrupt_inputs_before_output_or_popen(
    prepared, monkeypatch, changed
):
    f = prepared
    if changed == "source":
        f["source"].write_bytes(b"changed CPU source")
    elif changed == "unselected-recipe":
        path = Path(f["spec"]["starts"][-1]["recipe_template"]["path"])
        path.write_bytes(path.read_bytes() + b" ")
    elif changed == "live-receipt":
        value = json.loads(f["live"].read_bytes())
        value["starts"][-1]["declaration_sha256"] = "sha256:" + "0" * 64
        f["save"](f["live"], value)
    else:
        value = json.loads(f["intent"].read_bytes())
        value["starts"][0]["start_id"] = "unknown-original-start"
        f["save"](f["intent"], value)

    def no_product(*args, **kwargs):
        pytest.fail("product Popen reached after invalid live admission")

    monkeypatch.setattr(runner.subprocess, "Popen", no_product)
    with pytest.raises((GateError, ValueError, KeyError)):
        dispatch.run_nine(f["intent"], f["live"])


@pytest.mark.parametrize("field", ["campaign", "receipt"])
def test_actual_execute_rejects_substituted_original_admission_paths(
    prepared, monkeypatch, field
):
    f = prepared
    other = f["intent"].parent / "substituted-original.json"
    other.write_bytes(b"{}")
    output = f["intent"].parent / "never-created-output"

    def no_product(*args, **kwargs):
        pytest.fail("product Popen reached after path substitution")

    monkeypatch.setattr(runner.subprocess, "Popen", no_product)
    with pytest.raises(GateError, match="substitute original source admission"):
        runner.execute(
            other if field == "campaign" else f["path"],
            other if field == "receipt" else f["base"],
            f["spec"]["starts"][0]["start_id"],
            output,
            native=True,
            check_remote=True,
            live_intent=f["intent"],
            live_receipt=f["live"],
        )
    assert not output.exists()


@pytest.mark.parametrize("kind", ["unqualified", "cleanup-false", "cleanup-error"])
def test_invalid_slot_stops_without_retry_or_next_start(tmp_path, monkeypatch, kind):
    path = tmp_path / "intent.json"
    path.write_text(
        json.dumps(
            {
                "base_campaign": {"path": str(tmp_path / "base.json")},
                "base_receipt": {"path": str(tmp_path / "base-receipt.json")},
                "starts": [
                    {
                        "start_id": str(i),
                        "grant_directory": str(tmp_path / str(i) / "control"),
                    }
                    for i in range(9)
                ],
            }
        )
    )
    result = copy.deepcopy(clean_negative())
    if kind == "unqualified":
        result["formal_start_validated"] = False
    elif kind == "cleanup-false":
        result["cleanup"]["devices_reclaimed"] = False
    else:
        result["cleanup_errors"] = ["retained actual error"]
    calls = []

    def execute(*args, **kwargs):
        calls.append(args)
        return result

    monkeypatch.setattr(runner, "execute", execute)
    rows = dispatch.run_nine(path, tmp_path / "live.json")
    assert len(calls) == len(rows) == 1
    assert rows[0]["result"] == result
