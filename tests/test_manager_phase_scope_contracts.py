"""Exact pure capability/original-cell bodies; no fake Plan or native completion."""

import ast
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTRAR = ROOT / "experiments/formal_campaign/h3_manager_phase_registration.py"


def namespace():
    tree = ast.parse(REGISTRAR.read_bytes())
    names = {"ManagerStart", "validate_original_cell", "validate_receipt_for_start"}
    extracted = ast.Module(
        body=[
            n
            for n in tree.body
            if isinstance(n, (ast.ClassDef, ast.FunctionDef)) and n.name in names
        ],
        type_ignores=[],
    )
    value = dict(json=json, os=os, _SCOPES={})

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    value["require"] = require
    exec(compile(extracted, str(REGISTRAR), "exec"), value)
    return value


def test_unissued_scope_and_subclass_cannot_authorize_start():
    values = namespace()
    cls = values["ManagerStart"]
    with pytest.raises(ValueError, match="not independently issued"):
        cls().selected("manager-crash-after-launch-r1-ecpa")

    class Forged(cls):
        pass

    with pytest.raises(ValueError, match="not independently issued"):
        Forged().selected("manager-crash-after-launch-r1-ecpa")


def test_private_anchor_start_owner_and_detached_views():
    values = namespace()
    cls = values["ManagerStart"]
    token = cls()
    sid = "manager-crash-after-launch-r1-ecpa"
    snapshot = dict(
        start_id=sid,
        context={"nested": [1]},
        original={"cell_id": "manager-crash-after-launch"},
        start={"start_id": sid},
        authority_binding={"authority": {}},
        source_observation={},
    )
    # Only this scope-unit fixture seeds the private anchor. It never pretends
    # that these small declarations passed the real source/native issuer.
    values["_SCOPES"][token] = (os.getpid(), json.dumps(snapshot).encode())
    detached, _, _ = token.selected(sid)
    detached["nested"].append(True)
    assert token.selected(sid)[0]["nested"] == [1]
    with pytest.raises(ValueError, match="change start"):
        token.selected("manager-crash-after-launch-r2-ecpa")
    values["_SCOPES"][token] = (os.getpid() + 1, json.dumps(snapshot).encode())
    with pytest.raises(ValueError, match="cross fork"):
        token.selected(sid)


@pytest.mark.parametrize(
    "field,value",
    [
        ("cell_id", "worker-crash"),
        ("target_role", "worker"),
        ("signal", "SIGTERM"),
        ("max_recovery_ms", 30001),
    ],
)
def test_original_cell_role_signal_and30s_are_not_relabeled(field, value):
    validate = namespace()["validate_original_cell"]
    original = dict(
        cell_id="manager-crash-after-launch",
        fault=dict(target_role="manager", signal="SIGKILL"),
        objective=dict(max_recovery_ms=30000),
    )
    validate(original)
    target = (
        original
        if field == "cell_id"
        else original["objective" if field == "max_recovery_ms" else "fault"]
    )
    target[field] = value
    with pytest.raises(ValueError, match="original Manager after-launch"):
        validate(original)


def test_real_route_generation_is_not_fabricated_for_second_candidate():
    path = ROOT / "experiments/formal_campaign/h3_manager_phase_authority.py"
    tree = ast.parse(path.read_bytes())
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "ManagerPhaseAuthority"
    )
    # Exercise precisely the new selector, not a mock native request/Plan.
    cls.bases = [ast.Name(id="object", ctx=ast.Load())]
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    values = {"require": require}
    exec(compile(module, str(path), "exec"), values)
    actor = values["ManagerPhaseAuthority"]()

    class Route:
        generation = None

    actor.route, actor.native_epochs = Route(), {}
    actor.enrollment = {"generation": 1}
    actor._validate_epoch_selection(1)
    with pytest.raises(ValueError):
        actor._validate_epoch_selection(0)
    actor.enrollment = {"generation": 2}
    with pytest.raises(ValueError):
        actor._validate_epoch_selection(1)
    actor.enrollment = {"generation": 1}
    actor.route.generation = 1
    with pytest.raises(ValueError):
        actor._validate_epoch_selection(1)


def test_existing_worker_epoch_gate_keeps_original_two_generation_rule():
    path = ROOT / "experiments/formal_campaign/h3_native_authority.py"
    tree = ast.parse(path.read_bytes())
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "NativeAuthority"
    )
    method = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "_validate_epoch_selection"
    )

    def require(ok, message):
        if not ok:
            raise ValueError(message)

    values = {"require": require}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(path), "exec"), values)

    class Actor:
        enrollment = {"generation": 1}

        class Route:
            generation = None

        route = Route()

    actor = Actor()
    with pytest.raises(ValueError):
        values["_validate_epoch_selection"](actor, 1)
    values["_validate_epoch_selection"](actor, 0)
    actor.enrollment = {"generation": 2}
    values["_validate_epoch_selection"](actor, 1)
