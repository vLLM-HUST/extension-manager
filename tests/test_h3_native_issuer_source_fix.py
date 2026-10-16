"""Tiny actual wheel bytes; full-audit boundary mocked, never qualification."""

import copy
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.formal_campaign import h3_native_registration as m
from experiments.formal_campaign import h3_runtime_source_closure
from experiments.native_attention_candidate import live_route_reader as routes


@pytest.fixture
def tiny(tmp_path, monkeypatch):
    wheels, distributions, payloads = {}, {}, {}
    installed_root = tmp_path / "site-packages"
    installed_root.mkdir()
    for role, distribution in routes.DISTRIBUTIONS.items():
        name = (
            "torch_npu/npu/_format.py"
            if role == "torch_npu"
            else f"cpu_{role}/__init__.py"
        )
        metadata_name = f"{distribution.replace('-', '_')}-0.0.1.dist-info/METADATA"
        metadata = (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: 0.0.1\n".encode()
        )
        raw = f"# tiny actual CPU wheel for {role}\n".encode()
        for relative, data in ((name, raw), (metadata_name, metadata)):
            path = installed_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        wheel = tmp_path / f"{role}.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(name, raw)
            archive.writestr(metadata_name, metadata)
        wheels[role] = {
            "path": str(wheel),
            "sha256": routes.registry.sha(wheel.read_bytes()),
            "version": "0.0.1",
        }
        distributions[distribution] = SimpleNamespace(
            version="0.0.1", locate_file=lambda relative: installed_root / relative
        )
    monkeypatch.setattr(routes.metadata, "distribution", distributions.__getitem__)
    for role, distribution in routes.DISTRIBUTIONS.items():
        payloads[role] = routes._installed_payload(wheels[role], distribution, {})
    config = tmp_path / "config.json"
    config.write_bytes(routes.registry.canonical({"wheel_artifacts": wheels}))
    recipe = tmp_path / "recipe.json"
    recipe.write_text("{}")
    fresh = {
        "config": {
            "path": str(config),
            "sha256": routes.registry.sha(config.read_bytes()),
        },
        "recipe": {"path": str(recipe)},
        "wheel_sha256": {r: w["sha256"] for r, w in wheels.items()},
        "installed_payload_sha256": routes.registry.sha(
            routes.registry.canonical(payloads)
        ),
    }
    calls = []

    def audit(*args):
        calls.append(args)
        return copy.deepcopy(fresh)

    monkeypatch.setattr(routes, "audit_cell_inputs", audit)
    guard = tmp_path / "guard.json"

    def phase():
        guard.write_bytes(
            routes.registry.canonical(
                {"source_arguments": {"input_audits": {"original": fresh}}}
            )
        )
        return {
            "native_guard": {
                "path": str(guard),
                "sha256": m.common.digest(guard.read_bytes()),
            }
        }

    return SimpleNamespace(
        phase=phase,
        fresh=fresh,
        wheels=wheels,
        payloads=payloads,
        calls=calls,
        root=installed_root,
    )


def test_seven_actual_wheels_include_real_declared_torch_dependency_only(tiny):
    _, result = m._native_wheel_payloads(tiny.fresh)
    target = str(tiny.root / "torch_npu/npu/_format.py")
    assert result[target] == routes.registry.sha(Path(target).read_bytes())
    assert tiny.calls and set(result) == set().union(
        *(p.keys() for p in tiny.payloads.values())
    )
    assert tiny.fresh["config"]["path"] not in result


@pytest.mark.parametrize("change", ["installed", "wheel", "claim", "inventory"])
def test_tampered_wheel_payload_and_caller_claim_rejected(tiny, monkeypatch, change):
    if change == "installed":
        (tiny.root / "torch_npu/npu/_format.py").write_text("mutated installed bytes")
    elif change == "wheel":
        Path(tiny.wheels["torch_npu"]["path"]).write_bytes(b"mutated archive")
    elif change == "inventory":
        tiny.fresh["installed_payload_sha256"] = "0" * 64
    else:
        forged = copy.deepcopy(tiny.fresh)
        forged["wheel_sha256"]["torch_npu"] = "0" * 64
        monkeypatch.setattr(routes, "audit_cell_inputs", lambda *args: forged)
    with pytest.raises((ValueError, RuntimeError)):
        m._native_wheel_payloads(tiny.fresh)


def test_original_four_source_proof_retained_and_collisions_rejected(tiny, monkeypatch):
    phase = tiny.phase()
    calls = []

    def closure(*args):
        calls.append(args)
        return {
            "actual_runtime": {
                "distributions": {
                    "manager": {"payload": {"/actual/four-source.py": "abcd"}}
                }
            }
        }

    monkeypatch.setattr(
        h3_runtime_source_closure, "verify_runtime_source_closure", closure
    )
    monkeypatch.setattr(m, "_phases", lambda start: [phase])
    value = m.installed_payloads(
        {"starts": [{}], "repositories": {}, "runtime_wheels": {}},
        {"fixed_identity": {}},
    )
    assert calls and value["/actual/four-source.py"] == "abcd"
    target = str(tiny.root / "torch_npu/npu/_format.py")
    monkeypatch.setattr(
        h3_runtime_source_closure,
        "verify_runtime_source_closure",
        lambda *args: {
            "actual_runtime": {
                "distributions": {"host": {"payload": {target: "wrong"}}}
            }
        },
    )
    with pytest.raises((ValueError, RuntimeError), match="collision"):
        m.installed_payloads(
            {"starts": [{}], "repositories": {}, "runtime_wheels": {}},
            {"fixed_identity": {}},
        )


def test_deduplicates_only_same_input_refs_within_one_call(tiny, monkeypatch):
    phase = tiny.phase()
    closure_calls = []

    def closure(*args):
        closure_calls.append(args)
        return {"actual_runtime": {"distributions": {}}}

    monkeypatch.setattr(
        h3_runtime_source_closure, "verify_runtime_source_closure", closure
    )
    monkeypatch.setattr(m, "_phases", lambda start: [phase, phase])
    spec, original = (
        {"starts": [{}], "repositories": {}, "runtime_wheels": {}},
        {"fixed_identity": {}},
    )
    first = m.installed_payloads(spec, original)
    assert len(tiny.calls) == 1 and len(closure_calls) == 2
    assert m.installed_payloads(spec, original) == first
    assert len(tiny.calls) == 2 and len(closure_calls) == 4


def test_same_input_refs_never_accept_different_caller_audit(tiny, monkeypatch):
    phase = tiny.phase()
    changed = copy.deepcopy(tiny.fresh)
    changed["installed_payload_sha256"] = "0" * 64
    path = Path(phase["native_guard"]["path"]).with_name("different-guard.json")
    path.write_bytes(
        routes.registry.canonical(
            {"source_arguments": {"input_audits": {"original": changed}}}
        )
    )
    other = {
        "native_guard": {
            "path": str(path),
            "sha256": m.common.digest(path.read_bytes()),
        }
    }
    monkeypatch.setattr(
        h3_runtime_source_closure,
        "verify_runtime_source_closure",
        lambda *args: {"actual_runtime": {"distributions": {}}},
    )
    monkeypatch.setattr(m, "_phases", lambda start: [phase, other])
    with pytest.raises((ValueError, RuntimeError), match="claim changed"):
        m.installed_payloads(
            {"starts": [{}], "repositories": {}, "runtime_wheels": {}},
            {"fixed_identity": {}},
        )
    assert len(tiny.calls) == 1
