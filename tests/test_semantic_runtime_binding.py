import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_semantic_obligations import BASE, compiled, payload

from vllm_hust_ext import semantic_runtime_binding as binding
from vllm_hust_ext.plan_artifact import plan_artifact_bytes
from vllm_hust_ext.runtime_evidence import launch_environment
from vllm_hust_ext.semantic_obligations import compile_native_semantic_plan


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    package = tmp_path / "installed"
    package.mkdir()
    (package / "manifest.json").write_text("{}")
    (package / "plugin.py").write_text("actual_payload = 1\n")
    (package / "plugin.pyc").write_bytes(b"ignored")
    (package / "example.dist-info").mkdir()
    (package / "example.dist-info" / "RECORD").write_text("ignored")
    dist = SimpleNamespace(
        metadata={"Name": "example-kv"},
        version="1.0.0",
        files=["manifest.json", "plugin.py", "plugin.pyc", "example.dist-info/RECORD"],
        locate_file=lambda name: package / name,
        read_text=lambda name: None,
    )
    monkeypatch.setattr(binding.metadata, "distribution", lambda name: dist)
    bundle = SimpleNamespace(
        bundle_id="org.example.kv",
        manifest=SimpleNamespace(bundle_version="1.0.0"),
        distribution_name="example-kv",
        distribution_version="1.0.0",
        manifest_path=package / "manifest.json",
    )
    plugins, _ = binding.installed_plugin_identities((bundle,))
    base = replace(BASE, plugins=plugins)
    plan, receipt = compile_native_semantic_plan(
        base,
        compiled(),
        extension_plugin_ids={"org.example.kv": plugins[0].id},
        required_worker_ordinals=(0, 1),
    )

    def write(name, value):
        path = tmp_path / name
        path.write_bytes(
            value if isinstance(value, bytes) else json.dumps(value).encode()
        )
        path.chmod(0o600)
        return path

    base_path = write("base.json", plan_artifact_bytes(base))
    plan_path = write("plan.json", plan_artifact_bytes(plan))
    receipt_path = write("binding.json", receipt)
    contract_path = write("contract.json", payload())
    map_path = write("map.json", {"org.example.kv": plugins[0].id})
    spec = binding.make_semantic_launch_spec(
        (bundle,),
        base_plan_path=base_path,
        plan_path=plan_path,
        binding_path=receipt_path,
        contract_paths=[contract_path],
        plugin_map_path=map_path,
        controller_instance="controller:fresh",
        candidate_generation=1,
        membership_epoch=0,
    )
    path = write("spec.json", spec)
    return SimpleNamespace(
        spec=spec,
        path=path,
        bundle=bundle,
        package=package,
        plan=plan,
        receipt_path=receipt_path,
        write=write,
        dist=dist,
    )


def test_actual_payload_bound_to_new_native_plan_and_fresh_uuid(frozen):
    spec = binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))
    first = launch_environment((frozen.bundle,), semantic_launch_spec=frozen.path)
    second = launch_environment((frozen.bundle,), semantic_launch_spec=frozen.path)
    assert first["VLLM_ECPA_PLAN_ID"] == frozen.plan.plan_id.rsplit(":", 1)[-1]
    assert first["VLLM_ECPA_LAUNCH_ID"] != second["VLLM_ECPA_LAUNCH_ID"]
    assert len(first) == 5
    context = binding.semantic_context_environment(frozen.path, spec)
    assert context["ECPA_SEMANTIC_EXECUTION_PLAN_ID"] == frozen.plan.plan_id


@pytest.mark.parametrize("file", ["plugin.py", "manifest.json"])
def test_actual_installed_bytes_not_record_hashes(frozen, file):
    (frozen.package / file).write_text("altered")
    with pytest.raises(ValueError, match="snapshot differs"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_installer_and_bytecode_variation_is_not_payload(frozen):
    (frozen.package / "plugin.pyc").write_bytes(b"new bytecode")
    (frozen.package / "example.dist-info/RECORD").write_text("new receipts")
    binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_plan_id", "a" * 64),
        ("execution_plan_id", "plan:wrong"),
        ("candidate_generation", True),
        ("membership_epoch", -1),
        ("controller_instance", "controller:"),
    ],
)
def test_identity_and_epoch_substitution_rejected(frozen, field, value):
    frozen.spec[field] = value
    frozen.write("spec.json", frozen.spec)
    with pytest.raises(ValueError):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_enabled_bundle_identity_and_set_are_exact(frozen):
    frozen.dist.version = "2.0.0"
    with pytest.raises(ValueError, match="distribution identity"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))
    with pytest.raises(ValueError):
        binding.validate_semantic_launch_spec(frozen.path, ())


def test_binding_recomputed_even_when_reference_hash_matches(frozen):
    receipt = json.loads(frozen.receipt_path.read_bytes())
    receipt["bindings"][0]["contract_manifest_sha256"] = "0" * 64
    frozen.write("binding.json", receipt)
    frozen.spec["binding"] = binding.artifact_reference(frozen.receipt_path)
    frozen.write("spec.json", frozen.spec)
    with pytest.raises(ValueError, match="compiled binding differs"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_mutated_contract_and_plan_cannot_reuse_binding(frozen):
    path = Path(frozen.spec["contracts"][0]["path"])
    contract = json.loads(path.read_bytes())
    contract["rollback"]["manager_owned"].append("changed")
    frozen.write("contract.json", contract)
    frozen.spec["contracts"][0] = binding.artifact_reference(path)
    frozen.write("spec.json", frozen.spec)
    with pytest.raises(ValueError, match="compiled binding differs"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_private_artifact_and_reserved_context_required(frozen, monkeypatch):
    frozen.path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))
    monkeypatch.setenv("ECPA_SEMANTIC_CONTROLLER_INSTANCE", "controller:injected")
    with pytest.raises(ValueError, match="Manager owns"):
        binding.semantic_context_environment(frozen.path, frozen.spec)


def test_changed_base_plugins_are_rejected(frozen):
    from vllm_hust_ext.plan_artifact import parse_plan_artifact

    path = Path(frozen.spec["base_plan"]["path"])
    base = parse_plan_artifact(path.read_bytes())
    foreign = replace(base.plugins[0], artifact_sha256="f" * 64)
    frozen.write("base.json", plan_artifact_bytes(replace(base, plugins=(foreign,))))
    frozen.spec["base_plan"] = binding.artifact_reference(path)
    frozen.write("spec.json", frozen.spec)
    with pytest.raises(ValueError, match="plugins differ"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_artifact_reference_hash_is_enforced(frozen):
    frozen.receipt_path.write_text("{}")
    with pytest.raises(ValueError, match="artifact bytes differ"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_payload_symlink_and_missing_inventory_fail_closed(frozen):
    path = frozen.package / "plugin.py"
    path.unlink()
    path.symlink_to(frozen.package / "manifest.json")
    with pytest.raises(ValueError, match="symbolic link"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))
    frozen.dist.files = []
    with pytest.raises(ValueError, match="inventory"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))


def test_duplicate_spec_json_is_rejected(frozen):
    frozen.path.write_text('{"schema":"first","schema":"second"}')
    with pytest.raises(ValueError, match="duplicate"):
        binding.validate_semantic_launch_spec(frozen.path, (frozen.bundle,))
