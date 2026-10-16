"""Temporary distribution metadata/payload fixtures; no installation command."""

import json
from dataclasses import asdict
from types import SimpleNamespace

from test_contract_compiler import manifest as contract_manifest

from experiments.formal_campaign.h3_dynamic_bindings import (
    canonical,
    derive_owned_plan,
    digest,
)
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.ecpa_model import HostCompatibility, Plan, PredecessorSnapshot
from vllm_hust_ext.plan_artifact import plan_artifact_bytes
from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities


def installed_binding(tmp_path, monkeypatch, count=1, semantic=False):
    site = tmp_path / "metadata-fixture"
    site.mkdir()
    ids = []
    contracts = []
    for index in range(count):
        bundle_id = f"org.cpu-fixture.mod-{index}"
        ids.append(bundle_id)
        package = f"cpu_fixture_mod_{index}"
        name = f"cpu-fixture-mod-{index}"
        root = site / package
        (root / "manifests").mkdir(parents=True)
        (root / "__init__.py").write_text("")
        (root / "plugin.py").write_text("def register():\n    return None\n")
        (root / "manifests/__init__.py").write_text("")
        value = {
            "schema_version": "0.3-experimental",
            "extension_id": bundle_id,
            "extension_version": "1.0.0",
            "kind": "in_process_plugin",
            "host": {
                "provider": "vllm",
                "name": "vllm",
                "version_range": ">=0.11,<0.12",
                "api_range": ">=1,<2",
            },
            "runtime": {
                "type": "python",
                "process_scope": "scheduler_and_ascend_worker",
                "isolation": "trusted_in_process",
            },
            "lifecycle_owner": "vllm",
            "protocols": [{"name": "vllm.general_plugins", "version_range": None}],
            "implementation": [
                {
                    "type": "python_entry_point",
                    "group": "vllm.general_plugins",
                    "name": f"fixture{index}",
                    "object": package + ".plugin:register",
                    "status": "active",
                }
            ],
            "requires_services": [],
            "requires_extensions": [],
            "resource_claims": [],
            "components": [
                {
                    "component_id": f"fixture{index}",
                    "contracts": ["vllm.general_plugins"],
                    "execution_planes": ["worker"],
                    "isolation": "trusted_in_process",
                    "implementation_ref": package + ".plugin:register",
                    "permissions": [],
                }
            ],
            "activation": {
                "entry_points": [
                    {"group": "vllm.general_plugins", "name": f"fixture{index}"}
                ],
                "environment": {},
                "additional_config": {},
            },
        }
        (root / "manifests/vllm-hust-extension-v0.3.json").write_text(json.dumps(value))
        dist = site / (name.replace("-", "_") + "-1.0.0.dist-info")
        dist.mkdir()
        (dist / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n"
        )
        (dist / "entry_points.txt").write_text(
            f"[vllm.general_plugins]\nfixture{index} = {package}.plugin:register\n"
            f"\n[vllm_hust.extension_bundles]\n{bundle_id} = {package}.manifests\n"
        )
        paths = [
            p.relative_to(site).as_posix() for p in root.rglob("*") if p.is_file()
        ] + [p.relative_to(site).as_posix() for p in dist.iterdir()]
        (dist / "RECORD").write_text(
            "".join(p + ",,\n" for p in paths)
            + str((dist / "RECORD").relative_to(site))
            + ",,\n"
        )
        contract = contract_manifest(bundle_id)
        if semantic:
            contract["process_obligations"][0]["event"] = (
                "selected-kv-native-arguments-completed"
            )
            contract["authority"]["runtime"][0]["event"] = (
                "selected-kv-native-arguments-completed"
            )
        p = tmp_path / f"contract-{index}.json"
        p.write_text(json.dumps(contract))
        contracts.append(p)
    monkeypatch.syspath_prepend(str(site))
    bundles = discover_bundles(ids)
    plugins, _ = installed_plugin_identities(bundles)
    base = Plan(
        plugins,
        HostCompatibility("vllm", "0.11.2", "vllm", "1"),
        (),
        (),
        PredecessorSnapshot(0, None, {}),
    )
    plan, bindings, snapshots = derive_owned_plan(
        base, bundles, [json.loads(p.read_bytes()) for p in contracts]
    )

    def ref(path):
        return {"path": str(path), "sha256": digest(path.read_bytes())}

    base_path = tmp_path / "base-template.json"
    base_path.write_bytes(
        canonical(
            {"schema": "ecpa-h3-uncompiled-deployment/v1", "deployment": asdict(base)}
        )
        + b"\n"
    )
    base_path.chmod(0o600)
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(plan_artifact_bytes(plan))
    plan_path.chmod(0o600)
    artifact = {
        "schema": "ecpa-h3-installed-obligation-bindings/v1",
        "base_template": ref(base_path),
        "plan": ref(plan_path),
        "contracts": [ref(p) for p in contracts],
        "bundle_ids": ids,
        "worker_ordinals": [0, 1],
        "bindings": bindings,
        "installed_snapshots": snapshots,
    }
    path = tmp_path / "installed-bindings.json"
    path.write_bytes(canonical(artifact) + b"\n")
    path.chmod(0o600)
    return SimpleNamespace(
        plan=plan,
        base=base,
        bundles=bundles,
        bindings=bindings,
        artifact_ref=ref(path),
        plan_ref=ref(plan_path),
        contracts=contracts,
        artifact=artifact,
        site=site,
    )
