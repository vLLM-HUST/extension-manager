"""CPU archival predicates with genuine production Plans; never qualification."""

import copy
import importlib.metadata
import json
from dataclasses import asdict, replace

import pytest
import test_h4_pair_activation as boundary_fixtures

from experiments.formal_campaign import h4_pair_activation as activation
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.ecpa_model import Plan, PluginIdentity
from vllm_hust_ext.manifest import BundleActivation, BundleManifest
from vllm_hust_ext.plan_artifact import (
    parse_plan_artifact,
    plan_artifact_bytes,
    read_plan_artifact,
)


@pytest.fixture
def archived(tmp_path, monkeypatch):
    # Only installed-identity discovery is a CPU boundary. The original H4
    # compiler, Plan constructor, serializer and parser are real production code.
    plugins, bundles = [], []
    for index, (bundle_id, ep_name) in enumerate(
        zip(activation.IDS, activation.EPS, strict=True)
    ):
        namespace, _, name = bundle_id.rpartition(".")
        plugins.append(PluginIdentity(namespace, name, "1.0.0", str(index + 1) * 64))
        bundles.append(
            InstalledBundle(
                bundle_id,
                f"cpu-{index}",
                "1.0.0",
                tmp_path / f"manifest-{index}.json",
                BundleManifest(bundle_id, "1.0.0", ">=1,<2", (), BundleActivation()),
                (
                    importlib.metadata.EntryPoint(
                        name=ep_name,
                        value=activation.EPS[ep_name],
                        group="vllm.general_plugins",
                    ),
                ),
            )
        )
    from vllm_hust_ext import semantic_runtime_binding

    monkeypatch.setattr(
        semantic_runtime_binding,
        "installed_plugin_identities",
        lambda ordered: (tuple(plugins), []),
    )
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "0.31.1")
    scope = activation.compile_original_lifecycle_plan(bundles)
    typed = parse_plan_artifact(activation.canonical(scope["execution_plan"]) + b"\n")
    assert type(typed) is Plan
    assert not hasattr(typed, "plan")
    assert typed.plugins == tuple(plugins)
    assert len(typed.obligations) == 6
    assert all(o.event == "invoked" for o in typed.obligations)
    artifact = tmp_path / "production-plan.json"
    artifact.write_bytes(plan_artifact_bytes(typed))
    assert read_plan_artifact(artifact).plan == typed

    boundary = boundary_fixtures.PairBoundaries()
    boundary.setUp()
    wrapper = dict(boundary.host, pid=90, start_ticks=10, session=90)
    boundary.host["session"] = 90
    for kernel in boundary.kernels.values():
        kernel["session"] = 90
    roster = boundary.roster()
    root = tmp_path / "activation"
    root.mkdir()

    def write(name, value):
        path = root / name
        path.write_bytes(value if type(value) is bytes else activation.canonical(value))
        return path

    def journal(name):
        path = write(name, boundary.raw)
        return {
            "original_path": "/CPU-original-loader-journal",
            "original_identity": {"device": 1, "inode": 2, "uid": 0, "mode": 384},
            "original_sha256": activation.sha(boundary.raw),
            "byte_exact_snapshot": activation.reference(path),
        }

    ready = {
        "passed": True,
        "arm": "vanilla-vllm-entry-points",
        "actual_host": boundary.host,
        "actual_manager": None,
        "native_launch": boundary.launch,
        "actual_roster": roster,
        "ready_original_journal": journal("ready.bin"),
    }
    final = {
        **copy.deepcopy(ready),
        "timed_out": False,
        "remaining_exact_epochs": [],
        "final_original_journal": journal("final.bin"),
        "final_live_roster": roster,
    }
    write("activation-ready.json", ready)
    write("activation-guard-receipt.json", final)
    write("actual-launch-intent.json", {"caller_kernel": wrapper})
    write(
        "baseline-owned-context.json",
        {
            "origin": "host-baseline",
            "publisher": boundary.host,
            "environment": boundary.launch,
            "Manager_handoff_or_ACK_claim": False,
        },
    )
    members = [{**wrapper, "ppid": 1}]
    for pid, kernel in boundary.kernels.items():
        members.append(
            {**kernel, "ppid": 90 if pid == 100 else 100 if pid == 101 else 101}
        )
    resource = tmp_path / "resources.json"
    resource.write_bytes(
        activation.canonical({"root": wrapper, "samples": [{"members": members}]})
    )
    spec = {
        "scope": "compatible-resource-pair.lifecycle-only",
        "original_h4_lifecycle_scope": scope,
        "plugin_identities": [asdict(p) for p in plugins],
    }
    # Admission/commands are independently tested elsewhere. This test starts
    # after that boundary and runs the complete archived activation predicates.
    monkeypatch.setattr(
        activation, "_registered_inputs", lambda *args: (root, spec, ready["arm"])
    )
    return tmp_path, wrapper, resource, spec, typed


def verify(archived):
    root, wrapper, resource, _, _ = archived
    return activation.verify_archived_activation(
        root, {}, wrapper, resource_archive=resource
    )


def test_real_compiled_plan_reaches_complete_archival_verification(archived):
    result = verify(archived)
    assert result["schema"] == "ecpa-h4-recomputed-pair-lifecycle-activation/v1"
    assert result["arm"] == "vanilla-vllm-entry-points"
    assert set(result["roster"]) == set(activation.EPS)
    assert (
        result["native_KV_completion_claim"] is result["public_release_claim"] is False
    )


def test_other_real_plugin_plan_rejected(archived):
    *_, spec, typed = archived
    changed = replace(
        typed,
        plugins=(
            replace(typed.plugins[0], artifact_sha256="f" * 64),
            *typed.plugins[1:],
        ),
    )
    spec["original_h4_lifecycle_scope"]["execution_plan"] = json.loads(
        plan_artifact_bytes(changed)
    )
    with pytest.raises(ValueError, match="scope ownership changed"):
        verify(archived)


def test_real_non_loader_obligation_plan_rejected(archived):
    *_, spec, typed = archived
    changed = replace(
        typed,
        obligations=(
            replace(typed.obligations[0], event="effective"),
            *typed.obligations[1:],
        ),
    )
    spec["original_h4_lifecycle_scope"]["execution_plan"] = json.loads(
        plan_artifact_bytes(changed)
    )
    with pytest.raises(ValueError, match="scope ownership changed"):
        verify(archived)


def test_later_original_journal_tamper_still_rejected(archived):
    root, *_ = archived
    (root / "activation/final.bin").write_bytes(b"changed original journal\n")
    with pytest.raises(ValueError, match="changed"):
        verify(archived)
