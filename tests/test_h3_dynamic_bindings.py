import copy

import pytest
from h3_dynamic_fixtures import installed_binding

from experiments.formal_campaign.h3_dynamic_bindings import (
    canonical,
    digest,
    verify_binding_artifact,
)


def test_two_actual_metadata_payloads_derive_distinct_owned_obligations(
    tmp_path, monkeypatch
):
    installed = installed_binding(tmp_path, monkeypatch, count=2)
    plan, bindings = verify_binding_artifact(installed.artifact_ref)
    assert len(plan.plugins) == len(plan.obligations) == len(bindings) == 2
    assert len({b["plugin_id"] for b in bindings}) == 2
    assert len({b["entry_point"]["name"] for b in bindings}) == 2


def test_actual_A_entrypoint_cannot_be_relabelled_as_B_artifact(tmp_path, monkeypatch):
    installed = installed_binding(tmp_path, monkeypatch, count=2)
    value = copy.deepcopy(installed.artifact)
    value["bindings"][1]["entry_point"] = value["bindings"][0]["entry_point"]
    path = tmp_path / "spoof-bindings.json"
    path.write_bytes(canonical(value) + b"\n")
    with pytest.raises(ValueError, match="artifact/contract-derived ownership"):
        verify_binding_artifact(
            {"path": str(path), "sha256": digest(path.read_bytes())}
        )


def test_current_payload_mutation_cannot_reuse_old_plugin_identity(
    tmp_path, monkeypatch
):
    installed = installed_binding(tmp_path, monkeypatch, count=2)
    source = installed.site / "cpu_fixture_mod_1/plugin.py"
    source.write_text(source.read_text() + "\nchanged=True\n")
    with pytest.raises(ValueError, match="actual installed PluginIdentity"):
        verify_binding_artifact(installed.artifact_ref)
