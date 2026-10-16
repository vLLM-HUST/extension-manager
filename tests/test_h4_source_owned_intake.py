"""CPU-only strict raw binding and failed-start semantics for H4 candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get("ECPA_H4_TEST_BASE", str(ROOT)))


def load(name, path, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def intake(monkeypatch):
    monkeypatch.syspath_prepend(str(BASE))
    import experiments.formal_campaign as package

    mirror = ROOT / "experiments/formal_campaign"
    monkeypatch.setattr(package, "__path__", [str(mirror), *package.__path__])
    load(
        "experiments.formal_campaign.h4_owned_resources",
        mirror / "h4_owned_resources.py",
        monkeypatch,
    )
    provenance = load(
        "experiments.formal_campaign.source_provenance",
        mirror / "source_provenance.py",
        monkeypatch,
    )
    monkeypatch.setattr(package, "source_provenance", provenance, raising=False)
    return load(
        "experiments.formal_campaign.h4_source_owned_intake",
        mirror / "h4_source_owned_intake.py",
        monkeypatch,
    )


def bind(root, name, value):
    path = root / name
    path.write_text(json.dumps(value))
    return {
        "path": name,
        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def failed_record(root, intake):
    from experiments.formal_campaign import source_provenance

    identity = {"server_pid": None, "server_start_ticks": None, "boot_id": "CPU-only"}
    snapshot = bind(
        root,
        "process.json",
        {
            "process_identity": identity,
            "source_owned_pair": {"resources": None, "activation": None},
        },
    )
    receipt = bind(
        root,
        "receipt.json",
        {
            "source_provenance_protocol_binding": {
                name: "sha256:" + "0" * 64
                for name in source_provenance.H4_SOURCE_OWNED_FILES
            }
        },
    )
    return {
        "status": "failed",
        "process_identity": identity,
        "artifacts": {
            "process_snapshot": snapshot,
            "deployment_receipt": receipt,
        },
    }


def test_failed_attempt_does_not_invent_activation_or_resources(tmp_path, intake):
    record = failed_record(tmp_path, intake)
    result = intake.verify_start(record, {}, tmp_path)
    assert result == {
        "activation_verified": False,
        "resource_coverage": "unverified-failed-start",
    }
    record["status"] = "complete"
    with pytest.raises(ValueError, match="lacks source-owned raw evidence"):
        intake.verify_start(record, {}, tmp_path)


def test_source_owned_receipt_cannot_omit_new_published_helpers(tmp_path, intake):
    record = failed_record(tmp_path, intake)
    record["artifacts"]["deployment_receipt"] = bind(tmp_path, "legacy.json", {})
    with pytest.raises(ValueError, match="outside admitted source"):
        intake.verify_start(record, {}, tmp_path)


def test_source_owned_artifact_cannot_escape_or_change_bytes(tmp_path, intake):
    reference = bind(tmp_path, "bound.json", {})
    assert intake.checked(tmp_path, reference) == tmp_path / "bound.json"
    (tmp_path / "bound.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest differs"):
        intake.checked(tmp_path, reference)
    with pytest.raises(ValueError, match="escapes run root"):
        intake.checked(tmp_path, dict(reference, path="../outside.json"))


def test_h4_extra_source_domain_preserves_h3_default(intake):
    from experiments.formal_campaign import source_provenance as source

    for family in ("h3", "h4"):
        version = 3 if family == "h3" else 2
        names = {
            "source_provenance.py",
            f"{family}_registration.py",
            f"{family}-deployment-receipt-v{version}.schema.json",
        }
        binding = {
            name: source.digest(
                (ROOT / "experiments/formal_campaign" / name).read_bytes()
            )
            for name in names
        }
        source.validate_protocol_binding(binding, family)
        if family == "h3":
            with pytest.raises(ValueError, match="cannot replace H3"):
                source.bind_protocol_source(
                    None, "unused", family, h4_source_owned=True
                )
            with pytest.raises(ValueError, match="incomplete"):
                source.validate_protocol_binding(
                    binding | {"h4_owned_resources.py": "sha256:" + "0" * 64}, family
                )
            continue
        extras = {
            name: source.digest(
                (ROOT / "experiments/formal_campaign" / name).read_bytes()
            )
            for name in source.H4_SOURCE_OWNED_FILES
        }
        source.validate_protocol_binding(binding | extras, family)
        incomplete = binding | extras
        incomplete.pop("h4_owned_resources.py")
        with pytest.raises(ValueError, match="incomplete"):
            source.validate_protocol_binding(incomplete, family)
