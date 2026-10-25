from __future__ import annotations

import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from vllm_hust_ext import runtime_evidence as evidence


class Scheduler:
    pass


class Admission:
    pass


class Worker:
    pass


CLASSES = {"scheduler": Scheduler, "admission": Admission, "worker": Worker}
CONTRACTS = {
    "scheduler": "vllm.scheduler-class.v1",
    "admission": "vllm.batch-admission-policy.v1",
    "worker": "vllm.worker-class.v1",
}


@pytest.fixture
def bundle(monkeypatch, tmp_path):
    for key in evidence._EVIDENCE_ENVIRONMENT:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(evidence, "config_path", lambda: tmp_path / "config.json")
    path = tmp_path / "manifest.json"
    path.write_text('{"test": "immutable bundle manifest"}')
    components = tuple(
        SimpleNamespace(
            component_id=role,
            contracts=(CONTRACTS[role],),
            implementation_ref=f"{cls.__module__}:{cls.__qualname__}",
        )
        for role, cls in CLASSES.items()
    )
    implementation = tuple(
        SimpleNamespace(
            type="python_module",
            attributes={
                "module": cls.__module__,
                "object": cls.__qualname__,
                "status": "active",
            },
        )
        for cls in CLASSES.values()
    )
    return SimpleNamespace(
        bundle_id="org.example.paired-carrier",
        manifest_path=path,
        manifest=SimpleNamespace(
            bundle_version="0.1", components=components, implementation=implementation
        ),
    )


def launch(bundle, monkeypatch):
    # A new Manager launch owns a fresh environment, not one inherited from a child.
    for key in evidence._EVIDENCE_ENVIRONMENT:
        monkeypatch.delenv(key, raising=False)
    environment = evidence.launch_environment((bundle,))
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    return environment


def emit(role):
    return evidence.emit_module_effective(
        CLASSES[role], role=role, request_count=2, output_token_count=2
    )


def test_import_launch_and_two_components_cannot_claim_three_component_effect(
    bundle, monkeypatch
):
    launch(bundle, monkeypatch)
    assert evidence.runtime_effective_evidence(bundle) is None
    assert emit("worker") and emit("scheduler")
    assert evidence.runtime_effective_evidence(bundle) is None
    assert emit("admission")
    status = evidence.runtime_effective_evidence(bundle)
    assert "components=3" in status
    assert "not an all-rank device qualification" in status
    events = evidence._module_records()
    assert all("entry_point" not in event for event in events)
    assert len(events) == 4


def test_next_launch_and_changed_manifest_cannot_borrow_previous_live_evidence(
    bundle, monkeypatch
):
    first = launch(bundle, monkeypatch)
    for role in CLASSES:
        emit(role)
    assert evidence.runtime_effective_evidence(bundle)
    second = launch(bundle, monkeypatch)
    assert first["VLLM_ECPA_LAUNCH_ID"] != second["VLLM_ECPA_LAUNCH_ID"]
    assert evidence.runtime_effective_evidence(bundle) is None
    for role in CLASSES:
        emit(role)
    assert evidence.runtime_effective_evidence(bundle)
    bundle.manifest_path.write_text('{"test": "different bytes"}')
    assert evidence.runtime_effective_evidence(bundle) is None


def test_forbidden_symbol_zero_outputs_and_forged_binding_cannot_emit(
    bundle, monkeypatch
):
    environment = launch(bundle, monkeypatch)
    with pytest.raises(ValueError, match="class/role"):
        evidence.emit_module_effective(
            Admission, role="worker", request_count=1, output_token_count=1
        )
    with pytest.raises(ValueError, match="positive"):
        evidence.emit_module_effective(
            Worker, role="worker", request_count=0, output_token_count=0
        )
    fake = type("Worker", (), {"__module__": Worker.__module__})
    with pytest.raises(ValueError, match="actual loaded"):
        evidence.emit_module_effective(
            fake, role="worker", request_count=1, output_token_count=1
        )
    for key, bad in [
        ("VLLM_ECPA_PLAN_ID", "forged-plan"),
        ("VLLM_ECPA_LAUNCH_ID", "forged-launch"),
        ("VLLM_HUST_EXT_MODULE_BINDING", "0" * 64),
        ("VLLM_ECPA_EVIDENCE_SINK", "other:callback"),
    ]:
        monkeypatch.setenv(key, bad)
        with pytest.raises(ValueError):
            emit("worker")
        monkeypatch.setenv(key, environment[key])
    monkeypatch.delenv("VLLM_HUST_EXT_MODULE_BINDING")
    with pytest.raises(ValueError, match="incomplete"):
        emit("worker")
    assert len(evidence._module_records()) == 1


def test_pid_reuse_or_one_dead_observed_participant_revokes_launch(bundle, monkeypatch):
    launch(bundle, monkeypatch)
    for role in CLASSES:
        emit(role)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        event = evidence._module_records()[-1].copy()
        event["process"] = {
            "host": evidence.socket.gethostname(),
            "pid": child.pid,
            "start_identity": evidence._start_identity(child.pid),
        }
        evidence._append(event)
        assert evidence.runtime_effective_evidence(bundle)
        child.kill()
        child.wait(timeout=5)
        assert evidence.runtime_effective_evidence(bundle) is None
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_wrong_class_or_launch_receipt_cannot_be_matched_after_journal_tamper(
    bundle, monkeypatch
):
    launch(bundle, monkeypatch)
    for role in CLASSES:
        emit(role)
    assert evidence.runtime_effective_evidence(bundle)
    event = evidence._module_records()[-1].copy()
    event["component"] = {**event["component"], "implementation_ref": "forged:Worker"}
    evidence._append(event)
    assert evidence.runtime_effective_evidence(bundle) is None


def test_inactive_declared_module_is_rejected_before_launch(bundle):
    bundle.manifest.implementation[0].attributes["status"] = "import_only"
    with pytest.raises(ValueError, match="active declared carrier"):
        evidence.launch_environment((bundle,))
    assert not evidence.evidence_path().exists()


def test_module_receipt_uses_actual_process_and_output_counts(bundle, monkeypatch):
    launch(bundle, monkeypatch)
    emit("scheduler")
    event = json.loads(evidence.evidence_path().read_text().splitlines()[-1])
    assert event["process"]["pid"] == os.getpid()
    assert event["process"]["start_identity"] == evidence._start_identity(os.getpid())
    assert event["request_count"] == event["output_token_count"] == 2
    assert event["component"]["role"] == "scheduler"


def test_missing_or_reused_process_birth_cannot_be_current(bundle, monkeypatch):
    launch(bundle, monkeypatch)
    for role in CLASSES:
        emit(role)
    event = evidence._module_records()[-1].copy()
    event["process"] = {
        "host": evidence.socket.gethostname(),
        "pid": 999999999,
        "start_identity": None,
    }
    assert not evidence._process_is_current(event["process"])
    event["process"] = {
        "host": evidence.socket.gethostname(),
        "pid": os.getpid(),
        "start_identity": "pid:reused:start_ticks:0",
    }
    evidence._append(event)
    assert evidence.runtime_effective_evidence(bundle) is None
