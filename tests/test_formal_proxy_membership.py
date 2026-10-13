"""Fixture bytes test fail-closed mechanics; they are not formal-real evidence."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import jsonschema
import pytest
from test_formal_process_snapshot import (
    EXECUTION,
    SLOTS,
    mutated,
    receipt,
)
from test_host_observer import BINDING, PLAN, host_event

from experiments.exposure_gate.loopback_traffic import _HostAuthorization
from experiments.false_effective.formal_proxy import (
    formal_proxy_command,
    formal_proxy_command_material,
    formal_proxy_source_sha256,
    prepare_formal_proxy_authorization,
    validate_formal_proxy_registration,
)
from vllm_hust_ext.exposure_gate import GateError
from vllm_hust_ext.formal_process_snapshot import make_transition
from vllm_hust_ext.formal_proxy_membership import derive_formal_proxy_membership
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def process_event(role: str, ordinal: int, pid: int, epoch: int) -> bytes:
    return mutated(
        host_event(),
        lambda value: value["process"].update(
            role=role,
            ordinal=ordinal,
            pid=pid,
            process_epoch=epoch,
            start_identity=f"pid:{pid}:start_ticks:{pid + 1000}",
            assignment_source="host",
        ),
    )


def transition(*extra: bytes):
    worker = process_event("worker", 0, 103, 13)
    return make_transition(
        SLOTS,
        EXECUTION,
        [receipt(worker), *(receipt(raw) for raw in extra)],
        frozen_at_ns=100,
    )


def test_membership_requires_host_owned_parent_engine_and_worker():
    value = transition(
        process_event("api-server", 0, 101, 11),
        process_event("engine-core-scheduler", 0, 102, 12),
    )
    rows = derive_formal_proxy_membership(value)
    assert [row["role"] for row in rows] == [
        "api-server",
        "engine-core-scheduler",
        "worker",
    ]


def test_environment_parent_cannot_be_promoted_to_formal_membership():
    parent = json.loads(process_event("api-server", 0, 101, 11))
    parent["process"]["assignment_source"] = "environment"
    # Recreate a valid event id through the common mutation helper.
    parent = mutated(
        json.dumps(parent, separators=(",", ":")).encode(),
        lambda _value: None,
    )
    value = transition(
        parent,
        process_event("engine-core-scheduler", 0, 102, 12),
    )
    with pytest.raises(ValueError, match="lacks host-owned roles: api-server"):
        derive_formal_proxy_membership(value)


def test_membership_rejects_epoch_replacement_for_one_slot():
    value = transition(
        process_event("api-server", 0, 101, 11),
        process_event("engine-core-scheduler", 0, 102, 12),
        process_event("engine-core-scheduler", 0, 104, 14),
    )
    with pytest.raises(ValueError, match="changed process epoch"):
        derive_formal_proxy_membership(value)


def test_preparation_binds_membership_and_reviewed_proxy_command(tmp_path: Path):
    value = transition(
        process_event("api-server", 0, 101, 11),
        process_event("engine-core-scheduler", 0, 102, 12),
    )
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    metadata = event_dir.stat()
    plan_path = (tmp_path / "plan.json").resolve()
    plan_path.write_bytes(plan_artifact_bytes(PLAN))
    plan_path.chmod(0o600)
    registration = {
        "schema": "ecpa-formal-proxy-registration/v1",
        "evidence_class": "formal-real",
        "authority": "independent-loopback-proxy",
        "proxy_command_digest": "sha256:" + "1" * 64,
        "proxy_source_sha256": "sha256:" + "3" * 64,
        "review_receipt_sha256": "sha256:" + "2" * 64,
        "reviewer_kind": "automated-independent",
        "public_port": 8187,
        "backend_port": 18187,
        "predecessor_port": 28187,
        "grant_holder": "formal-runner",
        "grant_token": 1,
        "grant_expires_at": 4_102_444_800,
    }
    output = (tmp_path / "authority.json").resolve()
    prepared = prepare_formal_proxy_authorization(
        output,
        plan_path=plan_path,
        event_dir=event_dir,
        event_directory_identity=(metadata.st_dev, metadata.st_ino),
        process_transition=value,
        required_processes=[
            {
                "host": "host-a",
                "role": "worker",
                "ordinal": 0,
                "process_epoch": 13,
            }
        ],
        bindings=[asdict(BINDING)],
        registration=registration,
    )
    schema = json.loads(
        Path(
            "experiments/exposure_gate/formal-host-authorization.schema.json"
        ).read_text()
    )
    jsonschema.Draft7Validator(schema).validate(prepared)
    assert output.stat().st_mode & 0o777 == 0o600
    assert prepared["registration"] == registration
    assert prepared["process_membership_sha256"].startswith("sha256:")
    authority = _HostAuthorization(output)
    assert authority.binding()["registration_sha256"] == prepared[
        "registration_sha256"
    ]
    claim = json.loads(output.with_name(output.name + ".claim").read_text())
    assert claim["authorization_path"] == str(output)
    assert claim["authorization_sha256"].startswith("sha256:")
    with pytest.raises(GateError, match="already claimed"):
        _HostAuthorization(output)

    copied = (tmp_path / "copied-authority.json").resolve()
    copied.write_bytes(output.read_bytes())
    copied.chmod(0o600)
    with pytest.raises(GateError, match="identity is incomplete"):
        _HostAuthorization(copied)
    with pytest.raises(FileExistsError):
        prepare_formal_proxy_authorization(
            output,
            plan_path=plan_path,
            event_dir=event_dir,
            event_directory_identity=(metadata.st_dev, metadata.st_ino),
            process_transition=value,
            required_processes=prepared["required_processes"],
            bindings=prepared["bindings"],
            registration=registration,
        )


def test_formal_proxy_command_freezes_public_and_backend_ports(tmp_path: Path):
    run_dir = tmp_path.resolve()
    registration = {
        "schema": "ecpa-formal-proxy-registration/v1",
        "evidence_class": "formal-real",
        "authority": "independent-loopback-proxy",
        "proxy_command_digest": "sha256:" + "0" * 64,
        "proxy_source_sha256": formal_proxy_source_sha256(),
        "review_receipt_sha256": "sha256:" + "2" * 64,
        "reviewer_kind": "automated-independent",
        "public_port": 8187,
        "backend_port": 18187,
        "predecessor_port": 28187,
        "grant_holder": "formal-runner",
        "grant_token": 9,
        "grant_expires_at": 4_102_444_800,
    }
    material = formal_proxy_command_material(run_dir, registration)
    registration["proxy_command_digest"] = material["digest"]
    assert formal_proxy_command(run_dir, registration) == material["argv"]
    assert material["argv"][material["argv"].index("--listen-port") + 1] == "8187"
    assert material["argv"][material["argv"].index("--candidate-port") + 1] == (
        "18187"
    )

    with pytest.raises(ValueError, match="registration is invalid"):
        validate_formal_proxy_registration(registration | {"public_port": 18187})
