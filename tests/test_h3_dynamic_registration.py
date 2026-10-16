"""Static nine-start policy validation; no future kernel or formal fixture receipt."""

import copy
import json
import sys
from pathlib import Path

import pytest
from h3_dynamic_fixtures import installed_binding
from jsonschema import ValidationError
from test_h3_registration import fixture as original_fixture
from test_h3_registration import load_registration

from experiments.formal_campaign import h3_dynamic_registration as reg
from experiments.formal_campaign.h3_dynamic_authority import canonical
from experiments.formal_campaign.h3_owned_worker_carrier import reference
from vllm_hust_ext.runtime_phase_handoff import manager_source_digests


def candidate(tmp_path, monkeypatch):
    installed = installed_binding(tmp_path, monkeypatch)
    from experiments.formal_campaign.h3_dynamic_bindings import (
        default_native_plan_binding,
    )

    raw, _, _ = original_fixture(load_registration(), tmp_path)
    original = json.loads(raw)
    original["cell_id"] = "worker-crash"
    original["fault"]["target_role"] = "worker"
    original["probe"]["request_count"] = 60
    original["probe"]["request_timeout_s"] = 10
    original_path = tmp_path / "original.json"
    original_path.write_bytes(canonical(original) + b"\n")
    source = reg.HERE / "h3_dynamic_host.py"
    source_ref = reference(source)
    spec = {
        "schema": reg.DOMAIN,
        "original_campaign": reference(original_path),
        "source_policy": {
            "schema": "ecpa-full-tuple-source-provenance-policy/v1",
            "components": {
                "manager": {
                    "repository": "vLLM-HUST/extension-manager",
                    "requirement": "merged-main",
                },
                "host": {
                    "repository": "vLLM-HUST/vllm-hust",
                    "requirement": "merged-main",
                },
                "accelerator": {
                    "repository": "vLLM-HUST/vllm-ascend",
                    "requirement": "published-commit",
                },
                "plugin:mod": {
                    "repository": "vLLM-HUST/mod",
                    "requirement": "published-commit",
                },
            },
        },
        "repositories": {
            role: {"path": str(tmp_path), "remote": "origin"}
            for role in ("manager", "host", "accelerator", "plugin:mod")
        },
        "plugin_source_roles": {"org.cpu-fixture.mod-0": "plugin:mod"},
        "runtime_wheels": {
            role: {
                "distribution": "CPU-shape-only",
                "module": "CPU-shape-only",
                "wheel": {
                    "path": "/absent/cpu-only.whl",
                    "sha256": "0" * 64,
                    "version": "0",
                    "revision": "1" * 40,
                },
            }
            for role in ("manager", "host", "accelerator", "plugin:mod")
        },
        "starts": [],
    }
    for repetition in (1, 2, 3):
        for arm in reg.ARMS:
            sid = f"worker-crash-r{repetition}-{arm}"
            root = tmp_path / sid
            root.mkdir(mode=0o700)
            phases = []
            for index in (0, 1):
                baseline = arm != "ecpa"
                phases.append(
                    {
                        "origin": "host-baseline"
                        if baseline
                        else "manager-native-handoff",
                        "argv": [
                            sys.executable,
                            str(source),
                            "baseline",
                            "serve",
                            "--disable-ecpa-manager",
                            "--manual-hooks"
                            if arm == "manual-integration"
                            else "--enable-entrypoints",
                        ]
                        if baseline
                        else [
                            sys.executable,
                            str(source),
                            "manager",
                            "run",
                            "--phase-binding-socket",
                            str(root / f"handoff{index}.sock"),
                            "--",
                            sys.executable,
                            str(source),
                            "managed-host",
                            "serve",
                        ],
                        "cwd": str(tmp_path),
                        "environment": {},
                        "sources": [source_ref],
                        "worker_ordinal": 0,
                        "required_worker_ordinals": [0, 1],
                        "evidence_path": str(root / f"phase{index}.jsonl"),
                        "handoff_path": None
                        if baseline
                        else str(root / f"handoff{index}.sock"),
                        "manager_source_sha256": {}
                        if baseline
                        else manager_source_digests(),
                        "plan_artifact": installed.plan_ref if baseline else None,
                        "launch_id": f"{sid}-phase{index}" if baseline else None,
                    }
                )
            recipe = {
                "schema": "ecpa-h3-owned-worker-recipe/v1",
                "arms": {a: {"phases": phases} for a in reg.ARMS},
                "authority": {
                    "source": reference(reg.HERE / "h3_dynamic_authority.py"),
                    "process_identity": None,
                    "socket": str(root / "authority.sock"),
                    "backend_endpoint": "http://127.0.0.1:18187",
                },
            }
            path = root / "recipe-template.json"
            path.write_bytes(canonical(recipe) + b"\n")
            start = {
                "start_id": sid,
                "arm": arm,
                "repetition": repetition,
                "arm_order": reg.load(reg.HERE / "protocol.json")["schedule"][
                    repetition - 1
                ].index(arm)
                + 1,
                "recipe_template": reference(path),
                "recovery_action": "bounded-operator-full-relaunch",
                "client_template": {
                    "schema": "ecpa-h3-client-window-spec/v1",
                    "start_id": sid,
                    "request_count": 60,
                    "concurrency": 8,
                    "interval_s": 0.2,
                    "timeout_s": 10,
                    "dispatch_slack_s": 0.5,
                    "request_url": "http://127.0.0.1:8187/v1/completions",
                    "retry_policy": "single-attempt-no-retry",
                    "payload": original["probe"]["request_payload"],
                    "response_expectation": original["probe"]["response_expectation"],
                },
                "authority": {
                    "command": [],
                    "journal": str(root / "authority.jsonl"),
                    "public_port": 8187,
                },
            }
            policy = {
                "schema": "ecpa-h3-dynamic-static-policy/v1",
                "start_id": sid,
                "registration_sha256": "sha256:" + "0" * 64,
                "static_deployment_sha256": spec["original_campaign"]["sha256"],
                "grant": {"holder": sid, "token": 1, "expires_at": 4102444800},
                "backend_endpoint": recipe["authority"]["backend_endpoint"],
                "model": original["probe"]["request_payload"]["model"],
                "worker_ordinals": [0, 1],
                "allowed_events": ["invoked"],
                "source_refs": [source_ref],
                "plan_artifacts": [installed.plan_ref],
                "host_evidence_paths": [p["evidence_path"] for p in phases]
                if baseline
                else [],
                "host_evidence_roots": [] if baseline else [str(root)],
                "native_plan_bindings": [
                    default_native_plan_binding(installed.artifact_ref)
                ],
                "api_argv": [p["argv"] for p in phases],
                "bindings": installed.bindings,
                "binding_artifacts": [installed.artifact_ref],
            }
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical(policy) + b"\n")
            start["policy"] = reference(policy_path)
            policy["registration_sha256"] = reg.scope_digest(
                spec["original_campaign"], start
            )
            policy_path.write_bytes(canonical(policy) + b"\n")
            start["policy"] = reference(policy_path)
            start["authority"]["command"] = [
                sys.executable,
                str(reg.HERE / "h3_dynamic_authority.py"),
                "--policy",
                str(policy_path),
                "--policy-sha256",
                start["policy"]["sha256"],
                "--journal",
                start["authority"]["journal"],
                "--socket",
                recipe["authority"]["socket"],
                "--public-port",
                "8187",
                "--owned-stdin-lifetime",
            ]
            spec["starts"].append(start)
    return spec


def test_nine_static_starts_have_no_future_kernel(tmp_path, monkeypatch):
    spec = candidate(tmp_path, monkeypatch)
    reg.validate_campaign(spec)
    start = spec["starts"][0]
    template = json.loads(Path(start["recipe_template"]["path"]).read_bytes())
    actual = {
        "pid": 123,
        "start_ticks": 456,
        "boot_id": "cpu-shape-only",
        "session": 123,
    }
    runtime = reg.materialize_recipe(template, actual)
    assert reg.validate_materialization(spec, start, runtime) == runtime
    runtime["arms"][start["arm"]]["phases"][1]["launch_id"] = "dead-reused-instance"
    with pytest.raises(Exception, match="changed frozen intent"):
        reg.validate_materialization(spec, start, runtime)
    changed = copy.deepcopy(spec)
    changed["starts"] = changed["starts"][:-1]
    with pytest.raises(ValidationError):
        reg.validate_campaign(changed)
    changed = copy.deepcopy(spec)
    changed["starts"][0]["client_template"]["interval_s"] = 1
    with pytest.raises(Exception, match="scope|workload"):
        reg.validate_campaign(changed)


def test_unpublished_cpu_fixture_cannot_issue_formal_receipt(tmp_path, monkeypatch):
    spec = candidate(tmp_path, monkeypatch)
    path = tmp_path / "campaign.json"
    path.write_bytes(canonical(spec) + b"\n")
    called = []

    def refuse(*args):
        called.append(True)
        raise ValueError("CPU tuple is unpublished")

    monkeypatch.setattr(reg.source_provenance, "observe_sources", refuse)
    with pytest.raises(ValueError, match="unpublished"):
        reg.issue(path, tmp_path / "receipt.json")
    assert called and not (tmp_path / "receipt.json").exists()


def test_completion_payload_freezes_explicit_tokenizer_option():
    from jsonschema import Draft7Validator

    schema = json.loads((reg.HERE / "h3-campaign.schema.json").read_bytes())
    validator = Draft7Validator(
        schema["properties"]["probe"]["properties"]["request_payload"]
    )
    payload = {
        "model": "ecpa-h3-native",
        "prompt": "already rendered chat template",
        "max_tokens": 128,
        "temperature": 0,
        "stream": False,
        "add_special_tokens": False,
    }
    validator.validate(payload)
    validator.validate({k: v for k, v in payload.items() if k != "add_special_tokens"})
    for invalid in (0, "false", None):
        with pytest.raises(ValidationError):
            validator.validate(dict(payload, add_special_tokens=invalid))
    with pytest.raises(ValidationError):
        validator.validate(dict(payload, messages=[]))


def test_native_start_control_paths_are_private_and_contained(tmp_path):
    from experiments.formal_campaign.h3_dynamic_runner import prepare_native_paths

    output = tmp_path / "actual-start"
    output.mkdir(mode=0o700)
    phase = {
        "evidence_path": str(output / "h0" / "events.jsonl"),
        "handoff_path": str(output / "h0" / "handoff.sock"),
        "native_bootstrap": {
            "native_context_path": str(output / "h0" / "native.json"),
            "tensor_context_path": str(output / "h0" / "tensor.json"),
        },
    }
    template = {"arms": {"ecpa": {"phases": [phase]}}}
    prepare_native_paths(template, {"arm": "ecpa"}, output)
    assert (output / "h0").stat().st_mode & 0o777 == 0o700
    assert not Path(phase["handoff_path"]).exists()
    phase["evidence_path"] = str(tmp_path / "outside.jsonl")
    with pytest.raises(Exception, match="escapes this actual start"):
        prepare_native_paths(template, {"arm": "ecpa"}, output)
    phase["evidence_path"] = str(output / "h0" / "events.jsonl")
    Path(phase["evidence_path"]).touch()
    with pytest.raises(Exception, match="fresh private paths"):
        prepare_native_paths(template, {"arm": "ecpa"}, output)
