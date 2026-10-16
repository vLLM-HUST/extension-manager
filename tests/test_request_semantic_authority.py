"""CPU-only compiler/trust/clock/one-use regressions; no native qualification."""

import copy
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_request_drain_consumer import legacy_recipe as legacy_recipe
from test_semantic_runtime_binding import frozen as frozen

from experiments.formal_campaign import source_provenance as provenance
from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import request_drain_consumer as consumer
from experiments.native_attention_candidate import request_phasebook as books
from experiments.native_attention_candidate import (
    request_semantic_authority as semantic,
)


def source_fixture():
    fixed = dict(
        manager_commit="1" * 40,
        host_commit="2" * 40,
        accelerator_commit="3" * 40,
        plugin_commits={"cpu": "4" * 40},
    )
    repositories = {
        "manager": provenance.MANAGER,
        "host": provenance.HOST,
        "accelerator": "org/accelerator",
        "plugin:cpu": "org/cpu",
    }
    policy = {
        "schema": provenance.POLICY,
        "components": {
            role: {
                "repository": name,
                "requirement": "merged-main"
                if role in {"manager", "host"}
                else "published-commit",
            }
            for role, name in repositories.items()
        },
    }
    observation = {
        "schema": provenance.OBSERVATION,
        "policy_sha256": provenance.digest(semantic.canonical(policy)),
        "subjects": provenance.subjects(fixed),
        "identity_verified": True,
        "components": {},
    }
    for role, commit in observation["subjects"].items():
        merged = role in {"manager", "host"}
        observation["components"][role] = dict(
            role=role,
            repository=repositories[role],
            remote="https://github.com/" + repositories[role],
            requested_commit=commit,
            remote_commit=commit,
            tree="5" * 40,
            clean_checkout=True,
            requirement=policy["components"][role]["requirement"],
            main_commit=commit if merged else None,
            merged_to_main=True if merged else None,
        )
    return fixed, policy, observation


@pytest.fixture
def permitted(frozen, legacy_recipe, tmp_path):
    fixed, policy, observation = source_fixture()
    book = books.declare(consumer.declare_recipe(legacy_recipe))
    leaf = tmp_path / "CPU-actual-input.bin"
    leaf.write_bytes(b"CPU test actual input bytes, not an installed seven-wheel audit")
    sources = {r["path"]: r["sha256"] for r in book["recipe"]["sources"]}
    sources.update(semantic.protocol_sources())
    sources[str(leaf)] = semantic.sha(leaf.read_bytes())
    refs = [
        semantic.reference(frozen.path),
        frozen.spec["base_plan"],
        frozen.spec["plan"],
        frozen.spec["binding"],
        frozen.spec["plugin_map"],
        *frozen.spec["contracts"],
    ]
    sources.update({r["path"]: r["sha256"] for r in refs})
    audits = {}
    for phase in book["recipe"]["phases"]:
        token = phase["tokenization"]
        binding = token["runtime_binding"]
        models = {r["path"]: r["sha256"] for r in token["assets"]}
        config = {
            "model_files": token["assets"],
            "calibration_artifact": semantic.reference(leaf),
            "wheel_artifacts": {
                name: {"sha256": "a" * 64} for name in routes.DISTRIBUTIONS
            },
        }
        cfg = tmp_path / (phase["phase_id"] + "-CPU-input-config.json")
        cfg.write_bytes(semantic.canonical(config))
        paths = set(sources) | set(models) | {str(cfg)}
        audits[phase["phase_id"]] = {
            "schema": routes.SCHEMA,
            "formal_result": False,
            "request_sha256": semantic.sha(semantic.canonical(phase["payload"])),
            "wheel_sha256": {name: "a" * 64 for name in routes.DISTRIBUTIONS},
            "wheel_revisions": {
                "manager": fixed["manager_commit"],
                "host": fixed["host_commit"],
                "ascend": fixed["accelerator_commit"],
                "mod": "4" * 40,
            },
            "source_files": sources,
            "file_state": {path: routes._state(Path(path).stat()) for path in paths},
            "config": semantic.reference(cfg),
            "model_sha256": semantic.sha(semantic.canonical(models)),
            "tokenizer_sha256": semantic.sha(
                semantic.canonical(
                    {
                        "tokenization": token,
                        "host_sources": {
                            r["path"]: r["sha256"] for r in binding["host_sources"]
                        },
                        "implementation": {
                            binding["implementation_source"]["path"]: binding[
                                "implementation_source"
                            ]["sha256"]
                        },
                    }
                )
            ),
            "calibration_sha256": semantic.sha(leaf.read_bytes()),
        }
    authority = semantic.RequestSemanticAuthority(
        b"CPU_ONLY_KEY" * 4,
        {provenance.digest(semantic.canonical(observation))},
        bundles=(frozen.bundle,),
        trusted_input_audits={
            semantic.sha(semantic.canonical(audit)) for audit in audits.values()
        },
    )
    args = dict(
        launch_spec_path=frozen.path,
        phasebook=book,
        fixed=fixed,
        source_policy=policy,
        source_observation=observation,
        input_audits=audits,
        native_sources={str(leaf): semantic.sha(leaf.read_bytes())},
    )
    permit = authority.issue_request_permit(**args)
    return authority, permit, args, frozen, leaf


def test_actual_compiler_binding_is_required_without_issuing_completion(permitted):
    authority, permit, args, frozen, leaf = permitted
    value = authority.permit_current(permit)
    assert value["launch"]["execution_plan_id"] == frozen.plan.plan_id
    assert value["event"] == semantic.EVENT
    assert value["compiled_binding"]["obligation_id"] in {
        o.obligation_id for o in frozen.plan.obligations
    }
    assert value["phasebook_sha256"] == semantic.sha(
        semantic.canonical(args["phasebook"])
    )
    assert value["formal_result"] is False and authority.ledgers == {}
    assert "response" not in value


@pytest.mark.parametrize(
    "change", ["installed-payload", "source", "plan", "input-state", "mac"]
)
def test_no_stale_permit_after_actual_byte_or_trust_change(permitted, change):
    authority, permit, args, frozen, leaf = permitted
    if change == "installed-payload":
        (frozen.package / "plugin.py").write_text(
            "changed actual installed CPU fixture"
        )
    elif change == "source":
        leaf.write_bytes(b"changed actual pinned source")
    elif change == "plan":
        frozen.write("plan.json", b"{}")
    elif change == "input-state":
        leaf.chmod(0o400)
    else:
        permit = copy.deepcopy(permit)
        permit["body"]["compiled_binding"]["obligation_id"] = "invented"
    with pytest.raises(ValueError):
        authority.permit_current(permit)


def test_input_trust_and_actual_source_observation_are_independent(permitted):
    authority, permit, args, frozen, leaf = permitted
    changed = copy.deepcopy(args)
    changed["input_audits"][next(iter(changed["input_audits"]))]["request_sha256"] = (
        "0" * 64
    )
    with pytest.raises(ValueError, match="independently trusted"):
        authority.issue_request_permit(**changed)
    changed = copy.deepcopy(args)
    changed["source_observation"]["components"]["host"]["merged_to_main"] = False
    with pytest.raises(ValueError):
        authority.issue_request_permit(**changed)


def test_source_lifetime_never_restarts_at_owner_verification():
    now = time.monotonic_ns()
    seal = now - 31_000_000_000
    expiry = semantic.source_expiry(seal, now + 240_000_000_000, now + 30_000_000_000)
    assert expiry < now
    assert expiry == seal + semantic.LIFETIME_NS
    assert semantic.source_expiry(now, now + 10, now + 100) == now + 10
    assert semantic.source_expiry(now, now + 100, now + 10) == now + 10
    with pytest.raises(ValueError):
        semantic.source_expiry(True, now, now)


def test_completion_is_once_ordered_and_fixed_identity():
    ledger = semantic.CompletionLedger()
    expiry = time.monotonic_ns() + 30_000_000_000
    ledger.reserve("first", "same-proof-and-original-expiry", 0)
    with pytest.raises(ValueError):
        ledger.reserve("first", "renewed-expiry", 0)
    with pytest.raises(ValueError):
        ledger.reserve("second", "proof", 1)
    writes = []
    ledger.consume(
        "first",
        "same-proof-and-original-expiry",
        0,
        expiry,
        lambda: writes.append(True),
    )
    assert writes == [True]
    with pytest.raises(ValueError):
        ledger.consume(
            "first",
            "same-proof-and-original-expiry",
            0,
            expiry,
            lambda: writes.append(True),
        )
    ledger.reserve("second", "new-request-new-proof", 1)
    assert len(writes) == 1


def test_failed_durable_consume_burns_completion():
    ledger = semantic.CompletionLedger()
    ledger.reserve("request", "original-proof", 0)

    def failed():
        raise OSError("actual fsync/write failure fixture")

    with pytest.raises(OSError):
        ledger.consume(
            "request", "original-proof", 0, time.monotonic_ns() + 1_000_000_000, failed
        )
    with pytest.raises(ValueError):
        ledger.reserve("request", "original-proof", 0)
    assert ledger.next_phase == 0 and "request" in ledger.spent


def test_python_c_helper_is_not_an_installed_manager(tmp_path):
    intent = tmp_path / "intent.json"
    spec = tmp_path / "spec.json"
    spec.write_bytes(b"{}")
    intent.write_bytes(
        semantic.canonical(
            {
                "schema": "ecpa-request-manager-invocation-intent/v1",
                "semantic_launch_spec": semantic.reference(spec),
                "phase_binding_socket": str(tmp_path / "wire.sock"),
                "host_command": ["CPU_ONLY"],
                "request_control_socket": str(tmp_path / "control.sock"),
            }
        )
    )
    cfg = tmp_path / "config.json"
    cfg.write_bytes(semantic.canonical({"python": sys.executable}))
    audit = {
        "config": semantic.reference(cfg),
        "source_files": {str(intent): semantic.sha(intent.read_bytes())},
        "file_state": {str(intent): routes._state(intent.stat())},
    }
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.read()"], stdin=subprocess.PIPE
    )
    try:
        manager = semantic.registry.process_identity(child.pid)
        with pytest.raises(ValueError, match="audited installed console"):
            semantic.observe_manager_invocation(
                manager, semantic.reference(intent), audit
            )
    finally:
        child.stdin.close()
        child.wait(timeout=5)


def test_audit_source_closure_cannot_be_self_selected(tmp_path):
    leaf = tmp_path / "actual.py"
    leaf.write_bytes(b"actual CPU source")
    sources = {str(leaf): semantic.sha(leaf.read_bytes())}
    audit = {
        "file_state": {str(leaf): routes._state(leaf.stat())},
        "source_files": {"unrelated": "0" * 64},
    }
    with pytest.raises(ValueError, match="exact source closure"):
        semantic.require_audited_sources(audit, sources)
    audit["source_files"] = sources
    semantic.require_audited_sources(audit, sources)
    leaf.write_bytes(b"changed source")
    with pytest.raises(ValueError):
        semantic.require_audited_sources(audit, sources)


@pytest.mark.parametrize(
    "corrupt",
    [
        None,
        "role",
        "epoch",
        "inode",
        "native-epoch",
        "native-host",
        "enrollment-only-epoch",
    ],
)
def test_original_manager_host_role_receipt_requires_exact_kernel_and_epoch(
    tmp_path, corrupt
):
    # Explicitly constructed CPU Host event fixture: verifies the parser/receipt
    # edge only, never claims this is genuine Manager or native completion.
    import json
    import os
    from types import SimpleNamespace

    from test_host_evidence import BINDING, raw_event

    path = tmp_path / "CPU-host-events.jsonl"
    kernel = semantic.registry.process_identity(os.getpid())
    process = {
        "host": "CPU_HOST",
        "role": "worker",
        "ordinal": 0,
        "pid": kernel["pid"],
        "start_identity": f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
        "process_epoch": 77,
        "assignment_source": "host",
    }
    plan_id, launch_id = "a" * 64, "CPU_ONLY_launch"
    events = [raw_event(process=process, plan_id=plan_id, launch_id=launch_id)]
    if corrupt == "role":
        events = [
            raw_event(
                process=process | {"pid": 1}, plan_id=plan_id, launch_id=launch_id
            )
        ]
    elif corrupt == "epoch":
        events.append(
            raw_event(
                process=process | {"process_epoch": 78},
                plan_id=plan_id,
                launch_id=launch_id,
            )
        )
    path.write_bytes(b"\n".join(events) + b"\n")
    path.chmod(0o600)
    meta = path.stat()
    captured = {
        "host_evidence": {
            "path": str(path),
            "identity": [meta.st_dev, meta.st_ino, meta.st_uid],
        },
        "record": {"environment": {"VLLM_ECPA_LAUNCH_ID": launch_id}},
    }
    authority = object.__new__(semantic.RequestSemanticAuthority)
    entry = SimpleNamespace(group=BINDING.group, name=BINDING.name, value=BINDING.value)
    authority.bundles = (
        SimpleNamespace(
            entry_points=(entry,),
            manifest=SimpleNamespace(activation=SimpleNamespace(entry_points=(entry,))),
        ),
    )
    sender = {"process": {**kernel, **process}}
    if corrupt == "native-epoch":
        sender["process"]["process_epoch"] = 78
    elif corrupt == "native-host":
        sender["process"]["host"] = "OTHER_NATIVE_HOST"
    spec = tmp_path / "CPU-native-spec.json"
    spec.write_bytes(semantic.canonical({"senders": [sender]}))
    enrollment = {
        "source_peers": copy.deepcopy([sender]),
        "spec": semantic.reference(spec),
    }
    if corrupt == "enrollment-only-epoch":
        enrollment["source_peers"][0]["process"]["process_epoch"] = 78
    if corrupt == "inode":
        moved = path.with_suffix(".original")
        path.rename(moved)
        path.write_bytes(moved.read_bytes())
        path.chmod(0o600)
    if corrupt:
        with pytest.raises(ValueError):
            authority._host_roles_current(
                captured, {"worker/0": kernel}, {"native_plan_id": plan_id}, enrollment
            )
    else:
        observed = authority._host_roles_current(
            captured, {"worker/0": kernel}, {"native_plan_id": plan_id}, enrollment
        )
        assert observed["roles"]["worker/0"]["process_epoch"] == 77
        assert observed["prefix_sha256"] == semantic.sha(path.read_bytes())
        assert json.loads(events[0])["process"]["pid"] == kernel["pid"]


@pytest.mark.parametrize(
    "name", ["snapshot/native.jsonl", "response.bin", "snapshot/artifact.bin"]
)
def test_only_exact_bound_global_prefix_may_exceed_eight_mib(tmp_path, name):
    # Checks bounded IO only; arbitrary CPU bytes are not a valid native journal.
    output = tmp_path / "request-0001"
    path = output / name
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"CPU_IO_BOUND_TEST_ONLY":1}\n' * 340_000)
    assert path.stat().st_size > 8 * 1024 * 1024
    if name == "snapshot/native.jsonl":
        files = semantic.snapshot_files(output)
        semantic.check_completion_files(
            {"files": files, "native_prefix_path": str(path)}
        )
        assert files[str(path)] == semantic.sha(path.read_bytes())
    else:
        with pytest.raises(ValueError):
            semantic.snapshot_files(output)


def test_global_prefix_still_has_sixty_four_mib_limit(tmp_path):
    output = tmp_path / "request-0001"
    prefix = output / "snapshot/native.jsonl"
    prefix.parent.mkdir(parents=True)
    with prefix.open("wb") as stream:
        stream.truncate(semantic.MAX_PREFIX_BYTES + 1)
    with pytest.raises(ValueError):
        semantic.snapshot_files(output)


def test_json_cannot_substitute_opaque_owner_verified_capability():
    authority = object.__new__(semantic.RequestSemanticAuthority)
    import threading

    authority.lock, authority.verified_capabilities = threading.RLock(), {}
    for supplied in ({"observation": "fake"}, semantic.VerifiedRequestCompletion()):
        with pytest.raises(ValueError, match="opaque owner-verified"):
            authority.verified_completion(supplied)


def test_original_producer_completion_clock_is_fixed_not_source_seal_or_owner_now():
    from experiments.native_attention_candidate import request_live_producer as producer

    issued = time.monotonic_ns()
    deadline, route_expiry = issued + 240_000_000_000, issued + 1800_000_000_000
    clock = producer.fixed_completion_clock(issued, deadline, route_expiry)
    assert clock["expires_monotonic_ns"] == issued + 30_000_000_000
    assert producer.fixed_completion_clock(issued, deadline, route_expiry) == clock
    assert (
        producer.fixed_completion_clock(issued, issued + 10, route_expiry)[
            "expires_monotonic_ns"
        ]
        == issued + 10
    )
    assert (
        producer.fixed_completion_clock(issued, deadline, issued + 20)[
            "expires_monotonic_ns"
        ]
        == issued + 20
    )
    with pytest.raises(ValueError):
        producer.fixed_completion_clock(issued, deadline, issued - 1)
    with pytest.raises(ValueError):
        producer.fixed_completion_clock(True, deadline, route_expiry)
    assert producer.completion_domain({}) == producer.COMPLETION
    with pytest.raises(ValueError):
        producer.completion_domain({"completion_domain": producer.FIXED_COMPLETION})


def test_failed_consume_burns_opaque_capability_and_revokes_deployment():
    import threading

    authority = object.__new__(semantic.RequestSemanticAuthority)
    authority.lock = threading.RLock()
    authority.revoked_deployments = set()
    capability = semantic.VerifiedRequestCompletion()
    authority.verified_capabilities = {
        capability: ({"body": {"deployment_sha256": "CPU_ONLY"}}, {})
    }

    def failed_current(*args):
        raise ValueError("actual epoch gone after owner verification")

    authority.deployment_current = failed_current
    with pytest.raises(ValueError, match="actual epoch gone"):
        authority.consume_request(
            {},
            {"sha256": "CPU_ONLY"},
            capability,
            route_reader=None,
            admission={},
            persist=lambda: None,
        )
    assert capability not in authority.verified_capabilities
    assert authority.revoked_deployments == {"CPU_ONLY"}
    with pytest.raises(ValueError, match="already burned"):
        authority.consume_request(
            {},
            {"sha256": "CPU_ONLY"},
            capability,
            route_reader=None,
            admission={},
            persist=lambda: None,
        )
