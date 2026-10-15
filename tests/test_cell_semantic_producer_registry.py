"""Real CPU process/socket bindings with explicitly synthetic semantic fixtures."""

import copy
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from experiments.formal_campaign import source_provenance as provenance
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.runtime_phase_handoff import bind_receiver

ROUTE = {}
OBSERVATION = {}


def cpu_route_reader():
    return copy.deepcopy(ROUTE)


def cpu_observation_verifier(**kwargs):
    # This is a declared CPU fixture, not an implementation of native semantics.
    return copy.deepcopy(OBSERVATION)


@pytest.fixture
def cell(tmp_path):
    global ROUTE, OBSERVATION
    tmp_path.chmod(0o700)
    plugin = PluginIdentity("org.example", "cpu", "1", "a" * 64)
    plan = Plan(
        (plugin,),
        HostCompatibility("CPU_FIXTURE", "1", "CPU", "CPU"),
        (),
        (EvidenceObligation("bounded", "worker", registry.EVENT, (0, 1)),),
        PredecessorSnapshot(0, None, {}),
    )
    scope = dict(
        execution_plan_id=plan.plan_id,
        native_plan_id=plan.plan_id.rsplit(":", 1)[1],
        native_launch_id=str(uuid.uuid4()),
        controller_instance="controller:CPU",
        candidate_generation=1,
        membership_epoch=0,
    )
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
    subjects = provenance.subjects(fixed)
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
        "policy_sha256": provenance.digest(provenance.canonical(policy)),
        "subjects": subjects,
        "identity_verified": True,
        "components": {},
    }
    for role, commit in subjects.items():
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
    # Only the CPU test's independent issuer trusts this synthetic observation.
    trust = {provenance.digest(provenance.canonical(observation))}
    issuer = registry.CellIssuer(
        b"CPU_TEST_ONLY_ISSUER_KEY_NOT_A_REAL_SECRET" * 2, trust
    )
    here = str(Path(__file__).resolve())
    reference = {"path": here, "sha256": registry.sha(Path(here).read_bytes())}
    registry_ref = {
        "path": str(Path(registry.__file__).resolve()),
        "sha256": registry.sha(Path(registry.__file__).read_bytes()),
    }
    recipe = {
        "phases": [
            {
                "phase_id": "CPU",
                "payload": {"CPU": True},
                "ack_time_policy": "CPU_FIXTURE_ONLY",
                "tokenization": {"runtime_binding": {"CPU": True}},
            }
        ],
        "tensor_consumer_contract": {"CPU": True},
        "attention_consumer_contract": {"CPU": True},
        "attention_drain_contract": {"CPU": True},
    }
    definition = dict(
        manager_handoff_sources=registry.manager_source_digests(),
        cell_id="CPU_FIXTURE_ONLY",
        execution_plan_id=plan.plan_id,
        obligation_id="bounded",
        event=registry.EVENT,
        scope=registry.SCOPE,
        plugin_ids=[plugin.id],
        profile_id=registry.recipe_profile_id(recipe),
        recipe_sha256=registry.sha(registry.canonical(recipe)),
        request_sha256=registry.sha(registry.canonical({"CPU": True})),
        model_sha256="a" * 64,
        tokenizer_sha256="b" * 64,
        calibration_sha256="c" * 64,
        wheel_sha256={
            k: "d" * 64
            for k in (
                "host",
                "ascend",
                "mod",
                "manager",
                "torch",
                "torch_npu",
                "triton",
            )
        },
        native_sources={here: reference["sha256"]},
        protocol_sources={
            "producer": reference,
            "verifier": {**reference, "callable": "cpu_observation_verifier"},
            "route_reader": {**reference, "callable": "cpu_route_reader"},
            "registry": registry_ref,
        },
    )
    permit = issuer.issue_permit(
        definition,
        execution_plan=plan,
        recipe=recipe,
        fixed=fixed,
        policy=policy,
        source_observation=observation,
    )
    processes = []
    server = connection = None
    try:
        env = os.environ | {
            "VLLM_ECPA_PLAN_ID": scope["native_plan_id"],
            "VLLM_ECPA_LAUNCH_ID": scope["native_launch_id"],
            "ECPA_SEMANTIC_EXECUTION_PLAN_ID": scope["execution_plan_id"],
            "ECPA_SEMANTIC_CONTROLLER_INSTANCE": scope["controller_instance"],
            "ECPA_SEMANTIC_CANDIDATE_GENERATION": "1",
            "ECPA_SEMANTIC_MEMBERSHIP_EPOCH": "0",
        }
        handoff_path = tmp_path / "handoff.sock"
        listener = bind_receiver(handoff_path, 10)
        launched = time.time_ns()
        handoff_env = {k: env[k] for k in ("VLLM_ECPA_PLAN_ID", "VLLM_ECPA_LAUNCH_ID")}
        handoff_env.update(
            VLLM_ECPA_EVIDENCE_SINK="vllm_hust_ext.runtime_evidence:record_event",
            VLLM_ECPA_EVIDENCE_STRICT="1",
            VLLM_HUST_EXT_EVIDENCE_PATH="/CPU-placeholder",
        )
        child_env = env | {
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")
        }
        code = (
            "import sys,json,time;from pathlib import Path;"
            "from vllm_hust_ext.runtime_phase_handoff import publish_native_binding;"
            "publish_native_binding(json.loads(sys.argv[1]),Path(sys.argv[2]));time.sleep(60)"
        )
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    code,
                    json.dumps(handoff_env),
                    str(handoff_path),
                ],
                env=child_env,
            )
        )
        try:
            handoff = issuer.accept_handoff(
                permit,
                listener=listener,
                path=handoff_path,
                manager=registry.process_identity(processes[0].pid),
                launched_wall_ns=launched,
            )
        finally:
            listener.close()
        for _ in range(3):
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"], env=env
                )
            )
        peers = {
            name: registry.process_identity(p.pid)
            for name, p in zip(
                ["api-server/0", "worker/0", "worker/1"], processes[1:], strict=True
            )
        }
        manager = registry.process_identity(processes[0].pid)
        producer = registry.process_identity(os.getpid())
        socket_path = tmp_path / "producer.sock"
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(socket_path))
        server.listen()
        connection = socket.socket(socket.AF_UNIX)
        connection.connect(str(socket_path))
        ROUTE = dict(
            execution_plan_id=scope["execution_plan_id"],
            native_launch_id=scope["native_launch_id"],
            generation=1,
            membership_epoch=0,
            controller_instance="controller:CPU",
            fence="CPU-fence-1",
            lease_expires_monotonic_ns=time.monotonic_ns() + 20_000_000_000,
        )
        senders = []
        for role, identity in peers.items():
            name, rank = role.split("/")
            senders.append(
                {
                    "process": {**identity, "role": name, "ordinal": int(rank)},
                    "source_files": [reference],
                }
            )
        values = {
            "recipe": recipe,
            "spec": {
                "native_plan_id": scope["native_plan_id"],
                "native_launch_id": scope["native_launch_id"],
                "senders": senders,
            },
            "policy": {},
            "drain_policy": {},
        }
        values["registration"] = {
            **scope,
            "manager_identity": manager,
            "spec_path": str(tmp_path / "spec.json"),
            "recipe_path": str(tmp_path / "recipe.json"),
            "producer_source_path": here,
            "producer_source_sha256": reference["sha256"],
            "probe_output": str(tmp_path / "CPU-probe"),
            "journal_path": str(tmp_path / "CPU-journal.jsonl"),
            "phase_id": "CPU",
            "collector_descriptor": {"CPU_fixture": True},
        }
        artifacts = {}
        for name, value in values.items():
            path = tmp_path / (name + ".json")
            path.write_bytes(registry.canonical(value))
            artifacts[name] = {
                "path": str(path),
                "sha256": registry.sha(path.read_bytes()),
            }
        deployment = issuer.bind_deployment(
            permit,
            handoff=handoff,
            scope=scope,
            manager=manager,
            peers=peers,
            producer=producer,
            socket_path=socket_path,
            connection=connection,
            artifacts=artifacts,
            route_reader=cpu_route_reader,
        )
        journal = tmp_path / "CPU-journal.jsonl"
        cpu_rows = [
            {"kind": kind}
            for kind in (
                ["CPU.start"] * 4
                + ["native.accepted"] * 3
                + ["tensor.artifact.accepted"] * 56
                + ["attention.operator.accepted"] * 56
                + ["attention.worker.drained"] * 2
            )
        ]
        journal.write_bytes(
            b"".join(registry.canonical(row) + b"\n" for row in cpu_rows)
        )
        OBSERVATION = dict(
            observed_typed_HTTP_ACK_join=True,
            finite_native_argument_completion_join=True,
            typed_archive_provenance={"full_phase_source_drained": True},
            tensor_receipt_count=56,
            operator_receipt_count=56,
            actual_raw_response_sha256="e" * 64,
            whole_journal_sha256=registry.sha(journal.read_bytes()),
        )
        args = dict(
            recipe=recipe,
            phase_id="CPU",
            output=Path(values["registration"]["probe_output"]),
            journal_path=journal,
            descriptor=values["registration"]["collector_descriptor"],
            spec_path=Path(artifacts["spec"]["path"]),
            policy_path=Path(artifacts["policy"]["path"]),
            drain_policy_path=Path(artifacts["drain_policy"]["path"]),
        )
        yield locals()
    finally:
        if connection is not None:
            connection.close()
        if server is not None:
            server.close()
        for process in processes:
            process.terminate()
            process.wait(timeout=5)


def quote(cell, verifier, nonce="6" * 64, expires=None):
    verifier.expect(nonce)
    return dict(
        schema="ecpa-live-native-semantic-quote/v1",
        nonce=nonce,
        registration_sha256=registry.sha(
            registry.canonical(cell["values"]["registration"])
        ),
        producer=cell["producer"],
        scope=cell["scope"],
        ready=True,
        reason="CPU semantic fixture only",
        formal_result=False,
        proof=dict(
            tensor_receipts=56,
            operator_receipts=56,
            worker_closures=2,
            full_prefix_records=121,
            request_sha256=cell["definition"]["request_sha256"],
            observation_sha256=registry.sha(registry.canonical(OBSERVATION)),
            response_sha256="e" * 64,
            issued_monotonic_ns=time.monotonic_ns(),
            expires_monotonic_ns=expires or time.monotonic_ns() + 10_000_000_000,
        ),
    )


def verify(cell, verifier, value, **kwargs):
    return verifier.verify(
        cell["permit"],
        cell["deployment"],
        value,
        connection=cell["connection"],
        route_reader=cpu_route_reader,
        observation_verifier=cpu_observation_verifier,
        observation_arguments=kwargs or cell["args"],
    )


def test_real_CPU_binding_and_nonce_replay(cell):
    verifier = registry.QuoteVerifier(cell["issuer"])
    value = quote(cell, verifier)
    result = verify(cell, verifier, value)
    assert result["status"] == "bounded-cell-quote-verified"
    assert result["formal_result"] is False and result["other_cells"] == "unverified"
    with pytest.raises(ValueError, match="replayed"):
        verify(cell, verifier, value)
    with pytest.raises(ValueError, match="reused"):
        verifier.expect(value["nonce"])


def test_permit_does_not_self_admit_invocation_or_unknown_sources(cell):
    args = dict(
        execution_plan=cell["plan"],
        recipe=cell["recipe"],
        fixed=cell["fixed"],
        policy=cell["policy"],
        source_observation=cell["observation"],
    )
    invocation = {**cell["definition"], "event": "invoked"}
    with pytest.raises(ValueError, match="semantic effect scope"):
        cell["issuer"].issue_permit(invocation, **args)
    different = copy.deepcopy(cell["observation"])
    different["components"]["accelerator"]["tree"] = "9" * 40
    with pytest.raises(ValueError, match="independently trusted"):
        cell["issuer"].issue_permit(
            cell["definition"], **(args | {"source_observation": different})
        )
    handoff = copy.deepcopy(cell["handoff"])
    handoff["body"]["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"] = str(uuid.uuid4())
    with pytest.raises(ValueError, match="authentication failed"):
        cell["issuer"].bind_deployment(
            cell["permit"],
            handoff=handoff,
            scope=cell["scope"],
            manager=cell["manager"],
            peers=cell["peers"],
            producer=cell["producer"],
            socket_path=cell["socket_path"],
            connection=cell["connection"],
            artifacts=cell["artifacts"],
            route_reader=cpu_route_reader,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "epoch",
        "route",
        "route_launch",
        "expiry",
        "request",
        "scope",
        "permit",
        "invocation",
        "old_artifact",
        "socket",
    ],
)
def test_precise_admission_counterexamples(cell, mutation):
    verifier = registry.QuoteVerifier(cell["issuer"])
    value = quote(cell, verifier)
    args = copy.deepcopy(cell["args"])
    if mutation == "epoch":
        cell["processes"][-1].terminate()
        cell["processes"][-1].wait(timeout=5)
    elif mutation == "route":
        ROUTE["fence"] = "new-generation-fence"
    elif mutation == "route_launch":
        ROUTE["native_launch_id"] = str(uuid.uuid4())
    elif mutation == "expiry":
        value["proof"]["expires_monotonic_ns"] = time.monotonic_ns() - 1
    elif mutation == "request":
        value["proof"]["request_sha256"] = "0" * 64
    elif mutation == "scope":
        value["scope"] = {**value["scope"], "membership_epoch": 1}
    elif mutation == "permit":
        cell["permit"]["body"]["cell"]["obligation_id"] = "invocation"
    elif mutation == "invocation":
        OBSERVATION["finite_native_argument_completion_join"] = False
        value["proof"]["observation_sha256"] = registry.sha(
            registry.canonical(OBSERVATION)
        )
    elif mutation == "old_artifact":
        args["spec_path"] = Path("/CPU_foreign_deployment/spec.json")
    else:
        cell["socket_path"].unlink()
        replacement = socket.socket(socket.AF_UNIX)
        try:
            replacement.bind(str(cell["socket_path"]))
            with pytest.raises(ValueError, match="socket replaced"):
                verify(cell, verifier, value)
        finally:
            replacement.close()
        return
    with pytest.raises((ValueError, OSError)):
        verify(cell, verifier, value, **args)


def test_lease_is_nonrenewable_and_verifier_must_be_the_pinned_function(cell):
    verifier = registry.QuoteVerifier(cell["issuer"])
    first = quote(cell, verifier)
    verify(cell, verifier, first)
    renewed = quote(
        cell,
        verifier,
        nonce="7" * 64,
        expires=first["proof"]["expires_monotonic_ns"] + 100,
    )
    with pytest.raises(ValueError, match="cannot be renewed"):
        verify(cell, verifier, renewed)
    value = quote(
        cell, verifier, nonce="8" * 64, expires=first["proof"]["expires_monotonic_ns"]
    )
    with pytest.raises(ValueError, match="callback function differs"):
        verifier.verify(
            cell["permit"],
            cell["deployment"],
            value,
            connection=cell["connection"],
            route_reader=cpu_route_reader,
            observation_verifier=cpu_route_reader,
            observation_arguments=cell["args"],
        )


@pytest.mark.parametrize(
    "counter",
    ["tensor_receipts", "operator_receipts", "worker_closures", "full_prefix_records"],
)
def test_quoted_counts_cannot_disagree_with_independently_checked_raw(cell, counter):
    verifier = registry.QuoteVerifier(cell["issuer"])
    value = quote(cell, verifier)
    value["proof"][counter] -= 1
    with pytest.raises(ValueError, match="counts differ"):
        verify(cell, verifier, value)
