"""CPU authority boundary fixtures; these never qualify native device effects."""

from __future__ import annotations

import copy
import json
import secrets
import time
from pathlib import Path

import pytest
from test_activation_profile import installation as installation
from test_baseline_host_binding import real_host as real_host
from test_baseline_live_producer import live_registration as live_registration

from experiments.native_attention_candidate import baseline_cell_issuer as authority
from experiments.native_attention_candidate import baseline_live_producer as producer
from experiments.native_attention_candidate import semantic_producer_registry as util

OBSERVED = {}
VERIFICATION_HOOK = None


def fixture_verifier(**_arguments):
    result = copy.deepcopy(OBSERVED)
    if VERIFICATION_HOOK is not None:
        VERIFICATION_HOOK()
    return result


def write(path, value):
    path.write_bytes(util.canonical(value))
    path.chmod(0o600)
    return {"path": str(path), "sha256": util.sha(path.read_bytes())}


@pytest.fixture
def proof_fixture(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    payload = {"CPU_FIXTURE_ONLY": True}
    recipe = {"phases": [{"phase_id": "cpu", "payload": payload}]}
    scope = {"CPU_SCOPE_ONLY": True}
    write(tmp_path / "scope.json", scope)
    registration = {
        "baseline_scope_reference": {
            "path": str(tmp_path / "scope.json"),
            "sha256": util.sha((tmp_path / "scope.json").read_bytes()),
        },
        "probe_output": str(tmp_path),
        "journal_path": str(tmp_path / "native.jsonl"),
        "spec_path": str(tmp_path / "spec.json"),
        "policy_path": str(tmp_path / "policy.json"),
        "drain_policy_path": str(tmp_path / "drain.json"),
        "phase_id": "cpu",
        "collector_descriptor": {"CPU_ONLY": True},
    }
    ref = write(tmp_path / "registration.json", registration)
    rows = (
        [{"kind": "tensor.artifact.accepted"}] * 56
        + [{"kind": "attention.operator.accepted"}] * 56
        + [{"kind": "attention.worker.drained"}] * 2
    )
    journal = b"".join(util.canonical(row) + b"\n" for row in rows)
    (tmp_path / "native.jsonl").write_bytes(journal)
    (tmp_path / "response.bin").write_bytes(b"CPU ONLY")
    OBSERVED.clear()
    OBSERVED.update(
        observed_typed_HTTP_ACK_join=True,
        finite_native_argument_completion_join=True,
        typed_archive_provenance={"full_phase_source_drained": True},
        tensor_receipt_count=56,
        operator_receipt_count=56,
        actual_raw_response_sha256=util.sha(b"CPU ONLY"),
        whole_journal_sha256=util.sha(journal),
    )
    now = time.monotonic_ns()
    proof = {
        "observation_sha256": util.sha(util.canonical(OBSERVED)),
        "request_sha256": util.sha(util.canonical(payload)),
        "response_sha256": util.sha(b"CPU ONLY"),
        "issued_monotonic_ns": now,
        "expires_monotonic_ns": now + 30_000_000_000,
        "tensor_receipts": 56,
        "operator_receipts": 56,
        "worker_closures": 2,
        "full_prefix_records": len(rows),
    }
    completion = {
        "schema": producer.COMPLETION,
        "origin": authority.ORIGIN,
        "producer": {"CPU_KERNEL_ONLY": 1},
        "registration_sha256": util.sha(util.canonical(registration)),
        "scope": scope,
        "proof": proof,
        "formal_result": False,
    }
    write(tmp_path / producer.RESERVED_OUTPUTS[0], completion)
    quote = {
        "schema": producer.QUOTE,
        "origin": authority.ORIGIN,
        "nonce": secrets.token_hex(32),
        "registration_sha256": completion["registration_sha256"],
        "producer": completion["producer"],
        "scope": scope,
        "ready": True,
        "reason": "CPU fixture, not qualification",
        "proof": copy.deepcopy(proof),
        "formal_result": False,
    }
    value = {
        "cell": {
            "request_sha256": proof["request_sha256"],
            "protocol_sources": {
                "verifier": {
                    "path": str(Path(__file__).resolve()),
                    "callable": "fixture_verifier",
                    "sha256": util.sha(Path(__file__).read_bytes()),
                }
            },
        }
    }
    binding = {
        "permit_sha256": "CPU-permit",
        "producer": completion["producer"],
        "artifacts": {"registration": ref},
        "route": {"lease_expires_monotonic_ns": proof["expires_monotonic_ns"]},
    }
    calls = []

    class CPUOnlyIssuer:
        def _permit(self, _permit):
            return value

        def _open(self, _deployment, schema):
            assert schema == authority.DEPLOYMENT
            return binding

        def _live(self, *_args):
            calls.append("current")
            return registration, recipe

    monkeypatch.setattr(authority, "_collector", lambda *_: calls.append("collector"))
    monkeypatch.setattr(
        authority.drain_consumer, "verify_observation", fixture_verifier
    )
    verifier = authority.BaselineQuoteVerifier(CPUOnlyIssuer())
    verifier.expect(quote["nonce"])
    quote["proof"]["issued_monotonic_ns"] = time.monotonic_ns()
    arguments = {
        "recipe": recipe,
        "phase_id": "cpu",
        "output": tmp_path,
        "descriptor": registration["collector_descriptor"],
        **{
            k: Path(registration[k])
            for k in ("spec_path", "journal_path", "policy_path", "drain_policy_path")
        },
    }
    return verifier, quote, arguments, completion, tmp_path, calls


def verify(data):
    verifier, quote, arguments, _, _, _ = data
    return verifier.verify(
        {"sha256": "CPU-permit"},
        {"sha256": "CPU-deployment"},
        quote,
        connection=None,
        route_reader=None,
        observation_arguments=arguments,
    )


def test_independent_fixture_reconstructs_counts_and_burns_nonce(proof_fixture):
    result = verify(proof_fixture)
    assert result["formal_result"] is False
    assert proof_fixture[-1] == ["current", "collector", "collector", "current"]
    with pytest.raises(ValueError, match="pending/replayed"):
        verify(proof_fixture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "ecpa-live-native-semantic-quote/v1"),
        ("origin", "Manager"),
        ("ready", 1),
        ("formal_result", 0),
    ],
)
def test_cross_origin_or_nonboolean_quote_rejected(proof_fixture, field, value):
    proof_fixture[1][field] = value
    with pytest.raises(ValueError, match="typed quote"):
        verify(proof_fixture)
    with pytest.raises(ValueError, match="pending/replayed"):
        verify(proof_fixture)


def test_unseen_completion_cannot_renew_first_quote(proof_fixture):
    data = proof_fixture
    completion = data[3]
    completion["proof"]["issued_monotonic_ns"] -= 1
    write(data[4] / producer.RESERVED_OUTPUTS[0], completion)
    with pytest.raises(ValueError, match="fixed lifetime"):
        verify(data)


def test_completion_scope_cannot_be_substituted(proof_fixture):
    completion = proof_fixture[3]
    completion["scope"] = {"another": "arm"}
    write(proof_fixture[4] / producer.RESERVED_OUTPUTS[0], completion)
    with pytest.raises(ValueError, match="fixed lifetime"):
        verify(proof_fixture)


@pytest.mark.parametrize("mutation", ["tensor", "closure", "response", "args"])
def test_full_raw_or_arguments_drift_rejected(proof_fixture, mutation):
    data = proof_fixture
    if mutation in {"tensor", "closure"}:
        path = data[4] / "native.jsonl"
        rows = path.read_bytes().splitlines()
        rows.pop(0 if mutation == "tensor" else -1)
        path.write_bytes(b"\n".join(rows) + b"\n")
    elif mutation == "response":
        (data[4] / "response.bin").write_bytes(b"another raw response")
    else:
        data[2]["spec_path"] = data[4] / "another-spec.json"
    with pytest.raises(
        ValueError, match="observation/counts/raw|observation arguments"
    ):
        verify(data)


def test_boolean_receipt_count_rejected(proof_fixture):
    proof_fixture[1]["proof"]["tensor_receipts"] = True
    with pytest.raises(ValueError, match="count types"):
        verify(proof_fixture)


def test_expensive_verification_expiry_fails_closed(proof_fixture, monkeypatch):
    data = proof_fixture
    expiry = data[1]["proof"]["expires_monotonic_ns"]

    def expire():
        monkeypatch.setattr(authority.time, "monotonic_ns", lambda: expiry)

    monkeypatch.setitem(globals(), "VERIFICATION_HOOK", expire)
    with pytest.raises(ValueError, match="expired during independent verification"):
        verify(data)


def test_envelopes_baseline_domain_and_tamper_guard():
    issuer = authority.BaselineCellIssuer(b"K" * 32, {"source"}, {"inputs"})
    envelope = issuer._seal(
        {"schema": authority.PERMIT, "origin": authority.ORIGIN, "formal_result": False}
    )
    assert issuer._open(envelope, authority.PERMIT)["origin"] == authority.ORIGIN
    with pytest.raises(ValueError, match="schema/result"):
        issuer._open(envelope, util.PERMIT)
    envelope["body"]["origin"] = "manager"
    with pytest.raises(ValueError, match="authentication"):
        issuer._open(envelope, authority.PERMIT)


def test_empty_input_trust_rejected():
    with pytest.raises(ValueError, match="input trust"):
        authority.BaselineCellIssuer(b"K" * 32, {"source"}, set())


class CPUActualRoute:
    def __init__(self, owner, route):
        self.owner, self.route = owner, route

    def read(self):
        return copy.deepcopy(self.route)


@pytest.fixture
def actual_registration_guard(live_registration):
    import socket
    import subprocess
    import sys

    from vllm_hust_ext.runtime_phase_handoff import process_identity

    path, registration, root, observer = live_registration
    source = (
        "import socket,sys,time; s=socket.socket(socket.AF_UNIX); "
        "s.bind(sys.argv[1]); s.listen(1); print('ready',flush=True); "
        "c,_=s.accept(); time.sleep(60)"
    )
    child = subprocess.Popen(
        [sys.executable, "-c", source, registration["producer_socket"]],
        stdout=subprocess.PIPE,
        text=True,
    )
    collector = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert child.stdout.readline().strip() == "ready"
        connection.connect(registration["producer_socket"])
        registration["collector_descriptor"]["collector"] = {"pid": collector.pid}
        reg_ref = write(path, registration)
        artifacts = {
            "registration": reg_ref,
            **{
                name: {
                    "path": registration[key],
                    "sha256": util.sha(Path(registration[key]).read_bytes()),
                }
                for name, key in (
                    ("recipe", "recipe_path"),
                    ("spec", "spec_path"),
                    ("policy", "policy_path"),
                    ("drain_policy", "drain_policy_path"),
                )
            },
        }
        scope = authority._object(registration["baseline_scope_reference"])
        route = {
            key: scope[key]
            for key in (
                "observer_trial_id",
                "arm",
                "activation_profile_sha256",
                "common_query_sha256",
            )
        }
        route.update(
            controller_instance="CPU-controller",
            generation=1,
            membership_epoch=0,
            fence="CPU-fence",
            lease_expires_monotonic_ns=time.monotonic_ns() + 30_000_000_000,
        )
        reader = CPUActualRoute(observer.owner, route)
        cell = {
            "native_sources": {
                s["path"]: s["sha256"]
                for s in registration["source_peers"][0]["source_files"]
            },
            "recipe_sha256": artifacts["recipe"]["sha256"],
            "common_query_sha256": scope["common_query_sha256"],
            "protocol_sources": {
                "producer": {
                    "path": registration["producer_source_path"],
                    "sha256": registration["producer_source_sha256"],
                },
                "controller": {
                    "path": str(Path(__file__).resolve()),
                    "sha256": util.sha(Path(__file__).read_bytes()),
                    "callable": "CPUActualRoute.read",
                },
            },
        }
        issuer = authority.BaselineCellIssuer(b"K" * 32, {"source"}, {"input"})
        bound = {
            "artifacts": artifacts,
            "producer": process_identity(child.pid),
            "socket_path": registration["producer_socket"],
            "route": copy.deepcopy(route),
            "socket_identity": util._socket(
                registration["producer_socket"], connection, process_identity(child.pid)
            ),
        }
        yield (
            issuer,
            {
                "cell": cell,
                "baseline_scope_reference": registration["baseline_scope_reference"],
                "activation_profile_reference": registration[
                    "activation_profile_reference"
                ],
            },
            bound,
            connection,
            reader,
        )
    finally:
        connection.close()
        for process in (child, collector):
            process.terminate()
            process.wait(5)


def test_actual_five_process_epoch_and_stock_Host_prefix_guard(
    actual_registration_guard,
):
    issuer, value, bound, connection, reader = actual_registration_guard
    registration, _ = issuer._live(value, bound, connection, reader.read)
    assert registration["origin"] == authority.ORIGIN
    reader.route["generation"] += 1
    with pytest.raises(ValueError, match="route changed or expired"):
        issuer._live(value, bound, connection, reader.read)


def test_actual_producer_kernel_reuse_is_rejected(actual_registration_guard):
    issuer, value, bound, connection, reader = actual_registration_guard
    registration = authority._object(bound["artifacts"]["registration"])
    bound["producer"] = registration["owner_kernel"]
    with pytest.raises(ValueError, match="five distinct"):
        issuer._live(value, bound, connection, reader.read)


@pytest.fixture
def trusted_permit_fixture(live_registration, monkeypatch):
    from experiments.native_attention_candidate import baseline_cached_controller
    from vllm_hust_ext.activation_profile import load_activation_profile

    path, r, _, _ = live_registration
    recipe = json.loads(Path(r["recipe_path"]).read_bytes())
    recipe.update(
        tensor_consumer_contract={"CPU_ONLY": True},
        attention_consumer_contract={"CPU_ONLY": True},
        attention_drain_contract={"CPU_ONLY": True},
    )
    recipe["phases"][0].update(
        ack_time_policy="CPU_ONLY", tokenization={"runtime_binding": {"CPU_ONLY": True}}
    )
    recipe_ref = write(Path(r["recipe_path"]), recipe)
    profile = load_activation_profile(
        Path(r["activation_profile_reference"]["path"]),
        r["activation_profile_reference"]["sha256"],
    )
    protocol = {}
    for role, module, callable_name in (
        ("producer", producer, None),
        ("issuer", authority, None),
        ("verifier", authority.drain_consumer, "verify_observation"),
        (
            "controller",
            baseline_cached_controller,
            "BaselineCachedController.read_route",
        ),
        ("input_audit", authority.inputs_module, None),
    ):
        source = Path(module.__file__).resolve()
        protocol[role] = {"path": str(source), "sha256": util.sha(source.read_bytes())}
        if callable_name:
            protocol[role]["callable"] = callable_name
    native = {s["path"]: s["sha256"] for s in r["source_peers"][0]["source_files"]}
    sources = {**native, **{ref["path"]: ref["sha256"] for ref in protocol.values()}}
    digest = "c" * 64
    cell = {
        "cell_id": "CPU-only-permit",
        "arm": "entry-points-unmanaged",
        "baseline_scope_sha256": r["baseline_scope_reference"]["sha256"],
        "activation_profile_sha256": profile.sha256,
        "common_query_sha256": r["common_query_reference"]["sha256"],
        "profile_id": util.recipe_profile_id(recipe),
        "recipe_sha256": recipe_ref["sha256"],
        "request_sha256": r["common_query_reference"]["sha256"],
        "model_sha256": digest,
        "tokenizer_sha256": digest,
        "calibration_sha256": profile.value()["calibration"]["sha256"],
        "wheel_sha256": {
            role: digest for role in authority.inputs_module.DISTRIBUTIONS
        },
        "native_sources": native,
        "protocol_sources": protocol,
    }
    fixed = {
        "manager_commit": "CPU-manager",
        "host_commit": "CPU-host",
        "accelerator_commit": "CPU-ascend",
        "plugin_commits": {"CPU": "CPU-mod"},
    }
    inputs = {
        name: cell[name]
        for name in (
            "profile_id",
            "request_sha256",
            "model_sha256",
            "tokenizer_sha256",
            "calibration_sha256",
            "wheel_sha256",
        )
    }
    inputs.update(
        schema=authority.inputs_module.SCHEMA,
        formal_result=False,
        source_files=sources,
        recipe=recipe_ref,
        file_state={
            source: authority.inputs_module._state(Path(source).stat())
            for source in sources
        },
        wheel_revisions={
            "manager": "CPU-manager",
            "host": "CPU-host",
            "ascend": "CPU-ascend",
            "mod": "CPU-mod",
        },
    )
    # This fixture tests issuer linkage only, never real source eligibility.
    monkeypatch.setattr(
        authority.source_provenance, "validate_observation", lambda *_: None
    )
    observation = {"CPU_ONLY": True}
    issuer = authority.BaselineCellIssuer(
        b"K" * 32,
        {util.sha(authority.source_provenance.canonical(observation))},
        {util.sha(util.canonical(inputs))},
    )
    args = {
        "baseline_scope_reference": r["baseline_scope_reference"],
        "activation_profile_reference": r["activation_profile_reference"],
        "recipe": recipe,
        "fixed": fixed,
        "policy": {"CPU_ONLY": True},
        "source_observation": observation,
        "inputs": inputs,
    }
    return issuer, cell, args


def test_permit_links_independent_inputs_profile_source_and_scope(
    trusted_permit_fixture,
):
    issuer, cell, args = trusted_permit_fixture
    permit = issuer.issue_permit(cell, **args)
    assert issuer._permit(permit)["cell"] == cell
    assert permit["body"]["origin"] == authority.ORIGIN
    assert permit["body"]["formal_result"] is False
    assert "execution_plan_id" not in permit["body"]["cell"]


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("calibration", "audited calibration"),
        ("controller", "controller implementation"),
        ("untrusted-inputs", "not independently trusted"),
    ],
)
def test_permit_rejects_misjoined_activation_or_authority(
    trusted_permit_fixture, mutation, reason
):
    issuer, cell, args = trusted_permit_fixture
    if mutation == "calibration":
        cell["calibration_sha256"] = "d" * 64
    elif mutation == "controller":
        cell["protocol_sources"]["controller"]["callable"] = "fake_route"
    else:
        args["inputs"]["request_sha256"] = "d" * 64
    with pytest.raises(ValueError, match=reason):
        issuer.issue_permit(cell, **args)
