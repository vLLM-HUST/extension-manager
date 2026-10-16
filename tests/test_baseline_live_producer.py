"""CPU transport/identity guards, never native hardware qualification."""

from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path

import pytest
from test_activation_profile import installation as installation
from test_baseline_host_binding import finish, launch, wait_for
from test_baseline_host_binding import real_host as real_host

from experiments.native_attention_candidate import baseline_host_binding as host
from experiments.native_attention_candidate import baseline_live_producer as producer
from experiments.native_attention_candidate import baseline_native_scope as native
from vllm_hust_ext.runtime_phase_handoff import process_identity


def reference(path, value, *, raw=False):
    path.write_bytes(value if raw else producer.canonical(value))
    path.chmod(0o600)
    return {"path": str(path), "sha256": producer.digest(path.read_bytes())}


@pytest.fixture
def live_registration(real_host):
    profile, root, sources = real_host
    profile.path.chmod(0o600)
    observer = host.HostObserver(
        root / "observer.sock",
        root / "ingress.jsonl",
        profile=profile,
        arm="entry-points-unmanaged",
        host_sources=sources,
    )
    payload = {"messages": [{"role": "user", "content": "finite CPU request"}]}
    query = reference(root / "query.json", payload)
    scope = native.create(observer.trial, observer.arm, profile.sha256, query["sha256"])
    scope_ref = scope.write(root / "native-scope.json")
    child = launch(
        observer, root, extra=scope.environment({}, scope_reference=scope_ref)
    )
    try:
        wait_for(
            lambda: (
                len(list(root.glob("ready-*.json"))) == 3 or child.poll() is not None
            )
        )
        assert child.poll() is None, child.stderr.read()
        peers = [json.loads(p.read_text()) for p in sorted(root.glob("ready-*.json"))]
        receipt = observer.finalize(peers)
        receipt_ref = reference(root / "receipt.json", receipt)
        native_source = Path(producer.drain_consumer.__file__).resolve()
        for peer in peers:
            p = peer["process"]
            peer["cmdline_sha256"] = producer.digest(
                Path(f"/proc/{p['pid']}/cmdline").read_bytes()
            )
            peer["source_files"] = [
                {
                    "path": str(native_source),
                    "sha256": producer.digest(native_source.read_bytes()),
                }
            ]
        aliases = scope.value()["native_correlation"]
        reference(
            root / "spec.json",
            {
                "native_plan_id": aliases["plan_id"],
                "native_launch_id": aliases["launch_id"],
                "senders": peers,
            },
        )
        reference(
            root / "recipe.json", {"phases": [{"phase_id": "one", "payload": payload}]}
        )
        reference(root / "policy.json", {})
        reference(root / "drain-policy.json", {})
        r = {
            "schema": producer.REGISTRATION,
            "origin": producer.ORIGIN,
            "baseline_scope_reference": scope_ref,
            "host_observer_receipt_reference": receipt_ref,
            "activation_profile_reference": {
                "path": str(profile.path),
                "sha256": profile.sha256,
            },
            "common_query_reference": query,
            "owner_kernel": observer.owner,
            "observer_kernel": observer.owner,
            "observer_socket_path": str(observer.path),
            "host_kernel": process_identity(child.pid),
            "source_peers": peers,
            "recipe_path": str(root / "recipe.json"),
            "phase_id": "one",
            "probe_output": str(root / "fresh-probe"),
            "spec_path": str(root / "spec.json"),
            "journal_path": str(root / "native.jsonl"),
            "policy_path": str(root / "policy.json"),
            "drain_policy_path": str(root / "drain-policy.json"),
            "collector_source": str(native_source),
            "collector_descriptor": {
                "collector_source_sha256": producer.digest(native_source.read_bytes())
            },
            "collector_socket_path": str(root / "collector.sock"),
            "producer_socket": str(root / "producer.sock"),
            "producer_source_path": str(Path(producer.__file__).resolve()),
            "producer_source_sha256": producer.digest(
                Path(producer.__file__).read_bytes()
            ),
            "max_validity_ns": 30_000_000_000,
            "formal_result": False,
        }
        registration = root / "registration.json"
        reference(registration, r)
        yield registration, r, root, observer
    finally:
        finish(child, root, observer)


def query(p):
    return {
        "schema": producer.QUERY,
        "nonce": secrets.token_hex(32),
        "registration_sha256": p.registration_sha256,
    }


def test_actual_host_constructor_has_no_Manager_or_effect_success(live_registration):
    path, r, _, _ = live_registration
    p = producer.BaselineLiveProducer(path)
    response = p.quote(query(p))
    assert response["ready"] is False and response["proof"] is None
    assert (
        response["origin"] == "baseline-host-observer"
        and response["formal_result"] is False
    )
    assert not {"manager_identity", "execution_plan_id", "native_binding"}.intersection(
        r
    )
    request = query(p)
    p.quote(request)
    with pytest.raises(ValueError, match="nonce replay"):
        p.quote(request)


@pytest.mark.parametrize(
    "mutation", ["fake_manager", "scope", "query", "kernel", "receipt", "ttl"]
)
def test_registration_rejects_actual_scope_epoch_and_raw_binding_drift(
    live_registration, mutation
):
    path, r, root, _ = live_registration
    if mutation == "fake_manager":
        r["manager_identity"] = r["owner_kernel"]
    if mutation == "scope":
        r["baseline_scope_reference"]["sha256"] = "0" * 64
    if mutation == "query":
        reference(
            root / "recipe.json", {"phases": [{"phase_id": "one", "payload": {}}]}
        )
    if mutation == "kernel":
        r["source_peers"][1]["process"]["start_ticks"] += 1
    if mutation == "receipt":
        (root / "ingress.jsonl").write_bytes(b"changed")
    if mutation == "ttl":
        r["max_validity_ns"] = 31_000_000_000
    reference(path, r)
    with pytest.raises((ValueError, KeyError)):
        producer.BaselineLiveProducer(path)


def test_actual_late_profile_config_change_revokes_quote(
    live_registration, monkeypatch
):
    path, _, _, _ = live_registration
    p = producer.BaselineLiveProducer(path)
    p.proof = {"expires_monotonic_ns": time.monotonic_ns() + 30_000_000_000}
    # Alter real frozen profile bytes; this is not a synthetic ready flag.
    p.profile.path.write_bytes(p.profile.raw + b" ")
    response = p.quote(query(p))
    assert response["ready"] is False and "profile" in response["reason"]
    assert p.failure is not None


def test_invocation_only_probe_never_mints_effect_proof(live_registration, monkeypatch):
    path, _, _, _ = live_registration
    p = producer.BaselineLiveProducer(path)
    monkeypatch.setattr(
        producer.drain_consumer,
        "execute_with_drain",
        lambda *a, **k: {"rpc_task_passed": True, "invoked": True},
    )
    p.execute_probe()
    response = p.quote(query(p))
    assert p.completed is True and p.proof is None and response["ready"] is False
    assert "native predicate failed" in response["reason"]
    with pytest.raises(ValueError, match="already started"):
        p.execute_probe()


def test_expiry_during_real_authentication_cannot_renew(monkeypatch, tmp_path):
    p = producer.BaselineLiveProducer.__new__(producer.BaselineLiveProducer)
    p.lock = threading.Lock()
    p.seen_nonces = set()
    p.failure = None
    p.registration_sha256 = "1" * 64
    p.identity = {"cpu_unit": True}
    p.scope = {"origin": producer.ORIGIN}
    expiry = time.monotonic_ns() + 15_000_000
    p.proof = {
        "expires_monotonic_ns": expiry,
        "issued_monotonic_ns": expiry - 30_000_000_000,
    }
    p.check_live = lambda: None
    p.phase = {}
    p.final_prefix = {"next_sequence": 1}
    journal = tmp_path / "journal"
    journal.write_bytes(b"raw")
    response = tmp_path / "response.bin"
    response.write_bytes(b"body")
    p.registration = {
        "journal_path": str(journal),
        "probe_output": str(tmp_path),
        "drain_policy_path": "unit",
    }
    p.journal_sha256 = producer.digest(b"raw")
    p.response_sha256 = producer.digest(b"body")

    def delayed_auth():
        time.sleep(0.02)
        return {"status": {"acknowledged_prefix": p.final_prefix}}

    p.authenticate = delayed_auth
    monkeypatch.setattr(
        producer.drain_consumer, "verify_sealed_status", lambda *a: True
    )
    result = p.quote(query(p))
    assert result["ready"] is False and result["proof"] is None
    assert "expired" in result["reason"] and p.proof["expires_monotonic_ns"] == expiry


@pytest.mark.parametrize("name", producer.RESERVED_OUTPUTS)
@pytest.mark.parametrize("kind", ["regular", "symlink"])
def test_reserved_outputs_reject_and_preserve_old_evidence(
    live_registration, name, kind
):
    path, _, root, _ = live_registration
    output = path.with_name(name)
    original = b"retained prior evidence\n"
    if kind == "regular":
        output.write_bytes(original)
    else:
        target = root / "retained-target"
        target.write_bytes(original)
        output.symlink_to(target)
    with pytest.raises(
        ValueError, match="reserved producer evidence output is not fresh"
    ):
        producer.BaselineLiveProducer(path)
    assert output.read_bytes() == original
    assert output.is_symlink() is (kind == "symlink")


@pytest.mark.parametrize("kind", ["regular", "symlink", "dangling"])
def test_exclusive_output_writer_never_overwrites_racing_artifact(tmp_path, kind):
    path = tmp_path / "output"
    target = tmp_path / "target"
    if kind == "regular":
        path.write_bytes(b"old")
    else:
        if kind == "symlink":
            target.write_bytes(b"old")
        path.symlink_to(target)
    with pytest.raises(FileExistsError):
        producer._write_new(path, b"new")
    assert path.is_symlink() is (kind != "regular")
    if kind == "dangling":
        assert not target.exists()
    else:
        assert path.read_bytes() == b"old"
