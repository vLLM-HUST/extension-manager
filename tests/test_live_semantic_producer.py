import hashlib
import threading
import time

from experiments.native_attention_candidate.live_semantic_producer import (
    QUERY,
    LiveProducer,
)


def fixture():
    p = LiveProducer.__new__(LiveProducer)
    p.identity = {"pid": 1}
    p.scope = {"test": "explicit CPU unit only"}
    p.registration_sha256 = hashlib.sha256(b"unit").hexdigest()
    p.lock = threading.Lock()
    p.proof = None
    p.failure = None
    return p


def query(p):
    return {
        "schema": QUERY,
        "nonce": "a" * 64,
        "registration_sha256": p.registration_sha256,
    }


def test_pending_probe_never_quotes_semantic_success():
    p = fixture()
    r = p.quote(query(p))
    assert r["ready"] is False and r["proof"] is None
    assert r["formal_result"] is False


def test_probe_failure_never_quotes_semantic_success():
    p = fixture()
    p.failure = "typed worker coverage missing"
    assert p.quote(query(p))["ready"] is False


def test_expired_fixed_lease_is_not_renewed():
    p = fixture()
    p.proof = {"expires_monotonic_ns": time.monotonic_ns() - 1}
    p.check_live = lambda: None
    r = p.quote(query(p))
    assert r["ready"] is False and "expired" in r["reason"]
    assert p.proof["expires_monotonic_ns"] < time.monotonic_ns()


def test_live_identity_failure_closes_an_existing_proof():
    p = fixture()
    p.proof = {"expires_monotonic_ns": time.monotonic_ns() + 1000000000}

    def fail():
        raise ValueError("worker epoch changed")

    p.check_live = fail
    r = p.quote(query(p))
    assert r["ready"] is False and r["proof"] is None
    assert "epoch changed" in r["reason"]
