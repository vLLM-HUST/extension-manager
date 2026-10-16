"""CPU closed-public lifecycle checks; never native device qualification."""

from __future__ import annotations

import http.client
import os
import threading
import time

import pytest

from experiments.native_attention_candidate import (
    baseline_cached_controller as controller,
)
from experiments.native_attention_candidate import baseline_cell_issuer as authority
from experiments.native_attention_candidate import baseline_native_scope as scopes
from experiments.native_attention_candidate import live_route_reader as inputs_module
from experiments.native_attention_candidate import semantic_producer_registry as util


@pytest.fixture
def closed(tmp_path):
    tmp_path.chmod(0o700)
    recipe = {
        "phases": [
            {
                "phase_id": "cpu",
                "payload": {"CPU_ONLY": True},
                "url": "http://127.0.0.1:1/cpu",
                "external_request_id": "cpu-request",
            }
        ]
    }
    query_sha = util.sha(util.canonical(recipe["phases"][0]["payload"]))
    scope = scopes.create(
        "baseline-trial:" + "a" * 64, "entry-points-unmanaged", "b" * 64, query_sha
    )
    ref = scope.write(tmp_path / "scope.json")
    pinned = tmp_path / "pinned-input"
    pinned.write_bytes(b"CPU input")
    value = {
        "cell": {"recipe_sha256": util.sha(util.canonical(recipe))},
        "baseline_scope_reference": ref,
        "inputs": {"file_state": {str(pinned): inputs_module._state(pinned.stat())}},
    }

    class CPUOnlyIssuer:
        def _permit(self, _permit):
            return value

    gate = controller.BaselineCachedController(
        CPUOnlyIssuer(),
        {"CPU": True},
        recipe=recipe,
        journal_path=tmp_path / "gate.jsonl",
    )
    try:
        yield gate, pinned, tmp_path
    finally:
        gate.close()


def request(gate, payload=None, request_id="cpu-request"):
    connection = http.client.HTTPConnection(
        "127.0.0.1", gate.server.server_port, timeout=2
    )
    try:
        connection.request(
            "POST",
            "/cpu",
            payload or util.canonical(gate.phase["payload"]),
            {"X-ECPA-Request-ID": request_id},
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_closed_and_prepared_never_grant_response(closed):
    gate, _, _ = closed
    assert request(gate) == (503, b"")
    gate.prepare(
        {"proof": {"expires_monotonic_ns": time.monotonic_ns() + 20_000_000_000}}
    )
    assert gate.state == "PREPARED"
    assert request(gate) == (503, b"")
    assert gate.read_route()["arm"] == "entry-points-unmanaged"
    with pytest.raises(ValueError, match="one-shot"):
        gate.prepare(
            {"proof": {"expires_monotonic_ns": time.monotonic_ns() + 1_000_000}}
        )


def test_verifying_public_does_not_wait_behind_transition(closed):
    gate, _, _ = closed
    gate.state = "VERIFYING"
    done = threading.Event()
    answer = []
    with gate.transition:
        thread = threading.Thread(
            target=lambda: (answer.append(request(gate)), done.set())
        )
        thread.start()
        assert done.wait(1), "closed request queued behind expensive verification"
    thread.join(2)
    assert answer == [(503, b"")]


def test_route_requires_current_inputs_and_cannot_reopen(closed):
    gate, pinned, _ = closed
    gate.prepare(
        {"proof": {"expires_monotonic_ns": time.monotonic_ns() + 20_000_000_000}}
    )
    pinned.write_bytes(b"changed")
    with pytest.raises(ValueError, match="input file changed"):
        gate.read_route()
    gate.revoke("CPU fixture source drift")
    assert request(gate) == (503, b"")
    with pytest.raises(ValueError, match="one-shot"):
        gate.prepare(
            {"proof": {"expires_monotonic_ns": time.monotonic_ns() + 1_000_000}}
        )


def test_journal_failure_revokes_before_authority(closed, monkeypatch):
    gate, _, _ = closed
    original = os.fsync

    def fail(descriptor):
        if descriptor == gate.journal:
            raise OSError("CPU injected durable journal failure")
        return original(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(controller.os, "fsync", fail)
        with pytest.raises(OSError, match="durable journal failure"):
            gate.prepare(
                {
                    "proof": {
                        "expires_monotonic_ns": time.monotonic_ns() + 20_000_000_000
                    }
                }
            )
    assert gate.state == "REVOKED" and gate.ticket is None and gate.prepared is None
    assert request(gate) == (503, b"")


def test_wrong_exact_request_remains_closed(closed):
    gate, _, _ = closed
    assert request(gate, b"another request") == (503, b"")
    assert request(gate, request_id="different") == (503, b"")


def test_separate_ticket_domain():
    issuer = authority.BaselineCellIssuer(b"K" * 32, {"source"}, {"inputs"})
    ticket = issuer._seal(
        {
            "schema": controller.TICKET,
            "origin": authority.ORIGIN,
            "formal_result": False,
        }
    )
    with pytest.raises(ValueError, match="schema/result"):
        issuer._open(ticket, "ecpa-local-verified-cached-cell-ticket/v1")


def test_close_idempotent_and_releases_public_port(closed):
    import socket

    gate, _, _ = closed
    port = gate.server.server_port
    gate.close()
    gate.close()
    assert gate.state == "REVOKED"
    with pytest.raises(OSError):
        os.fstat(gate.journal)
    with socket.socket() as connection:
        assert connection.connect_ex(("127.0.0.1", port)) != 0


def test_close_releases_resources_even_if_final_journal_fsync_fails(
    closed, monkeypatch
):
    import socket

    gate, _, _ = closed
    port = gate.server.server_port
    original = os.fsync

    def fail(descriptor):
        if descriptor == gate.journal:
            raise OSError("CPU close fsync failure")
        return original(descriptor)

    with monkeypatch.context() as patch:
        patch.setattr(controller.os, "fsync", fail)
        with pytest.raises(OSError, match="close fsync failure"):
            gate.close()
    gate.close()
    assert gate.state == "REVOKED" and gate.ticket is None
    with pytest.raises(OSError):
        os.fstat(gate.journal)
    with socket.socket() as connection:
        assert connection.connect_ex(("127.0.0.1", port)) != 0
