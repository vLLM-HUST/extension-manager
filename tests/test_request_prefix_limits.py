"""CPU byte-limit regressions at consumption; no native qualification fixture."""

import hmac
import time

import pytest

from experiments.native_attention_candidate import request_prefix_ticket as tickets


def consumption_fixture(tmp_path, monkeypatch):
    # Isolate consumption of already-checked bytes. This deliberately supplies
    # no producer, source receipts or native grant and cannot qualify a request.
    tmp_path.chmod(0o700)
    prefix = tmp_path / "native.jsonl"
    prefix.write_bytes(b"CPU journal size regression only\n" * (300 * 1024))
    assert 8 * 1024 * 1024 < prefix.stat().st_size < 64 * 1024 * 1024
    response = tmp_path / "response.bin"
    response.write_bytes(b"CPU response only")
    forwarder = tickets.RequestForwarder.__new__(tickets.RequestForwarder)
    forwarder.key = b"CPU test key only: never native authority"
    forwarder.output = tmp_path
    forwarder.next_phase = 0
    monkeypatch.setattr(forwarder, "_current", lambda: None)
    admission = {"admission_nonce": "CPU-test-only"}
    body = {
        "admission": admission,
        "phase_index": 0,
        "expires_monotonic_ns": time.monotonic_ns() + 30_000_000_000,
        "prefix_manifest": {
            "sealed_prefix_sha256": tickets.digest(prefix.read_bytes()),
            "files": [
                {"path": str(prefix), "sha256": tickets.digest(prefix.read_bytes())}
            ],
        },
        "response": {
            "path": str(response),
            "sha256": tickets.digest(response.read_bytes()),
        },
    }
    envelope = {
        "body": body,
        "mac": hmac.digest(forwarder.key, tickets.canonical(body), "sha256").hex(),
    }
    forwarder.pending = envelope
    return forwarder, envelope, admission, prefix, response


def test_consume_accepts_retained_journal_above_ordinary_file_limit(
    tmp_path, monkeypatch
):
    forwarder, ticket, admission, _, response = consumption_fixture(
        tmp_path, monkeypatch
    )
    assert forwarder._consume(ticket, admission) == response.read_bytes()
    assert forwarder.next_phase == 1 and forwarder.pending is None
    assert (tmp_path / "consume-0000.json").is_file()


def test_ordinary_response_limit_remains_eight_mebibytes(tmp_path, monkeypatch):
    _, _, _, prefix, _ = consumption_fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="owner/type/size"):
        tickets.read_regular(prefix)


def test_large_journal_does_not_raise_individual_artifact_limit(tmp_path, monkeypatch):
    forwarder, ticket, admission, prefix, _ = consumption_fixture(
        tmp_path, monkeypatch
    )
    artifact = tmp_path / "CPU-artifact.bin"
    artifact.write_bytes(prefix.read_bytes())
    ticket["body"]["prefix_manifest"]["files"].append(
        {"path": str(artifact), "sha256": tickets.digest(artifact.read_bytes())}
    )
    ticket["mac"] = hmac.digest(
        forwarder.key, tickets.canonical(ticket["body"]), "sha256"
    ).hex()
    with pytest.raises(ValueError, match="owner/type/size"):
        forwarder._consume(ticket, admission)
    assert not (tmp_path / "consume-0000.json").exists()


def test_consume_rejects_retained_journal_above_existing_sixty_four_mebibytes(
    tmp_path, monkeypatch
):
    forwarder, ticket, admission, prefix, _ = consumption_fixture(
        tmp_path, monkeypatch
    )
    with prefix.open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="owner/type/size"):
        forwarder._consume(ticket, admission)
    assert not (tmp_path / "consume-0000.json").exists()
    assert forwarder.next_phase == 0
