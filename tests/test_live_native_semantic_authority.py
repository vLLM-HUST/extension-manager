"""Protocol counterexamples use a real local Unix peer, never NPU evidence."""

import http.client
import json
import os
import socket
import threading
import time

import pytest

from experiments.native_attention_candidate import live_authority as module
from experiments.native_attention_candidate import live_cohort as cohort
from experiments.native_attention_candidate.live_cohort import public_request_headers


@pytest.fixture
def live(tmp_path):
    tmp_path.chmod(0o700)
    source = tmp_path / "producer.py"
    source.write_text("# protocol fixture only\n")
    phase = {
        "phase_id": "p0",
        "url": "http://127.0.0.1:29508/v1/chat/completions",
        "payload": {"model": "fixture-only", "messages": []},
        "external_request_id": "frozen-0",
    }
    recipe = tmp_path / "recipe.json"
    recipe.write_bytes(module.canonical({"phases": [phase]}))
    plan = tmp_path / "plan.json"
    plan.write_bytes(module.canonical({"plan_id": "execution-0"}))
    output = tmp_path / "probe"
    output.mkdir()
    request = module.canonical(phase["payload"])
    response = b'{"choices":[{"message":{"content":"protocol-fixture-only"}}]}'
    (output / "request.bin").write_bytes(request)
    (output / "response.bin").write_bytes(response)
    (output / "response-metadata.json").write_bytes(
        module.canonical(
            {
                "schema": "ecpa-observed-KV-HTTP-response/v2",
                "status": 200,
                "url": phase["url"],
                "request_sha256": module.digest(request),
                "response_sha256": module.digest(response),
            }
        )
    )
    sockpath = tmp_path / "producer.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(sockpath))
    sockpath.chmod(0o600)
    listener.listen()
    listener.settimeout(0.1)
    epoch = module.identity(os.getpid())
    reg = {
        "schema": "ecpa-live-native-semantic-registration/v1",
        "formal_result": False,
        "plan_path": str(plan),
        "recipe_path": str(recipe),
        "phase_id": "p0",
        "probe_output": str(output),
        "max_validity_ns": 30_000_000_000,
        "manager_identity": epoch,
        "owner_identity": epoch,
        "source_peers": [epoch],
        "producer_socket": str(sockpath),
        "producer_source_path": str(source),
        "producer_source_sha256": module.digest(source.read_bytes()),
        **{key: "scope-" + key for key in module.SCOPE_KEYS},
    }
    reg["execution_plan_id"] = "execution-0"
    regpath = tmp_path / "registration.json"
    # Deliberately pretty-print the file: the cross-process digest is canonical.
    regpath.write_text(json.dumps(reg, indent=2) + "\n")
    descriptor = {
        "schema": "ecpa-live-native-semantic-producer-ready/v1",
        "producer": epoch,
        "source_sha256": module.digest(source.read_bytes()),
        "socket_path": str(sockpath),
        "registration_sha256": module.digest(module.canonical(reg)),
        "socket_identity": {
            "device": sockpath.stat().st_dev,
            "inode": sockpath.stat().st_ino,
        },
    }
    descriptor_path = tmp_path / "producer-ready.json"
    descriptor_path.write_bytes(module.canonical(descriptor))
    state = {"mutate": lambda quote: None, "queries": [], "stop": False}

    def serve():
        while not state["stop"]:
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            with connection:
                query = json.loads(connection.makefile("rb").readline())
                state["queries"].append(query)
                issued = time.monotonic_ns()
                quote = {
                    "schema": "ecpa-live-native-semantic-quote/v1",
                    "nonce": query["nonce"],
                    "registration_sha256": descriptor["registration_sha256"],
                    "producer": epoch,
                    "ready": True,
                    "reason": "protocol fixture only",
                    "scope": {key: reg[key] for key in module.SCOPE_KEYS},
                    "formal_result": False,
                    "proof": {
                        "observation_sha256": "a" * 64,
                        "request_sha256": module.digest(request),
                        "response_sha256": module.digest(response),
                        "issued_monotonic_ns": issued,
                        "expires_monotonic_ns": issued + 5_000_000_000,
                        "tensor_receipts": 56,
                        "operator_receipts": 56,
                        "full_prefix_records": 261,
                        "worker_closures": 2,
                    },
                }
                state["mutate"](quote)
                connection.sendall(module.canonical(quote) + b"\n")

    thread = threading.Thread(target=serve)
    thread.start()
    journal = tmp_path / "authority.jsonl"
    authority = module.Authority(regpath, descriptor_path, journal)
    yield authority, state, output, source, journal, request, response
    state["stop"] = True
    thread.join(timeout=2)
    listener.close()
    authority.journal.close()


def release(live, **kwargs):
    authority, _, _, _, _, request, _ = live
    return authority.handle(
        kwargs.get("method", "POST"),
        kwargs.get("path", "/v1/chat/completions"),
        kwargs.get("body", request),
        kwargs.get("request_id", "frozen-0"),
    )


def test_repeat_frozen_release_challenges_each_read_and_hashchains(live):
    authority, state, _, _, journal, _, response = live
    assert release(live)[:2] == (200, response)
    assert release(live)[:2] == (200, response)
    assert authority.handle("GET", "/__semantic_status", b"", None)[0] == 200
    assert len({query["nonce"] for query in state["queries"]}) == 3
    previous = "0" * 64
    for sequence, raw in enumerate(journal.read_bytes().splitlines(), 1):
        entry = json.loads(raw)
        sha = entry.pop("sha256")
        assert entry["sequence"] == sequence and entry["previous_sha256"] == previous
        assert sha == module.digest(module.canonical(entry))
        assert entry["formal_result"] is False
        if entry["event"] == "public-request":
            assert (
                module.digest(module.canonical(entry["producer_quote"]))
                == entry["quote_sha256"]
            )
            assert entry["producer_quote"]["nonce"] in {
                query["nonce"] for query in state["queries"]
            }
            assert (
                entry["validation_started_monotonic_ns"]
                <= entry["producer_quote"]["proof"]["issued_monotonic_ns"]
                <= entry["validation_completed_monotonic_ns"]
            )
        previous = sha


@pytest.mark.parametrize(
    "change", ["nonce", "scope", "stale", "partial", "unready", "producer", "formal"]
)
def test_quote_counterexamples_fail_closed(live, change):
    def mutate(quote):
        if change == "nonce":
            quote["nonce"] = "f" * 64
        elif change == "scope":
            quote["scope"]["native_launch_id"] = "another-launch"
        elif change == "stale":
            quote["proof"]["expires_monotonic_ns"] = 0
        elif change == "partial":
            quote["proof"]["worker_closures"] = 1
        elif change == "unready":
            quote["ready"], quote["proof"] = False, None
        elif change == "producer":
            quote["producer"] = {**quote["producer"], "start_ticks": 0}
        else:
            quote["formal_result"] = True

    live[1]["mutate"] = mutate
    assert release(live)[0] == 503


@pytest.mark.parametrize(
    "kwargs",
    [
        {"body": b"{}"},
        {"request_id": "future-request"},
        {"path": "/v1/completions"},
        {"method": "PUT"},
    ],
)
def test_other_work_is_rejected_even_with_valid_live_proof(live, kwargs):
    assert release(live, **kwargs)[0] == 503
    assert len(live[1]["queries"]) == 1


@pytest.mark.parametrize("target", ["response", "source", "epoch"])
def test_live_files_and_kernel_epoch_are_rechecked(live, target):
    assert release(live)[0] == 200
    authority, _, output, source, _, _, _ = live
    if target == "response":
        (output / "response.bin").write_bytes(b"tampered")
    elif target == "source":
        source.write_bytes(b"changed")
    else:
        authority.descriptor["producer"] = {
            **authority.descriptor["producer"],
            "start_ticks": 0,
        }
    assert release(live)[0] == 503


def test_public_runner_headers_cross_actual_http_authority(live):
    authority = live[0]
    server = module.HTTPServer(("127.0.0.1", 0), module.make_handler(authority))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    phase = {
        **authority.phase,
        "headers": {"Content-Type": "application/json", "X-Request-Id": "frozen-0"},
    }

    def post(headers, body):
        connection = http.client.HTTPConnection(*server.server_address, timeout=5)
        try:
            connection.request("POST", authority.request_path, body, headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    try:
        # Backend's request header alone must never authorize public release.
        assert post(phase["headers"], authority.frozen_request)[0] == 503
        headers = public_request_headers(phase)
        assert post(headers, authority.frozen_request) == (200, live[-1])
        assert post(headers, b"{}")[0] == 503
        assert (
            post({**headers, "X-ECPA-Request-ID": "another"}, authority.frozen_request)[
                0
            ]
            == 503
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.parametrize("changed", [False, True])
def test_worker_fault_refuses_a_reused_process_epoch(monkeypatch, changed):
    expected = {"pid": 123, "start_ticks": 456, "session": 123, "boot_id": "boot"}
    current = {**expected, "start_ticks": 999} if changed else expected
    signals = []
    monkeypatch.setattr(cohort, "process_identity", lambda pid: current)
    monkeypatch.setattr(cohort.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    if changed:
        with pytest.raises(ValueError, match="epoch changed"):
            cohort.signal_registered_worker(expected)
        assert signals == []
    else:
        assert cohort.signal_registered_worker(expected) == expected
        assert signals == [(123, cohort.signal.SIGTERM)]
