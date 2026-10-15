"""Real CPU sockets and public lifecycle; all native semantics are CPU fixtures."""

import copy
import http.client
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import test_cell_semantic_producer_registry as cpu

from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from experiments.native_attention_candidate import staged_cell_cohort as cohort
from experiments.native_attention_candidate import staged_cell_controller as staged
from vllm_hust_ext.runtime_phase_handoff import bind_receiver, process_identity

registry_cell = cpu.cell


def request(controller, payload=None, request_id="CPU-request"):
    body = registry.canonical({"CPU": True}) if payload is None else payload
    conn = http.client.HTTPConnection(
        "127.0.0.1", controller.server.server_port, timeout=5
    )
    try:
        conn.request("POST", "/CPU", body, {"X-ECPA-Request-ID": request_id})
        result = conn.getresponse()
        return result.status, result.read()
    finally:
        conn.close()


@pytest.fixture
def prepared(registry_cell, request):
    data = registry_cell
    issuer, definition = data["issuer"], copy.deepcopy(data["definition"])
    module_path = str(Path(staged.__file__).resolve())
    definition["protocol_sources"]["route_reader"] = {
        "path": module_path,
        "sha256": routes._hash(module_path),
        "callable": "PreparedCandidateReader.read",
    }
    recipe = data["recipe"]
    phase = recipe["phases"][0]
    phase.update(url="http://127.0.0.1:1/CPU", external_request_id="CPU-request")
    data["args"]["output"].mkdir()
    body = b'{"CPU_ONLY_RESPONSE":true}'
    response_sha = registry.sha(body)
    output = data["args"]["output"]
    (output / "response.bin").write_bytes(body)
    (output / "request.bin").write_bytes(registry.canonical(phase["payload"]))
    (output / "response-metadata.json").write_bytes(
        registry.canonical(
            {
                "schema": "ecpa-observed-KV-HTTP-response/v2",
                "status": 200,
                "request_sha256": definition["request_sha256"],
                "response_sha256": response_sha,
                "url": phase["url"],
            }
        )
    )
    cpu.OBSERVATION["actual_raw_response_sha256"] = response_sha
    recipe_ref = data["artifacts"]["recipe"]
    Path(recipe_ref["path"]).write_bytes(registry.canonical(recipe))
    recipe_ref["sha256"] = routes._hash(recipe_ref["path"])
    definition["recipe_sha256"] = recipe_ref["sha256"]
    permit = issuer.issue_permit(
        definition,
        execution_plan=data["plan"],
        recipe=recipe,
        fixed=data["fixed"],
        policy=data["policy"],
        source_observation=data["observation"],
    )
    # CPU fixture reuses the actual authenticated exchange under an equivalent
    # Plan/Manager scope. Production owner must capture once under its own permit.
    handoff = issuer._seal(
        {**data["handoff"]["body"], "permit_sha256": permit["sha256"]}
    )
    inputs = {
        key: definition[key]
        for key in (
            "profile_id",
            "request_sha256",
            "model_sha256",
            "tokenizer_sha256",
            "calibration_sha256",
            "wheel_sha256",
        )
    }
    inputs.update(
        schema=routes.SCHEMA,
        formal_result=False,
        recipe=recipe_ref,
        file_state={module_path: routes._state(Path(module_path).stat())},
        wheel_revisions={
            "manager": data["fixed"]["manager_commit"],
            "host": data["fixed"]["host_commit"],
            "ascend": data["fixed"]["accelerator_commit"],
            "mod": data["fixed"]["plugin_commits"]["cpu"],
        },
    )
    expected = routes.controller_cell_binding(
        issuer,
        permit,
        handoff,
        inputs,
        trusted_input_audits={registry.sha(registry.canonical(inputs))},
    )
    controller = staged.StagedCellController(
        issuer=issuer,
        permit=permit,
        expected_cell=expected,
        scope=data["scope"],
        control_path=output.parent / "stage.sock",
        phase=phase,
        journal_path=output.parent / "stage-journal.jsonl",
    )
    data["connection"].close()
    server, stop = data["server"], threading.Event()
    server.settimeout(0.1)
    expiry = time.monotonic_ns() + getattr(request, "param", 20_000_000_000)
    mutate = {}

    def serve():
        while not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with connection:
                raw = bytearray()
                while not raw.endswith(b"\n"):
                    piece = connection.recv(4096)
                    if not piece:
                        break
                    raw.extend(piece)
                if not raw:
                    continue
                query = json.loads(raw)
                quote = cpu.quote(
                    data,
                    type("Noop", (), {"expect": lambda self, nonce: None})(),
                    nonce=query["nonce"],
                    expires=expiry,
                )
                quote["proof"]["response_sha256"] = response_sha
                quote["proof"].update(mutate.get("proof", {}))
                quote.update(mutate.get("quote", {}))
                connection.sendall(registry.canonical(quote) + b"\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    sources = {
        str(Path(module.__file__).resolve()): routes._hash(module.__file__)
        for module in (routes, staged, registry)
    }
    # Explicit CPU independent audit source admission for the real adapter files.
    # Rebuild the expected audit digest before preparing a candidate.
    inputs["source_files"] = sources
    expected = routes.controller_cell_binding(
        issuer,
        permit,
        handoff,
        inputs,
        trusted_input_audits={registry.sha(registry.canonical(inputs))},
    )
    controller.expected_cell = expected
    try:
        yield dict(
            data=data,
            controller=controller,
            handoff=handoff,
            inputs=inputs,
            sources=sources,
            mutate=mutate,
            body=body,
            expiry=expiry,
        )
    finally:
        controller.close()
        stop.set()
        thread.join(2)


def commit(prepared):
    p, data = prepared, prepared["data"]
    return staged.bind_and_commit_cached(
        p["controller"],
        handoff=p["handoff"],
        manager=data["manager"],
        peers=data["peers"],
        producer=data["producer"],
        producer_socket=data["socket_path"],
        artifacts=data["artifacts"],
        inputs=p["inputs"],
        authority_sources=p["sources"],
        observation_verifier=cpu.cpu_observation_verifier,
        observation_arguments=data["args"],
    )


def test_real_closed_prepare_commit_exact_request_and_epoch_revocation(prepared):
    controller = prepared["controller"]
    assert request(controller)[0] == 503
    result = commit(prepared)
    assert result["formal_result"] is False
    assert (
        result["deployment"]["body"]["route"]["lease_expires_monotonic_ns"]
        == prepared["expiry"]
    )
    # Full verifier may no longer be used: admission must use its authenticated
    # immutable ticket and actual fresh producer exchange/current OS checks.
    controller.verifier.verify = lambda *args, **kwargs: pytest.fail(
        "full verification repeated"
    )
    assert request(controller) == (200, prepared["body"])
    assert request(controller, b"{}")[0] == 503
    assert request(controller, request_id="wrong")[0] == 503
    assert request(controller) == (200, prepared["body"])
    prepared["data"]["processes"][2].terminate()
    prepared["data"]["processes"][2].wait(timeout=3)
    assert time.monotonic_ns() < prepared["expiry"]
    assert request(controller)[0] == 503
    assert controller.state == "REVOKED"
    with pytest.raises(ValueError, match="one-shot"):
        controller.prepare({"proof": {"expires_monotonic_ns": prepared["expiry"]}})


@pytest.mark.parametrize(
    "kind", ["renew", "replay", "response", "raw", "ticket", "typed_count"]
)
def test_ticket_cannot_cover_proof_renewal_replay_or_changed_raw_response(
    prepared, kind
):
    commit(prepared)
    controller = prepared["controller"]
    if kind == "renew":
        prepared["mutate"]["proof"] = {"expires_monotonic_ns": prepared["expiry"] + 1}
    elif kind == "typed_count":
        prepared["mutate"]["proof"] = {"tensor_receipts": 56.0}
    elif kind == "replay":
        prepared["mutate"]["quote"] = {"nonce": "a" * 64}
    elif kind == "response":
        (prepared["data"]["args"]["output"] / "response.bin").write_bytes(
            b"CPU_CHANGED"
        )
    elif kind == "raw":
        prepared["data"]["journal"].write_bytes(b"CPU_CHANGED")
    else:
        controller.ticket["body"]["proof_identity"]["response_sha256"] = "f" * 64
    assert request(controller)[0] == 503
    assert controller.state == "REVOKED"


def test_slow_full_verification_never_opens_expired_candidate(prepared, monkeypatch):
    # A real verifier still runs; advance the clock only after its valid typed
    # result, exercising the post-verification cutoff rather than a fake ready bit.
    controller = prepared["controller"]
    original = controller.verifier.verify

    def slow(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr(staged.time, "monotonic_ns", lambda: prepared["expiry"] + 1)
        return result

    monkeypatch.setattr(controller.verifier, "verify", slow)
    with pytest.raises(ValueError, match="lease|expired"):
        commit(prepared)
    assert controller.state == "REVOKED"
    assert request(controller)[0] == 503


def test_public_during_actual_slow_commit_is_immediately_503(prepared, monkeypatch):
    controller = prepared["controller"]
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = controller.verifier.verify
    errors = []

    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(4), "test never released full verifier"
        return original(*args, **kwargs)

    monkeypatch.setattr(controller.verifier, "verify", slow)

    def background_commit():
        try:
            commit(prepared)
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=background_commit)
    worker.start()
    try:
        assert entered.wait(3)
        assert controller.state == "VERIFYING"
        assert request(controller)[0] == 503
        assert not finished.is_set() and not release.is_set()
    finally:
        release.set()
        worker.join(5)
    assert not errors and finished.is_set()
    assert request(controller)[0] == 200


def test_new_owner_handoff_captures_actual_wire_once(registry_cell):
    fixture = registry_cell
    directory = Path(fixture["handoff_path"]).parent / "new-owner-wire"
    directory.mkdir(mode=0o700)
    path = directory / "native.sock"
    listener = bind_receiver(path, 5)
    launched = time.time_ns()
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            fixture["code"],
            json.dumps(fixture["handoff_env"]),
            str(path),
        ],
        env=fixture["child_env"],
    )
    try:
        sealed = cohort.capture_owner_handoff(
            fixture["issuer"],
            fixture["permit"],
            listener=listener,
            path=path,
            manager=process_identity(child.pid),
            launched_wall_ns=launched,
            raw_record_path=directory / "wire.bin",
        )
        raw = (directory / "wire.bin").read_bytes()
        record = sealed["body"]["record"]
        assert registry.sha(raw) == record["binding_sha256"]
        assert json.loads(raw)["publisher"] == process_identity(child.pid)
        assert record["environment"] == json.loads(raw)["environment"]
        assert (
            fixture["issuer"]._open(sealed, registry.HANDOFF)["permit_sha256"]
            == fixture["permit"]["sha256"]
        )
    finally:
        listener.close()
        child.terminate()
        child.wait(timeout=3)


def block_only_event_fsync_past_fixed_expiry(controller, event, expiry, monkeypatch):
    """Hold the targeted real journal fsync until the real fixed clock expires."""
    original_write = controller._write_record
    original_fsync = staged.os.fsync
    current = threading.local()
    blocked = threading.Event()

    def write(kind, **fields):
        current.event = kind
        try:
            return original_write(kind, **fields)
        finally:
            current.event = None

    def fsync(descriptor):
        if (
            descriptor == controller.journal
            and getattr(current, "event", None) == event
        ):
            blocked.set()
            remaining = (expiry - time.monotonic_ns()) / 1_000_000_000
            if remaining > 0:
                time.sleep(remaining + 0.02)
        return original_fsync(descriptor)

    monkeypatch.setattr(controller, "_write_record", write)
    monkeypatch.setattr(staged.os, "fsync", fsync)
    return blocked


@pytest.mark.parametrize("prepared", [2_000_000_000], indirect=True)
def test_real_HTTP_response_log_fsync_cannot_admit_after_fixed_expiry(
    prepared, monkeypatch
):
    controller = prepared["controller"]
    result = commit(prepared)
    original_expiry = result["ticket"]["body"]["proof_identity"]["expires_monotonic_ns"]
    blocked = block_only_event_fsync_past_fixed_expiry(
        controller, "request.cached_response", original_expiry, monkeypatch
    )
    assert time.monotonic_ns() < original_expiry
    status, body = request(controller)
    assert blocked.is_set() and time.monotonic_ns() >= original_expiry
    assert status == 503 and body == b""
    assert controller.state == "REVOKED" and controller.ticket is None
    assert original_expiry == prepared["expiry"]


@pytest.mark.parametrize("prepared", [2_000_000_000], indirect=True)
def test_commit_log_fsync_cannot_open_after_fixed_expiry(prepared, monkeypatch):
    controller = prepared["controller"]
    blocked = block_only_event_fsync_past_fixed_expiry(
        controller, "candidate.commit", prepared["expiry"], monkeypatch
    )
    with pytest.raises(ValueError, match="expired during commit log fsync"):
        commit(prepared)
    assert blocked.is_set() and time.monotonic_ns() >= prepared["expiry"]
    assert controller.state == "REVOKED" and controller.ticket is None
    assert request(controller)[0] == 503
