from __future__ import annotations

import copy
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from experiments.native_challenge_candidate import request_runner as runner


def recipe(tmp_path, port):
    source = tmp_path / "source.py"
    source.write_text("# explicit CPU fixture source; not Host/model evidence\n")
    return runner.make_recipe(
        [
            ("phase0", f"http://127.0.0.1:{port}/v1/chat/completions", "cpu-fixture"),
            ("phase1", f"http://127.0.0.1:{port}/v1/chat/completions", "cpu-fixture"),
        ],
        [
            {
                "role": "cpu-fixture",
                "path": str(source),
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }
        ],
    )


@pytest.mark.parametrize(
    "mode,passes",
    [
        ("correct", True),
        ("wrong-nonce", False),
        ("wrong-id", False),
        ("wrong-stop", False),
    ],
)
def test_cpu_real_http_is_nonce_bound_but_never_a_native_join(tmp_path, mode, passes):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert self.headers["X-Request-Id"] == payload["request_id"]
            calls.append(payload)
            content = payload["messages"][0]["content"].removeprefix("Reply exactly ")
            body = {
                "model": payload["model"],
                "id": "chatcmpl-" + payload["request_id"],
                "usage": {"completion_tokens": 1},
                "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            }
            if mode == "wrong-nonce":
                body["choices"][0]["message"]["content"] = "ECPA-CHALLENGE-" + "0" * 32
            elif mode == "wrong-id":
                body["id"] = "chatcmpl-otherphase"
            elif mode == "wrong-stop":
                body["choices"][0]["finish_reason"] = "length"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        spec = recipe(tmp_path, server.server_port)
        results = [
            runner.run_rpc_only(spec, p["phase_id"], tmp_path / p["phase_id"])
            for p in spec["phases"]
        ]
        assert len(calls) == 2
        assert calls[0]["request_id"] != calls[1]["request_id"]
        assert all(r["rpc_task_passed"] is passes for r in results)
        assert all(
            r["native_join_qualified"] is False
            and r["hardware_result"] is False
            and r["formal_result"] is False
            for r in results
        )
        assert (tmp_path / "phase0/response.bin").is_file()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (
            lambda d: d["phases"][1].update(
                client_request_id=d["phases"][0]["client_request_id"]
            ),
            "reuse",
        ),
        (
            lambda d: d["phases"][0].update(runtime_request_id="guessed-suffix"),
            "minted/mapped",
        ),
        (lambda d: d.update(formal_result=True), "scope"),
        (
            lambda d: d["phases"][0]["headers"].update({"X-Request-Id": "other"}),
            "header",
        ),
        (lambda d: d["phases"][0]["payload"].update(n=2), "single bounded"),
    ],
)
def test_frozen_request_scope_fails_closed(tmp_path, mutation, match):
    spec = recipe(tmp_path, 12345)
    mutation(spec)
    with pytest.raises(ValueError, match=match):
        runner.validate(spec)


def test_actual_manager_binding_and_exact_phase_must_precede_http(tmp_path):
    spec = recipe(tmp_path, 12345)
    phase = spec["phases"][0]
    registered = {
        k: phase[k]
        for k in (
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        )
    }
    collector = {
        "schema": "ecpa-native-semantic-collector-prereg/v1",
        "native_plan_id": "actual-after-handoff",
        "native_launch_id": "actual-minted-launch",
        "phases": [registered],
    }
    runner.require_phase_registration(phase, collector)
    wrong = copy.deepcopy(collector)
    wrong["phases"][0]["challenge_nonce"] = "wrong"
    with pytest.raises(ValueError, match="preregistration differs"):
        runner.require_phase_registration(phase, wrong)
    wrong = copy.deepcopy(collector)
    wrong["native_launch_id"] = ""
    with pytest.raises(ValueError, match="actual native identity"):
        runner.require_phase_registration(phase, wrong)


def test_freeze_cli_recipe_is_private_source_bound_and_cannot_overwrite(tmp_path):
    spec = recipe(tmp_path, 12345)
    configuration = {
        "phase_targets": [
            {"phase_id": p["phase_id"], "url": p["url"], "model": p["payload"]["model"]}
            for p in spec["phases"]
        ],
        "sources": spec["sources"],
    }
    output = tmp_path / "private" / "recipe.json"
    frozen = runner.freeze_file(configuration, output)
    assert frozen["sha256"] == runner.sha(output.read_bytes())
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.parent.stat().st_mode & 0o777 == 0o700
    body = json.loads(output.read_bytes())
    assert body["native_ids_preregistered_before_launch"] is False
    assert body["formal_result"] is False
    with pytest.raises(FileExistsError):
        runner.freeze_file(configuration, output)
