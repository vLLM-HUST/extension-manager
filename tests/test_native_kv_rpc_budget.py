"""Real CPU HTTP timing, frozen budget only; never a Host/model qualification."""

from __future__ import annotations

import copy
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from experiments.native_challenge_candidate import kv_request_runner as kv
from experiments.native_challenge_candidate import request_runner as runner


class CPUFixtureTokenizer:
    def apply_chat_template(self, messages, **kwargs):
        return [1] * (30 + messages[0]["content"].count("pad "))


def make_recipe(port, budget=None):
    source = Path(__file__).resolve()
    binding = {"path": str(source), "sha256": runner.sha(source.read_bytes())}
    return kv.make_kv_recipe(
        [("phase0", f"http://127.0.0.1:{port}/v1/chat/completions", "CPU-fixture")],
        [{"role": "CPU-fixture", **binding}],
        CPUFixtureTokenizer(),
        [binding],
        materialized_row=True,
        rpc_budget_s=budget,
    )


@pytest.mark.parametrize(
    "budget", [True, False, 0, -1, float("nan"), float("inf"), 601, 10**1000, "180"]
)
def test_invalid_frozen_budget_rejected(budget):
    with pytest.raises(ValueError, match="finite positive"):
        make_recipe(12345, budget)


def test_budget_opt_in_and_default_are_source_explicit():
    old = make_recipe(12345)
    assert "rpc_budget_s" not in old["phases"][0]
    assert runner.run_rpc_only.__defaults__ == (30,)
    new = make_recipe(12345, 180)
    assert new["phases"][0]["rpc_budget_s"] == 180
    changed = copy.deepcopy(new)
    changed["schema"] = kv.SCHEMA
    with pytest.raises(ValueError, match="opt-in KV v2"):
        kv.validate_kv(changed)


@pytest.mark.parametrize(
    "mode", ["socket-timeout", "frozen-succeeds", "trickle-over-budget"]
)
def test_actual_http_observes_budget_without_claiming_absolute_deadline(tmp_path, mode):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            body = runner.canonical(
                {
                    "id": "chatcmpl-" + payload["request_id"],
                    "model": payload["model"],
                    "usage": {"prompt_tokens": 1201, "completion_tokens": 40},
                    "choices": [
                        {
                            "message": {
                                "content": payload["messages"][0]["content"].split(
                                    "\nReply exactly: "
                                )[-1]
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
            )
            if mode != "trickle-over-budget":
                time.sleep(0.04)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                if mode == "trickle-over-budget":
                    # Each gap is below socket timeout; total read exceeds budget.
                    split = max(1, len(body) // 8)
                    for offset in range(0, len(body), split):
                        self.wfile.write(body[offset : offset + split])
                        self.wfile.flush()
                        time.sleep(0.025)
                else:
                    self.wfile.write(body)
            except BrokenPipeError:
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        budget = (
            None
            if mode == "socket-timeout"
            else (0.5 if mode == "frozen-succeeds" else 0.12)
        )
        recipe = make_recipe(server.server_port, budget)
        output = tmp_path / "out"
        # Short source-injected legacy call default verifies real socket behavior;
        # frozen phase budget overrides this argument rather than silently changing.
        result = runner.run_rpc_only(recipe, "phase0", output, timeout=0.015)
        assert result["rpc_task_passed"] is (mode == "frozen-succeeds")
        assert result["rpc_budget_from_frozen_phase"] is (budget is not None)
        assert (
            result["rpc_completed_monotonic_ns"] >= result["rpc_dispatch_monotonic_ns"]
        )
        assert (
            result["native_join_qualified"] is False
            and result["formal_result"] is False
        )
        if mode == "trickle-over-budget":
            assert result["rpc_elapsed_gate_passed"] is False
            assert "elapsed exceeds" in result["failure"]
            metadata = json.loads((output / "response-metadata.json").read_bytes())
            with pytest.raises(ValueError, match="elapsed exceeds"):
                runner.verify_rpc_budget(recipe["phases"][0], metadata)
        elif mode == "frozen-succeeds":
            metadata = json.loads((output / "response-metadata.json").read_bytes())
            assert metadata["rpc_budget_s"] == 0.5
            runner.verify_rpc_budget(recipe["phases"][0], metadata)
            metadata["rpc_budget_s"] = 0.6
            with pytest.raises(ValueError, match="receipt differs"):
                runner.verify_rpc_budget(recipe["phases"][0], metadata)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
