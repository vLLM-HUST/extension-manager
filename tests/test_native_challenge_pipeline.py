"""Actual CPU HTTP/Unix process path; fixture facts never qualify Host/GPU."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_native_semantic_collector import SENDER_CODE, command, read_line

from experiments.exposure_gate import native_semantic_collector as collector
from experiments.native_challenge_candidate import collector_client, request_runner

ROOT = Path(__file__).parents[1]
SOURCE = Path(collector.__file__)


@pytest.mark.parametrize("missing_rank", [False, True])
def test_frozen_nonce_http_and_actual_three_peer_durable_transport(
    tmp_path, missing_rank
):
    tmp_path.chmod(0o700)
    fixture_source = tmp_path / "fixture_peer.py"
    fixture_source.write_text(SENDER_CODE)
    peers, processes = [], []
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    server = None
    thread = None
    try:
        for role, ordinal in (("api-server", 0), ("worker", 0), ("worker", 1)):
            child = subprocess.Popen(
                [sys.executable, str(fixture_source), role, str(ordinal)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            processes.append(child)
            process = read_line(child)
            peers.append(
                {
                    "process": process,
                    "peer_uid": os.getuid(),
                    "peer_gid": os.getgid(),
                    "cmdline_sha256": collector.sha(
                        Path(f"/proc/{child.pid}/cmdline").read_bytes()
                    ),
                    "source_files": [
                        {
                            "path": str(fixture_source),
                            "sha256": collector.sha(fixture_source.read_bytes()),
                        },
                        {
                            "path": str(SOURCE),
                            "sha256": collector.sha(SOURCE.read_bytes()),
                        },
                    ],
                }
            )
        run = {"children": processes[:3]}
        response_acks = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )
                external = "chatcmpl-" + payload["request_id"]
                runtime = "CPU-fixture-runtime-" + payload["request_id"]
                response_acks.append(
                    command(
                        run,
                        0,
                        {
                            "schema": collector.MAPPING,
                            "plan_id": "CPU-fixture-plan",
                            "launch_id": "CPU-fixture-launch",
                            "external_request_id": external,
                            "runtime_request_id": runtime,
                        },
                    )
                )
                rows = [{"group": 0, "row": 0, "blocks": [10, 11]}]
                for index in (1,) if missing_rank else (1, 2, 1, 2):
                    fact = {
                        "schema": collector.UPLOAD,
                        "plan_id": "CPU-fixture-plan",
                        "launch_id": "CPU-fixture-launch",
                        "runtime_request_id": runtime,
                        "observed_after_barrier_monotonic_ns": "NOW",
                        "device": "npu:0",
                        "uploaded_rows": rows,
                        "uploaded_rows_sha256": collector.sha(
                            collector.canonical(rows)
                        ),
                        "scope": "NPU-block-table-prefix-readback-only",
                        "kv_tensor_equivalence": None,
                        "attention_consumed_observed_tensor": None,
                        "full_generation_quality": None,
                    }
                    response_acks.append(command(run, index, fact))
                body = {
                    "id": external,
                    "model": payload["model"],
                    "usage": {"completion_tokens": 1},
                    "choices": [
                        {
                            "message": {
                                "content": payload["messages"][0][
                                    "content"
                                ].removeprefix("Reply exactly ")
                            },
                            "finish_reason": "stop",
                        }
                    ],
                }
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        recipe = request_runner.make_recipe(
            [
                (
                    "phase0",
                    f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                    "CPU-fixture",
                )
            ],
            [
                {
                    "role": "CPU-fixture",
                    "path": str(fixture_source),
                    "sha256": collector.sha(fixture_source.read_bytes()),
                }
            ],
        )
        phase = recipe["phases"][0]
        spec = {
            "schema": collector.SPEC,
            "classification": request_runner.CLASSIFICATION,
            "formal_producer_registration": False,
            "native_plan_id": "CPU-fixture-plan",
            "native_launch_id": "CPU-fixture-launch",
            "frozen_monotonic_ns": __import__("time").monotonic_ns(),
            "max_event_age_ns": 60_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": peers,
            "phases": [
                {
                    k: phase[k]
                    for k in (
                        "phase_id",
                        "client_request_id",
                        "challenge_nonce",
                        "external_request_id",
                        "expected_ranks",
                    )
                }
            ],
        }
        spec_path, socket_path, journal = (
            tmp_path / name for name in ("spec.json", "collector.sock", "raw.jsonl")
        )
        spec_path.write_bytes(collector.canonical(spec))
        spec_path.chmod(0o600)
        authority = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "experiments.exposure_gate.native_semantic_collector",
                "--spec",
                str(spec_path),
                "--socket",
                str(socket_path),
                "--journal",
                str(journal),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
        processes.append(authority)
        ready = read_line(authority)
        run.update(socket=socket_path, ready=ready)
        observed = collector_client.identity(authority.pid)
        assert observed == ready["collector"]
        descriptor = {
            **ready,
            "launcher_observed_identity": observed,
            "launcher_observed_cmdline_sha256": collector.sha(
                Path(f"/proc/{authority.pid}/cmdline").read_bytes()
            ),
        }
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        recipe_path = tmp_path / "recipe.json"
        recipe_raw = request_runner.canonical(recipe)
        recipe_path.write_bytes(recipe_raw)
        recipe_path.chmod(0o600)
        descriptor_path = tmp_path / "launcher-observation.json"
        descriptor_path.write_bytes(request_runner.canonical(descriptor))
        descriptor_path.chmod(0o600)
        cli = subprocess.run(
            [
                sys.executable,
                "-m",
                "experiments.native_challenge_candidate.request_runner",
                "execute",
                str(recipe_path),
                "--expected-sha256",
                request_runner.sha(recipe_raw),
                "--phase",
                "phase0",
                "--output",
                str(tmp_path / "out"),
                "--collector-socket",
                str(socket_path),
                "--collector-launcher-descriptor",
                str(descriptor_path),
                "--collector-spec",
                str(spec_path),
                "--collector-source",
                str(SOURCE),
                "--collector-journal",
                str(journal),
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            timeout=30,
        )
        assert cli.returncode == (1 if missing_rank else 0), cli.stderr
        result = json.loads(cli.stdout)
        assert result["rpc_task_passed"] is True
        assert all("ack" in response for response in response_acks)
        assert result.get("native_request_upload_transport_join", False) is (
            not missing_rank
        )
        assert (
            result["native_join_qualified"] is False
            and result["hardware_result"] is False
            and result["formal_result"] is False
        )
        if not missing_rank:
            proof = json.loads(
                (tmp_path / "out/native-transport-join.json").read_bytes()
            )
            assert proof["source_authenticated_native_upload_records"] == 4
            assert proof["KV_MOD_semantic_obligation_satisfied"] is None
            post = json.loads((tmp_path / "out/collector-after.json").read_bytes())
            post["status"]["acknowledged_prefix"]["next_sequence"] -= 1
            with pytest.raises(ValueError, match="ACK|prefix|seal"):
                collector_client.read_verified_phase(spec_path, journal, phase, post)
        else:
            assert any(
                message in result["native_join_failure"]
                for message in ("two-rank coverage incomplete", "proof incomplete")
            )
    finally:
        if server is not None:
            if thread is not None and thread.is_alive():
                server.shutdown()
                thread.join(timeout=2)
            server.server_close()
        for child in reversed(processes):
            child.terminate()
            child.wait(timeout=5)
