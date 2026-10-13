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
from experiments.native_challenge_candidate import (
    collector_client,
    kv_archive,
    kv_request_runner,
    request_runner,
)

ROOT = Path(__file__).parents[1]
SOURCE = Path(collector.__file__)


@pytest.mark.parametrize(
    "mode",
    [
        "complete",
        "generic-only",
        "preprojection-only",
        "wrong-destination",
        "wrong-prompt-count",
        "short-decode",
        "wrong-nonce",
    ],
)
def test_new_kv_long_nonce_http_and_actual_three_peer_semantic_transport(
    tmp_path, mode
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
                blocks = list(range(10, 18))
                rows = [{"group": 0, "row": 0, "blocks": blocks}]

                def emit_projection(index):
                    transaction = {
                        "runtime_request_id": runtime,
                        "attention_group": 0,
                        "semantic_anchor": 1201,
                        "physical_anchor": 1024,
                        "destination_block_ids": blocks,
                        "host_cpu_block_ids": blocks,
                        "allocation_block_size": 128,
                        "compression_threshold_tokens": 1152,
                    }
                    fact = {
                        "schema": collector.PROJECTION,
                        "plan_id": "CPU-fixture-plan",
                        "launch_id": "CPU-fixture-launch",
                        **transaction,
                        "metadata_row": 0,
                        "transaction_id": collector.sha(
                            collector.canonical(transaction)
                        ),
                        "operation": collector.PROJECTION_OPERATION,
                        "scope": collector.PROJECTION_SCOPE,
                        "host_mapping": "identity-host-block-id-projection",
                        "kv_tensor_equivalence": None,
                        "attention_consumed_observed_tensor": None,
                        "full_generation_quality": None,
                    }
                    response_acks.append(command(run, index, fact))

                if mode not in {"generic-only", "preprojection-only"}:
                    for index in (1, 2):
                        emit_projection(index)
                if mode == "wrong-destination":
                    rows = [{"group": 0, "row": 0, "blocks": list(range(20, 28))}]
                for index in (1, 2, 1, 2):
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
                if mode == "preprojection-only":
                    for index in (1, 2):
                        emit_projection(index)
                body = {
                    "id": external,
                    "model": payload["model"],
                    "usage": {
                        "completion_tokens": 1 if mode == "short-decode" else 40,
                        "prompt_tokens": 1200 if mode == "wrong-prompt-count" else 1201,
                    },
                    "choices": [
                        {
                            "message": {
                                "content": payload["messages"][0]["content"].split(
                                    "\nReply exactly: "
                                )[-1]
                                + (" badnonce" if mode == "wrong-nonce" else "")
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

        class CPUFixtureTokenizer:
            def apply_chat_template(self, messages, **kwargs):
                return [1] * (30 + messages[0]["content"].count("pad "))

        recipe = kv_request_runner.make_kv_recipe(
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
            CPUFixtureTokenizer(),
            [
                {
                    "path": str(fixture_source),
                    "sha256": collector.sha(fixture_source.read_bytes()),
                }
            ],
        )
        phase = recipe["phases"][0]
        spec = {
            "schema": collector.KV_SPEC,
            "kv_requirements": {"phase0": dict(kv_request_runner.REQUIREMENTS)},
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
        assert cli.returncode == (0 if mode == "complete" else 1), cli.stderr
        result = json.loads(cli.stdout)
        assert all("ack" in response for response in response_acks)
        assert (result.get("KV_MOD_metadata_upload_binding_observed") is True) == (
            mode == "complete"
        )
        assert result["formal_result"] is False and result["hardware_result"] is False
        assert result["KV_MOD_semantic_obligation_satisfied"] is None
        assert result["full_objective_satisfied"] is None
        if mode in {
            "complete",
            "generic-only",
            "preprojection-only",
            "wrong-destination",
        }:
            sealed = kv_archive.seal(
                recipe_path,
                spec_path,
                journal,
                tmp_path / "out",
                descriptor_path,
                tmp_path / "archive",
            )
            if mode == "complete":
                # Replay uses archived bytes after original fixture source is gone.
                fixture_source.unlink()
                portable = kv_archive.verify(
                    tmp_path / "archive", sealed["manifest_sha256"], "phase0"
                )
                assert portable["KV_MOD_metadata_upload_binding_observed"] is True
                assert portable["fresh_OS_peer_authentication_performed"] is False
                assert portable["formal_result"] is False
                # Integrity alone cannot promote a body with a wrong nonce.
                manifest_path = tmp_path / "archive/manifest.json"
                manifest = json.loads(manifest_path.read_bytes())
                body_path = tmp_path / "archive/response.bin"
                body = json.loads(body_path.read_bytes())
                body["choices"][0]["message"]["content"] = "different nonce"
                body_path.write_bytes(request_runner.canonical(body))
                metadata_path = tmp_path / "archive/response-metadata.json"
                metadata = json.loads(metadata_path.read_bytes())
                metadata["response_sha256"] = request_runner.sha(body_path.read_bytes())
                metadata_path.write_bytes(request_runner.canonical(metadata))
                for name in ["response.bin", "response-metadata.json"]:
                    manifest["file_sha256"][name] = request_runner.sha(
                        (tmp_path / "archive" / name).read_bytes()
                    )
                manifest_path.write_bytes(request_runner.canonical(manifest))
                with pytest.raises(ValueError, match="nonce"):
                    kv_archive.verify(
                        tmp_path / "archive",
                        request_runner.sha(manifest_path.read_bytes()),
                        "phase0",
                    )
            else:
                with pytest.raises(ValueError, match="KV|projection|destination"):
                    kv_archive.verify(
                        tmp_path / "archive", sealed["manifest_sha256"], "phase0"
                    )
        if mode == "complete":
            proof = json.loads(
                (tmp_path / "out/native-transport-join.json").read_bytes()
            )
            assert proof["source_authenticated_KV_projection_records"] == 2
            assert proof["source_authenticated_native_upload_records"] == 4
            post = json.loads((tmp_path / "out/collector-after.json").read_bytes())
            post["status"]["acknowledged_prefix"]["next_sequence"] -= 1
            with pytest.raises(ValueError, match="ACK|prefix|seal"):
                collector_client.read_verified_phase(
                    spec_path, journal, phase, post, require_kv=True
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
