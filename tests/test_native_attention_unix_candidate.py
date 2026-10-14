"""Complete actual CPU HTTP/Unix mixed chain; all serving/metadata are fixtures."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_attention_candidate import (
    attention_consumer,
    operator_observer,
)
from experiments.native_attention_candidate import (
    collector as attention_collector,
)
from experiments.native_challenge_candidate import (
    kv_request_runner,
    kv_time_policy,
    request_runner,
)
from experiments.native_kv_tensor_candidate import (
    artifact_transport,
    campaign_consumer,
    runtime_contract,
    witness,
)

ROOT = Path(__file__).parents[1]
CPU_SOURCE = Path(__file__).with_name("fixtures") / "native_attention_cpu_peer.py"


class CPUFixtureTokenizer:
    def apply_chat_template(self, messages, **kwargs):
        return list(range(1201))

    def encode(self, text, **kwargs):
        return list(range(40))


def read(child):
    assert select.select([child.stdout], [], [], 10)[0], "CPU child timeout"
    raw = child.stdout.readline()
    assert raw, child.stderr.read()
    return json.loads(raw)


@pytest.fixture(scope="module")
def observation(tmp_path_factory):
    root = tmp_path_factory.mktemp("mixed-real-CPU")
    root.chmod(0o700)
    source = root / "CPU_peer.py"
    source.write_bytes(CPU_SOURCE.read_bytes())
    procs, senders = [], []
    env = os.environ | {"PYTHONPATH": str(ROOT)}
    server = None
    try:
        for role, rank in [("api-server", 0), ("worker", 0), ("worker", 1)]:
            child = subprocess.Popen(
                [sys.executable, str(source), role, str(rank)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            procs.append(child)
            peer = read(child)
            files = [
                source,
                Path(native.__file__),
                Path(artifact_transport.__file__),
                Path(witness.__file__),
                Path(runtime_contract.__file__),
                Path(attention_collector.__file__),
                Path(operator_observer.__file__),
            ]
            senders.append(
                dict(
                    process=peer,
                    peer_uid=os.getuid(),
                    peer_gid=os.getgid(),
                    cmdline_sha256=native.sha(
                        Path(f"/proc/{child.pid}/cmdline").read_bytes()
                    ),
                    source_files=[
                        dict(path=str(p), sha256=native.sha(p.read_bytes()))
                        for p in files
                    ],
                )
            )
        ready = {}
        errors = []

        def command(index, op, **kw):
            child = procs[index]
            own = directories.get(str(child.pid))
            child.stdin.write(
                json.dumps(dict(op=op, ready=ready, dir=own, **kw)) + "\n"
            )
            child.stdin.flush()
            result = read(child)
            if "rejected" in result:
                raise ValueError(result["rejected"])

        class HTTP(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    payload = json.loads(
                        self.rfile.read(int(self.headers["Content-Length"]))
                    )
                    command(0, "mapping", external="chatcmpl-" + payload["request_id"])
                    command(1, "facts")
                    command(2, "facts")
                    command(1, "attention")
                    command(2, "attention")
                    expected = recipe["phases"][0]["response_oracle"]["expected"]
                    body = request_runner.canonical(
                        dict(
                            id="chatcmpl-" + payload["request_id"],
                            model=payload["model"],
                            choices=[
                                dict(
                                    message=dict(content=expected), finish_reason="stop"
                                )
                            ],
                            usage=dict(prompt_tokens=1201, completion_tokens=40),
                        )
                    )
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as error:
                    errors.append(str(error))
                    self.send_error(500)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        binding = [
            dict(
                path=str(Path(campaign_consumer.__file__)),
                sha256=native.sha(Path(campaign_consumer.__file__).read_bytes()),
            ),
            dict(path=str(source), sha256=native.sha(source.read_bytes())),
        ]
        recipe = kv_request_runner.make_kv_recipe(
            [
                (
                    "phase",
                    f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                    "CPU_FIXTURE_ONLY",
                )
            ],
            binding,
            CPUFixtureTokenizer(),
            [
                dict(
                    path=str(Path(__file__)),
                    sha256=native.sha(Path(__file__).read_bytes()),
                )
            ],
            materialized_row=True,
            rpc_budget_s=180,
            prompt_variant=kv_request_runner.STRICT_COPY,
            ack_time_policy=kv_time_policy.FINAL_PREFIX_POLICY,
        )
        recipe = attention_consumer.declare_attention_recipe(
            campaign_consumer.declare_tensor_recipe(recipe)
        )
        phase = recipe["phases"][0]
        spec = dict(
            schema=native.KV_SPEC_V2,
            classification="CPU_REVIEW_CANDIDATE_ONLY",
            formal_producer_registration=False,
            native_plan_id="plan",
            native_launch_id="launch",
            frozen_monotonic_ns=time.monotonic_ns(),
            max_event_age_ns=60_000_000_000,
            max_uploads_per_rank=256,
            senders=senders,
            phases=[
                {
                    k: phase[k]
                    for k in [
                        "phase_id",
                        "client_request_id",
                        "challenge_nonce",
                        "external_request_id",
                        "expected_ranks",
                    ]
                }
            ],
            kv_requirements={"phase": phase["kv_requirements"]},
        )
        spec_path = root / "spec.json"
        spec_path.write_bytes(native.canonical(spec))
        spec_path.chmod(0o600)
        directories = {}
        for child in procs[1:]:
            folder = root / f"worker-{child.pid}"
            folder.mkdir()
            folder.chmod(0o700)
            info = folder.stat()
            directories[str(child.pid)] = dict(
                path=str(folder), identity=[info.st_dev, info.st_ino]
            )
        policy = dict(
            schema=artifact_transport.RUNTIME_POLICY,
            classification="REAL_RUNTIME_UNQUALIFIED",
            formal_registration=False,
            native_spec_sha256=native.sha(spec_path.read_bytes()),
            worker_directories=directories,
            requirements={
                "phase": dict(
                    layer_indices=list(range(28)),
                    semantic_anchor=1201,
                    physical_anchor=1024,
                )
            },
        )
        policy_path = root / "policy.json"
        policy_path.write_bytes(native.canonical(policy))
        policy_path.chmod(0o600)
        journal = root / "native.jsonl"
        sock = root / "native.sock"
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "experiments.native_attention_candidate.collector",
                "--spec",
                str(spec_path),
                "--policy",
                str(policy_path),
                "--journal",
                str(journal),
                "--socket",
                str(sock),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        procs.append(child)
        ready.update(read(child))
        descriptor = ready | dict(
            launcher_observed_identity=ready["collector"],
            launcher_observed_cmdline_sha256=native.sha(
                Path(f"/proc/{child.pid}/cmdline").read_bytes()
            ),
        )
        output = root / "rpc"
        result = attention_consumer.execute_with_attention(
            recipe,
            "phase",
            output,
            socket_path=sock,
            descriptor=descriptor,
            spec_path=spec_path,
            collector_source_path=Path(attention_collector.__file__),
            journal_path=journal,
            policy_path=policy_path,
        )
        assert not errors, errors
        assert result["rpc_task_passed"] is True, result
        assert result["mixed_attention_HTTP_ACK_join"] is True, result
        (root / "recipe.json").write_bytes(native.canonical(recipe))
        (root / "descriptor.json").write_bytes(native.canonical(descriptor))
        yield dict(
            root=root,
            recipe=recipe,
            descriptor=descriptor,
            output=output,
            spec=spec_path,
            policy=policy_path,
            journal=journal,
            result=result,
            command=command,
            socket=sock,
        )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        for child in reversed(procs):
            child.terminate()
            child.wait(timeout=5)


def test_actual_cpu_http_and_four_process_attention_chain(observation):
    events = [
        json.loads(line) for line in observation["journal"].read_bytes().splitlines()
    ]
    assert len(events) == 120
    assert sum(e["kind"] == "attention.operator.accepted" for e in events) == 56
    after = json.loads((observation["output"] / "collector-after.json").read_bytes())
    assert after["status"]["acknowledged_prefix"]["next_sequence"] == len(events)
    assert observation["result"]["formal_result"] is False
    assert observation["result"]["mixed_attention_HTTP_ACK_join"] is True
    assert observation["result"]["operator_receipt_count"] == 56


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_cache",
        "wrong_metadata_seq",
        "false_ACK",
        "wrong_clock",
        "wrong_worker",
        "replay",
    ],
)
def test_actual_unix_source_counterexamples(observation, mutation):
    import base64
    import copy

    events = [
        json.loads(line) for line in observation["journal"].read_bytes().splitlines()
    ]
    event = next(e for e in events if e["kind"] == "attention.operator.accepted")
    fact = copy.deepcopy(json.loads(base64.b64decode(event["raw_base64"])))
    if mutation == "wrong_cache":
        fact["native_arguments"]["cache_views"]["K"]["storage_ptr"] += 1
        fact["native_argument_descriptors"]["key_cache"]["view"]["storage_ptr"] += 1
        fact["native_argument_descriptors_sha256"] = native.sha(
            native.canonical(fact["native_argument_descriptors"])
        )
    elif mutation == "wrong_metadata_seq":
        fact["native_arguments"]["sequence_lengths"] = [1026]
    elif mutation == "false_ACK":
        fact["materialization_ack"]["raw_sha256"] = "0" * 64
        fact["materialization_ack"]["ack_sha256"] = native.sha(
            native.canonical(
                {
                    k: v
                    for k, v in fact["materialization_ack"].items()
                    if k != "ack_sha256"
                }
            )
        )
    elif mutation == "wrong_clock":
        fact["native_stream_completed_ns"] = fact["native_call_started_ns"] - 1
    elif mutation == "wrong_worker":
        fact["process"]["start_ticks"] += 1
    original = observation["journal"].read_bytes()
    with pytest.raises(ValueError):
        observation["command"](1, "attack", fact=fact)
    assert observation["journal"].read_bytes() == original


def test_actual_unix_unregistered_kernel_peer_rejected(observation):
    import base64

    events = [
        json.loads(line) for line in observation["journal"].read_bytes().splitlines()
    ]
    event = next(e for e in events if e["kind"] == "attention.operator.accepted")
    fact = json.loads(base64.b64decode(event["raw_base64"]))
    descriptor = observation["descriptor"]
    with pytest.raises(ValueError, match="kernel peer"):
        native.submit_fact(
            observation["socket"],
            fact,
            expected_collector=descriptor["collector"],
            expected_socket_identity=tuple(descriptor["socket_identity"]),
            expected_collector_source_sha256=descriptor["collector_source_sha256"],
            expected_archive_identity=descriptor["archive_identity"],
        )
