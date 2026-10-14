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
from experiments.native_challenge_candidate import (
    kv_request_runner,
    kv_time_policy,
    request_runner,
)
from experiments.native_kv_tensor_candidate import (
    artifact_transport,
    campaign_consumer,
    witness,
)

ROOT = Path(__file__).parents[1]
CPU_SOURCE = Path(__file__).with_name("fixtures") / "native_tensor_cpu_peer.py"


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
        recipe = campaign_consumer.declare_tensor_recipe(recipe)
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
            schema=artifact_transport.POLICY,
            classification="CPU_SOURCE_CANDIDATE_ONLY",
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
                "experiments.native_kv_tensor_candidate.artifact_transport",
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
        result = campaign_consumer.execute_with_tensor(
            recipe,
            "phase",
            output,
            socket_path=sock,
            descriptor=descriptor,
            spec_path=spec_path,
            collector_source_path=Path(artifact_transport.__file__),
            journal_path=journal,
            policy_path=policy_path,
        )
        assert not errors, errors
        assert result["mixed_typed_HTTP_ACK_join"] is True, result
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
        )
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        for child in reversed(procs):
            child.terminate()
            child.wait(timeout=5)


def test_actual_cpu_http_and_four_process_mixed_chain(observation):
    result = observation["result"]
    assert result["rpc_task_passed"] and result["mixed_typed_HTTP_ACK_join"]
    assert result["tensor_receipt_count"] == 56
    assert result["hardware_result"] is False and result["GPU_qualification"] is None
    observed = json.loads(
        (observation["output"] / "typed-HTTP-ACK-observation.json").read_bytes()
    )
    assert observed["typed_plan_projection_upload_join"][
        "two_rank_plan_projection_upload_join"
    ]
    assert observed["typed_archive_provenance"]["durable_artifact_join_complete"]


def _load(path):
    return json.loads(path.read_bytes())


def _write(path, value):
    path.write_bytes(native.canonical(value))


def _verify(root):
    return campaign_consumer.verify_observation(
        _load(root / "recipe.json"),
        "phase",
        root / "rpc",
        descriptor=_load(root / "descriptor.json"),
        spec_path=root / "spec.json",
        journal_path=root / "native.jsonl",
        policy_path=root / "policy.json",
    )


def _rechain(root, events):
    import base64

    previous = "0" * 64
    for sequence, event in enumerate(events):
        event.update(sequence=sequence, previous_sha256=previous)
        event.pop("event_sha256", None)
        event["event_sha256"] = native.sha(native.canonical(event))
        previous = event["event_sha256"]
    (root / "native.jsonl").write_bytes(
        b"".join(native.canonical(event) + b"\n" for event in events)
    )
    ack = _load(root / "rpc/collector-after.json")
    ack["status"]["acknowledged_prefix"] = dict(
        next_sequence=len(events), last_event_sha256=previous
    )
    raw = native.canonical(ack["status"])
    ack.update(
        status_raw_base64=base64.b64encode(raw).decode(),
        status_raw_sha256=native.sha(raw),
    )
    _write(root / "rpc/collector-after.json", ack)


@pytest.mark.parametrize(
    "case",
    [
        "native_destination_fork",
        "missing_later_prefix",
        "missing_final_ACK",
        "stale_final_ACK",
        "HTTP503",
        "undeclared_source",
        "helper_source_unpinned",
        "late_source_envelope",
    ],
)
def test_rehashed_actual_cpu_counterexamples(observation, tmp_path, case):
    import base64
    import shutil

    root = tmp_path / case
    shutil.copytree(
        observation["root"],
        root,
        ignore=shutil.ignore_patterns("native.sock", "__pycache__"),
    )
    events = [
        json.loads(line) for line in (root / "native.jsonl").read_bytes().splitlines()
    ]
    if case == "native_destination_fork":
        for event in events:
            if event["kind"] != "native.accepted":
                continue
            fact = json.loads(base64.b64decode(event["raw_base64"]))
            if fact["schema"] == native.PROJECTION_V2:
                fact["destination_block_ids"][0] = 20
                fact["host_cpu_block_ids"][0] = 20
                keys = [
                    "runtime_request_id",
                    "attention_group",
                    "semantic_anchor",
                    "physical_anchor",
                    "destination_block_ids",
                    "host_cpu_block_ids",
                    "allocation_block_size",
                    "compression_threshold_tokens",
                    "scheduled_appended_block_ids",
                    "metadata_effect_monotonic_ns",
                ]
                fact["transaction_id"] = native.sha(
                    native.canonical({k: fact[k] for k in keys})
                )
            elif fact["schema"] == native.UPLOAD:
                fact["uploaded_rows"][0]["blocks"][0] = 20
                fact["uploaded_rows_sha256"] = native.sha(
                    native.canonical(fact["uploaded_rows"])
                )
            raw = native.canonical(fact)
            event.update(
                raw_base64=base64.b64encode(raw).decode(), raw_sha256=native.sha(raw)
            )
        _rechain(root, events)
    elif case == "missing_later_prefix":
        events = [
            e
            for e in events
            if not (
                e["kind"] == "native.accepted"
                and json.loads(base64.b64decode(e["raw_base64"]))["schema"]
                == native.UPLOAD
            )
        ]
        _rechain(root, events)
    elif case == "missing_final_ACK":
        (root / "rpc/collector-after.json").unlink()
    elif case == "stale_final_ACK":
        ack = _load(root / "rpc/collector-after.json")
        ack["status"]["issued_monotonic_ns"] = (
            min(
                e["accepted_monotonic_ns"]
                for e in events
                if "accepted_monotonic_ns" in e
            )
            - 1
        )
        raw = native.canonical(ack["status"])
        ack.update(
            status_raw_base64=base64.b64encode(raw).decode(),
            status_raw_sha256=native.sha(raw),
        )
        _write(root / "rpc/collector-after.json", ack)
    elif case == "HTTP503":
        metadata = _load(root / "rpc/response-metadata.json")
        metadata["status"] = 503
        _write(root / "rpc/response-metadata.json", metadata)
    elif case in ("undeclared_source", "helper_source_unpinned"):
        recipe = _load(root / "recipe.json")
        if case == "undeclared_source":
            recipe.pop("tensor_consumer_contract")
        else:
            recipe["sources"] = [
                s
                for s in recipe["sources"]
                if not s["path"].endswith("projection_tensor_join.py")
            ]
        _write(root / "recipe.json", recipe)
    else:
        event = next(e for e in events if e["kind"] == "tensor.artifact.accepted")
        fact = json.loads(base64.b64decode(event["raw_base64"]))
        fact["monotonic_ns"] = (
            _load(root / "rpc/response-metadata.json")["received_monotonic_ns"] + 1
        )
        raw = native.canonical(fact)
        event.update(
            raw_base64=base64.b64encode(raw).decode(), raw_sha256=native.sha(raw)
        )
        _rechain(root, events)
    with pytest.raises((ValueError, KeyError, OSError, IndexError, TypeError)):
        _verify(root)


def test_observed_wrong_model_task_is_false_not_formal_failure(observation, tmp_path):
    import shutil

    root = tmp_path / "wrong-model-task"
    shutil.copytree(
        observation["root"], root, ignore=shutil.ignore_patterns("native.sock")
    )
    body = _load(root / "rpc/response.bin")
    body["choices"][0]["message"]["content"] = "CPU_OBSERVED_WRONG_ANSWER"
    _write(root / "rpc/response.bin", body)
    metadata = _load(root / "rpc/response-metadata.json")
    metadata["response_sha256"] = native.sha((root / "rpc/response.bin").read_bytes())
    _write(root / "rpc/response-metadata.json", metadata)
    observed = _verify(root)
    assert observed["model_task_passed"] is False
    assert observed["observed_typed_HTTP_ACK_join"] is False
    assert observed["full_objective_satisfied"] is None
    assert observed["formal_result"] is False


def test_portable_source_resolver_keeps_original_recipe(observation, tmp_path):
    recipe = observation["recipe"]
    original = native.canonical(recipe)
    mapped = {}

    def sources(value):
        if isinstance(value, dict):
            if "path" in value and "sha256" in value:
                yield value
            for item in value.values():
                yield from sources(item)
        elif isinstance(value, list):
            for item in value:
                yield from sources(item)

    for index, source in enumerate(sources(recipe)):
        copy = tmp_path / str(index)
        copy.write_bytes(Path(source["path"]).read_bytes())
        mapped[source["path"]] = copy

    def verify():
        return campaign_consumer.verify_observation(
            recipe,
            "phase",
            observation["output"],
            descriptor=observation["descriptor"],
            spec_path=observation["spec"],
            journal_path=observation["journal"],
            policy_path=observation["policy"],
            source_resolver=lambda path: mapped[path],
        )

    assert verify()["observed_typed_HTTP_ACK_join"] is True
    assert native.canonical(recipe) == original
    mapped[str(Path(campaign_consumer.__file__).resolve())].write_bytes(b"wrong oracle")
    with pytest.raises(ValueError):
        verify()
