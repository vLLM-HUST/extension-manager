"""Two actual HTTP arrivals/Unix source chains; synthetic CPU fixture only."""

import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import suppress
from pathlib import Path

import pytest
from test_native_attention_drain_unix import CPUFixtureTokenizer

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_attention_candidate import (
    attention_consumer,
    drain_collector,
    drain_consumer,
    drain_time_policy,
    operator_observer,
    phase_drain,
    request_drain_collector,
    request_drain_consumer,
)
from experiments.native_attention_candidate import request_phasebook as books
from experiments.native_attention_candidate.request_prefix_ticket import (
    RequestForwarder,
    RequestServer,
)
from experiments.native_challenge_candidate import kv_request_runner, kv_time_policy
from experiments.native_kv_tensor_candidate import (
    artifact_transport,
    campaign_consumer,
    runtime_contract,
    witness,
)

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def read(process):
    assert select.select([process.stdout], [], [], 20)[0], "CPU source startup timeout"
    raw = process.stdout.readline()
    assert raw, "CPU source exited before its ready frame"
    return json.loads(raw)


def write(path, value):
    books.write_new(path, books.canonical(value))
    return path


@pytest.mark.parametrize(
    "tamper,producer_clock",
    [
        (None, False),
        ("snapshot-bytes", False),
        ("response-bytes", False),
        ("peer-epoch", False),
        (None, True),
    ],
)
def test_two_public_arrivals_each_cause_new_verified_upstream_execution(
    tmp_path, monkeypatch, tamper, producer_clock
):
    tmp_path.chmod(0o700)
    env = os.environ | {"PYTHONPATH": str(ROOT) + ":" + str(ROOT / "src")}
    monkeypatch.setenv("PYTHONPATH", env["PYTHONPATH"])
    peer = tmp_path / "CPU-peer.py"
    # Explicitly synthetic fixture adaptation, never a production source patch.
    source = (ROOT / "tests/fixtures/native_attention_drain_cpu_peer.py").read_text()
    source = source.replace('"CPU-runtime"', "runtime").replace(
        "    c = json.loads(line)",
        '    c = json.loads(line)\n    runtime = c["runtime"]',
    )
    source = source.replace(
        "                for f, ack in materializations.values():\n"
        "                    observer.remember_acknowledged_materialization(f, ack)",
        "            for f, ack in materializations.values():\n"
        "                observer.remember_acknowledged_materialization(f, ack)",
    )
    peer.write_text(source)
    host_source = ROOT / "tests/fixtures/request_forward_cpu_host.py"
    private_port = port()
    recipe = kv_request_runner.make_kv_recipe(
        [
            (
                f"phase-{i}",
                f"http://127.0.0.1:{private_port}/v1/chat/completions",
                "CPU_FIXTURE_ONLY",
            )
            for i in range(2)
        ],
        [
            {
                "path": str(Path(campaign_consumer.__file__).resolve()),
                "sha256": native.sha(Path(campaign_consumer.__file__).read_bytes()),
            },
            {"path": str(peer), "sha256": native.sha(peer.read_bytes())},
        ],
        CPUFixtureTokenizer(),
        [
            {
                "path": str(ROOT / "tests/test_native_attention_drain_unix.py"),
                "sha256": native.sha(
                    (ROOT / "tests/test_native_attention_drain_unix.py").read_bytes()
                ),
            }
        ],
        materialized_row=True,
        rpc_budget_s=180,
        prompt_variant=kv_request_runner.STRICT_COPY,
        ack_time_policy=kv_time_policy.FINAL_PREFIX_POLICY,
    )
    recipe = drain_consumer.declare_drain_recipe(
        attention_consumer.declare_attention_recipe(
            campaign_consumer.declare_tensor_recipe(recipe)
        ),
        upload_tail_policy=drain_time_policy.NONWITNESS_UPLOAD_TAIL,
    )
    recipe = request_drain_consumer.declare_recipe(recipe)
    book = books.declare(recipe)
    host = collector = forwarder = public = thread = None
    log = (tmp_path / "CPU-processes.log").open("wb")
    try:
        host = subprocess.Popen(
            [
                sys.executable,
                str(host_source),
                "--peer-source",
                str(peer),
                "--port",
                str(private_port),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=log,
            env=env,
            text=True,
            start_new_session=True,
        )
        launched = read(host)
        source_files = [
            peer,
            *[
                Path(module.__file__).resolve()
                for module in (
                    native,
                    artifact_transport,
                    witness,
                    runtime_contract,
                    attention_consumer.attention_collector,
                    operator_observer,
                    drain_collector,
                    phase_drain,
                    request_drain_collector,
                )
            ],
        ]
        senders = [
            {
                "process": process,
                "peer_uid": os.getuid(),
                "peer_gid": os.getgid(),
                "cmdline_sha256": native.sha(
                    Path(f"/proc/{process['pid']}/cmdline").read_bytes()
                ),
                "source_files": [
                    {"path": str(path), "sha256": native.sha(path.read_bytes())}
                    for path in source_files
                ],
            }
            for process in launched["peers"]
        ]
        keys = (
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        )
        spec = {
            "schema": native.KV_SPEC_V2,
            "classification": "CPU_REVIEW_CANDIDATE_ONLY",
            "formal_producer_registration": False,
            "native_plan_id": "plan",
            "native_launch_id": "launch",
            "frozen_monotonic_ns": time.monotonic_ns(),
            "max_event_age_ns": 60_000_000_000,
            "max_uploads_per_rank": 256,
            "senders": senders,
            "phases": [{key: phase[key] for key in keys} for phase in recipe["phases"]],
            "kv_requirements": {
                phase["phase_id"]: phase["kv_requirements"]
                for phase in recipe["phases"]
            },
        }
        spec_path = write(tmp_path / "spec.json", spec)
        directories = {}
        for sender in senders[1:]:
            pid = sender["process"]["pid"]
            directory = tmp_path / f"worker-{pid}"
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
            metadata = directory.stat()
            directories[str(pid)] = {
                "path": str(directory),
                "identity": [metadata.st_dev, metadata.st_ino],
            }
        policy = {
            "schema": artifact_transport.RUNTIME_POLICY,
            "classification": "REAL_RUNTIME_UNQUALIFIED",
            "formal_registration": False,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "worker_directories": directories,
            "requirements": {
                phase["phase_id"]: {
                    "layer_indices": list(range(28)),
                    "semantic_anchor": 1201,
                    "physical_anchor": 1024,
                }
                for phase in recipe["phases"]
            },
        }
        policy_path = write(tmp_path / "policy.json", policy)
        drain = {
            "schema": request_drain_collector.POLICY,
            "native_spec_sha256": native.sha(spec_path.read_bytes()),
            "tensor_policy_sha256": native.sha(policy_path.read_bytes()),
            "phase_ids": [phase["phase_id"] for phase in recipe["phases"]],
            "required_ranks": [0, 1],
            "formal_registration": False,
        }
        drain_path = write(tmp_path / "drain-policy.json", drain)
        journal = tmp_path / "native.jsonl"
        native_socket = tmp_path / "native.sock"
        collector = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "experiments.native_attention_candidate.request_drain_collector",
                "--spec",
                str(spec_path),
                "--policy",
                str(policy_path),
                "--journal",
                str(journal),
                "--socket",
                str(native_socket),
                "--drain-policy",
                str(drain_path),
            ],
            stdout=subprocess.PIPE,
            stderr=log,
            env=env,
            text=True,
            start_new_session=True,
        )
        ready = read(collector)
        descriptor = ready | {
            "launcher_observed_identity": ready["collector"],
            "launcher_observed_cmdline_sha256": native.sha(
                Path(f"/proc/{collector.pid}/cmdline").read_bytes()
            ),
        }
        host.stdin.write(
            json.dumps({"ready": ready, "directories": directories, "recipe": recipe})
            + "\n"
        )
        host.stdin.flush()
        assert read(host)["HTTP_ready"]
        enrollment = books.enroll_after_spawn(
            book, spec_path=spec_path, host_process=host
        )

        class FixedClockForwarder(RequestForwarder):
            owner_verification_count = 0
            guard_events = None

            def _trace_guard(self, name):
                if self.guard_events is None:
                    self.guard_events = []
                self.guard_events.append((self.next_phase, name))

            def _after_producer_guard(self, phase, admission):
                from experiments.native_attention_candidate import (
                    request_semantic_controller as semantic_control,
                )

                self._trace_guard("after-producer")
                semantic_control.SemanticRequestForwarder._after_producer_guard(
                    self, phase, admission
                )

            def _after_owner_observation_guard(self, phase, admission):
                from experiments.native_attention_candidate import (
                    request_semantic_controller as semantic_control,
                )

                self._trace_guard("after-owner")
                semantic_control.SemanticRequestForwarder._after_owner_observation_guard(
                    self, phase, admission
                )

            def _before_response_release_guard(self, envelope, admission):
                from experiments.native_attention_candidate import (
                    request_semantic_controller as semantic_control,
                )

                self._trace_guard("before-base-release")
                semantic_control.SemanticRequestForwarder._before_response_release_guard(
                    self, envelope, admission
                )

            def _verify_owner_observation(self, *args):
                self.owner_verification_count += 1
                self._trace_guard("full-owner-verification")
                return super()._verify_owner_observation(*args)

            def _producer_completion_registration(self):
                from experiments.native_attention_candidate import request_live_producer

                return {
                    "completion_domain": request_live_producer.FIXED_COMPLETION,
                    "original_route_expires_monotonic_ns": fixed_route_expiry,
                }

        fixed_route_expiry = time.monotonic_ns() + 1800_000_000_000
        forwarder_class = FixedClockForwarder if producer_clock else RequestForwarder
        forwarder = forwarder_class(
            book,
            enrollment,
            output=tmp_path / "forward",
            descriptor=descriptor,
            socket_path=native_socket,
            spec_path=spec_path,
            policy_path=policy_path,
            drain_policy_path=drain_path,
            collector_source_path=Path(request_drain_collector.__file__).resolve(),
            journal_path=journal,
        )
        producer_ready = forwarder.start_producer()
        assert (
            len(
                {
                    os.getpid(),
                    producer_ready["producer"]["pid"],
                    collector.pid,
                    *(sender["process"]["pid"] for sender in senders),
                }
            )
            == 6
        )
        assert len(journal.read_bytes().splitlines()) == 4  # No seed probe occurred.
        if tamper:
            original_consume = forwarder._consume

            def changed_after_owner_verification(envelope, admission):
                if tamper == "snapshot-bytes":
                    target = Path(
                        envelope["body"]["prefix_manifest"]["files"][0]["path"]
                    )
                    target.write_bytes(target.read_bytes() + b"tampered")
                elif tamper == "response-bytes":
                    Path(envelope["body"]["response"]["path"]).write_bytes(
                        b"changed response"
                    )
                else:
                    os.kill(senders[2]["process"]["pid"], signal.SIGTERM)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        try:
                            native.identity(senders[2]["process"]["pid"])
                        except (OSError, ValueError):
                            break
                        time.sleep(0.01)
                return original_consume(envelope, admission)

            monkeypatch.setattr(forwarder, "_consume", changed_after_owner_verification)
        public = RequestServer(("127.0.0.1", 0), forwarder)
        thread = threading.Thread(target=public.serve_forever, daemon=True)
        thread.start()
        responses = []
        first_snapshot = None
        for index, phase in enumerate(recipe["phases"]):
            request = urllib.request.Request(
                f"http://127.0.0.1:{public.server_port}/v1/chat/completions",
                data=native.canonical(phase["payload"]),
                headers=phase["headers"],
            )
            if tamper:
                with pytest.raises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(request, timeout=30)
                assert rejected.value.code == 503
                assert forwarder.failure is not None
                assert not (tmp_path / "forward/consume-0000.json").exists()
                assert (
                    tmp_path / "forward/request-0000/owner-independent-observation.json"
                ).exists()
                return
            with urllib.request.urlopen(request, timeout=30) as response:
                assert response.status == 200
                body = response.read()
            responses.append(json.loads(body)["id"])
            output = tmp_path / "forward" / f"request-{index:04d}"
            observation = json.loads(
                (output / "owner-independent-observation.json").read_bytes()
            )
            assert (
                observation["tensor_receipt_count"]
                == observation["operator_receipt_count"]
                == 56
            )
            assert not observation["formal_result"]
            completion_record = json.loads(
                (output / "producer-command-completion.json").read_bytes()
            )
            from experiments.native_attention_candidate import request_live_producer

            if producer_clock:
                assert (
                    completion_record["schema"]
                    == request_live_producer.FIXED_COMPLETION
                )
                claim = json.loads(
                    (forwarder.output / f"claim-{index:04d}.json").read_bytes()
                )
                assert completion_record["expires_monotonic_ns"] == min(
                    completion_record["issued_monotonic_ns"] + 30_000_000_000,
                    claim["deadline_monotonic_ns"],
                    fixed_route_expiry,
                )
                assert (
                    completion_record["issued_monotonic_ns"]
                    <= forwarder._producer_completion_receipt.received_monotonic_ns
                )
                assert (
                    forwarder._producer_completion_receipt.wire
                    == (output / "producer-command-completion.json").read_bytes()
                    + b"\n"
                )
            else:
                assert completion_record["schema"] == request_live_producer.COMPLETION
                assert "issued_monotonic_ns" not in completion_record
                assert "expires_monotonic_ns" not in completion_record
            snapshot = (output / "snapshot/native.jsonl").read_bytes()
            if index == 0:
                first_snapshot = snapshot
                before_replay = journal.read_bytes()
                try:
                    urllib.request.urlopen(request, timeout=30)
                    raise AssertionError("duplicate public request was admitted")
                except urllib.error.HTTPError as error:
                    assert error.code == 503
                assert journal.read_bytes() == before_replay
            else:
                assert snapshot.startswith(first_snapshot) and len(snapshot) > len(
                    first_snapshot
                )
                assert (
                    tmp_path / "forward/request-0000/snapshot/native.jsonl"
                ).read_bytes() == first_snapshot
        assert len(set(responses)) == 2
        events = [json.loads(line) for line in journal.read_bytes().splitlines()]
        assert sum(e["kind"] == "tensor.artifact.accepted" for e in events) == 112
        assert sum(e["kind"] == "attention.operator.accepted" for e in events) == 112
        assert sum(e["kind"] == "attention.worker.drained" for e in events) == 4
        assert forwarder.next_phase == 2 and forwarder.pending is None
        if producer_clock:
            assert forwarder.owner_verification_count == 2
            assert forwarder.guard_events == [
                (index, event)
                for index in (0, 1)
                for event in (
                    "after-producer",
                    "full-owner-verification",
                    "after-owner",
                    "before-base-release",
                )
            ]
        # The second proof must verify historical payloads as well as its own56.
        snapshot = tmp_path / "forward/request-0001/snapshot/native.jsonl"
        original_prefix = snapshot.read_bytes()
        prior = next(
            event
            for event in events
            if event["kind"] == "tensor.artifact.accepted"
            and event["phase"]["phase_id"] == recipe["phases"][0]["phase_id"]
        )
        artifact = snapshot.parent / prior["artifact"]["basename"]
        original_artifact = artifact.read_bytes()
        artifact.write_bytes(original_artifact + b" ")
        with pytest.raises(ValueError):
            request_drain_consumer.verify_observation(
                recipe,
                recipe["phases"][1]["phase_id"],
                tmp_path / "forward/request-0001",
                descriptor=descriptor,
                spec_path=spec_path,
                journal_path=snapshot,
                policy_path=policy_path,
                drain_policy_path=drain_path,
            )
        assert snapshot.read_bytes() == original_prefix
    finally:
        if public:
            public.shutdown()
            public.server_close()
        if forwarder:
            forwarder.close()
        if collector:
            collector.terminate()
            collector.wait(timeout=5)
        if host:
            with suppress(ProcessLookupError):
                os.killpg(host.pid, signal.SIGTERM)
            host.wait(timeout=5)
        log.close()
