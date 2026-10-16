"""Real independent Unix grant observations; CPU control evidence only."""

import copy
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate import loopback_traffic
from experiments.native_attention_candidate import live_route_reader as routes
from experiments.native_attention_candidate import (
    request_semantic_authority as semantic,
)
from experiments.native_attention_candidate import (
    request_semantic_controller as controller,
)
from vllm_hust_ext.exposure_gate import LeaseGrant


@pytest.fixture
def actual_grant(tmp_path):
    tmp_path.chmod(0o700)
    endpoint, journal = tmp_path / "authority.sock", tmp_path / "authority.jsonl"
    grant = LeaseGrant("CPU_CONTROLLER", 17, int(time.time()) + 90)
    argv = [
        sys.executable,
        "-m",
        "experiments.exposure_gate.loopback_traffic",
        "--socket",
        str(endpoint),
        "--journal",
        str(journal),
        "--predecessor-port",
        "1",
        "--candidate-port",
        "2",
        "--predecessor-snapshot",
        json.dumps(
            {"generation": 0, "plan_id": "CPU_PREDECESSOR", "rendered_inputs": {}}
        ),
        "--grant-holder",
        grant.holder,
        "--grant-token",
        str(grant.fencing_token),
        "--grant-expires-at",
        str(grant.expires_at),
    ]
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ | {"PYTHONPATH": "src"},
    )
    try:
        assert select.select([process.stdout], [], [], 10)[0]
        ready = json.loads(process.stdout.readline())
        assert ready["port"] > 0
        adapter = loopback_traffic.LoopbackTrafficAdapter(endpoint, grant)
        adapter.close(1)
        source = Path(loopback_traffic.__file__).resolve()
        audits = {
            "CPU": {
                "source_files": {str(source): semantic.sha(source.read_bytes())},
                "file_state": {str(source): routes._state(source.stat())},
            }
        }
        launch = {"controller_instance": grant.holder, "candidate_generation": 1}
        observation = controller.observe_route_grant(
            process, socket_path=endpoint, launch=launch, input_audits=audits
        )
        yield process, adapter, observation, audits, launch
    finally:
        process.terminate()
        process.communicate(timeout=10)


def test_actual_original_grant_clock_raw_peer_and_predecessor(actual_grant):
    process, adapter, observation, audits, launch = actual_grant
    expiry = observation["original_monotonic_expiry_ns"]
    assert observation["original_route"]["generation"] == 0
    assert observation["candidate_generation"] == 1
    assert observation["grant"]["fencing_token"] == 17
    assert observation["query_before"]["kernel_peer"]["pid"] == process.pid
    assert observation["query_before"]["raw_base64"]
    assert controller.route_grant_current(observation, audits) == expiry
    assert controller.route_grant_current(observation, audits) == expiry


def test_actual_grant_cannot_rebind_holder_generation_or_source(actual_grant):
    process, adapter, observation, audits, launch = actual_grant
    for changed in (
        {**launch, "controller_instance": "invented"},
        {**launch, "candidate_generation": 2},
    ):
        with pytest.raises(ValueError):
            controller.observe_route_grant(
                process,
                socket_path=observation["descriptor"]["socket_path"],
                launch=changed,
                input_audits=audits,
            )
    bad_audits = copy.deepcopy(audits)
    bad_audits["CPU"]["source_files"] = {"invented": "0" * 64}
    with pytest.raises(ValueError, match="source closure"):
        controller.route_grant_current(observation, bad_audits)


def test_real_external_route_action_permanently_supersedes_prepared_root(actual_grant):
    process, adapter, observation, audits, launch = actual_grant
    adapter.close_all()
    with pytest.raises(ValueError):
        controller.route_grant_current(observation, audits)


def test_caller_cannot_supply_authority_fence_or_expiry():
    with pytest.raises(TypeError):
        controller.RequestRouteControl(
            "/tmp/self-selected",
            launch={},
            native_launch_id="fake",
            expires_monotonic_ns=time.monotonic_ns() + 30_000_000_000,
        )
    with pytest.raises(TypeError):
        controller.PreparedRequestRouteReader(
            socket_path="/tmp/self-selected",
            authority={},
            authority_sources={},
            authority_command_sha256="0" * 64,
            input_audits={},
            expected_binding={},
        )


def test_python_c_is_not_an_independent_grant_authority():
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.read()"], stdin=subprocess.PIPE
    )
    try:
        with pytest.raises(ValueError, match="actual pinned controller"):
            controller._authority_argv(semantic.registry.process_identity(child.pid))
    finally:
        child.stdin.close()
        child.wait(timeout=5)


@pytest.mark.parametrize("invalidate", ["clock", "epoch", "source"])
def test_final_release_guard_rejects_invalidation_after_response_io(
    tmp_path, invalidate
):
    # Exercise only the final guard, never pretend a full native observation passed.
    forwarder = object.__new__(controller.SemanticRequestForwarder)
    leaf = tmp_path / "real-response.bin"
    leaf.write_bytes(b"CPU response read before invalidation")
    ticket = {
        "body": {
            "files": {str(leaf): semantic.sha(leaf.read_bytes())},
            "native_prefix_path": str(leaf),
            "expires_monotonic_ns": time.monotonic_ns() + 30_000_000_000,
        }
    }
    admission = {"deadline_monotonic_ns": time.monotonic_ns() + 240_000_000_000}
    forwarder._current = lambda: None
    if invalidate == "clock":
        ticket["body"]["expires_monotonic_ns"] = time.monotonic_ns() - 1
    elif invalidate == "source":
        leaf.write_bytes(b"source invalidated after base response IO")
    else:

        def lost_epoch():
            raise ValueError("actual peer disappeared during base response IO")

        forwarder._current = lost_epoch
    with pytest.raises(ValueError):
        forwarder._release_guard(ticket, admission)
    assert forwarder.failure.startswith("semantic release permanently closed")


def test_real_grant_io_rechecks_complete_input_union_after_reply(
    actual_grant, tmp_path, monkeypatch
):
    process, adapter, observation, audits, launch = actual_grant
    leaf = tmp_path / "actual-CPU-mutable-input.bin"
    leaf.write_bytes(b"before real Unix query")
    expanded = copy.deepcopy(audits)
    expanded["CPU"]["file_state"][str(leaf)] = routes._state(leaf.stat())
    cut = semantic._AuditCut(expanded)
    original = controller.IndependentGrantObserver.exchange
    changed = False

    def actual_reply_then_mutation(self, *args, **kwargs):
        nonlocal changed
        result = original(self, *args, **kwargs)
        if not changed:
            leaf.write_bytes(b"mutated after actual authenticated Unix reply")
            changed = True
        return result

    monkeypatch.setattr(
        controller.IndependentGrantObserver, "exchange", actual_reply_then_mutation
    )
    with pytest.raises(ValueError, match="audited input"):
        controller.route_grant_current(observation, expanded, _cut=cut)
    assert changed  # No mocked query or fabricated grant/consumer PASS.


@pytest.mark.parametrize(
    "hook",
    [
        "_after_producer_guard",
        "_after_owner_observation_guard",
        "_before_response_release_guard",
    ],
)
def test_legacy_default_guard_hooks_keep_dynamic_full_current_failure(hook):
    # Guard dispatch contract only; no mocked native consumer or qualification.
    forwarder = object.__new__(controller.RequestForwarder)
    reached = []

    def rejected():
        reached.append("full-current")
        raise ValueError("CPU guard rejection")

    forwarder._current = rejected
    with pytest.raises(ValueError, match="CPU guard rejection"):
        getattr(forwarder, hook)({}, {})
    assert reached == ["full-current"]
