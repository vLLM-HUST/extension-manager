"""Authentication and sealed-prefix bounds using real CPU Unix intake only."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_request_drain_collector import live as live

from experiments.native_attention_candidate import request_collector_client as client
from experiments.native_attention_candidate import request_drain_collector as intake


def test_private_authentication_binds_independently_enrolled_tensor_policy(live):
    descriptor = live["descriptor"] | {"policy_sha256": "0" * 64}
    with pytest.raises(ValueError, match="independently enrolled tensor policy"):
        client.authenticate(
            live["socket"],
            descriptor,
            live["spec_path"],
            Path(intake.__file__),
            drain_policy_path=live["drain"],
        )
    assert live["authenticate"]()["status"]["schema"] == intake.STATUS


def test_authenticated_closed_phase_bounds_reject_mutations(live):
    receipt = live["complete"](1)
    original = receipt["status"]
    policy = json.loads(live["drain"].read_bytes())
    spec = live["spec"]
    key = "CPU-runtime-1"
    mutations = [
        lambda s: s.update(schema="ecpa-native-semantic-collector-status/v1"),
        lambda s: s["source_drain"]["runtimes"][key].update(complete=False),
        lambda s: s["source_drain"]["runtimes"][key].update(ranks=[0]),
        lambda s: s["source_drain"]["runtimes"][key].update(sealed_prefix_bytes=0),
        lambda s: s["source_drain"]["runtimes"][key].update(sealed_prefix_sha256="bad"),
        lambda s: s["source_drain"]["runtimes"][key].update(
            sealed_monotonic_ns=s["issued_monotonic_ns"] + 1
        ),
        lambda s: s["source_drain"]["runtimes"][key]["sealed_prefix"].update(
            next_sequence=s["acknowledged_prefix"]["next_sequence"] + 1
        ),
        lambda s: s["source_drain"]["runtimes"][key]["sealed_prefix"].update(
            last_event_sha256="0" * 64
        ),
    ]
    for mutate in mutations:
        status = copy.deepcopy(original)
        mutate(status)
        with pytest.raises(ValueError):
            client.validate_request_status(status, spec, policy)
    client.validate_request_status(original, spec, policy)
