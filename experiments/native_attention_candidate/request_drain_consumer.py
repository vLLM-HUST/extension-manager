"""Explicit request-scoped native observation over an unmodified global prefix.

Every original record and artifact is verified before selecting a request report.
A source-owned first-seal prefix may precede the collector's current global head;
neither receipt nor journal is rewritten to look like the legacy single cell.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from experiments.native_challenge_candidate import kv_request_runner as kv
from experiments.native_kv_tensor_candidate import projection_tensor_join

from . import attention_consumer as core
from . import drain_collector as original_drain
from . import drain_consumer as original_consumer
from . import drain_time_policy, phase_drain
from . import request_collector_client as client
from . import request_drain_collector as collector
from . import request_http_runner as http_runner  # noqa: F401 -- explicit protocol API

RECIPE = "ecpa-request-native-kv-campaign/v1"
CONTRACT = "ecpa-request-native-drain-consumer/v1"
SCHEMA = "ecpa-request-native-observation/v1"
SCOPE = "full-original-global-prefix-selected-request"
canonical, sha, require = core.canonical, core.sha, core.require
_NEW_SOURCES = (
    "request_drain_consumer.py",
    "request_drain_collector.py",
    "request_collector_client.py",
    "request_http_runner.py",
    "request_phasebook.py",
    "request_prefix_ticket.py",
    "request_live_producer.py",
)


def expected_sources():
    paths = [Path(__file__).with_name(name) for name in _NEW_SOURCES]
    paths += [
        Path(module.__file__).resolve()
        for module in (
            core,
            kv,
            original_drain,
            original_consumer,
            drain_time_policy,
            phase_drain,
            projection_tensor_join,
        )
    ]
    return {str(p.resolve()): sha(p.read_bytes()) for p in paths}


def declare_recipe(recipe):
    """Declare a NEW prospective protocol, never reinterpret an executed archive."""
    kv.validate_kv(recipe)
    original_consumer.require_declared_drain_recipe(recipe)
    require(
        recipe["schema"] == kv.SCHEMA_V2
        and recipe["attention_drain_contract"].get("upload_tail_policy")
        == drain_time_policy.NONWITNESS_UPLOAD_TAIL,
        "new requests require the complete original bounded native contract",
    )
    value = copy.deepcopy(recipe)
    value["schema"] = RECIPE
    del value["attention_drain_contract"]
    for phase in value["phases"]:
        phase["ack_client_source_sha256"] = sha(Path(client.__file__).read_bytes())
    sources = expected_sources()
    old = {row["path"]: row["sha256"] for row in value["sources"]}
    require(
        all(p not in old or old[p] == d for p, d in sources.items()),
        "prospective source declaration conflicts",
    )
    value["sources"] = [
        {"path": p, "sha256": d} for p, d in sorted({**old, **sources}.items())
    ]
    value["request_drain_contract"] = {
        "schema": CONTRACT,
        "scope": SCOPE,
        "required_ranks": [0, 1],
        "upload_tail_policy": drain_time_policy.NONWITNESS_UPLOAD_TAIL,
        "source_sha256": sources,
        "formal_result": False,
    }
    validate_recipe(value)
    return value


def validate_recipe(recipe, *, source_resolver=None):
    kv.validate_kv_fields(
        recipe,
        supported_schemas={RECIPE},
        materialized_schema=RECIPE,
        ack_client_source=(
            Path(client.__file__).name,
            sha(Path(client.__file__).read_bytes()),
        ),
        source_resolver=source_resolver,
    )
    core.require_declared_attention_recipe(recipe, source_resolver=source_resolver)
    require(
        "attention_drain_contract" not in recipe,
        "new request protocol cannot claim a legacy drain declaration",
    )
    contract = recipe.get("request_drain_contract")
    require(
        isinstance(contract, dict)
        and {k: v for k, v in contract.items() if k != "source_sha256"}
        == {
            "schema": CONTRACT,
            "scope": SCOPE,
            "required_ranks": [0, 1],
            "upload_tail_policy": drain_time_policy.NONWITNESS_UPLOAD_TAIL,
            "formal_result": False,
        },
        "new request native consumer declaration differs",
    )
    declared, expected = contract["source_sha256"], expected_sources()
    require(
        isinstance(declared, dict) and len(declared) == len(expected),
        "new request source inventory differs",
    )
    if source_resolver is None:
        require(declared == expected, "new request imported/source bytes differ")
    else:
        for current, digest in expected.items():
            originals = [p for p in declared if Path(p).name == Path(current).name]
            require(len(originals) == 1, "new request source basename is ambiguous")
            resolved = Path(source_resolver(originals[0]))
            require(
                declared[originals[0]] == digest
                and resolved.is_absolute()
                and resolved.is_file()
                and sha(resolved.read_bytes()) == digest,
                "new request copied/imported source bytes differ",
            )
    pinned = {r["path"]: r["sha256"] for r in recipe["sources"]}
    require(
        all(pinned.get(p) == d for p, d in declared.items()),
        "new request source declaration absent from frozen recipe",
    )


def sealed_state(receipt, phase, drain_policy_path):
    status = receipt["status"]
    source = status.get("source_drain")
    require(
        status["schema"] == collector.STATUS
        and status["failed"] is False
        and status["formal_producer_registration"] is False
        and receipt["formal_result"] is False
        and isinstance(source, dict)
        and source["schema"] == collector.POLICY
        and source["policy_sha256"] == sha(Path(drain_policy_path).read_bytes()),
        "new request authenticated collector/policy schema differs",
    )
    selected = [
        (runtime, state)
        for runtime, state in source["runtimes"].items()
        if state["phase"]["phase_id"] == phase["phase_id"]
    ]
    require(len(selected) == 1, "new request source has missing/ambiguous runtime")
    runtime, state = selected[0]
    require(
        state["phase"]["external_request_id"] == phase["external_request_id"]
        and state["complete"] is True
        and state["ranks"] == [0, 1]
        and type(state["sealed_prefix_bytes"]) is int
        and state["sealed_prefix_bytes"] > 0
        and type(state["sealed_monotonic_ns"]) is int
        and state["sealed_monotonic_ns"] > 0
        and isinstance(state["sealed_prefix_sha256"], str)
        and len(state["sealed_prefix_sha256"]) == 64,
        "new request is not source-sealed on both actual workers",
    )
    prefix = state["sealed_prefix"]
    current = status["acknowledged_prefix"]
    require(
        set(prefix) == {"next_sequence", "last_event_sha256"}
        and type(prefix["next_sequence"]) is int
        and prefix["next_sequence"] >= 4
        and type(current["next_sequence"]) is int
        and current["next_sequence"] >= prefix["next_sequence"]
        and (current["next_sequence"] != prefix["next_sequence"] or current == prefix),
        "new request sealed prefix is not an ancestor of authenticated global head",
    )
    return runtime, state


def verify_sealed_status(receipt, phase, drain_policy_path):
    sealed_state(receipt, phase, drain_policy_path)
    return True


def sealed_prefix(receipt, phase, drain_policy_path):
    return sealed_state(receipt, phase, drain_policy_path)[1]["sealed_prefix"]


def verify_time_contract(phase, events, metadata, before, after, descriptor, peer_uid):
    source = after["status"]["source_drain"]
    states = [
        s
        for s in source["runtimes"].values()
        if s["phase"]["phase_id"] == phase["phase_id"]
    ]
    require(len(states) == 1, "request timing lacks unique source seal")
    state = states[0]
    require(
        not any(
            s["phase"]["phase_id"] == phase["phase_id"]
            for s in before["status"]["source_drain"]["runtimes"].values()
        ),
        "request timing forbids a seeded/reused phase",
    )
    prefix = state["sealed_prefix"]
    first = before["status"]["acknowledged_prefix"]
    require(
        type(first["next_sequence"]) is int
        and 0 < first["next_sequence"] < len(events)
        and events[first["next_sequence"] - 1]["event_sha256"]
        == first["last_event_sha256"],
        "actual before ACK is not an ancestor of retained full global chain",
    )
    require(
        events[-1]["accepted_monotonic_ns"]
        <= state["sealed_monotonic_ns"]
        <= after["status"]["issued_monotonic_ns"],
        "source seal clock is outside its final raw intake/authentication window",
    )
    value = drain_time_policy.verify_time_contract(
        phase,
        events,
        metadata,
        before,
        after,
        descriptor,
        peer_uid,
        upload_tail_policy=drain_time_policy.NONWITNESS_UPLOAD_TAIL,
        retained_prefix=prefix,
    )
    return {
        **value,
        "schema": "ecpa-request-source-close-time-observation/v1",
        "retained_global_prefix": prefix,
        "authenticated_current_global_prefix": after["status"]["acknowledged_prefix"],
        "source_sealed_monotonic_ns": state["sealed_monotonic_ns"],
    }


def verify_observation(
    recipe,
    phase_id,
    output,
    *,
    descriptor,
    spec_path,
    journal_path,
    policy_path,
    source_resolver=None,
    drain_policy_path=None,
):
    """Recompute the full original prefix and exact selected-request semantics."""
    require(drain_policy_path is not None, "new request drain policy is mandatory")
    validate_recipe(recipe, source_resolver=source_resolver)
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    output = Path(output)
    raw = Path(journal_path).read_bytes()
    events = [json.loads(x) for x in raw.splitlines()]
    after = json.loads((output / "collector-after.json").read_bytes())
    runtime, state = sealed_state(after, phase, drain_policy_path)
    require(
        len(raw) == state["sealed_prefix_bytes"]
        and sha(raw) == state["sealed_prefix_sha256"],
        "retained original global bytes differ from actual first source seal",
    )
    collector.verify_raw_prefix(raw, state["sealed_prefix"])
    spec_raw = Path(spec_path).read_bytes()
    spec = json.loads(spec_raw)
    policy = json.loads(Path(drain_policy_path).read_bytes())
    for receipt in (
        json.loads((output / "collector-before.json").read_bytes()),
        after,
    ):
        client.validate_request_status(receipt["status"], spec, policy)
    require(
        1 <= len(spec["phases"]) <= collector.MAX_PHASES
        and len(events) >= 4
        and events[3]["kind"] == collector.START_KIND
        and events[3]["schema"] == collector.START
        and events[3]["phase_ids"] == [p["phase_id"] for p in spec["phases"]]
        and events[3]["inherited_collector_source_sha256"]
        == sha(Path(original_drain.__file__).read_bytes()),
        "new request raw protocol start/source/phase book differs",
    )
    observed = core.verify_observation(
        recipe,
        phase_id,
        output,
        descriptor=descriptor,
        spec_path=spec_path,
        journal_path=journal_path,
        policy_path=policy_path,
        source_resolver=source_resolver,
        drain_policy_path=drain_policy_path,
        observation_protocol=sys.modules[__name__],
    )
    require(
        observed["model_task_passed"] is True
        and observed["observed_typed_HTTP_ACK_join"] is True
        and observed["finite_native_argument_completion_join"] is True
        and observed["typed_archive_provenance"]["full_phase_source_drained"] is True
        and observed["tensor_receipt_count"]
        == observed["operator_receipt_count"]
        == 56,
        "new request full native/model task predicate failed",
    )
    closures = [
        row
        for row in observed["typed_archive_provenance"]["source_drains"]
        if row["phase_id"] == phase_id
    ]
    require(
        len(closures) == 2
        and {r["rank"] for r in closures} == {0, 1}
        and {r["runtime_request_id"] for r in closures} == {runtime},
        "new request lacks exact two actual source closures",
    )
    require(
        Path(journal_path).read_bytes() == raw,
        "original global prefix changed during verification",
    )
    return {
        **observed,
        "schema": SCHEMA,
        "scope": SCOPE,
        "phase_id": phase_id,
        "external_request_id": phase["external_request_id"],
        "runtime_request_id": runtime,
        "request_sha256": sha(canonical(phase["payload"])),
        "response_sha256": observed["actual_raw_response_sha256"],
        "full_global_prefix": state["sealed_prefix"],
        "full_global_prefix_bytes": len(raw),
        "full_global_prefix_sha256": sha(raw),
        "full_global_prefix_records": len(events),
        "worker_closure_count": 2,
        "full_phase_source_drained": observed["typed_archive_provenance"][
            "full_phase_source_drained"
        ],
        "formal_result": False,
    }
