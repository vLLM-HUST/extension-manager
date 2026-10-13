"""Two-stage formal process identity, derived from retained host bytes.

This validates unsigned host journals inside the declared trusted experiment
boundary. It does not upgrade the same-UID journal to a cryptographic authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, cast

from .ecpa_model import canonical_bytes
from .host_evidence import parse_host_event


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def validate_slots(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("formal logical process slots are missing")
    keys = []
    for row in value:
        if not isinstance(row, dict) or set(row) != {"host", "role", "ordinal"}:
            raise ValueError("formal logical slots must not contain prelaunch epochs")
        if any(
            not isinstance(row[k], str) or not row[k] or row[k].strip() != row[k]
            for k in ("host", "role")
        ):
            raise ValueError("formal logical process slot is malformed")
        if (
            isinstance(row["ordinal"], bool)
            or not isinstance(row["ordinal"], int)
            or row["ordinal"] < 0
        ):
            raise ValueError("formal logical process ordinal is malformed")
        keys.append((row["host"], row["role"], row["ordinal"]))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError("formal logical slots are duplicate or noncanonical")
    return cast(list[dict[str, Any]], json.loads(canonical_bytes(value)))


def derive_snapshot(
    slots: Any, execution: dict[str, str], receipts: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Reconstruct epochs/PIDs from exact host-event bytes; reject ambiguity."""
    if (
        not isinstance(execution, dict)
        or set(execution) != {"plan_id", "launch_id", "controller_instance"}
        or any(
            not isinstance(v, str) or not v or v.strip() != v
            for v in execution.values()
        )
    ):
        raise ValueError("snapshot execution identity is malformed")
    if not isinstance(receipts, list):
        raise ValueError("snapshot host receipts are malformed")
    logical = validate_slots(slots)
    expected = {(r["host"], r["role"], r["ordinal"]) for r in logical}
    assigned: dict[tuple[str, str, int], dict[str, Any]] = {}
    events: set[str] = set()
    for receipt in receipts:
        if (
            not isinstance(receipt, dict)
            or set(receipt) != {"raw_base64", "raw_sha256"}
            or not all(isinstance(v, str) for v in receipt.values())
        ):
            raise ValueError("snapshot host receipt is malformed")
        raw = base64.b64decode(receipt["raw_base64"], validate=True)
        if receipt["raw_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise ValueError("snapshot host receipt digest mismatch")
        event = parse_host_event(raw)
        if event["event_id"] in events:
            raise ValueError("snapshot contains replayed host receipt")
        events.add(event["event_id"])
        process = event["process"]
        if (
            event["plan_id"] != execution["plan_id"]
            or event["launch_id"] != execution["launch_id"]
            or event["binding_status"] != "bound"
            or process.get("assignment_source") != "host"
            or (
                event["observation_kind"] != "loader_lifecycle"
                and event["controller_instance_id"] != execution["controller_instance"]
            )
        ):
            raise ValueError("snapshot contains unbound or cross-launch host evidence")
        key = (process["host"], process["role"], process["ordinal"])
        if key not in expected:
            continue
        prefix = f"pid:{process['pid']}:start_ticks:"
        if not process["start_identity"].startswith(prefix):
            raise ValueError("snapshot host start identity is malformed")
        try:
            ticks = int(process["start_identity"][len(prefix) :])
        except ValueError as exc:
            raise ValueError("snapshot host start ticks are malformed") from exc
        if (
            ticks <= 0
            or process["start_identity"] != prefix + str(ticks)
            or process["pid"] <= 0
        ):
            raise ValueError("snapshot host start ticks are malformed")
        row = {**process, "start_ticks": ticks}
        if key in assigned and assigned[key] != row:
            raise ValueError("snapshot logical slot has replacement or multiple epochs")
        assigned[key] = row
    if set(assigned) != expected:
        raise ValueError("snapshot is missing required logical process slots")
    rows = [assigned[key] for key in sorted(assigned)]
    if len({(r["host"], r["pid"], r["start_ticks"]) for r in rows}) != len(rows):
        raise ValueError("snapshot duplicates one Linux process across slots")
    return rows


def make_transition(
    slots: Any,
    execution: dict[str, str],
    receipts: list[dict[str, Any]],
    *,
    frozen_at_ns: int,
) -> dict[str, Any]:
    logical = validate_slots(slots)
    processes = derive_snapshot(logical, execution, receipts)
    return {
        "schema": "ecpa-formal-process-transition/v1",
        "execution_identity": dict(execution),
        "logical_slots": logical,
        "logical_slots_digest": digest(logical),
        "processes": processes,
        "processes_digest": digest(processes),
        "host_receipts": receipts,
        "frozen_at_ns": frozen_at_ns,
    }


def validate_transition(
    value: Any, slots: Any, execution: dict[str, str]
) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "execution_identity",
        "logical_slots",
        "logical_slots_digest",
        "processes",
        "processes_digest",
        "host_receipts",
        "frozen_at_ns",
    }:
        raise ValueError("formal process transition is missing or malformed")
    if (
        isinstance(value["frozen_at_ns"], bool)
        or not isinstance(value["frozen_at_ns"], int)
        or value["frozen_at_ns"] <= 0
    ):
        raise ValueError("formal process freeze time is malformed")
    expected = make_transition(
        slots, execution, value["host_receipts"], frozen_at_ns=value["frozen_at_ns"]
    )
    if value != expected:
        raise ValueError("formal process transition differs from host receipts")
    return cast(list[dict[str, Any]], expected["processes"])


def validate_runner_snapshots(
    identity: dict[str, Any], command: dict[str, Any]
) -> list[dict[str, Any]]:
    """Validate the runner's prelaunch/postlaunch transition without /proc access."""
    slots = identity.get("required_process_slots")
    execution = command.get("execution_identity", {})
    rows = validate_transition(command.get("process_transition"), slots, execution)
    required = [
        {k: row[k] for k in ("host", "role", "ordinal", "process_epoch")}
        for row in rows
    ]
    if identity.get("required_processes") != required:
        raise ValueError("formal process epochs differ from postlaunch freeze")
    prelaunch = command.get("prelaunch_snapshot")
    if (
        not isinstance(prelaunch, dict)
        or set(prelaunch)
        != {
            "schema",
            "execution_identity",
            "logical_slots",
            "logical_slots_digest",
            "prepared_at_ns",
        }
        or prelaunch["schema"] != "ecpa-formal-logical-snapshot/v1"
        or prelaunch["execution_identity"] != execution
        or prelaunch["logical_slots"] != slots
        or prelaunch["logical_slots_digest"] != digest(slots)
        or isinstance(prelaunch["prepared_at_ns"], bool)
        or not isinstance(prelaunch["prepared_at_ns"], int)
    ):
        raise ValueError("prelaunch logical snapshot differs from frozen slots")
    frozen_at = command["process_transition"]["frozen_at_ns"]
    try:
        launched = command["monotonic_start_ns"]
        ready = command["phase_bounds"]["service-ready"][0]
        if any(
            isinstance(t, bool) or not isinstance(t, int) for t in (launched, ready)
        ):
            raise ValueError("runner snapshot transition times are malformed")
        if not 0 < prelaunch["prepared_at_ns"] <= launched <= frozen_at < ready:
            raise ValueError(
                "formal process freeze is outside launch/readiness transition"
            )
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("runner snapshot transition times are malformed") from exc
    return rows
