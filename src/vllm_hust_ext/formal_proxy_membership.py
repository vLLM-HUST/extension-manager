"""Fail-closed process membership for an independent formal traffic authority.

The proxy consumes host-owned vLLM process identities.  The runner may prepare
the frozen input, but it cannot manufacture missing parent, engine, or worker
roles from its own PID tree.  Unsigned same-UID journals remain inside the
declared experiment trust boundary and are never promoted by this module.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any, cast

from .formal_process_snapshot import validate_transition
from .host_event_sink import read_events
from .host_evidence import parse_host_event
from .host_observer import read_linux_process_identity

FORMAL_PROXY_ROLES = frozenset({"api-server", "engine-core-scheduler", "worker"})
_MEMBERSHIP_FIELDS = {
    "host",
    "role",
    "ordinal",
    "process_epoch",
    "pid",
    "start_identity",
}


def _member(process: dict[str, Any]) -> dict[str, Any]:
    return {field: process[field] for field in sorted(_MEMBERSHIP_FIELDS)}


def _validate_members(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not values:
        raise ValueError("formal proxy process membership is missing")
    rows: list[dict[str, Any]] = []
    logical: set[tuple[str, str, int]] = set()
    linux: set[tuple[str, int, str]] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != _MEMBERSHIP_FIELDS:
            raise ValueError("formal proxy process membership is malformed")
        host, role, start = value["host"], value["role"], value["start_identity"]
        ordinal, epoch, pid = (
            value["ordinal"],
            value["process_epoch"],
            value["pid"],
        )
        if (
            not isinstance(host, str)
            or not host
            or host.strip() != host
            or role not in FORMAL_PROXY_ROLES
            or isinstance(ordinal, bool)
            or not isinstance(ordinal, int)
            or ordinal < 0
            or isinstance(epoch, bool)
            or not isinstance(epoch, int)
            or epoch < 0
            or isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or not isinstance(start, str)
            or start != f"pid:{pid}:start_ticks:{start.rsplit(':', 1)[-1]}"
        ):
            raise ValueError("formal proxy process identity is malformed")
        try:
            if int(start.rsplit(":", 1)[-1]) <= 0:
                raise ValueError
        except (AttributeError, ValueError) as exc:
            raise ValueError(
                "formal proxy process start identity is malformed"
            ) from exc
        slot = (host, role, ordinal)
        linux_identity = (host, pid, start)
        if slot in logical:
            raise ValueError("formal proxy membership repeats a logical slot")
        if linux_identity in linux:
            raise ValueError("formal proxy membership reuses one Linux identity")
        logical.add(slot)
        linux.add(linux_identity)
        rows.append(dict(value))
    rows.sort(key=lambda row: (row["host"], row["role"], row["ordinal"]))
    if values != rows:
        raise ValueError("formal proxy process membership is not canonical")
    roles = {row["role"] for row in rows}
    if roles != FORMAL_PROXY_ROLES:
        missing = ",".join(sorted(FORMAL_PROXY_ROLES - roles))
        raise ValueError(f"formal proxy membership lacks host-owned roles: {missing}")
    if sum(row["role"] == "api-server" for row in rows) != 1:
        raise ValueError("formal proxy membership requires one api-server parent")
    return rows


def derive_formal_proxy_membership(transition: Any) -> list[dict[str, Any]]:
    """Derive all three vLLM process layers from retained host event bytes."""
    if not isinstance(transition, dict):
        raise ValueError("formal process transition is missing")
    execution = transition.get("execution_identity")
    if not isinstance(execution, dict):
        raise ValueError("formal proxy execution identity is missing")
    execution = cast(dict[str, str], execution)
    slots = transition.get("logical_slots")
    validate_transition(transition, slots, execution)
    assigned: dict[tuple[str, str, int], dict[str, Any]] = {}
    seen: set[str] = set()
    for receipt in transition["host_receipts"]:
        raw = base64.b64decode(receipt["raw_base64"], validate=True)
        if receipt["raw_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
            raise ValueError("formal proxy host receipt digest mismatch")
        event = parse_host_event(raw)
        if event["event_id"] in seen:
            raise ValueError("formal proxy membership contains replayed evidence")
        seen.add(event["event_id"])
        process = event["process"]
        if (
            event["binding_status"] != "bound"
            or event["plan_id"] != execution["plan_id"]
            or event["launch_id"] != execution["launch_id"]
        ):
            raise ValueError("formal proxy membership contains cross-launch evidence")
        if process.get("assignment_source") != "host":
            continue
        if process["role"] not in FORMAL_PROXY_ROLES:
            continue
        key = (process["host"], process["role"], process["ordinal"])
        row = _member(process)
        prior = assigned.setdefault(key, row)
        if prior != row:
            raise ValueError("formal proxy logical slot changed process epoch")
    rows = [assigned[key] for key in sorted(assigned)]
    return _validate_members(rows)


def verify_formal_proxy_membership(
    root: Path,
    *,
    expected_directory_identity: tuple[int, int],
    execution_identity: dict[str, str],
    members: Any,
) -> list[dict[str, Any]]:
    """Re-read authority-visible journals and live Linux identities."""
    expected = _validate_members(members)
    records = read_events(root, expected_directory_identity)
    observed: dict[tuple[str, str, int], dict[str, Any]] = {}
    for record in records:
        event = record.event
        process = event["process"]
        if (
            event["binding_status"] != "bound"
            or event["plan_id"] != execution_identity["plan_id"]
            or event["launch_id"] != execution_identity["launch_id"]
            or process.get("assignment_source") != "host"
            or process["role"] not in FORMAL_PROXY_ROLES
        ):
            continue
        key = (process["host"], process["role"], process["ordinal"])
        row = _member(process)
        prior = observed.setdefault(key, row)
        if prior != row:
            raise ValueError("formal proxy observed a replaced process epoch")
    expected_by_slot = {
        (row["host"], row["role"], row["ordinal"]): row for row in expected
    }
    if observed != expected_by_slot:
        raise ValueError("formal proxy journal differs from frozen process membership")
    for row in expected:
        live = read_linux_process_identity(row["pid"], row["start_identity"])
        if live["pid"] != row["pid"]:
            raise ValueError("formal proxy live process identity changed")
    return expected
