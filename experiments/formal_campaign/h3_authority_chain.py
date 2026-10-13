"""Independent route recovery facts from traffic-owned chained raw events.

This proves control-route restoration only. HTTP/model correctness, Host
coverage, source admission, and formal campaign qualification are separate gates.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from experiments.exposure_gate.loopback_traffic import read_traffic_journal  # noqa: E402


def snapshot_digest(snapshot: dict[str, Any]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {"snapshot": snapshot},
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
    )


def verify_recovery_chain(
    path: Path,
    *,
    expected_proxy: dict[str, Any],
    registration_sha256: str,
    launch_id: str,
    prepared_route: dict[str, Any],
    fault_ns: int,
    restart_ns: int,
    completion_ns: int,
) -> dict[str, Any]:
    events = read_traffic_journal(path)
    return verify_recovery_events(
        events,
        expected_proxy=expected_proxy,
        registration_sha256=registration_sha256,
        launch_id=launch_id,
        prepared_route=prepared_route,
        fault_ns=fault_ns,
        restart_ns=restart_ns,
        completion_ns=completion_ns,
    )


def verify_recovery_events(
    events: list[dict[str, Any]],
    *,
    expected_proxy: dict[str, Any],
    registration_sha256: str,
    launch_id: str,
    prepared_route: dict[str, Any],
    fault_ns: int,
    restart_ns: int,
    completion_ns: int,
) -> dict[str, Any]:
    if not events or not 0 < fault_ns < restart_ns < completion_ns:
        raise ValueError("authority recovery lifecycle order invalid")
    previous = "sha256:" + "0" * 64
    last_ns = 0
    if sum(e.get("kind") == "authority.start" for e in events) != 1:
        raise ValueError("authority recovery repeats a start")
    for index, event in enumerate(events, 1):
        if event.get("schema") != "ecpa-loopback-route-journal/v1":
            raise ValueError("authority recovery journal schema differs")
        if event.get("sequence") != index or event.get("previous_sha256") != previous:
            raise ValueError("authority recovery chain is broken or duplicated")
        raw = json.dumps(
            event, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        previous = "sha256:" + hashlib.sha256(raw).hexdigest()
        if any(
            event.get("proxy_" + key) != expected_proxy[key]
            for key in ("pid", "start_ticks", "boot_id")
        ):
            raise ValueError("authority recovery process identity differs")
        observed = event.get("monotonic_ns", 0)
        if not last_ns < observed:
            raise ValueError("authority recovery timestamps are missing or replayed")
        last_ns = observed
    start = events[0]
    binding = start["detail"].get("authorization") or {}
    if (
        start["kind"] != "authority.start"
        or binding.get("launch_id") != launch_id
        or binding.get("registration_sha256") != registration_sha256
    ):
        raise ValueError("authority recovery registration is not start bound")
    if start["monotonic_ns"] >= fault_ns or start["route"] != prepared_route:
        raise ValueError("authority predecessor was not established before fault")
    for event in events:
        if event["monotonic_ns"] <= completion_ns and (
            event["route"] != prepared_route
            or event["kind"] in {"route.open.intent", "route.open.applied"}
        ):
            raise ValueError(
                "before-effect recovery exposed or changed the prepared predecessor"
            )
    restored = [e for e in events if e["kind"] == "route.restore.applied"]
    intents = [e for e in events if e["kind"] == "route.restore.intent"]
    if len(restored) != 1 or len(intents) != 1:
        raise ValueError("authority recovery lacks one native restore effect")
    intent, applied = intents[0], restored[0]
    if (
        not restart_ns
        < intent["monotonic_ns"]
        < applied["monotonic_ns"]
        <= completion_ns
    ):
        raise ValueError("authority restore was not effected after restart")
    if (
        applied["sequence"] != intent["sequence"] + 1
        or applied["route"] != prepared_route
        or intent["detail"].get("generation") != prepared_route["generation"]
    ):
        raise ValueError("authority restored a different predecessor")
    later = [
        e
        for e in events
        if applied["sequence"] <= e["sequence"] and e["monotonic_ns"] <= completion_ns
    ]
    if any(e["route"] != prepared_route for e in later):
        raise ValueError("authority predecessor changed after restoration")
    return {
        "final_route": "predecessor",
        "predecessor_preserved": True,
        "rollback_classification": "RESTORED_STRONG",
        "route": prepared_route,
        "authority_chain_sha256": previous,
        "restore_sequence": applied["sequence"],
    }


def verify_native_recovery(prepared: dict[str, Any], recovered: dict[str, Any]) -> None:
    """Verify retained native journal extension, rather than recovery.json labels."""
    before = prepared["native_rows"]
    after = recovered["native_rows"]
    if after[: len(before)] != before or len(after) <= len(before):
        raise ValueError("native recovery journal does not extend the prepared intent")
    if [row["seq"] for row in after] != list(range(1, len(after) + 1)):
        raise ValueError("native recovery journal sequence is broken")
    if any(r["operation"] == "close" and r["kind"] == "receipt" for r in after):
        raise ValueError(
            "before-effect close was unexpectedly completed during rollback"
        )
    for operation in ("rollback",):
        intents = [
            r for r in after if r["operation"] == operation and r["kind"] == "intent"
        ]
        receipts = [
            r for r in after if r["operation"] == operation and r["kind"] == "receipt"
        ]
        if (
            len(intents) != 1
            or len(receipts) != 1
            or receipts[0]["seq"] <= intents[0]["seq"]
        ):
            raise ValueError(
                "native recovery lacks exactly one ordered operation receipt"
            )
        if intents[0]["operation_id"] != receipts[0]["operation_id"]:
            raise ValueError("native recovery operation receipt is not intent bound")
    state = recovered["native_state"]
    old = prepared["native_state"]
    for key in (
        "predecessor_digest",
        "predecessor_generation",
        "predecessor_json",
        "candidate_generation",
    ):
        if state.get(key) != old.get(key):
            raise ValueError(
                "native recovery changed the prepared generation or predecessor"
            )
    if (
        state.get("state") != "ROLLED_BACK"
        or state.get("route_generation") != old["predecessor_generation"]
        or state.get("route_fence") != f"fence-{old['predecessor_generation']}"
    ):
        raise ValueError(
            "native recovery did not reconcile to the prepared predecessor"
        )
