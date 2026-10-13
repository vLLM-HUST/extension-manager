"""Validate a live durable native intent before an H3 prepare crash.

This adapter is ECPA-only. Baselines must supply their own native transaction
protocol; importing ECPA recovery into a baseline is forbidden.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any


def rows_digest(rows: list[dict[str, Any]]) -> str:
    return (
        "sha256:"
        + hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    )


def identity(pid: int) -> dict[str, Any]:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    if fields[0] == "Z":
        raise ValueError("prepare target is a zombie")
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "session": int(fields[3]),
    }


def validate_native_prepare(
    config: dict[str, Any],
    barrier: dict[str, Any],
    target: dict[str, Any],
    launcher_pid: int,
    launch_id: str,
    launched_ns: int,
    state_before: dict[str, Any],
) -> dict[str, Any]:
    if config["protocol"] != "ecpa-native-close-prepare-barrier/v1":
        raise ValueError("unsupported native prepare protocol")
    if (
        barrier.get("schema") != config["protocol"]
        or barrier.get("phase") != "durable-close-intent-before-effect"
    ):
        raise ValueError("health readiness is not a durable prepare barrier")
    live = identity(target["pid"])
    if live != barrier.get("manager") or live["session"] != launcher_pid:
        raise ValueError("prepare barrier does not belong to the live launch session")
    if any(live[k] != target[k] for k in ("pid", "start_ticks", "boot_id")):
        raise ValueError("prepare target identity changed")
    observed = barrier.get("observed_monotonic_ns", 0)
    if (
        not launched_ns <= observed <= time.monotonic_ns()
        or barrier.get("launch_id") != launch_id
    ):
        raise ValueError("stale or replayed prepare barrier")
    journal = Path(config["journal_path"]).resolve()
    if Path(barrier.get("journal_path", "")).resolve() != journal:
        raise ValueError("prepare journal differs from frozen path")
    with sqlite3.connect(journal.as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        state = dict(
            db.execute("SELECT * FROM gate_state WHERE singleton=1").fetchone()
        )
        rows = [
            dict(row)
            for row in db.execute("SELECT * FROM gate_transition ORDER BY seq")
        ]
    for row in [state, *rows]:
        for key, value in row.items():
            if isinstance(value, bytes):
                row[key] = value.decode()
    intents = [
        row for row in rows if row["operation"] == "close" and row["kind"] == "intent"
    ]
    receipts = [
        row for row in rows if row["operation"] == "close" and row["kind"] == "receipt"
    ]
    if len(intents) != 1 or receipts:
        raise ValueError(
            "native close intent is absent, duplicated, or already effected"
        )
    intent = intents[0]
    if intent["seq"] != barrier.get("intent_sequence") or intent[
        "operation_id"
    ] != barrier.get("intent_operation_id"):
        raise ValueError("native intent identity differs")
    if rows_digest(rows) != barrier.get("native_rows_sha256"):
        raise ValueError("native intent journal changed")
    if state["predecessor_digest"] != state_before["predecessor_digest"]:
        raise ValueError("native predecessor differs from authority probe")
    route = state_before.get("route", {})
    if (
        route.get("generation") != state["predecessor_generation"]
        or route.get("fence") != f"fence-{state['predecessor_generation']}"
    ):
        raise ValueError("authority no longer serves the prepared predecessor")
    return {
        "barrier": barrier,
        "native_state": state,
        "native_rows": rows,
        "target_session": os.getsid(target["pid"]),
        "verified_monotonic_ns": time.monotonic_ns(),
    }


def wait_native_prepare(config: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    deadline = time.monotonic() + config["timeout_s"]
    path = Path(config["barrier_path"])
    while time.monotonic() < deadline:
        if path.exists():
            return validate_native_prepare(
                config, json.loads(path.read_text()), **kwargs
            )
        time.sleep(0.05)
    raise TimeoutError("durable prepare barrier did not appear; no fault injected")
