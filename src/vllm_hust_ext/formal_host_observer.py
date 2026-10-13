"""Independent production observer for the formal-real vLLM-HUST path.

The runner supplies only an invocation identity.  This process derives
activation, invocation and coverage from the deployment-owned host journal and
the immutable post-launch process snapshot.  It never consumes a SUT verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .ecpa_model import canonical_bytes
from .formal_process_snapshot import validate_transition
from .host_event_sink import read_events

CAPTURE_SCHEMA = "ecpa-formal-observer-capture/v1"
MAX_CAPTURE_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 1024 * 1024
CONTRACT_TOKENS = {
    "entry-points-unmanaged": ("--enable-entrypoints",),
    "explicit-manual-hooks": ("--manual-hooks",),
    "manager-controlled-activation": (
        "formal-run",
        "--plan",
        "--launch-id",
        "--controller-instance",
        "--host-event-dir",
        "--",
    ),
}


class FormalObserverError(ValueError):
    """The independent host observation cannot be established."""


def _positive_integer(value: str, name: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise FormalObserverError(f"{name} is invalid") from exc
    if parsed <= 0:
        raise FormalObserverError(f"{name} is invalid")
    return parsed


def _linux_identity(pid: int) -> dict[str, Any]:
    root = Path("/proc") / str(pid)
    try:
        before = (root / "stat").read_bytes()
        close = before.rfind(b")")
        fields = before[close + 2 :].split()
        start_ticks = int(fields[19])
        argv_raw = (root / "cmdline").read_bytes()
        after = (root / "stat").read_bytes()
        after_close = after.rfind(b")")
        after_ticks = int(after[after_close + 2 :].split()[19])
    except (FileNotFoundError, IndexError, OSError, ValueError) as exc:
        raise FormalObserverError("observed process identity is unavailable") from exc
    argv = [
        item.decode(errors="surrogateescape") for item in argv_raw.split(b"\0") if item
    ]
    if close < 0 or start_ticks <= 0 or start_ticks != after_ticks or not argv:
        raise FormalObserverError("observed process identity is unstable")
    return {"pid": pid, "start_ticks": start_ticks, "argv": argv}


def _read_canonical_object(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink():
        raise FormalObserverError("process snapshot path is not canonical")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        raw = resolved.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise FormalObserverError("process snapshot is unavailable") from exc
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or not isinstance(value, dict)
        or raw != canonical_bytes(value) + b"\n"
    ):
        raise FormalObserverError("process snapshot is not canonical")
    return value


def _read_capture() -> dict[str, Any]:
    raw = sys.stdin.buffer.readline(MAX_CAPTURE_BYTES + 1)
    if not raw.endswith(b"\n") or len(raw) > MAX_CAPTURE_BYTES:
        raise FormalObserverError("observer capture request is missing or oversized")
    try:
        value = json.loads(raw[:-1])
    except (UnicodeDecodeError, ValueError) as exc:
        raise FormalObserverError("observer capture request is invalid") from exc
    required = {
        "schema",
        "phase",
        "scenario",
        "plan_id",
        "launch_id",
        "controller_instance",
        "invocation_id",
        "sequence",
        "challenge",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != CAPTURE_SCHEMA
        or value.get("phase") != "observer-captured"
        or value.get("scenario") != "partial-worker-coverage"
        or raw[:-1] != canonical_bytes(value)
        or value.get("sequence") != 4
        or any(
            not isinstance(value.get(name), str) or not value[name]
            for name in (
                "plan_id",
                "launch_id",
                "controller_instance",
                "invocation_id",
                "challenge",
            )
        )
    ):
        raise FormalObserverError("observer capture request is not canonical")
    return value


def _environment(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise FormalObserverError(f"{name} is required")
    return value


def _write_all(descriptor: int, raw: bytes) -> None:
    while raw:
        written = os.write(descriptor, raw)
        if written <= 0:
            raise FormalObserverError("observer result channel closed")
        raw = raw[written:]


def observe(args: argparse.Namespace, capture: dict[str, Any]) -> dict[str, Any]:
    execution = {
        "plan_id": _environment("ECPA_PLAN_ID"),
        "launch_id": _environment("ECPA_LAUNCH_ID"),
        "controller_instance": _environment("ECPA_CONTROLLER_INSTANCE"),
    }
    if any(capture[name] != value for name, value in execution.items()):
        raise FormalObserverError("capture request differs from execution identity")
    if _environment("ECPA_OBSERVER_SOURCE_ROLE") != "host-observer":
        raise FormalObserverError("observer authority is not formal host-observer")

    snapshot = _read_canonical_object(Path(_environment("ECPA_PROCESS_SNAPSHOT_PATH")))
    processes = validate_transition(snapshot, snapshot.get("logical_slots"), execution)
    required = {
        (row["host"], row["role"], row["ordinal"], row["process_epoch"]): row
        for row in processes
    }

    sut_identity = _linux_identity(
        _positive_integer(_environment("ECPA_SUT_PID"), "SUT pid")
    )
    contract = _environment("ECPA_EXPECTED_CONTRACT")
    required_tokens = CONTRACT_TOKENS.get(contract)
    if required_tokens is None or any(
        token not in sut_identity["argv"] for token in required_tokens
    ):
        raise FormalObserverError("SUT argv does not establish the activation path")

    records = read_events(
        Path(args.event_dir),
        (args.device, args.inode),
        max_total_bytes=MAX_JOURNAL_BYTES,
    )
    entry_point = {
        "group": args.entry_point_group,
        "name": args.entry_point_name,
        "value": args.entry_point_value,
    }

    def bound(item: Any) -> bool:
        observed_event = item.event
        return bool(
            observed_event["plan_id"] == execution["plan_id"]
            and observed_event["launch_id"] == execution["launch_id"]
            and observed_event["binding_status"] == "bound"
            and observed_event["entry_point"] == entry_point
        )

    by_process: dict[tuple[str, str, int, int], dict[str, Any]] = {}
    effective = False
    for item in records:
        event = item.event
        if not bound(item):
            continue
        if (
            event["event"] == "effective"
            and event["observation_kind"] == "runtime_effective"
        ):
            effective = True
        if (
            event["event"] != "invoked"
            or event["observation_kind"] != "loader_lifecycle"
        ):
            continue
        process = event["process"]
        key = (
            process["host"],
            process["role"],
            process["ordinal"],
            process["process_epoch"],
        )
        frozen = required.get(key)
        if frozen is None or process.get("assignment_source") != "host":
            continue
        live = _linux_identity(process["pid"])
        if (
            live["start_ticks"] != frozen["start_ticks"]
            or process["start_identity"] != frozen["start_identity"]
            or process["pid"] != frozen["pid"]
        ):
            raise FormalObserverError("effect process differs from frozen identity")
        observed = {
            key: process[key]
            for key in (
                "host",
                "role",
                "ordinal",
                "process_epoch",
                "pid",
                "start_identity",
            )
        }
        observed.update(
            start_ticks=live["start_ticks"],
            argv=live["argv"],
            assignment_source="host",
        )
        previous = by_process.get(key)
        if previous is not None and previous != observed:
            raise FormalObserverError("effect process identity is ambiguous")
        by_process[key] = observed

    effect_processes = [by_process[key] for key in sorted(by_process)]
    coverage = len(effect_processes) / len(required)
    common = {
        "source_role": "host-observer",
        "clock": "monotonic",
        "monotonic_ns": time.monotonic_ns(),
        **execution,
        "invocation_id": capture["invocation_id"],
        "sequence": capture["sequence"],
        "challenge": capture["challenge"],
        "sut_process_identity": sut_identity,
    }

    def make_event(name: str, value: Any, **extra: Any) -> dict[str, Any]:
        return {"event": name, "value": value, **extra, **common}

    workers = [row for row in processes if row["role"] == "worker"]
    worker_evidence = [row for row in effect_processes if row["role"] == "worker"]
    return {
        "events": [
            make_event("activation-path", contract),
            make_event("effective-claim", effective),
            make_event(
                "plugin-invoked",
                bool(effect_processes),
                effect_process_identities=effect_processes,
            ),
            make_event("coverage", coverage),
            make_event("conflict-decision", "not-applicable"),
            make_event("rollback-class", None),
            make_event("worker_inventory", workers),
            make_event("worker_evidence", worker_evidence),
        ]
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecpa-formal-observer")
    parser.add_argument("--event-dir", required=True)
    parser.add_argument("--device", required=True, type=int)
    parser.add_argument("--inode", required=True, type=int)
    parser.add_argument("--entry-point-group", required=True)
    parser.add_argument("--entry-point-name", required=True)
    parser.add_argument("--entry-point-value", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        capture = _read_capture()
        result = observe(args, capture)
        descriptor = _positive_integer(_environment("ECPA_OBSERVER_FD"), "observer fd")
        _write_all(descriptor, canonical_bytes(result))
        return 0
    except (FormalObserverError, OSError, ValueError) as exc:
        print(f"ecpa-formal-observer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
