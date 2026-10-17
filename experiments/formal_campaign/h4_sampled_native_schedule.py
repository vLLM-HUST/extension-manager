"""Frozen H4 full traffic schedule and explicit32 native selection; no runtime IDs."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

SCHEMA = "ecpa-h4-sampled-native-schedule/v1"
TOTAL_REQUESTS = 272
WARMUP_REQUESTS = 16
MEASURED_REQUESTS = 256
SELECTED_INDICES = tuple(range(16)) + tuple(16 + 16 * i for i in range(16))
SAMPLE_REQUESTS = 32
CONCURRENCY = 8
TIMEOUT_SECONDS = 120


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def read_schedule(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve() == path,
        "canonical schedule path required",
    )
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= 8 * 1024 * 1024,
            "private bounded schedule required",
        )
        raw = b""
        while part := os.read(descriptor, 65536):
            raw += part
            require(len(raw) <= 8 * 1024 * 1024, "schedule grew beyond bound")
        after = os.fstat(descriptor)
        require(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and len(raw) == after.st_size,
            "schedule changed while reading",
        )
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    validate_schedule(value)
    require(canonical(value) == raw, "schedule must preserve canonical frozen bytes")
    return value, raw


def validate_schedule(value):
    require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "request_count",
            "warmup_count",
            "measured_count",
            "concurrency",
            "timeout_s",
            "selected_all_indices",
            "requests",
        },
        "exact H4 schedule fields required",
    )
    require(
        value["schema"] == SCHEMA
        and type(value["request_count"]) is int
        and value["request_count"] == TOTAL_REQUESTS
        and type(value["warmup_count"]) is int
        and value["warmup_count"] == WARMUP_REQUESTS
        and type(value["measured_count"]) is int
        and value["measured_count"] == MEASURED_REQUESTS
        and type(value["concurrency"]) is int
        and value["concurrency"] == CONCURRENCY
        and type(value["timeout_s"]) is int
        and value["timeout_s"] == TIMEOUT_SECONDS,
        "original H4 traffic/window differs",
    )
    require(
        type(value["selected_all_indices"]) is list
        and all(type(index) is int for index in value["selected_all_indices"])
        and tuple(value["selected_all_indices"]) == SELECTED_INDICES,
        "native selection must be16warmup plus16 uniformly spaced measured requests",
    )
    require(
        type(value["requests"]) is list and len(value["requests"]) == TOTAL_REQUESTS,
        "complete original272 request declarations required",
    )
    ids, external, phases = set(), set(), set()
    for index, row in enumerate(value["requests"]):
        require(
            type(row) is dict
            and set(row)
            == {
                "all_index",
                "request_id",
                "external_request_id",
                "phase_id",
                "body_sha256",
                "selected",
            },
            "exact original H4 request declaration required",
        )
        require(
            type(row["all_index"]) is int
            and row["all_index"] == index
            and type(row["selected"]) is bool
            and row["selected"] == (index in SELECTED_INDICES)
            and type(row["request_id"]) is str
            and bool(row["request_id"])
            and type(row["external_request_id"]) is str
            and bool(row["external_request_id"])
            and type(row["phase_id"]) is str
            and bool(row["phase_id"])
            and type(row["body_sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", row["body_sha256"]),
            "H4 request identity/body differs",
        )
        require(
            row["request_id"] not in ids
            and row["external_request_id"] not in external
            and row["phase_id"] not in phases,
            "H4 schedule repeats identity",
        )
        ids.add(row["request_id"])
        external.add(row["external_request_id"])
        phases.add(row["phase_id"])
    return value


def bind_selected_phases(spec, schedule):
    validate_schedule(schedule)
    selected = [row for row in schedule["requests"] if row["selected"]]
    require(
        len(spec["phases"]) == SAMPLE_REQUESTS
        and [
            (p["phase_id"], p["client_request_id"], p["external_request_id"])
            for p in spec["phases"]
        ]
        == [
            (r["phase_id"], r["request_id"], r["external_request_id"]) for r in selected
        ],
        "native phases must exactly match ordered frozen H4 sample subset",
    )
    return selected
