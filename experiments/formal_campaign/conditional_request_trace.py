"""Durable original request.start/end/client.stop prefix; no request replay."""

from __future__ import annotations

import os
import threading
import time

if __package__:
    from .conditional_common import canonical, require, sha
else:
    from conditional_common import canonical, require, sha


class RequestTrace:
    def __init__(self, path, schedule, body, *, start_id, plan_id, launch_id):
        self.fd = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        self.lock = threading.RLock()
        self.sequence = 0
        self.previous = "0" * 64
        self.declared = {r["request_id"]: r for r in schedule}
        require(len(self.declared) == 272, "original272 required")
        self.body_sha256 = sha(body)
        self.started = set()
        self.ended = set()
        self.closed = False
        self.binding = dict(start_id=start_id, plan_id=plan_id, launch_id=launch_id)
        self.append("client.start", dict(request_count=272, selected_count=32))

    def append(self, kind, detail):
        with self.lock:
            require(not self.closed, "original request trace already closed")
            record = dict(
                schema="ecpa-h4-conditional-original-request-trace/v1",
                **self.binding,
                kind=kind,
                detail=detail,
                sequence=self.sequence,
                previous_sha256=self.previous,
                observed_raw_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW),
            )
            record["event_sha256"] = sha(canonical(record))
            raw = canonical(record) + b"\n"
            remaining = memoryview(raw)
            while remaining:
                count = os.write(self.fd, remaining)
                require(count > 0, "original trace short write")
                remaining = remaining[count:]
            os.fsync(self.fd)
            self.sequence += 1
            self.previous = record["event_sha256"]

    def start(self, rid, dispatch_ns, deadline_ns):
        with self.lock:
            require(
                rid in self.declared and rid not in self.started,
                "unknown/duplicate original request; no retries",
            )
            require(
                deadline_ns == dispatch_ns + 120_000_000_000,
                "original absolute120 deadline",
            )
            self.started.add(rid)
            self.append(
                "request.start",
                dict(
                    request_id=rid,
                    all_index=self.declared[rid]["all_index"],
                    dispatch_ns=dispatch_ns,
                    original_deadline_ns=deadline_ns,
                    body_sha256=self.body_sha256,
                ),
            )

    def end(self, row):
        with self.lock:
            rid = row["request_id"]
            require(
                rid in self.started and rid not in self.ended,
                "unknown/duplicate request end",
            )
            self.ended.add(rid)
            self.append("request.end", row)

    def close(self, *, complete):
        with self.lock:
            try:
                if complete:
                    require(
                        self.started == self.ended == set(self.declared),
                        "client.stop cannot fill absent requests",
                    )
                    self.append("client.stop", dict(started=272, completed=272))
            finally:
                if not self.closed:
                    os.close(self.fd)
                    self.closed = True


def replay_trace(raw, schedule, body, *, binding, allow_incomplete, served_model):
    import json

    from experiments.formal_campaign.analyze import (
        h4_decode_body,
        h4_request_identity_observation,
        h4_response_summary,
    )

    require(
        raw.endswith(b"\n") and len(raw) <= 128 * 1024 * 1024,
        "canonical original trace prefix required",
    )
    declared = {r["request_id"]: r for r in schedule}
    started = {}
    ended = {}
    previous = "0" * 64
    stop = None
    previous_clock = 0
    rows = raw.splitlines()
    require(rows, "original client trace absent")
    for sequence, line in enumerate(rows):
        row = json.loads(line)
        require(
            set(row)
            == {
                "schema",
                "start_id",
                "plan_id",
                "launch_id",
                "kind",
                "detail",
                "sequence",
                "previous_sha256",
                "observed_raw_ns",
                "event_sha256",
            }
            and row["schema"] == "ecpa-h4-conditional-original-request-trace/v1"
            and type(row["sequence"]) is int
            and type(row["observed_raw_ns"]) is int
            and row["observed_raw_ns"] > previous_clock,
            "original trace domain/fields/RAW sequence differ",
        )
        previous_clock = row["observed_raw_ns"]
        event_hash = row.pop("event_sha256")
        require(
            canonical(dict(row, event_sha256=event_hash)) == line
            and row["sequence"] == sequence
            and row["previous_sha256"] == previous
            and sha(canonical(row)) == event_hash
            and all(row[k] == v for k, v in binding.items()),
            "original trace chain/start/Plan/launch changed",
        )
        previous = event_hash
        kind = row["kind"]
        detail = row["detail"]
        require(stop is None, "events after original client.stop")
        if sequence == 0:
            require(
                kind == "client.start"
                and detail == dict(request_count=272, selected_count=32),
                "original client header differs",
            )
            continue
        if kind == "request.start":
            require(
                set(detail)
                == {
                    "request_id",
                    "all_index",
                    "dispatch_ns",
                    "original_deadline_ns",
                    "body_sha256",
                },
                "original request start fields differ",
            )
            rid = detail["request_id"]
            require(
                rid in declared
                and rid not in started
                and detail["all_index"] == declared[rid]["all_index"],
                "unknown/duplicate original RID",
            )
            require(
                type(detail["dispatch_ns"]) is int
                and detail["dispatch_ns"] > 0
                and type(detail["original_deadline_ns"]) is int
                and type(detail["all_index"]) is int
                and detail["body_sha256"] == sha(body)
                and detail["original_deadline_ns"]
                == detail["dispatch_ns"] + 120_000_000_000
                and detail["dispatch_ns"] <= row["observed_raw_ns"],
                "original request/body/deadline changed",
            )
            require(
                len(set(started) - set(ended)) < 8, "original c8 concurrency exceeded"
            )
            require(
                declared[rid]["kind"] == "warmup"
                or len([r for r in ended if declared[r]["kind"] == "warmup"]) == 16,
                "original measured phase precedes completed warmup16",
            )
            started[rid] = dict(detail, start_event_raw_ns=row["observed_raw_ns"])
        elif kind == "request.end":
            require(
                set(detail)
                == {
                    "request_id",
                    "kind",
                    "request_headers",
                    "request_identity",
                    "dispatch_ns",
                    "original_deadline_ns",
                    "complete_ns",
                    "error",
                    "http_request",
                    "http_response",
                    "watchdog_fired",
                    "status_code",
                    "response_nonempty",
                    "output_tokens",
                    "response_model",
                },
                "original request end fields differ",
            )
            rid = detail["request_id"]
            require(
                rid in started and rid not in ended,
                "unstarted/duplicate original outcome",
            )
            start = started[rid]
            require(
                detail["kind"] == declared[rid]["kind"]
                and type(detail["watchdog_fired"]) is bool
                and (detail["error"] is None or isinstance(detail["error"], str))
                and type(detail["complete_ns"]) is int
                and detail["dispatch_ns"] == start["dispatch_ns"]
                and detail["original_deadline_ns"] == start["original_deadline_ns"]
                and start["start_event_raw_ns"]
                <= detail["complete_ns"]
                <= row["observed_raw_ns"]
                and h4_decode_body(detail["http_request"]) == body,
                "original HTTP bytes/clocks changed",
            )
            summary = h4_response_summary(detail["http_response"])
            require(
                all(detail[k] == v for k, v in summary.items())
                and detail["request_identity"]
                == h4_request_identity_observation(
                    rid, detail["request_headers"], detail["http_response"]
                ),
                "recorded HTTP summary differs from raw body",
            )
            ended[rid] = dict(declared[rid], **detail)
        elif kind == "client.stop":
            require(
                set(started) == set(ended) == set(declared)
                and detail == dict(started=272, completed=272),
                "synthetic/incomplete original stop",
            )
            stop = row
        else:
            raise ValueError("unknown original trace event")
    require(
        allow_incomplete or stop is not None, "original finite client window incomplete"
    )
    results = [ended[r["request_id"]] for r in schedule if r["request_id"] in ended]
    failures = [
        r["request_id"]
        for r in results
        if r["error"] is not None
        or r["watchdog_fired"]
        or r["complete_ns"] > r["original_deadline_ns"]
        or r["status_code"] != 200
        or r["response_model"] != served_model
        or not r["response_nonempty"]
        or not 0 < r["output_tokens"] <= 64
        or r["request_identity"]["server_completion_matches_sent_request_id"]
        is not True
    ]
    return dict(
        rows=results,
        started=started,
        ended=ended,
        stop=stop,
        complete=stop is not None and not failures,
        actual_failures=failures,
        original_start_count=len(started),
    )
