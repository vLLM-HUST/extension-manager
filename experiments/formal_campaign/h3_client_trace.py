"""Frozen finite-window HTTP client and independent delivery-trace verifier.

One attempt per logical request; no automatic retry. Delivery by each attempt's
frozen deadline is observable. Timeout does not prove nonexecution. Backend
side-effect exactly-once, Host effectiveness and formal admission remain separate.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ZERO = "sha256:" + "0" * 64
SCHEMA = "ecpa-h3-client-window/v1"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def process_identity() -> dict[str, Any]:
    fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": os.getpid(),
        "start_ticks": int(fields[19]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def validate_spec(spec: dict[str, Any]) -> None:
    if spec.get("schema") != "ecpa-h3-client-window-spec/v1":
        raise ValueError("client window spec schema differs")
    if not isinstance(spec.get("start_id"), str) or not spec["start_id"]:
        raise ValueError("client window requires a start ID")
    for key, maximum in (("request_count", 10000), ("concurrency", 128)):
        if type(spec.get(key)) is not int or not 1 <= spec[key] <= maximum:
            raise ValueError("client window count or concurrency is invalid")
    for key in ("interval_s", "timeout_s", "dispatch_slack_s"):
        if type(spec.get(key)) not in (int, float) or not 0 < spec[key] <= 3600:
            raise ValueError("client window timing is invalid")
    if not spec.get("request_url", "").startswith("http://127.0.0.1:"):
        raise ValueError("client window requires an explicit loopback authority")
    if spec.get("retry_policy") != "single-attempt-no-retry":
        raise ValueError("client window retry semantics are not frozen")
    if not isinstance(spec.get("payload"), dict) or not spec["payload"].get("model"):
        raise ValueError("client window requires frozen model payload")
    if not isinstance(spec.get("response_expectation"), dict):
        raise ValueError("client window requires a frozen response oracle")


def run_client(
    spec: dict[str, Any], path: Path, ready_path: Path | None = None
) -> None:
    validate_spec(spec)
    identity = process_identity()
    previous = ZERO
    sequence = 0
    lock = threading.Lock()
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )

    def record(kind: str, detail: dict[str, Any]) -> None:
        nonlocal previous, sequence
        with lock:
            sequence += 1
            event = {
                "schema": SCHEMA,
                "sequence": sequence,
                "previous_sha256": previous,
                "monotonic_ns": time.monotonic_ns(),
                "client": identity,
                "kind": kind,
                "detail": detail,
            }
            raw = canonical(event)
            pending = raw + b"\n"
            while pending:
                count = os.write(descriptor, pending)
                if count <= 0:
                    raise OSError("client trace write failed")
                pending = pending[count:]
            os.fsync(descriptor)
            previous = sha(raw)

    payload = canonical(spec["payload"])
    anchor = time.monotonic_ns()
    record(
        "client.start",
        {
            "start_id": spec["start_id"],
            "spec_sha256": sha(canonical(spec)),
            "schedule_anchor_ns": anchor,
        },
    )
    if ready_path:
        ready_path.write_text(json.dumps({"client": identity, "anchor_ns": anchor}))

    def attempt(index: int, scheduled_ns: int) -> None:
        request_id = f"{spec['start_id']}/request-{index:05d}"
        sent_ns = time.monotonic_ns()
        deadline_ns = sent_ns + int(spec["timeout_s"] * 1e9)
        record(
            "request.start",
            {
                "request_id": request_id,
                "scheduled_ns": scheduled_ns,
                "sent_ns": sent_ns,
                "deadline_ns": deadline_ns,
                "body_base64": base64.b64encode(payload).decode(),
                "body_sha256": sha(payload),
            },
        )
        request = urllib.request.Request(
            spec["request_url"],
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-ECPA-Request-ID": request_id,
            },
        )
        detail: dict[str, Any] = {
            "request_id": request_id,
            "status": 0,
            "admission_id": None,
            "body_base64": "",
            "body_sha256": sha(b""),
        }
        try:
            try:
                response = urllib.request.urlopen(request, timeout=spec["timeout_s"])
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise ValueError("response exceeds frozen client bound")
                detail.update(
                    status=response.status,
                    admission_id=response.headers.get("X-ECPA-Admission-ID"),
                    body_base64=base64.b64encode(body).decode(),
                    body_sha256=sha(body),
                )
        except (OSError, ValueError) as exc:
            detail["error"] = type(exc).__name__
        detail["finished_ns"] = time.monotonic_ns()
        record("request.finish", detail)

    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=spec["concurrency"]
        ) as pool:
            futures = []
            for index in range(spec["request_count"]):
                scheduled = anchor + int(index * spec["interval_s"] * 1e9)
                delay = (scheduled - time.monotonic_ns()) / 1e9
                if delay > 0:
                    time.sleep(delay)
                futures.append(pool.submit(attempt, index, scheduled))
            for future in futures:
                future.result()
        record("client.stop", {"request_count": spec["request_count"]})
    finally:
        os.close(descriptor)


def read_client_trace(path: Path) -> list[dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024 or not raw.endswith(b"\n"):
        raise ValueError("client trace is oversized or truncated")
    previous = ZERO
    events = []
    last_ns = 0
    owner = None
    for index, line in enumerate(raw.splitlines(), 1):
        event = json.loads(line)
        if (
            canonical(event) != line
            or event.get("schema") != SCHEMA
            or event.get("sequence") != index
            or event.get("previous_sha256") != previous
        ):
            raise ValueError("client trace chain is broken or noncanonical")
        if owner is None:
            owner = event.get("client")
        if event.get("client") != owner or event.get("monotonic_ns", 0) <= last_ns:
            raise ValueError("client trace identity/time changed")
        last_ns = event["monotonic_ns"]
        previous = sha(line)
        events.append(event)
    return events


def verify_window(
    spec: dict[str, Any],
    client_path: Path,
    authority_path: Path,
    *,
    expected_client: dict[str, Any],
    fault_ns: int,
    recovery_ns: int,
) -> dict[str, Any]:
    validate_spec(spec)
    from experiments.exposure_gate.loopback_traffic import read_traffic_journal

    client = read_client_trace(client_path)
    unknown = {
        "coverage": "incomplete",
        "lost_requests": None,
        "duplicated_requests": None,
        "backend_execution_duplicates": None,
    }
    if not client or client[0]["kind"] != "client.start":
        return unknown
    begin = client[0]
    if (
        begin["client"] != expected_client
        or begin["detail"].get("start_id") != spec["start_id"]
        or begin["detail"].get("spec_sha256") != sha(canonical(spec))
    ):
        raise ValueError("client trace is not frozen/start/process bound")
    if (
        sum(e["kind"] == "client.start" for e in client) != 1
        or sum(e["kind"] == "client.stop" for e in client) > 1
    ):
        raise ValueError("client trace repeats lifecycle markers")
    if client[-1]["kind"] != "client.stop":
        return unknown
    sends = [e for e in client if e["kind"] == "request.start"]
    finishes = [e for e in client if e["kind"] == "request.finish"]
    expected_ids = {
        f"{spec['start_id']}/request-{i:05d}" for i in range(spec["request_count"])
    }
    if (
        len(sends) != len(expected_ids)
        or len(finishes) != len(expected_ids)
        or {e["detail"].get("request_id") for e in sends} != expected_ids
        or {e["detail"].get("request_id") for e in finishes} != expected_ids
    ):
        return unknown
    anchor = begin["detail"]["schedule_anchor_ns"]
    sent = {e["detail"]["request_id"]: e for e in sends}
    finished = {e["detail"]["request_id"]: e for e in finishes}
    for index in range(spec["request_count"]):
        detail = sent[f"{spec['start_id']}/request-{index:05d}"]["detail"]
        scheduled = anchor + int(index * spec["interval_s"] * 1e9)
        if detail["scheduled_ns"] != scheduled or not scheduled <= detail[
            "sent_ns"
        ] <= scheduled + int(spec["dispatch_slack_s"] * 1e9):
            return unknown
        if detail["deadline_ns"] != detail["sent_ns"] + int(spec["timeout_s"] * 1e9):
            raise ValueError("client deadline differs from frozen timeout")
        body = base64.b64decode(detail["body_base64"], validate=True)
        if body != canonical(spec["payload"]) or detail["body_sha256"] != sha(body):
            raise ValueError("client request differs from frozen payload")
    times = [e["detail"]["sent_ns"] for e in sends]
    if not min(times) < fault_ns < recovery_ns < max(times) or not any(
        fault_ns <= t <= recovery_ns for t in times
    ):
        return unknown
    authority = read_traffic_journal(authority_path)
    expected_authority = spec.get("authority_process_identity")
    if not isinstance(expected_authority, dict):
        return unknown
    if expected_authority.get("boot_id") != expected_client.get("boot_id") or any(
        any(
            e.get("proxy_" + key) != expected_authority.get(key)
            for key in ("pid", "start_ticks", "boot_id")
        )
        for e in authority
    ):
        raise ValueError("authority/client process epoch differs")
    starts = authority[0]["detail"].get("authorization") or {}
    if starts.get("launch_id") != spec["start_id"] or starts.get(
        "registration_sha256"
    ) != spec.get("authority_registration_sha256"):
        raise ValueError("authority journal belongs to another launch")
    backend_registration = spec.get("backend_registration")
    if backend_registration is not None and authority[0]["detail"].get(
        "backend_registration_sha256"
    ) != sha(canonical(backend_registration)):
        raise ValueError("backend registration differs from frozen descriptor")
    backend_generation_complete = isinstance(backend_registration, dict) and bool(
        backend_registration
    )
    admitted: dict[str, list[dict[str, Any]]] = {}
    completed: dict[str, list[dict[str, Any]]] = {}
    admission_ids = set()
    for event in authority:
        detail = event["detail"]
        rid = detail.get("request_id")
        if rid not in expected_ids:
            continue
        if event["kind"] in {"request.admit", "request.reject"}:
            aid = detail.get("admission_id")
            if not isinstance(aid, str) or not aid or aid in admission_ids:
                raise ValueError("authority admission identity is missing or replayed")
            admission_ids.add(aid)
            if (
                detail.get("request_sha256") != sha(canonical(spec["payload"]))
                or detail.get("method") != "POST"
            ):
                raise ValueError("authority admission differs from frozen request")
            admitted.setdefault(rid, []).append(event)
        elif event["kind"] == "request.complete":
            completed.setdefault(rid, []).append(event)
    lost = 0
    response_ids = []
    for rid in expected_ids:
        start = sent[rid]["detail"]
        end = finished[rid]["detail"]
        if not start["sent_ns"] <= end["finished_ns"] <= finished[rid]["monotonic_ns"]:
            raise ValueError("client request completion precedes dispatch")
        body = base64.b64decode(end["body_base64"], validate=True)
        if sha(body) != end["body_sha256"]:
            raise ValueError("client response bytes changed")
        if end["status"] != 200 or end["finished_ns"] > start["deadline_ns"]:
            lost += 1
            continue
        matching = [
            e
            for e in completed.get(rid, [])
            if e["detail"].get("admission_id") == end.get("admission_id")
        ]
        admissions = [
            e
            for e in admitted.get(rid, [])
            if e["detail"].get("admission_id") == end.get("admission_id")
            and e["kind"] == "request.admit"
        ]
        if len(matching) != 1 or len(admissions) != 1:
            raise ValueError(
                "delivered response lacks a unique authority admission/completion"
            )
        observed = matching[0]
        if (
            not start["sent_ns"]
            <= admissions[0]["monotonic_ns"]
            < observed["monotonic_ns"]
            <= end["finished_ns"]
            or observed["detail"].get("status") != end["status"]
            or observed["detail"].get("body_sha256") != sha(body)
            or base64.b64decode(observed["detail"]["body_base64"], validate=True)
            != body
        ):
            raise ValueError(
                "delivered response differs from authority upstream bytes/order"
            )
        if backend_generation_complete:
            upstream = observed["detail"]
            binding = backend_registration.get(str(upstream["backend_port"]))
            if (
                not binding
                or upstream.get("backend_host") != "127.0.0.1"
                or not isinstance(upstream.get("backend_identity"), dict)
                or {
                    k: v
                    for k, v in upstream["backend_identity"].items()
                    if k != "listener_inode"
                }
                != binding
                or not str(
                    upstream["backend_identity"].get("listener_inode", "")
                ).isdigit()
                or binding.get("generation") != observed["route"]["generation"]
                or binding.get("model") != spec["payload"]["model"]
                or not binding.get("launch_id")
            ):
                raise ValueError(
                    "response is not bound to frozen live backend generation"
                )
        parsed = json.loads(body)
        if (
            parsed.get("model") != spec["payload"]["model"]
            or not isinstance(parsed.get("id"), str)
            or not parsed["id"]
        ):
            return unknown
        choices = parsed.get("choices")
        if (
            not isinstance(choices, list)
            or len(choices) != 1
            or not isinstance(choices[0], dict)
            or choices[0].get("index") != 0
            or choices[0].get("finish_reason") != "stop"
            or choices[0].get("text") != spec["response_expectation"].get("text_equals")
        ):
            raise ValueError("delivered response fails the frozen functional oracle")
        response_ids.append(parsed["id"])
    duplicate_admissions = sum(max(0, len(rows) - 1) for rows in admitted.values())
    return {
        "coverage": "complete-finite-delivery-window",
        "lost_requests": lost,
        "duplicated_requests": None,
        "reused_successful_response_ids": len(response_ids) - len(set(response_ids)),
        "duplicate_admissions": duplicate_admissions,
        "backend_execution_duplicates": None,
        "retry_policy": spec["retry_policy"],
        "request_count": spec["request_count"],
        "formal_result": False,
        "backend_generation_coverage": "frozen-live-process-and-response-bound"
        if backend_generation_complete
        else "missing-independent-backend-registration",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--ready", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--authority-trace", type=Path)
    parser.add_argument("--client-identity", type=Path)
    parser.add_argument("--fault-ns", type=int)
    parser.add_argument("--recovery-ns", type=int)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text())
    if args.verify:
        if (
            args.authority_trace is None
            or args.client_identity is None
            or args.fault_ns is None
            or args.recovery_ns is None
        ):
            parser.error(
                "verification requires authority trace, client identity "
                "and fault/recovery markers"
            )
        identity_doc = json.loads(args.client_identity.read_text())
        owner = identity_doc.get("client", identity_doc)
        print(
            json.dumps(
                verify_window(
                    spec,
                    args.trace,
                    args.authority_trace,
                    expected_client=owner,
                    fault_ns=args.fault_ns,
                    recovery_ns=args.recovery_ns,
                ),
                sort_keys=True,
            )
        )
    else:
        run_client(spec, args.trace, args.ready)


if __name__ == "__main__":
    main()
