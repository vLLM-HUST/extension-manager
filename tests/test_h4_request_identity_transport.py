"""HTTP transport evidence only; no native/semantic or formal-result claim."""

import copy
import hashlib
import importlib.util
import json
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def modules(monkeypatch):
    directory = ROOT / "experiments/formal_campaign"
    analyzer = load_script("h4_request_identity_analyzer", directory / "analyze.py")
    monkeypatch.setitem(sys.modules, "analyze", analyzer)
    runner = load_script("h4_request_identity_runner", directory / "run_h4.py")
    return analyzer, runner


def original_workload():
    # Exact original dimensions, not an H3/native-compression workload.
    return dict(
        served_model="h4-http-fixture",
        prompt="fixture short prompt",
        max_tokens=64,
        temperature=0.0,
        seed=12012,
        warmup_requests=16,
        measured_requests=256,
        concurrency=8,
        request_timeout_seconds=120,
    )


def completion_body(request_id, *, include_id=True):
    body = dict(
        model="h4-http-fixture",
        choices=[dict(text="CPU fixture response", index=0)],
        usage=dict(completion_tokens=64),
    )
    if include_id:
        body["id"] = f"cmpl-{request_id}"
    return json.dumps(body, sort_keys=True).encode()


@contextmanager
def actual_http_stub(*, include_returned_ids):
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            supplied = self.headers.get_all("X-Request-Id", [])
            observed.append(dict(headers=list(self.headers.items()), body=raw))
            request_id = supplied[0] if len(supplied) == 1 else "missing"
            response = completion_body(request_id, include_id=include_returned_ids)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if include_returned_ids:
                self.send_header("X-Request-Id", request_id)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/completions", observed
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def verified_raw(analyzer, row, workload):
    raw = dict(
        launch_definition=dict(served_model=workload["served_model"]),
        requests=[row],
    )
    analyzer._verify_h4_requests(raw, workload)
    return raw


def raw_row(analyzer, *, returned_header="measured-0000", include_id=True):
    workload = original_workload()
    request_id = "measured-0000"
    headers = [] if returned_header is None else [["X-Request-Id", returned_header]]
    response = dict(
        status_code=200,
        headers=headers,
        **analyzer.h4_body_binding(completion_body(request_id, include_id=include_id)),
    )
    request_headers = [["X-request-id", request_id]]
    row = dict(
        request_id=request_id,
        request_headers=request_headers,
        request_identity=analyzer.h4_request_identity_observation(
            request_id, request_headers, response
        ),
        http_request=analyzer.h4_body_binding(
            analyzer.h4_request_payload(workload, workload["served_model"])
        ),
        http_response=response,
        **analyzer.h4_response_summary(response),
    )
    return row, workload


@pytest.mark.parametrize("include_returned_ids", [True, False])
def test_real_urllib_request_and_server_recorded_header(
    modules, monkeypatch, include_returned_ids
):
    analyzer, runner = modules
    # The real HTTP peer is this test's local stub; never consult an HTTP proxy.
    opener = runner.urllib.request.build_opener(runner.urllib.request.ProxyHandler({}))
    monkeypatch.setattr(runner.urllib.request, "urlopen", opener.open)
    workload = original_workload()
    payload = analyzer.h4_request_payload(workload, workload["served_model"])
    request_id = "measured-0007"
    with actual_http_stub(include_returned_ids=include_returned_ids) as (url, seen):
        row = runner.request_once(url, payload, 120, request_id, "measured")
    assert len(seen) == 1
    assert seen[0]["body"] == payload
    assert [v for k, v in seen[0]["headers"] if k.lower() == "x-request-id"] == [
        request_id
    ]
    assert [v for k, v in row["request_headers"] if k.lower() == "x-request-id"] == [
        request_id
    ]
    assert analyzer.h4_decode_body(row["http_request"]) == payload
    body = analyzer.h4_decode_body(row["http_response"])
    assert row["http_response"]["body_sha256"] == (
        "sha256:" + hashlib.sha256(body).hexdigest()
    )
    assert json.loads(body).get("id") == (
        f"cmpl-{request_id}" if include_returned_ids else None
    )
    identity = row["request_identity"]
    assert identity["server_header_request_id"] == (
        request_id if include_returned_ids else None
    )
    assert identity["server_completion_id"] == (
        f"cmpl-{request_id}" if include_returned_ids else None
    )
    assert identity["server_header_matches_sent_request_id"] is (
        True if include_returned_ids else None
    )
    assert identity["server_completion_matches_sent_request_id"] is (
        True if include_returned_ids else None
    )
    verified_raw(analyzer, row, workload)


@pytest.mark.parametrize("field", ["header", "body", "both-disagree"])
def test_actual_returned_identity_conflict_is_rejected(modules, field):
    analyzer, _ = modules
    row, workload = raw_row(analyzer)
    if field in {"header", "both-disagree"}:
        row["http_response"]["headers"] = [["X-Request-Id", "other-request"]]
    if field in {"body", "both-disagree"}:
        row["http_response"].update(
            analyzer.h4_body_binding(completion_body("yet-another-request"))
        )
    # Even truthful metadata cannot turn a mismatched actual response into a join.
    row["request_identity"] = analyzer.h4_request_identity_observation(
        row["request_id"], row["request_headers"], row["http_response"]
    )
    with pytest.raises(ValueError, match="different request identity"):
        verified_raw(analyzer, row, workload)


@pytest.mark.parametrize(
    "mutation", ["metadata", "boolean-type", "body-sha", "body-bytes"]
)
def test_independent_intake_rejects_metadata_or_original_body_tampering(
    modules, mutation
):
    analyzer, _ = modules
    row, workload = raw_row(analyzer)
    if mutation == "metadata":
        row["request_identity"]["server_completion_id"] = "cmpl-forged"
    elif mutation == "boolean-type":
        row["request_identity"]["server_header_matches_sent_request_id"] = 1
    elif mutation == "body-sha":
        row["http_response"]["body_sha256"] = "sha256:" + "0" * 64
    else:
        replacement = analyzer.h4_body_binding(completion_body("forged"))
        row["http_response"]["body_base64"] = replacement["body_base64"]
    with pytest.raises(ValueError, match="identity differs|body hash differs"):
        verified_raw(analyzer, row, workload)


@pytest.mark.parametrize("response", [None, "missing", "ambiguous"])
def test_absence_does_not_become_host_consumption_evidence(modules, response):
    analyzer, _ = modules
    row, workload = raw_row(analyzer, returned_header=None, include_id=False)
    raw_response = row["http_response"]
    if response is None:
        raw_response = None
    elif response == "ambiguous":
        raw_response["headers"] = [
            ["X-Request-Id", row["request_id"]],
            ["x-request-id", "other"],
        ]
    observation = analyzer.h4_request_identity_observation(
        row["request_id"], row["request_headers"], raw_response
    )
    for field in (
        "server_header_request_id",
        "server_completion_id",
        "server_header_matches_sent_request_id",
        "server_completion_matches_sent_request_id",
    ):
        assert observation[field] is None
    if response is not None:
        row["request_identity"] = observation
        verified_raw(analyzer, row, workload)


@pytest.mark.parametrize("missing", ["request_headers", "request_identity"])
def test_partial_new_observation_rejected_and_legacy_row_retained(modules, missing):
    analyzer, _ = modules
    row, workload = raw_row(analyzer)
    incomplete = copy.deepcopy(row)
    del incomplete[missing]
    with pytest.raises(ValueError, match="incomplete"):
        verified_raw(analyzer, incomplete, workload)
    del row["request_headers"]
    del row["request_identity"]
    verified_raw(analyzer, row, workload)


def test_original_request_dimensions_and_payload_are_retained(modules, monkeypatch):
    analyzer, runner = modules
    calls = []
    worker_counts = []

    class Completed:
        def __init__(self, value):
            self.value = value

        def result(self):
            return self.value

    class RecordingPool:
        def __init__(self, *, max_workers):
            worker_counts.append(max_workers)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, function, *args):
            return Completed(function(*args))

    def record_request(*args):
        calls.append(args)
        return dict(request_id=args[3], kind=args[4])

    monkeypatch.setattr(runner, "ThreadPoolExecutor", RecordingPool)
    monkeypatch.setattr(runner, "request_once", record_request)
    workload = original_workload()
    before = copy.deepcopy(workload)
    rows = runner.drive_requests("http://unused.invalid/v1/completions", workload)
    assert workload == before
    assert worker_counts == [8, 8]
    assert len(rows) == len(calls) == 16 + 256
    assert [r["request_id"] for r in rows[:16]] == [
        f"warmup-{i:04d}" for i in range(16)
    ]
    assert [r["request_id"] for r in rows[16:]] == [
        f"measured-{i:04d}" for i in range(256)
    ]
    expected = analyzer.h4_request_payload(workload, workload["served_model"])
    assert all(call[1] == expected and call[2] == 120.0 for call in calls)
    assert json.loads(expected) == dict(
        model=workload["served_model"],
        prompt=workload["prompt"],
        max_tokens=64,
        temperature=0.0,
        seed=12012,
    )


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [["X-Request-Id", "other"]],
        [
            ["X-Request-Id", "measured-0000"],
            ["x-request-id", "measured-0000"],
        ],
    ],
)
def test_sent_header_cannot_be_missing_rebound_or_duplicated(modules, headers):
    analyzer, _ = modules
    row, workload = raw_row(analyzer)
    row["request_headers"] = headers
    with pytest.raises(ValueError, match="transmitted request-ID header"):
        verified_raw(analyzer, row, workload)
