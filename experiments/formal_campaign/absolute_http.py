"""Actual loopback HTTP with one original absolute120s watchdog; no retries."""

from __future__ import annotations

import contextlib
import http.client
import socket
import threading
import time
from urllib.parse import urlparse


def request_once(endpoint, payload, timeout, request_id, kind, trace=None):
    from experiments.formal_campaign.analyze import (
        h4_body_binding,
        h4_request_identity_observation,
        h4_response_summary,
    )

    if timeout != 120:
        raise ValueError("original absolute120s required")
    parsed = urlparse(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("declared direct actual loopback endpoint required")

    def now():
        return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)

    dispatch = now()
    deadline = dispatch + 120_000_000_000
    if trace is not None:
        trace.start(request_id, dispatch, deadline)
    lock = threading.Lock()
    state = dict(fired=False, completed=False)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection = http.client.HTTPConnection("127.0.0.1", parsed.port)
    response_evidence = None
    error = None
    headers = {"Content-Type": "application/json", "X-Request-Id": request_id}

    def expire():
        with lock:
            if state["completed"]:
                return
            state["fired"] = True
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    timer = threading.Timer(120, expire)
    timer.daemon = True
    timer.start()
    try:
        sock.settimeout(max(0.001, (deadline - now()) / 1e9))
        sock.connect(("127.0.0.1", parsed.port))
        connection.sock = sock
        connection.request("POST", parsed.path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        completed = now()
        with lock:
            if state["fired"] or completed > deadline:
                raise TimeoutError("original absolute120s exceeded/cancelled body")
            state["completed"] = True
        response_evidence = dict(
            status_code=response.status,
            headers=list(response.getheaders()),
            **h4_body_binding(raw),
        )
    except Exception as exc:
        completed = now()
        error = type(exc).__name__ + ": " + str(exc)
    finally:
        with lock:
            state["completed"] = True
        timer.cancel()
        connection.close()
        sock.close()
        timer.join()
    request_headers = [list(item) for item in headers.items()]
    row = dict(
        request_id=request_id,
        kind=kind,
        request_headers=request_headers,
        request_identity=h4_request_identity_observation(
            request_id, request_headers, response_evidence
        ),
        dispatch_ns=dispatch,
        original_deadline_ns=deadline,
        complete_ns=completed,
        error=error,
        http_request=h4_body_binding(payload),
        http_response=response_evidence,
        watchdog_fired=state["fired"],
        **h4_response_summary(response_evidence),
    )
    if trace is not None:
        trace.end(row)
    return row
