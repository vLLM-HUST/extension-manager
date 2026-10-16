"""Exactly one fresh bounded upstream HTTP request, never native qualification."""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from experiments.native_challenge_candidate import collector_client, request_runner

from .request_phasebook import canonical, digest, require, write_new

METADATA = "ecpa-request-observed-HTTP-response/v1"


def run_rpc_only(recipe, phase_id, output):
    from .request_drain_consumer import validate_recipe

    validate_recipe(recipe)
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    budget = request_runner.validate_rpc_budget(phase["rpc_budget_s"])
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    output.chmod(0o700)
    request_raw = canonical(phase["payload"])
    write_new(output / "request.bin", request_raw)
    write_new(output / "headers.json", canonical(phase["headers"]))
    result = {
        "schema": "ecpa-request-upstream-HTTP-task/v1",
        "phase_id": phase_id,
        "rpc_task_passed": False,
        "formal_result": False,
        "native_join_status": "unjoined",
        "effect_qualification": None,
    }
    started = time.monotonic_ns()
    try:
        request = urllib.request.Request(
            phase["url"], data=request_raw, headers=phase["headers"], method="POST"
        )
        response = urllib.request.urlopen(request, timeout=budget)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, ValueError) as error:
        result["failure"] = str(error)
        result["completed_monotonic_ns"] = time.monotonic_ns()
        write_new(output / "upstream-task.json", canonical(result))
        return result
    with response:
        raw = response.read(8 * 1024 * 1024 + 1)
        received = time.monotonic_ns()
        require(len(raw) <= 8 * 1024 * 1024, "actual upstream response oversized")
        metadata = {
            "schema": METADATA,
            "status": response.status,
            "headers": list(response.headers.items()),
            "url": response.geturl(),
            "request_sha256": digest(request_raw),
            "response_sha256": digest(raw),
            "sent_monotonic_ns": started,
            "received_monotonic_ns": received,
            "client": collector_client.identity(os.getpid()),
            "client_source_sha256": digest(Path(__file__).read_bytes()),
            "rpc_budget_s": budget,
            "rpc_budget_semantics": "socket-timeout-and-observed-HTTP-elapsed-gate",
        }
    write_new(output / "response.bin", raw)
    write_new(output / "response-metadata.json", canonical(metadata))
    try:
        request_runner.verify_rpc_budget(phase, metadata, metadata_schema=METADATA)
        parsed = json.loads(raw)
        choice = parsed["choices"][0]
        require(
            metadata["status"] == 200 and parsed["model"] == phase["payload"]["model"],
            "actual upstream status/model differs",
        )
        require(
            parsed["id"] == phase["expected_response_id"],
            "actual upstream response identity differs",
        )
        text = choice["message"]["content"]
        require(
            isinstance(text, str)
            and text.strip() == phase["response_oracle"]["expected"]
            and choice["finish_reason"] == "stop",
            "actual upstream frozen task oracle failed",
        )
        require(
            parsed["usage"]["prompt_tokens"]
            == phase["tokenization"]["prompt_token_count"]
            and type(parsed["usage"]["completion_tokens"]) is int
            and parsed["usage"]["completion_tokens"]
            >= phase["minimum_completion_tokens"],
            "actual upstream prompt/decode token window differs",
        )
        result["rpc_task_passed"] = True
    except (ValueError, KeyError, IndexError, TypeError) as error:
        result["failure"] = str(error)
    result.update(
        status=metadata["status"],
        response_sha256=digest(raw),
        rpc_dispatch_monotonic_ns=started,
        rpc_completed_monotonic_ns=received,
    )
    write_new(output / "upstream-task.json", canonical(result))
    return result
