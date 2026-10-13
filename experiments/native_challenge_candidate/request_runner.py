"""Freeze phase-specific challenge requests; native authority join stays separate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = "ecpa-native-challenge-campaign/v1"
CLASSIFICATION = "CPU_REVIEW_CANDIDATE_ONLY"


def canonical(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def make_recipe(phase_targets, sources):
    """Freeze public nonces before launches; never mint Manager native identities."""
    phases = []
    for phase_id, url, model in phase_targets:
        client_id, nonce = secrets.token_hex(16), secrets.token_hex(16)
        expected = "ECPA-CHALLENGE-" + nonce
        phases.append(
            {
                "phase_id": phase_id,
                "client_request_id": client_id,
                "challenge_nonce": nonce,
                "external_request_id": "chatcmpl-" + client_id,
                "expected_response_id": "chatcmpl-" + client_id,
                "expected_ranks": [0, 1],
                "url": url,
                "headers": {
                    "Content-Type": "application/json",
                    "X-Request-Id": client_id,
                },
                "payload": {
                    "request_id": client_id,
                    "model": model,
                    "messages": [
                        {"role": "user", "content": "Reply exactly " + expected}
                    ],
                    "temperature": 0,
                    "max_tokens": 96,
                    "n": 1,
                    "stream": False,
                },
                "response_oracle": {
                    "expected": expected,
                    "strip_outer_whitespace": True,
                    "finish_reason": "stop",
                },
            }
        )
    recipe = {
        "schema": SCHEMA,
        "classification": CLASSIFICATION,
        "formal_result": False,
        "frozen_utc": datetime.now(timezone.utc).isoformat(),
        "frozen_monotonic_ns": time.monotonic_ns(),
        "request_scope": "preregistered-client-challenge-only",
        "native_ids_preregistered_before_launch": False,
        "sources": sources,
        "phases": phases,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
    }
    validate(recipe)
    return recipe


def validate(recipe):
    require(
        recipe["schema"] == SCHEMA
        and recipe["classification"] == CLASSIFICATION
        and recipe["formal_result"] is False
        and recipe["native_ids_preregistered_before_launch"] is False,
        "challenge scope changed",
    )
    require(
        all(
            recipe[k] is None
            for k in ("lost_requests", "duplicate_requests", "full_objective_satisfied")
        ),
        "unknown objective promoted",
    )
    require(recipe["sources"], "concrete source bindings required")
    for source in recipe["sources"]:
        path = Path(source["path"])
        require(
            path.is_absolute()
            and path.is_file()
            and sha(path.read_bytes()) == source["sha256"],
            "frozen source bytes changed",
        )
    phases = recipe["phases"]
    require(0 < len(phases) <= 64, "bounded explicit phase list required")
    for name in (
        "phase_id",
        "client_request_id",
        "challenge_nonce",
        "expected_response_id",
    ):
        require(
            len({p[name] for p in phases}) == len(phases),
            "phase/request/challenge reuse",
        )
    for phase in phases:
        require(
            re.fullmatch(r"[a-zA-Z0-9._-]{1,80}", phase["phase_id"]) is not None,
            "invalid phase ID",
        )
        require(
            all(
                re.fullmatch(r"[0-9a-f]{32}", phase[k]) is not None
                for k in ("client_request_id", "challenge_nonce")
            ),
            "unique 128-bit client/challenge required",
        )
        url = urlsplit(phase["url"])
        require(
            url.scheme == "http"
            and url.hostname == "127.0.0.1"
            and url.port is not None
            and url.path == "/v1/chat/completions"
            and not url.query
            and not url.fragment
            and url.username is None,
            "direct loopback completion endpoint required",
        )
        client_id, nonce = phase["client_request_id"], phase["challenge_nonce"]
        require(
            phase["external_request_id"]
            == phase["expected_response_id"]
            == "chatcmpl-" + client_id,
            "source-bound external response ID changed",
        )
        require(phase["expected_ranks"] == [0, 1], "retain both TP2 ranks")
        require(
            phase["headers"]
            == {"Content-Type": "application/json", "X-Request-Id": client_id},
            "request header identity changed",
        )
        payload = phase["payload"]
        require(
            payload["request_id"] == client_id
            and payload["messages"]
            == [{"role": "user", "content": "Reply exactly ECPA-CHALLENGE-" + nonce}],
            "frozen challenge payload changed",
        )
        require(
            payload["temperature"] == 0
            and payload["n"] == 1
            and payload["max_tokens"] == 96
            and payload["stream"] is False,
            "single bounded task policy changed",
        )
        require(
            phase["response_oracle"]
            == {
                "expected": "ECPA-CHALLENGE-" + nonce,
                "strip_outer_whitespace": True,
                "finish_reason": "stop",
            },
            "exact nonce oracle changed",
        )
        require(
            not any(
                k in phase
                for k in ("native_plan_id", "native_launch_id", "runtime_request_id")
            ),
            "native IDs must be actually minted/mapped after launch",
        )


def require_phase_registration(phase, collector_spec):
    """Scope match only; caller must separately authenticate the collector peer."""
    require(
        collector_spec["schema"] == "ecpa-native-semantic-collector-prereg/v1",
        "collector schema changed",
    )
    matches = [
        p for p in collector_spec["phases"] if p["phase_id"] == phase["phase_id"]
    ]
    require(len(matches) == 1, "phase not uniquely registered")
    expected = {
        k: phase[k]
        for k in (
            "phase_id",
            "client_request_id",
            "challenge_nonce",
            "external_request_id",
            "expected_ranks",
        )
    }
    require(
        matches[0] == expected, "collector request/challenge preregistration differs"
    )
    require(
        collector_spec["native_plan_id"] and collector_spec["native_launch_id"],
        "actual native identity binding required before HTTP",
    )


def run_rpc_only(recipe, phase_id, output, timeout=30):
    """Execute one request, never replay an ambiguously dispatched challenge.

    This is client-side task evidence only. It cannot authorize native facts or
    qualify a native join without the separate durable source-peer collector.
    """
    validate(recipe)
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    raw_request = canonical(phase["payload"])
    (output / "request.bin").write_bytes(raw_request)
    (output / "headers.json").write_bytes(canonical(phase["headers"]))
    result = {
        "classification": CLASSIFICATION,
        "formal_result": False,
        "phase_id": phase_id,
        "client_request_id": phase["client_request_id"],
        "challenge_nonce": phase["challenge_nonce"],
        "recipe_sha256": sha(canonical(recipe)),
        "rpc_task_passed": False,
        "native_join_qualified": False,
        "native_join_status": "unjoined",
        "missing_evidence": [
            "authenticated-native-mapping",
            "rank0-upload",
            "rank1-upload",
        ],
        "hardware_result": False,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
    }
    try:
        request = urllib.request.Request(
            phase["url"], data=raw_request, headers=phase["headers"]
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body, status = response.read(), response.status
        (output / "response.bin").write_bytes(body)
        result["status"] = status
        result["response_sha256"] = sha(body)
        data = json.loads(body)
        choice = data["choices"][0]
        content = choice["message"]["content"]
        require(
            status == 200
            and data["model"] == phase["payload"]["model"]
            and data["usage"]["completion_tokens"] > 0,
            "completed model RPC missing",
        )
        require(
            data["id"] == phase["expected_response_id"],
            "external response identity mismatch",
        )
        require(
            isinstance(content, str)
            and content.strip() == phase["response_oracle"]["expected"]
            and choice["finish_reason"] == "stop",
            "phase challenge task_oracle_failed",
        )
        result["rpc_task_passed"] = True
    except urllib.error.HTTPError as exc:
        body = exc.read()
        (output / "response.bin").write_bytes(body)
        result.update(status=exc.code, response_sha256=sha(body), failure=str(exc))
    except (OSError, ValueError, KeyError, IndexError) as exc:
        result["failure"] = str(exc)
    (output / "result.json").write_bytes(canonical(result))
    return result


def execute_with_collector(
    recipe,
    phase_id,
    output,
    *,
    socket_path,
    descriptor,
    spec_path,
    collector_source_path,
    journal_path,
):
    """Authenticated durable native transport join; no KV effect qualification."""
    from .collector_client import authenticate, private_read, read_verified_phase

    validate(recipe)
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    try:
        collector_spec = json.loads(private_read(spec_path))
        require_phase_registration(phase, collector_spec)
        before = authenticate(socket_path, descriptor, spec_path, collector_source_path)
    except (OSError, ValueError, KeyError) as exc:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        result = {
            "classification": CLASSIFICATION,
            "formal_result": False,
            "phase_id": phase_id,
            "http_attempted": False,
            "rpc_task_passed": False,
            "native_join_qualified": False,
            "hardware_result": False,
            "native_join_failure": str(exc),
            "recipe_sha256": sha(canonical(recipe)),
            "KV_MOD_semantic_obligation_satisfied": None,
            "GPU_semantic_qualification": None,
            "full_objective_satisfied": None,
        }
        (output / "collector-launcher-descriptor.json").write_bytes(
            canonical(descriptor)
        )
        (output / "result.json").write_bytes(canonical(result))
        return result
    result = run_rpc_only(recipe, phase_id, output)
    (output / "collector-before.json").write_bytes(canonical(before))
    if not result["rpc_task_passed"]:
        return result
    try:
        after = authenticate(socket_path, descriptor, spec_path, collector_source_path)
        (output / "collector-after.json").write_bytes(canonical(after))
        joined = read_verified_phase(spec_path, journal_path, phase, after)
        (output / "native-transport-join.json").write_bytes(canonical(joined))
        result["native_request_upload_transport_join"] = True
        result["native_join_status"] = "authenticated-durable-transport-only"
        result["missing_evidence"] = []
        result["KV_MOD_semantic_obligation_satisfied"] = None
        result["GPU_semantic_qualification"] = None
        result["native_join_qualified"] = False
    except (OSError, ValueError, KeyError, ImportError) as exc:
        result["native_join_failure"] = str(exc)
    (output / "result.json").write_bytes(canonical(result))
    return result


def freeze_file(configuration, output):
    targets = [
        (p["phase_id"], p["url"], p["model"]) for p in configuration["phase_targets"]
    ]
    recipe = make_recipe(targets, configuration["sources"])
    require(output.is_absolute(), "absolute frozen recipe path required")
    output.parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    parent = output.parent.stat()
    require(
        parent.st_uid == os.getuid() and parent.st_mode & 0o777 == 0o700,
        "private owned freeze directory required",
    )
    raw = canonical(recipe)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "path": str(output),
        "sha256": sha(raw),
        "phases": len(recipe["phases"]),
        "formal_result": False,
        "native_ids_preregistered_before_launch": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser(
        "freeze", help="freeze unique client IDs/nonces before launch"
    )
    freeze.add_argument("configuration", type=Path)
    freeze.add_argument("--output", type=Path, required=True)
    rpc = commands.add_parser(
        "rpc-only", help="run client task only; never native qualification"
    )
    rpc.add_argument("recipe", type=Path)
    rpc.add_argument("--expected-sha256", required=True)
    rpc.add_argument("--phase", required=True)
    rpc.add_argument("--output", type=Path, required=True)
    execute = commands.add_parser(
        "execute",
        help="authenticated native transport join; not KV semantic qualification",
    )
    execute.add_argument("recipe", type=Path)
    execute.add_argument("--expected-sha256", required=True)
    execute.add_argument("--phase", required=True)
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--collector-socket", type=Path, required=True)
    execute.add_argument("--collector-launcher-descriptor", type=Path, required=True)
    execute.add_argument("--collector-spec", type=Path, required=True)
    execute.add_argument("--collector-source", type=Path, required=True)
    execute.add_argument("--collector-journal", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        print(
            json.dumps(
                freeze_file(json.loads(args.configuration.read_text()), args.output),
                indent=2,
            )
        )
        return 0
    raw = args.recipe.read_bytes()
    require(sha(raw) == args.expected_sha256, "recipe differs from frozen bytes")
    if args.command == "execute":
        result = execute_with_collector(
            json.loads(raw),
            args.phase,
            args.output,
            socket_path=args.collector_socket,
            descriptor=json.loads(args.collector_launcher_descriptor.read_text()),
            spec_path=args.collector_spec,
            collector_source_path=args.collector_source,
            journal_path=args.collector_journal,
        )
    else:
        result = run_rpc_only(json.loads(raw), args.phase, args.output)
    print(json.dumps(result, indent=2))
    return (
        0
        if result["rpc_task_passed"]
        and (
            args.command == "rpc-only"
            or result.get("native_request_upload_transport_join") is True
        )
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
