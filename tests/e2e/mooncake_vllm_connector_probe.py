from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request

OPERATIONS = ("lookup_exists", "save_put", "load_get")


def get(url: str, timeout: float = 5) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def post(url: str, body: dict[str, object], timeout: float = 120) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        details = error.read().decode(errors="replace")
        raise RuntimeError(
            f"POST {url} returned HTTP {error.code}: {details}"
        ) from error


def wait_ready(base_url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            get(f"{base_url}/health")
            return
        except (OSError, urllib.error.URLError):
            time.sleep(2)
    raise TimeoutError(f"vLLM did not become ready within {timeout}s")


def metrics(base_url: str) -> tuple[dict[str, float], list[str]]:
    text = get(f"{base_url}/metrics").decode()
    totals: dict[str, float] = {}
    evidence: list[str] = []
    for line in text.splitlines():
        if "mooncake_store_operation" not in line or line.startswith("#"):
            continue
        evidence.append(line)
        for operation in OPERATIONS:
            if f'operation="{operation}"' not in line or 'status="ok"' not in line:
                continue
            if not line.startswith("vllm:mooncake_store_operation_keys_total"):
                continue
            match = re.search(r"\s([0-9.eE+-]+)$", line)
            if match:
                totals[operation] = totals.get(operation, 0.0) + float(match.group(1))
    return totals, evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18084")
    parser.add_argument("--model", default="Qwen3-0.6B")
    parser.add_argument("--ready-timeout", type=float, default=600)
    args = parser.parse_args()

    wait_ready(args.base_url, args.ready_timeout)
    before, _ = metrics(args.base_url)
    prompt = "Mooncake connector cache-hit acceptance token sequence. " * 128
    request = {
        "model": args.model,
        "prompt": prompt,
        "max_tokens": 1,
        "temperature": 0,
    }
    first = post(f"{args.base_url}/v1/completions", request)
    time.sleep(3)
    after_first, _ = metrics(args.base_url)
    second = post(f"{args.base_url}/v1/completions", request)
    time.sleep(3)
    after_second, evidence = metrics(args.base_url)

    deltas = {
        operation: after_second.get(operation, 0) - before.get(operation, 0)
        for operation in OPERATIONS
    }
    result = {
        "first_id": first.get("id"),
        "second_id": second.get("id"),
        "after_first": after_first,
        "after_second": after_second,
        "deltas": deltas,
        "metric_evidence": evidence,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if deltas["save_put"] <= 0:
        raise AssertionError("first request did not save Mooncake Store keys")
    if deltas["lookup_exists"] <= 0:
        raise AssertionError("requests did not perform Mooncake Store lookup")
    if deltas["load_get"] <= 0:
        raise AssertionError("second request did not load a Mooncake Store cache hit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
