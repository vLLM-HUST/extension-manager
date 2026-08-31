from __future__ import annotations

import argparse
import json

from mooncake_vllm_connector_probe import metrics, post, wait_ready


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18084")
    parser.add_argument("--model", default="Qwen3-0.6B")
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    wait_ready(args.base_url, 30)
    request = {
        "model": args.model,
        "prompt": f"Mooncake service-state acceptance {args.tag}. " * 64,
        "max_tokens": 1,
        "temperature": 0,
    }
    before, _ = metrics(args.base_url)
    response = post(f"{args.base_url}/v1/completions", request)
    after, evidence = metrics(args.base_url)
    print(
        json.dumps(
            {
                "request_id": response.get("id"),
                "before": before,
                "after": after,
                "metric_evidence": evidence,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
