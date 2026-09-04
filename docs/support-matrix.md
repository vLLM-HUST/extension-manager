# Experimental support matrix

No row below is a stable v1 promise. “Passed” means a pinned combination has
real evidence; it does not widen the result to every version in an experimental
manifest range.

| Host path | Pinned passing evidence | Remaining release gate |
| --- | --- | --- |
| vLLM-HUST 0.28 / BidKV 0.2 | Source and installed-package integration pass for the typed `vllm.preemption-policy` v1 path. Runtime status is **unknown**, not compatible. The former 0.23/Qwen3-0.6B and Qwen2.5-3B runs are historical evidence only. | Independent Qwen3.8-27B, Ascend TP4, graph capture/replay run proving invocation, output correctness, metrics and failover; official contract review |
| Mooncake standalone | Official non-CUDA 0.3.12.post1 TransferEngine TCP and Store REST on `a100-dev` | Cross-version, transport and multi-node matrix |
| MooncakeStoreConnector / Ascend | vLLM 0.23 + vLLM Ascend + NPU wheel 0.3.11.post1, nine-key save/load and outage/recovery on NPU 4 | Matrix beyond the pinned `ascend` transport and `load_async=true` combination |
| Production Stack control plane | Commit `1b87c11a`, chart 0.1.12, Helm 4.2.4, Kubernetes 1.34.11: render, dry-run, lifecycle rollback, controller, Router and HPA evidence | Additional Kubernetes/Helm versions and permission-denial matrix |
| Production Stack real-model Router | arm64 source build routed an absent backend as HTTP 500, then existing GLM-4-32B as HTTP 200/`ROUTER_OK` without restarting vLLM; commit `7611dfa` was built, smoke-tested and published to GHCR by GitHub-hosted runners, then pulled and entrypoint-tested on arm64 server 91 | Additional Kubernetes/Helm versions and permission-denial matrix; amd64 and self-hosted infrastructure are not required |

## Rollback ownership

- In-process vLLM policies and connectors roll back on the next vLLM process
  start after Manager disable; hot unload is not promised.
- Mooncake owns its service and KV-data lifecycle. Manager disable never stops
  the service or clears data, and enabled intent survives a temporary outage.
- Kubernetes operators own Helm history, apply, rollback, and uninstall.
  Manager only plans, renders, dry-run checks and projects evidence.

Alpha remains **NO-GO** until the remaining version, permission, failure and
rollback matrix is repeatable. No old 0.23 result qualifies the new Sage Mate
baseline, and enabled intent is not runtime-effectiveness evidence.
