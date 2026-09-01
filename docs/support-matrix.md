# Experimental support matrix

No row below is a stable v1 promise. “Passed” means a pinned combination has
real evidence; it does not widen the result to every version in an experimental
manifest range.

| Host path | Pinned passing evidence | Remaining release gate |
| --- | --- | --- |
| vLLM-HUST / BidKV | vLLM-HUST 0.23 typed `vllm.scheduler.policy.v1`; 91 passed contract tests plus real Qwen3-0.6B load, three `UTILITY_ACTIVE` preemptions, request completion, disable and next-process built-in fallback | Repeat from clean release image/wheels; official vLLM remains unsupported until an upstream contract is released |
| Mooncake standalone | Official non-CUDA 0.3.12.post1 TransferEngine TCP and Store REST on `a100-dev` | Cross-version, transport and multi-node matrix |
| MooncakeStoreConnector / Ascend | vLLM 0.23 + vLLM Ascend + NPU wheel 0.3.11.post1, nine-key save/load and outage/recovery on NPU 4 | Matrix beyond the pinned `ascend` transport and `load_async=true` combination |
| LMCache MP | Official 0.5.4 CPU-SHM LOOKUP/STORE/RETRIEVE/CHECKSUM and service outage/recovery | Real online `LMCacheMPConnector` data path and 0.5.x matrix; standalone evidence cannot report the connector healthy |
| LMCache Ascend in-process | Server 91, Qwen3-0.6B, vLLM/vLLM-Ascend 0.23 and pinned LMCache 0.4.3 + LMCache-Ascend `v0.4.3-4-gc86fa99`: 2236 tokens stored, hit and retrieved | Controlled backend outage/recompute/recovery; deterministic cross-process hash; Prometheus conflict; unmodified upstream and cross-version matrix |
| Production Stack control plane | Commit `1b87c11a`, chart 0.1.12, Helm 4.2.4, Kubernetes 1.34.11: render, dry-run, lifecycle rollback, controller, Router and HPA evidence | Additional Kubernetes/Helm versions and permission-denial matrix |
| Production Stack real-model Router | arm64 source build routed an absent backend as HTTP 500, then existing GLM-4-32B as HTTP 200/`ROUTER_OK` without restarting vLLM | Official v0.1.12 Router image has no arm64 manifest |

## Rollback ownership

- In-process vLLM policies and connectors roll back on the next vLLM process
  start after Manager disable; hot unload is not promised.
- Mooncake and LMCache own service and KV-data lifecycle. Manager disable never
  stops a service or clears data, and enabled intent survives a temporary
  outage.
- Kubernetes operators own Helm history, apply, rollback, and uninstall.
  Manager only plans, renders, dry-run checks and projects evidence.

Alpha remains **NO-GO** until the BidKV online result is repeated from clean
release artifacts, supported artifacts exist for claimed architectures, and the version,
permission, failure and rollback matrix are repeatable. BidKV is supported on
the pinned vLLM-HUST 0.23 host contract; that is not a claim of official-vLLM
compatibility.
