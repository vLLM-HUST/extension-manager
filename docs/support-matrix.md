# Experimental support matrix

No row below is a stable v1 promise. “Passed” means a pinned combination has
real evidence; it does not widen the result to every version in an experimental
manifest range.

| Host path | Pinned passing evidence | Remaining release gate |
| --- | --- | --- |
| vLLM / BidKV | Fresh vLLM-HUST 0.23 fails closed because the private legacy selector is absent | Upstream RFC #51608 and draft PR #51601 do not yet provide a stable out-of-tree scheduler contract |
| Mooncake standalone | Official non-CUDA 0.3.12.post1 TransferEngine TCP and Store REST on `a100-dev` | Cross-version, transport and multi-node matrix |
| MooncakeStoreConnector / Ascend | vLLM 0.23 + vLLM Ascend + NPU wheel 0.3.11.post1, nine-key save/load and outage/recovery on NPU 4 | Matrix beyond the pinned `ascend` transport and `load_async=true` combination |
| LMCache MP | Official 0.5.4 CPU-SHM LOOKUP/STORE/RETRIEVE/CHECKSUM and service outage/recovery | Real online vLLM MP connector data path and 0.5.x matrix |
| LMCache Ascend | Separate profile and fail-closed readiness checks | Current 0.4.3 environment lacks a working health/data path; it cannot inherit the MP result |
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

Alpha remains **NO-GO** until BidKV has a stable upstream contract, supported
release artifacts exist for claimed architectures, and the version,
permission, failure and rollback matrix is repeatable.
