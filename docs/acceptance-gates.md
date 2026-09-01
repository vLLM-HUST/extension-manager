# Alpha and v1 acceptance gates

Alpha publication remains blocked until all gates are repeatable on supported
hosts.

1. vLLM/BidKV: the main distribution registers no private
   `vllm.victim_selector` entry point. vLLM-HUST 0.23 owns the minimal generic
   `vllm.scheduler.policy.v1` materializer, while BidKV supplies only the policy
   implementation. On server 91, 8 host contract tests and 4 installed BidKV
   materialization/trace tests pass. A real Qwen3-0.6B serving run then produced
   three `UTILITY_ACTIVE` selections under full KV pressure; all requests
   completed, and disable plus next-process restart restored the built-in path
   with no BidKV load. The remaining release gate is repeating this from clean
   pushed-commit image/wheel artifacts. Official vLLM remains unsupported until
   its upstream contract is released. See
   `docs/evidence/bidkv-vllm-hust-0.23-ascend91-2026-09-01.md`.
2. Mooncake: render both `MooncakeConnector` and `MooncakeStoreConnector`,
   verify a real externally operated service, preserve enabled intent during an
   outage, report degraded evidence, recover without reinstall, and never start
   or delete the service implicitly. **The official 0.3.12.post1 non-CUDA wheel
   has passed a two-process 1 MiB TransferEngine TCP write and an isolated Store
   REST put/exist/get/remove round trip on `a100-dev`.** Ordinary remove was
   correctly lease-gated. **The Ascend NPU path has also passed a real vLLM
   MooncakeStoreConnector nine-key save/load hit and master
   outage/degraded/recovery cycle.** See
   `docs/evidence/mooncake-0.3.12.post1-tcp-a100-2026-09-01.md` and
   `docs/evidence/mooncake-store-vllm-ascend-180-2026-09-01.md`.
3. Production Stack: render values against the official chart, run Helm
   template and Kubernetes server dry-run, inspect router/controller/autoscaler
   rollout state, reject conflicts, and prove that no apply/uninstall occurs.
   The isolated Router chart lifecycle (install, upgrade, explicit rollback,
   automatic rollback on a missing image, and uninstall) has passed. Official
   controller business reconciliation, Router-to-external-backend traffic, and
   a metrics-backed Router scale decision now also pass in Kubernetes 1.34.11.
   A negative test proves that an HPA cannot share `Deployment.spec.replicas`
   ownership with the current `VLLMRouter` controller. **Real-model traffic now
   passes on `180-ascend-bench`:** an absent backend produced HTTP 500, and
   reconnecting only the isolated Router to the existing GLM-4-32B service
   produced HTTP 200 and `ROUTER_OK` without restarting vLLM. Mock traffic no
   longer satisfies Manager health. The official v0.1.12 Router image has no
   arm64 manifest, so a Production Stack release-supported image matrix remains
   a release gate. See
   `docs/evidence/production-stack-real-model-180-2026-09-01.md`.
4. Cross-cutting: incompatible host/API ranges, missing required services,
   duplicate registrations, configuration conflicts, rollback, partial health,
   and permission denial have explicit expected results.
6. Packaging: clean-environment install, disable, forget, and uninstall work on
   112 and 91 without stale enabled intent, replacing `VLLM_PLUGINS`, or
   modifying the vLLM source tree.

Only after these gates pass may the schema be revised and frozen as v1 and an
alpha package be published.
