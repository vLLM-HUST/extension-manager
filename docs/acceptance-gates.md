# Alpha and v1 acceptance gates

Alpha publication remains blocked until all gates are repeatable on supported
hosts.

1. vLLM/BidKV: the main distribution registers no private
   `vllm.victim_selector` entry point, and a fresh official vLLM fails closed.
   After upstream RFC #51608/PR #51601 freezes a Preemption contract, migrate
   the import-only legacy adapter, then install, discover, validate, configure,
   enable, plan, render, launch, observe real policy selection, disable,
   restart, and verify upstream fallback.
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
3. LMCache: target the official 0.5.x `lmcache server` interface, render MP and
   supported dynamic V1 connector configurations, verify service version via
   `/lmc_version`, verify readiness via `/healthcheck`, and run the official
   CPU-SHM server benchmark through LOOKUP, STORE, RETRIEVE, and CHECKSUM.
   Preserve enabled intent across outage/recovery, reject nonofficial module
   paths, and never clear, evict, or delete cache data implicitly.
   **Passed for LMCache 0.5.4 on `a100-dev` (2026-09-01):** the immutable
   official image completed the CPU-SHM LOOKUP/STORE/RETRIEVE/CHECKSUM path at
   100% checksum pass rate, and Manager health, degradation, recovery,
   disable, and forget projections passed. See
   `docs/evidence/lmcache-0.5.4-a100-2026-09-01.md`.
4. Production Stack: render values against the official chart, run Helm
   template and Kubernetes server dry-run, inspect router/controller/autoscaler
   rollout state, reject conflicts, and prove that no apply/uninstall occurs.
   The isolated Router chart lifecycle (install, upgrade, explicit rollback,
   automatic rollback on a missing image, and uninstall) has passed. Official
   controller business reconciliation, Router-to-external-backend traffic, and
   a metrics-backed Router scale decision now also pass in Kubernetes 1.34.11.
   A negative test proves that an HPA cannot share `Deployment.spec.replicas`
   ownership with the current `VLLMRouter` controller. A real model backend and
   a Production Stack release-supported image matrix remain release gates.
5. Cross-cutting: incompatible host/API ranges, missing required services,
   duplicate registrations, configuration conflicts, rollback, partial health,
   and permission denial have explicit expected results.
6. Packaging: clean-environment install, disable, forget, and uninstall work on
   112 and 91 without stale enabled intent, replacing `VLLM_PLUGINS`, or
   modifying the vLLM source tree.

Only after these gates pass may the schema be revised and frozen as v1 and an
alpha package be published.
