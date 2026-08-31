# Alpha and v1 acceptance gates

Alpha publication remains blocked until all gates are repeatable on supported
hosts.

1. vLLM/BidKV: install, discover, validate, configure, enable, plan, render,
   launch, observe policy selection, disable, restart, and verify upstream
   fallback.
2. Mooncake: render both `MooncakeConnector` and `MooncakeStoreConnector`,
   verify a real externally operated service, preserve enabled intent during an
   outage, report degraded evidence, recover without reinstall, and never start
   or delete the service implicitly.
3. LMCache: render MP and supported V1 connector configurations, verify a real
   external MP service through `/healthcheck`, preserve enabled intent across
   outage/recovery, reject nonofficial module paths, and never clear, evict, or
   delete cache data implicitly.
4. Production Stack: render values against the official chart, run Helm
   template and Kubernetes server dry-run, inspect router/controller/autoscaler
   rollout state, reject conflicts, and prove that no apply/uninstall occurs.
   The isolated Router chart lifecycle (install, upgrade, explicit rollback,
   automatic rollback on a missing image, and uninstall) has passed. Real
   LoRA CRD establishment, controller probe rollout, and HPA target lookup also
   pass. Official controller business reconciliation, a metrics-backed scale
   decision, and Router-to-model traffic remain.
5. Cross-cutting: incompatible host/API ranges, missing required services,
   duplicate registrations, configuration conflicts, rollback, partial health,
   and permission denial have explicit expected results.
6. Packaging: clean-environment install, disable, forget, and uninstall work on
   112 and 91 without stale enabled intent, replacing `VLLM_PLUGINS`, or
   modifying the vLLM source tree.

Only after these gates pass may the schema be revised and frozen as v1 and an
alpha package be published.
