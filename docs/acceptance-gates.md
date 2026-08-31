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
3. Production Stack: render values against the official chart, run Helm
   template and Kubernetes server dry-run, inspect router/controller/autoscaler
   rollout state, reject conflicts, and prove that no apply/uninstall occurs.
4. Cross-cutting: incompatible host/API ranges, missing required services,
   duplicate registrations, configuration conflicts, rollback, partial health,
   and permission denial have explicit expected results.
5. Packaging: clean-environment install/uninstall works on 112 and 91 without
   replacing `VLLM_PLUGINS` or modifying the vLLM source tree.

Only after these gates pass may the schema be revised and frozen as v1 and an
alpha package be published.
