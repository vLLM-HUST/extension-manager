# vLLM-HUST Extension Manager

`vllm-hust-ext` is a provider-neutral control point for discovering, validating,
configuring, enabling, planning, rendering, and checking vLLM-HUST extensions.
It is not a vLLM distribution, deployment system, or control plane.

The core owns static manifests, compatibility, persistent intent, lifecycle
state, conflict checks, and delegation. Host Providers retain runtime
authority:

- the vLLM Provider renders launch configuration for in-process extensions;
- the Mooncake Provider reuses official vLLM connectors and checks externally
  operated Mooncake services;
- the LMCache Provider renders the official MP connector configuration and
  checks externally operated LMCache services without clearing cache data; and
- the Production Stack Provider renders Helm/Kubernetes inputs and dry-run
  plans without applying them.

A plugin, KV connector, external KV system, and control-plane policy remain
different kinds. Installing or enabling an adapter never gives this manager
authority to start shared services, change drivers, delete KV data, or mutate a
production cluster.

> **Compatibility freeze:** Manifest `0.2-experimental` and the former Bundle
> v1 prototype are not stable APIs. No alpha package will be published until
> the vLLM, KV-system, and control-plane end-to-end gates pass.

```bash
pip install vllm-hust-ext
pip install bidkv

vllm-hust-ext extension list
vllm-hust-ext extension status org.vllm-hust.bidkv
vllm-hust-ext extension enable org.vllm-hust.bidkv
vllm-hust-ext extension plan org.vllm-hust.bidkv
vllm-hust-ext extension render org.vllm-hust.bidkv
vllm-hust-ext extension check org.vllm-hust.bidkv
vllm-hust-ext run -- vllm serve MODEL
```

External KV profiles follow the same install/configure/enable flow. For
example, the experimental LMCache profile renders an official vLLM connector
argument without starting or modifying the LMCache service:

```bash
pip install vllm-hust-lmcache-provider
vllm-hust-ext extension configure org.vllm-hust.lmcache-provider \
  --file lmcache-config.json
vllm-hust-ext extension enable org.vllm-hust.lmcache-provider
vllm-hust-ext run --dry-run -- vllm serve MODEL
```

Only one enabled extension may claim vLLM's `--kv-transfer-config` in a single
process. Enabling Mooncake and LMCache together therefore fails closed instead
of silently choosing one. Experimental profile wheels pin the exact Manager
development version until the compatibility contract is frozen.

Installing an extension distribution only makes it discoverable. Enabling is
explicit and stored in the user configuration. Discovery reads installed
distribution metadata and the static bundle manifest without importing its
implementation modules.

Third-party host providers register factories only under the project-owned
entry-point group `vllm_hust_ext.providers`. Extension distributions register
static manifests under `vllm_hust.extension_bundles`. Neither namespace claims
an unofficial `vllm.*` entry-point group.

