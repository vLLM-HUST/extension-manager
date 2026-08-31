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
  checks externally operated LMCache services without clearing cache data;
- the separate LMCache-Ascend adapter profile renders the official in-process
  Ascend connector and does not claim that an LMCache MP service exists; and
- the Production Stack Provider renders Helm/Kubernetes inputs and dry-run
  plans without applying them.

A plugin, KV connector, external KV system, and control-plane policy remain
different kinds. Installing or enabling an adapter never gives this manager
authority to start shared services, change drivers, delete KV data, or mutate a
production cluster.

Mooncake runtime detection covers the mutually exclusive official CUDA,
CUDA 13, non-CUDA, NPU, MUSA, and EFA wheel variants. Installing more than one
variant is reported as an incompatible/degraded environment instead of picking
one arbitrarily.

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

The BidKV example currently describes the legacy experimental
`vllm.victim_selector` contract. The fresh vLLM-HUST 0.23 fork does not provide
that protocol, so Manager compatibility remains unverified/incompatible unless
the host supplies explicit protocol evidence. New core work must align with
upstream scheduler-plugin RFC #51608 and draft PR #51601 instead of adding a
second private victim-selector API.

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

LMCache-Ascend is a platform backend plus a vLLM adapter, not another top-level
KV service. Its separate profile therefore has no `requires_services` entry and
uses the exact official dynamic module path:

```bash
pip install vllm-hust-lmcache-ascend-adapter
vllm-hust-ext extension configure \
  org.vllm-hust.lmcache-ascend-vllm-adapter \
  --file lmcache-ascend-config.json
vllm-hust-ext extension enable \
  org.vllm-hust.lmcache-ascend-vllm-adapter
vllm-hust-ext run --dry-run -- vllm serve MODEL
```

`LMCacheMPConnector` is a host-recognized connector and must not be paired with
a fabricated `lmcache.integration.vllm.lmcache_mp_connector` module. Dynamic
connectors are accepted only when their connector name exactly matches the
official LMCache or LMCache-Ascend module path.

Only one enabled extension may claim vLLM's `--kv-transfer-config` in a single
process. Enabling Mooncake and LMCache together therefore fails closed instead
of silently choosing one. Experimental profile wheels pin the exact Manager
development version until the compatibility contract is frozen.

Package removal is deliberately split from runtime intent. Stop or restart the
host process as appropriate, then disable and forget the extension before using
the Python package manager:

```bash
vllm-hust-ext extension disable org.vllm-hust.lmcache-provider
vllm-hust-ext extension forget org.vllm-hust.lmcache-provider
pip uninstall vllm-hust-lmcache-provider
```

`forget` only removes Manager-owned configuration and enabled intent. It
refuses enabled extensions and never stops a shared service, clears KV data, or
deletes Kubernetes resources.

Installing an extension distribution only makes it discoverable. Enabling is
explicit and stored in the user configuration. Discovery reads installed
distribution metadata and the static bundle manifest without importing its
implementation modules.

Third-party host providers register factories only under the project-owned
entry-point group `vllm_hust_ext.providers`. Extension distributions register
static manifests under `vllm_hust.extension_bundles`. Neither namespace claims
an unofficial `vllm.*` entry-point group.

