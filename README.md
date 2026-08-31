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

Production Stack health evidence is not accepted as a bare boolean:
`cluster_reachable=true` requires `cluster_evidence`, and
`rollout_healthy=true` requires both a reachable cluster and
`rollout_evidence`. Rendered operator plans keep install, upgrade, rollback,
and uninstall as explicit operator-owned `null` actions.

Mooncake runtime detection covers the mutually exclusive official CUDA,
CUDA 13, non-CUDA, NPU, MUSA, and EFA wheel variants. Installing more than one
variant is reported as an incompatible/degraded environment instead of picking
one arbitrarily. The experimental Mooncake profile currently declares
`>=0.3.12.post1,<0.4`. Its Store REST and vLLM KV configuration surfaces are
marked explicitly unversioned because upstream does not publish independent
protocol semantic versions; the Manager does not invent `1.0` contracts for
them.

The official 0.3.12.post1 non-CUDA wheel has completed both a two-process 1 MiB
TransferEngine TCP write and an isolated Store put/exist/get/remove round trip
on `a100-dev`. Store deletion remained subject to Mooncake's object lease and
was performed only for the probe's UUID-scoped key after lease expiry. This is
data-path evidence, not yet a vLLM connector cache-hit result; alpha remains
frozen until that final connector gate and the other host gates pass.

> **Compatibility freeze:** Manifest `0.2-experimental` and the former Bundle
> v1 prototype are not stable APIs. No alpha package will be published until
> the vLLM, KV-system, and control-plane end-to-end gates pass.

```bash
pip install vllm-hust-ext
pip install bidkv

vllm-hust-ext extension list
vllm-hust-ext extension status org.vllm-hust.bidkv
vllm-hust-ext extension check org.vllm-hust.bidkv
```

The BidKV example currently describes the legacy experimental
`vllm.victim_selector` contract. The fresh vLLM-HUST 0.23 fork does not provide
that protocol. The main BidKV distribution no longer registers this private
entry point, and Manager `run` refuses an unverified or incompatible in-process
scheduler policy. New core work must align with upstream scheduler-plugin RFC
#51608 and draft PR #51601 instead of adding a second private victim-selector
API. There is no supported fresh-fork enable command until that contract is
stable and the real scheduler/rollback gates pass.

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

The current LMCache profile targets the official 0.5.x `lmcache server`
surface. Compatibility is read from the external service's `/lmc_version`
endpoint and health from `/healthcheck`; a local `lmcache` installation is not
treated as proof of the remote service version. The 0.5.4 wheel exposes
`LMCacheMPConnector` and `LMCacheConnectorV1Dynamic`; the former needs no
fabricated dynamic module path.

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

