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
- the Production Stack Provider renders Helm/Kubernetes inputs and dry-run
  plans without applying them.

A plugin, KV connector, external KV system, and control-plane policy remain
different kinds. Installing or enabling an adapter never gives this manager
authority to start shared services, change drivers, delete KV data, or mutate a
production cluster.

Production Stack health evidence is not accepted as a bare boolean:
`cluster_reachable=true` requires `cluster_evidence`, and
`rollout_healthy=true` requires both a reachable cluster and
`rollout_evidence` plus structured `component_evidence` for controller
reconciliation, Router traffic, and an autoscaler decision. It also requires a
configured Kubernetes context, a vLLM OpenAI backend endpoint, and structured
`router_data_plane_evidence`: mock traffic cannot claim health, and the
evidence must show a real model plus backend 5xx and recovered 2xx results. A reported
`ownership_conflicts` entry projects `incompatible + degraded`; in particular,
an HPA and a `VLLMRouter` controller may not both own
`Deployment.spec.replicas`. Rendered operator plans keep install, upgrade,
rollback, and uninstall as explicit operator-owned `null` actions.

The official Production Stack controller at commit `1b87c11a` has now
reconciled a `VLLMRouter` into owned RBAC, Service, and Deployment resources in
an isolated Kubernetes 1.34.11 cluster. The official Router forwarded an
OpenAI-compatible completion request to an external test backend, and a real
metrics-server CPU signal scaled a separately owned Router Deployment from one
to three replicas. The separation is intentional: a negative test proved that
placing an HPA on the operator-owned Deployment creates a two-writer conflict.
On the arm64 host `180-ascend-bench`, a Router built from the same upstream
commit returned HTTP 500 for an absent backend, then HTTP 200 and `ROUTER_OK`
from the existing `zai-org/GLM-4-32B-0414` service after only the isolated
Router was reconfigured. The product does not require amd64. The
`vLLM-HUST/production-stack-hust` thin fork now passes a GitHub-hosted arm64
image build and Router entrypoint smoke test on `main`; publication and clean
host reproduction remain gated. No self-hosted Actions runner is required.

Mooncake runtime detection covers the mutually exclusive official CUDA,
CUDA 13, non-CUDA, NPU, MUSA, and EFA wheel variants. Installing more than one
variant is reported as an incompatible/degraded environment instead of picking
one arbitrarily. The experimental Mooncake profile currently declares
`>=0.3.11.post1,<0.4`. Its Store REST and vLLM KV configuration surfaces are
marked explicitly unversioned because upstream does not publish independent
protocol semantic versions; the Manager does not invent `1.0` contracts for
them.

The official 0.3.12.post1 non-CUDA wheel has completed both a two-process 1 MiB
TransferEngine TCP write and an isolated Store put/exist/get/remove round trip
on `a100-dev`. A separate Ascend NPU 4 run completed a real
MooncakeStoreConnector save/load hit: nine keys and 133,191,072 bytes each way,
with local prefix caching disabled. Master outage produced partial save
failures while inference remained available, and recovery restored save/load
without restarting vLLM. Alpha remains frozen for the remaining online
restart/rollback and support-matrix gates.

> **Compatibility freeze:** Manifest `0.2-experimental` and the former Bundle
> v1 prototype are not stable APIs. No alpha package will be published until
> the vLLM, KV-system, and control-plane end-to-end gates pass.

The pinned pass/fail combinations and lifecycle rollback owners are summarized
in [`docs/support-matrix.md`](docs/support-matrix.md). A passing point does not
implicitly validate the rest of an experimental version range.

```bash
pip install vllm-hust-ext
pip install bidkv

vllm-hust-ext extension list
vllm-hust-ext extension status org.vllm-hust.bidkv
vllm-hust-ext extension check org.vllm-hust.bidkv
```

BidKV is supported by the pinned vLLM-HUST 0.23 host through the generic typed
`vllm.scheduler.policy.v1` contract. The main BidKV distribution does not
register the private legacy `vllm.victim_selector` entry point. Manager
converts the extension manifest to the host-native startup manifest, selects
`org.vllm-hust.bidkv/victim-selector`, and refuses incompatible official-vLLM
hosts. This support statement applies to vLLM-HUST, not to official vLLM while
the upstream scheduler-plugin contract is still unsettled.

```bash
vllm-hust-ext extension enable org.vllm-hust.bidkv
vllm-hust-ext run -- vllm serve MODEL
```

Only one enabled extension may claim vLLM's `--kv-transfer-config` in a single
process. The Manager rejects conflicting connector plans instead of silently
choosing one. Package removal remains separate from runtime intent: `forget`
only removes Manager-owned configuration and enabled intent and never stops a
shared service, clears KV data, or deletes Kubernetes resources.

Installing an extension distribution only makes it discoverable. Enabling is
explicit and stored in the user configuration. Discovery reads installed
distribution metadata and the static bundle manifest without importing its
implementation modules.

Third-party host providers register factories only under the project-owned
entry-point group `vllm_hust_ext.providers`. Extension distributions register
static manifests under `vllm_hust.extension_bundles`. Neither namespace claims
an unofficial `vllm.*` entry-point group.

