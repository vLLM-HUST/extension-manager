# Baseline Host callback observer

`experiments/native_attention_candidate/baseline_host_binding.py` adds an
explicit **activation-only**, nonformal baseline observation. It does not create
a Manager handoff, prove compiled Plan execution, or qualify tensor/operator
effects. Host Python plugins keep their existing trusted in-process boundary:
Unix peer credentials authenticate the process, not malicious Python call stacks.

Before starting the Host, create `HostObserver(socket_path, journal_path,
profile=profile, arm=arm, host_sources=host_sources)` in a fresh owned mode0700
directory. `profile` is a loaded selected-KV `ActivationProfile`; `arm` is
`entry-points-unmanaged` or `explicit-manual-hooks`. `host_sources` maps canonical
installed paths to exact SHA256 for these five files:

- `vllm/plugins/__init__.py`
- `vllm/plugins/evidence.py`
- `vllm/entrypoints/cli/main.py`
- `vllm/v1/executor/multiproc_executor.py`
- `vllm/v1/engine/core.py`

Merge `observer.environment()` into the **exec environment** of the actual
baseline Host, then call `observer.attach_host(process_identity(child.pid))`.
The environment selects this module's `record_event` as the strict real Host
sink and binds the owner, trial, profile, actual direct MOD enable and identical
provider configuration. It sets enabled Manager bundles empty; after baseline
configuration, absent or empty remains accepted, while nonempty is rejected.
It neither supplies native correlation aliases nor interprets evidence `bound`
as Manager authentication. A separate baseline-native scope may supply opaque
correlation aliases, but must independently bind that scope and current `/proc`
environment to the resulting observer record.

Each callback uses a new Unix connection, fresh owner nonce, SO_PEERCRED, current
kernel epoch, owned Host ancestry, actual exec environment, profile/calibration
and source validation. The owner fsyncs the hash-chained ingress record before
sending its exact envelope digest ACK. The callback rejects a substituted owner,
changed socket, nonce or ACK. Rejected ingress prevents finalization.

After startup provides actual API0/worker0/worker1 process peers, call
`observer.finalize(peers)`. It requires each peer's current kernel and a matching
authenticated callback carrying **Host-assigned** identity. Earlier environment
roles cannot be promoted by merely passing a peers JSON. For each exact epoch,
the selected-KV resolved→invoked chain must match the arm: stock resolution for
vanilla, `baseline-explicit-callable` resolution for manual. `invoked` remains an
activation fact, including the possibility of a callable returning without an
effect; the later full native consumer must independently establish all effects.

Real Host47 calls the serve parent's identity binder when argv selects `serve`,
and calls the worker identity binder at the beginning of `worker_main`; neither
is conditional on Manager activation. CPU integration tests run the exact CLI
binder and CPU-safe worker prefix from real source, then the full real Host
loader/evidence and this socket transport in three live Python processes. They
isolate heavyweight Host dependencies and use a CPU MOD fixture. These tests
are not native or hardware qualification. Set `ECPA_TEST_HOST_SOURCE_ROOT` to an
installed/source Host root to run them elsewhere; they explicitly skip when
real Host sources are unavailable. Protocol-negative subprocess tests need no
installed Host.

The return schema is `ecpa-baseline-host-observer/v1`, with
`origin=baseline-host-observer`, `activation_only=true`,
`effect_qualification=null`, and `formal_result=false`. It includes owner/Host
and joined peers, observer trial/profile/source identities, authenticated socket
identity and exact ingress **prefix** bytes/hash/last-record hash. Freeze it only
after startup callbacks have settled; additional callbacks change a fresh
finalization and must not be retrofitted into an older frozen record. Always
`observer.close()` in owner cleanup. This module does not implement the next
baseline producer/issuer, native scope or a public response controller.
