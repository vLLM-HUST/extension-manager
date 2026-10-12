# Related-work and baseline audit (editorial notes, not submission text)

Status: source-checked on 2026-10-12. The authors must verify these comparisons
and write the final scientific interpretation. OSDI '27 [requires comparison
with recent and historical systems work](https://www.usenix.org/conference/osdi27/call-for-papers)
and permits AI editing assistance, not a wholly or largely AI-generated paper.
No formal H1--H4 result is implied by this audit.

## Closest mechanisms

| Mechanism | Fact established by its cited design | Boundary to test against ECPA |
| --- | --- | --- |
| [vLLM plugin API](https://docs.vllm.ai/en/latest/design/plugin_system/) and [OSGi Core](https://docs.osgi.org/specification/osgi.core/8.0.0/) | Entry-point loading and bundle/service lifecycle, respectively. | Does a load/active state establish plan-specific invocation in every frozen worker epoch? The cited APIs do not define ECPA's answer; do not claim they are generally unsafe. |
| [Envoy xDS](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol) and [Kubernetes API conventions](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md) | Versioned configuration delivery, ACK/NACK and desired/observed status. xDS explicitly defines ACK/NACK over resource validity. | Compare the exact ACK/condition fact with an application-level plugin invocation fact. A faithful baseline must retain xDS and readiness behavior rather than treating ACK as an invocation receipt. |
| [Consistent network update](https://doi.org/10.1145/2342356.2342427) | Versioned exposure protects packets from mixed network policies. | ECPA borrows the exposure question but its obligations span plugin/provider/worker authorities, not per-packet policy consistency. |
| [Kitsune](https://doi.org/10.1145/2384616.2384635) | Explicit dynamic update points and program-state transformation. | ECPA coordinates separately installed extensions; it neither transforms live program state nor proves transformer correctness. |
| [in-toto](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | Authorized software-supply-chain steps and artifact provenance. | Artifact provenance can authenticate an input; it does not alone establish a live worker's planned effect. |
| ECPA design in this repository | Frozen process targets, resource claims, authority-specific evidence, a traffic-exposure condition and a predecessor rollback target are specified. | These are **design dimensions**, not validated advantages until real multi-MOD and host-worker experiments in #59--#63 pass. |

For a paper mechanism table, compare at least seven dimensions: frozen target
set, evidence authority, freshness/epoch binding, traffic gate, conflict
ownership, rollback target, and process coverage. Avoid a binary checkmark
unless both systems are compared under the same threat and failure model.

| Dimension | Loading/lifecycle API | xDS/status mechanism | Provenance mechanism | ECPA specified status |
| --- | --- | --- | --- | --- |
| Frozen target set | Entry-point or bundle identity, not a serving-worker epoch in the cited API. | Configuration resources and clients, not ECPA's obligation set. | Artifact/step subjects. | Plan-required process roles and ordinals; real elastic epochs untested. |
| Evidence authority | Loader or registry. | Config receiver / controller status writer. | Authorized supply-chain actor. | Host/provider/traffic authority by obligation; real issuer still pending. |
| Freshness and epoch | Load/lifecycle event. | Resource version and nonce or generation. | Provenance statement for a build step. | Plan, launch, process epoch and replay fence specified; formal host campaign pending. |
| Exposure gate | Not defined by the cited plugin API. | Proxy route/readiness can be controlled, but plugin effect must be supplied separately. | No serving route in cited design. | CPU-fixture loopback gate exists; formal host-bound route untested. |
| Conflict ownership | Service/package resolution. | Resource type/config validity. | Step/artifact authorization. | Typed resource claims and projection; real independent-MOD oracle pending. |
| Rollback target | Bundle/lifecycle state. | Last valid configuration may remain in use. | Prior artifact provenance. | Pinned predecessor plan and fail-safe class; matched host rollback pending. |
| Process coverage | No inference-worker obligation in cited API. | Receiver ACK is not each downstream hook invocation. | No live inference-worker coverage. | Frozen per-obligation coverage in reference model and CPU fixture; formal-real cells absent. |

## Inference-system context, not control-plane performance baselines

- [PagedAttention/vLLM (SOSP '23)](https://doi.org/10.1145/3600006.3613165)
  and [PRETZEL (OSDI '18)](https://www.usenix.org/conference/osdi18/presentation/lee)
  study memory management and prediction-serving pipelines.
- [DistServe](https://www.usenix.org/conference/osdi24/presentation/zhong-yinmin)
  separates prefill and decode; [Llumnix](https://www.usenix.org/conference/osdi24/presentation/sun-biao)
  studies request migration; [Sarathi-Serve](https://www.usenix.org/conference/osdi24/presentation/agrawal)
  studies prefill/decode scheduling (all OSDI '24). These choices create
  realistic process, KV and scheduling surfaces for extension composition.
- None of their published throughput gains can be attributed to ECPA. The H4
  primary cost baseline must run the **same host algorithm**, model, topology
  and workload under manual integration; vanilla entry-point loading remains
  a separate arm.

## Baseline-fidelity and evidence work still open

1. Freeze the vanilla-entry-point, manual-integration and ECPA command,
   package, host/plugin/provider commits, model snapshot, workload and
   process topology before any formal run (#59, #62).
2. Record what each baseline actually observes: loader return, configuration
   ACK, health/readiness, per-worker invocation, and external route admission
   are distinct facts. A manual baseline must use the same hook/flag and
   operator checks available without ECPA, not a deliberately weak strawman.
3. Include a plausible ACK-plus-readiness-plus-manual-health alternative in
   the final mechanism comparison if implemented faithfully; currently it is
   **not** an executed fourth arm.
4. Label the source-bound real-MOD preflight and loopback CPU fixture
   separately from an independent H2 ownership oracle and formal H1 traffic
   trace. No precision/recall or runtime-effectiveness result follows from
   either preliminary artifact.
5. Reserve final title/abstract/introduction quantitative claims and a
   full-width mechanism table for measured H1--H4 results and author review.
   A second inference runtime is external-validity work, not present evidence.
