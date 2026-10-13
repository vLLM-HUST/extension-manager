# Internal hostile review: evidence-bound inference-extension activation

This is an internal adversarial review for issue #64, not an external peer
review, a human approval gate, or evidence that OSDI will accept the work.
Reviewed on 2026-10-13: Manager main
`0a6fdbc7784a0db0a92fc50615f5ca3efbf5f966`, `paper/main.tex`, its related-work
ledger, and the source-bound baseline/native and model-window artifacts.
The H2 correction additionally uses the four frozen audit files in local
`7889512b0b98b6a17d887511357823f2d5acab53`, published as PR #160. Its merge/CI
status is separate from the scientific assessment below. No paper source,
historical prediction, baseline, experiment input, or raw trace was changed.

## Verdict and a precise research contribution

**Current verdict: NO-GO for a validated prevention/recovery/low-overhead
Research Track headline.** The completed matched H1 cell falsifies prevention
for its tested runtime. H2's eligible independent subset is n=4, TP2/TN2,
FP0/FN0; one historical reject consumed an already diagnosed report and must
be excluded. H3/H4 formal counts remain zero. The real 60-request qualification
is useful new feasibility evidence, but cannot repair those missing results.

A concrete, non-product contribution worth pursuing is an **epoch-scoped
admission protocol for heterogeneous inference extensions**: compile a finite
set of semantic obligations and named observer authorities; bind each to the
plan, launch, serving-process incarnation and route generation; then refine
transaction intents through independently observed effects, queries and
receipts at the traffic boundary. The research question is whether this
composition prevents externally visible false effectiveness under evidence
loss, process replacement and interrupted activation while retaining useful
availability. Packaging APIs, SQLite, hash manifests and an enabled-state UI
are implementation choices, not this contribution.

This is a proposed systems contribution, not an established novelty theorem
or a successful implementation claim. A serious alternative is a competent
versioned rollout controller plus readiness checks, fencing and a routing
proxy. ECPA must demonstrate where a finite, authority-specific extension
obligation adds safety or diagnosis beyond that alternative, with equivalent
information and workload. Merely renaming existing mechanisms is insufficient.

## Claim-by-claim challenge

| Paper claim or mechanism | Closest prior mechanism; challenge | Admissible evidence and required boundary |
| --- | --- | --- |
| Contract declares capabilities, resources, lifecycle and process obligations (contribution 1) | OSGi already resolves modules and has lifecycles; Kubernetes controllers already distinguish desired and observed state. Declarative fields alone are not a new systems result. | Make the distinctive unit the frozen semantic obligation across serving roles and independent authorities. Demonstrate multiple extension classes whose effects cannot be represented by a single receiver readiness bit; n4 composition results do not establish taxonomy completeness. |
| Immutable execution plan/compiler (contribution 2) | Dependency resolution, typed resource ownership and configuration validation are established techniques. | Claim the implemented compilation boundary and explicit unknown outcomes. Evaluate nontrivial, independently derived interactions and both install orders before claiming broad composability; exclude supplied diagnoses from detection scores. |
| Transactional activation, exposure and rollback (contribution 2) | Transaction commit, compensation and consistent network update precede ECPA. | Identify the intent/effect/query/receipt refinement across a source that actually controls traffic. SQLite crash recovery is neither distributed atomic commit nor physical exactly once. The predecessor is a route/plan snapshot, not a guarantee that external data was restored. |
| Host evidence and independent evaluation (contribution 3) | Acto checks operator convergence, rollback and erroneous operations; Anvil verifies reconciliation liveness. | Potential value is a falsifiable inference-specific obligation oracle and separation of status from exposure. H1's failure is a valid scientific finding, not proof that ECPA prevents the failure. Do not claim first end-to-end controller testing or stronger liveness than Anvil. |
| Freshness, epochs, leases and fences | Leases, versioned updates and transaction identity are historical primitives. | Application to serving-process incarnations can be useful. Need real old/new worker replacement and stale-writer faults, not just different descriptor strings. Hash integrity does not authenticate an artifact against malicious same-user rewriting. |
| Safety argument and four invariants | A proof that the gate opens only after a validator says complete is conditional on truthful semantic sources and exclusive traffic ownership. | State premises explicitly and distinguish the specification from implementation refinement. Wording such as “the gate enforces” or “ECPA enforces” must identify which model/implementation and qualification scope. H1 demonstrates a missing refinement step. |
| Dynamic inference extension context | dLoRA/Toppings already perform real adapter loading/switching; Llumnix migrates live requests; EcoServe cyclically schedules inference instances to keep prefill processing available; this is not model-version or configuration rollout. | Do not imply serving systems lack dynamic coordination. ECPA targets heterogeneous independently packaged extension obligations, not a better adapter loader, migration algorithm or scheduler. |
| Recovery and serving availability | Role-isolated restart/reconnect is demonstrated by RobustRL; the contexts differ, but recovery of one control role while others stay alive is not itself new. | The 60-request run kills the native coordinator while both model backends stay live. It establishes bounded control-route reconciliation and delivered responses, not model-backend restart, candidate replacement correctness, full Host-effect correctness or availability for arbitrary failures. |
| Portability, standards and interoperability | Mature lifecycle standards already exist. | One vLLM-HUST/Ascend cell proves neither independent host adoption nor a cross-framework standard. Host/Ascend unpublished or unmerged inputs remain formal-admission blockers even when local functionality succeeds. |

The distinction “not specified by the cited property” is not a claim that a
prior system cannot implement ECPA's obligations. This review does not claim an
exhaustive novelty search. Comparisons below use primary paper/venue sources
and official API documentation, checked live on the review date; abstract-level
mechanism descriptions do not warrant undocumented implementation claims.

## Recent serving mechanisms and historical foundations

| Primary source, checked 2026-10-13 | Mechanism and consequence for positioning |
| --- | --- |
| [EcoServe, OSDI 2026](https://www.usenix.org/conference/osdi26/presentation/du) | Partial disaggregation cyclically activates inference instances to preserve prefill availability, with adaptive routing. This is cyclic inference scheduling/prefill activation, not model-version or configuration rolling deployment; ECPA must distinguish obligation admission from scheduling coordination. |
| [RobustRL, OSDI 2026](https://www.usenix.org/conference/osdi26/presentation/chen-zhenqian) | Role-based isolation and detect/restart/reconnect allow living roles to continue. This is RL post-training rather than independent inference extensions; ECPA cannot use its own coordinator-only fault to claim a new general recovery principle. |
| [Agentix, NSDI 2026](https://www.usenix.org/conference/nsdi26/presentation/luo) | Program-aware scheduling uses dependencies/context across LLM calls. Semantic serving context is already an explicit systems object; ECPA's contract must be about activation obligations rather than claim generic semantic awareness. |
| [Toppings, ATC 2025](https://www.usenix.org/conference/atc25/presentation/li-suyi-toppings) | Coordinates CPU computation, loading and GPU switching for LoRA adapters. A concrete dynamic extension class with actual execution effects, useful to motivate a future effect oracle; not an ECPA baseline result. |
| [Mooncake, FAST 2025](https://www.usenix.org/conference/fast25/presentation/qin) | KV-centric disaggregation combines caches and scheduling across hardware resources. It motivates external resource/authority boundaries; its production scale and gains are not inherited by ECPA. |
| [SGLang, NeurIPS 2024](https://proceedings.nips.cc/paper_files/paper/2024/hash/724be4472168f31ba1c9ac630f15dec8-Abstract-Conference.html) | Frontend/runtime semantics, RadixAttention and structured decoding provide serving optimizations. A future second-host evaluation would require native obligations, not a claim based on a portable JSON manifest alone. |
| [dLoRA, OSDI 2024](https://www.usenix.org/conference/osdi24/presentation/wu-bingyang) and [Llumnix, OSDI 2024](https://www.usenix.org/conference/osdi24/presentation/sun-biao) | Adapter merge/unmerge and request/adapter migration, and live request rescheduling, respectively. Compare their stated properties without claiming they verify arbitrary third-party plugins or that they cannot be extended to do so. |
| [Acto, SOSP 2023, author paper](https://marshtompsxd.github.io/pub/sosp23_acto.pdf) | End-to-end operator testing already covers desired-state convergence, recovery and erroneous operations. Independent tests alone are not ECPA's novelty; obligation granularity and process epoch scope must carry the difference. |
| [Anvil, OSDI 2024](https://www.usenix.org/conference/osdi24/presentation/sun-xudong) | Verified eventually stable reconciliation is stronger liveness evidence than ECPA's finite abstract model or one recovery trace. Admission safety and liveness must be separated. |
| [Abstractions for Network Update, SIGCOMM 2012, author paper](https://www.cs.princeton.edu/~dpw/papers/network-update-sigcomm12.pdf) | Controlled version transitions establish per-packet/per-flow consistency. ECPA borrows exposure discipline and does not establish those network properties. |
| [Consensus on Transaction Commit, TODS 2006, author publication](https://www.microsoft.com/en-us/research/publication/consensus-on-transaction-commit/) | Distinguishes two-phase commit and fault-tolerant Paxos Commit. A single SQLite coordinator with independently queried effects is not a new consensus or nonblocking distributed commit algorithm. |
| [Envoy xDS, official protocol](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol) | Versioned configuration and ACK/NACK semantics are a concrete alternative foundation. The comparator must include competent routing/readiness behavior, not only a bare ACK. |
| [OSGi Core R8, official specification](https://docs.osgi.org/specification/osgi.core/8.0.0/) and [in-toto, USENIX Security 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | Mature module lifecycles and artifact provenance respectively. Lifecycle success and provenance do not, by themselves, establish an inference effect in all required processes. These limitations do not imply the systems are defective. |

No numerical gains from the cited serving papers are transferred to ECPA.
Search results for recent recovery preprints were not treated as peer-reviewed
mechanisms when a matching primary venue record was not verified.

## Baseline fidelity and the comparison that matters

The exact H1 entry-point/manual/ECPA paths retain identical pinned host, model,
plugin, hardware and TP2 topology. The common launcher may carry measurement
instrumentation, but observer data must remain outside each baseline's activation
policy. A baseline's measurement receipt cannot become an ECPA admission guard.
The baseline native-source audit correctly says Manager-afterprepare is N/A
for unmanaged entry points/manual hooks; adding ECPA transactions to those arms
would change the intervention. N/A is also not baseline failure or zero recovery.

A future fair recovery comparison needs a common *observable failure objective*
(such as an owned serving worker's death and the system's native restart path),
not identically named internal phases absent from two arms. Keep the original
inapplicable cell and preregister a new applicable one; worker-relaunch tooling
is not a completed three-arm experiment. Externally launched backends that stay
alive during a Manager SIGKILL cannot establish baseline worker recovery.

For prevention, include a strong design comparator: documented manual rollout
with a versioned proxy, process-role readiness and explicit health checks, or a
controller using equivalent observer inputs. Freeze its policy before seeing
outcomes and measure safety *and* useful successful admissions. A reject-all or
closed-route system trivially looks safe but is not useful. This alternative is
currently unexecuted; do not publish a ranking. An ablation should vary one
primitive at a time (epoch binding, authority separation, semantic obligation,
traffic admission), sharing instrumentation and fault observation. This is a
proposal requiring new registration, not a retrofit of historical arms.

## What the real 60-request window does and does not establish

PR #158's archived 186 files and portable verifier independently join all 60
frozen IDs to authority observations across durable native prepare, actual
coordinator SIGKILL, restart and reconciliation. In this bounded schedule,
deadline delivery loss is 0, duplicate admissions are 0 and reused successful
response IDs are 0. The independently checked route remains predecessor
generation 0 through client.stop, not just until the first recovery marker.
The candidate is live but never exposed. Runtime source is exact Manager
`3a55952299655d8319c49f34efa59946fc30d63f`, distinct from later analysis source.

These are delivery/control-route observations. Backend execution duplicates,
side-effect exactly once and the full objective remain unknown. Both Qwen
backends keep running and use the same model; an exact response oracle verifies
completion bytes but is not a semantic extension-effect oracle or a proof of
correctness when replacing model generations. Seven phase markers do not
substitute for the independent complete finite client trace. Neither does a
60-request schedule establish tail-latency, throughput, overhead, traffic
coverage outside the frozen interval, general fault tolerance, or H1 prevention.
A route that always serves the predecessor can pass this before-effect recovery
case without implementing useful successful candidate admission.

## Required paper corrections and limitations

The reviewed main has stale hard-coded “five-case”, “n=5”, and “two admits and
three rejects” statements in the introduction, implementation/evaluation
summary, H2 limitations and conclusion. PR #160's report-input audit supports
replacing these with n4/TP2/TN2 and explaining the excluded report-consumption
case. Do not overwrite historical predictions or relabel that provider as an
independent detector. Paper agents should apply this correction after the audit
merges; this independent review does not edit their files.

The related-work ledger's “real traffic authority is absent” is now too broad:
an independent live HTTP authority has nonformal finite-window qualification.
The formal real-host prevention boundary remains missing. Update the ledger
with those two distinct statements, keeping H1's falsification intact.
Likewise, distinguish an implemented reference invariant from a validated
end-to-end invariant and an abstract model from implementation refinement.

Explicit limitations should include trusted same-user host/runner rather than
malicious-plugin isolation; semantically false authorized sources; incomplete
obligation taxonomy; fixed TP2 process membership; no established elastic
replacement correctness; single Host/Ascend tuple; matched recovery/performance
arms absent; before-effect-only model-window recovery; live predecessor and
no candidate exposure; unknown backend execution duplicates; and short, frozen
synthetic completion workload rather than representative serving load. Formal
Host/Ascend merged-source admission remains separate from local qualification.

## Next falsifiable work, in order

1. Admit the exact source-matched Host/Ascend tuple through the existing formal
   gate; implement and observe a traffic boundary bound to actual native Host
   semantic effect. Do not relax issuer rules to fill a result cell.
2. Register a fresh matched H1 cell with actual full-obligation admission,
   independently observed omission/replacement and revocation. Preserve the
   historical falsified cell. Require useful valid-candidate admissions too.
3. Expand independently derived H2 interactions across conflict surfaces and
   orders; retain unknown outcomes and report the prediagnosed input case
   separately. Current n4 perfection is descriptive, not prevalence evidence.
4. Execute a new native common-fault H3 comparison from each arm's actual
   lifecycle, including failures after effects as well as before effects,
   rather than inferring success from the finite coordinator-only window.
5. Run preregistered H4 under equivalent manual/ECPA workload and conditions,
   retaining startup versus steady-state metrics and bounds.

These are scientific acceptance conditions, not a request to wait for human
review. Meanwhile the executable artifacts, falsified H1 result and honest
finite-window qualification are reviewable progress. Current evidence supports
a contract, reference protocol and evaluation finding; it does not yet support
claiming an OSDI-ready prevention system.
