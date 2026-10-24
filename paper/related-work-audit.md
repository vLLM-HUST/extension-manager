# Related-work and novelty audit

2026-10-15 supplement: the public paper now compares directly with distributed
predicate checking (D3S, NSDI 2008) and distinguishes its finite source-drained
observation from a distributed snapshot or continuing effect guarantee. The
source-checked argument and same-information predicate-monitor baseline design
are in
[`distributed-predicate-and-source-closure-audit-20261015.md`](../docs/research/distributed-predicate-and-source-closure-audit-20261015.md).
That stronger comparator is not implemented or measured; no claim that ECPA
must be safer with identical information follows. The historical ledger below
remains dated 2026-10-13; its then-missing traffic authority is not a claim that
later nonformal HTTP-gate qualifications never occurred.

Literature sources: checked 2026-10-13 against original conference, DOI, or
author paper pages. Runtime evidence: reconciled 2026-10-14 against the sealed
artifacts and implementation pointers below. This is an internal claim ledger,
not submission text. One H1 cell is complete and falsifies prevention; H2 has
four independently scored source cases; H3/H4 have zero formal runs. A real
authority-owned HTTP gate has invocation-only qualification. Its formal
semantic producer and matched prevention evaluation remain incomplete.

## Defensible contribution after H1

The crisp systems contribution that the current evidence can support is:

> A falsifiable activation contract and protocol that freeze the required
> serving-process epochs, assign each effect obligation to the authority able
> to observe it, and require those facts before external exposure.

The protocol is implemented enough to collect and validate a real nine-start
cell. It is not yet a validated prevention mechanism: in the partial-worker
cell, all three ECPA starts retained an effective claim at 0.5 process coverage.
The paper must say that this falsifies H1 for the tested implementation. A real
traffic-boundary authority followed by a fresh matched rerun is required before
claiming that ECPA prevents false-effective exposure.

This positioning separates four artifacts that reviewers can otherwise
conflate:

1. The **contract** declares typed resources, process obligations, evidence
   authority, and a rollback predecessor.
2. The **protocol** binds plan, launch, process epoch, source, and evidence.
3. The **reference implementation** failed the tested prevention property.
   A subsequently qualified HTTP enforcement point accepts invocation evidence;
   formal effect obligations are still unverified and fail closed. That later
   qualification does not revise the original H1 result.
4. The **evaluation method** made that failure observable; validator PASS says
   the record is admissible, not that H1 passed.

## Closest mechanisms

| Mechanism and primary source | What the cited work establishes | Exact boundary to ECPA |
| --- | --- | --- |
| [D3S, NSDI '08](https://www.usenix.org/conference/nsdi-08/presentation/d3s-debugging-deployed-distributed-systems) | Instrumented distributed predicates over ordered global snapshots, with membership and failures. | Closest runtime-checking comparison. ECPA's proposed difference is declaration-to-obligation compilation and generation admission, not process-local event collection. An equally informed monitor and gate is unmeasured. |
| [Chandy--Lamport, TOCS '85](https://www.microsoft.com/en-us/research/publication/distributed-snapshots-determining-global-states-distributed-system/) | Distributed global-state snapshots and stable-property detection. | A finite source-drained ACK is not the complete snapshot algorithm, an uninstrumented-channel cut, or proof of continuing numerical effectiveness. |
| [Acto, SOSP '23](https://doi.org/10.1145/3600006.3613161) | End-to-end generated tests check whether a cloud operator drives a managed system to desired states and recovers from erroneous states. | Closest testing analogue. Its state oracle does not by itself assign an inference hook's effect to a distinct producer authority or freeze every serving-process epoch. |
| [Anvil, OSDI '24](https://www.usenix.org/conference/osdi24/presentation/sun-xudong) | Verifies eventual stable reconciliation for Kubernetes controllers under failures and asynchrony. | Stronger controller-liveness reasoning than ECPA. ECPA's narrower question is whether authority-owned effect facts cover a fixed inference plan before exposure; it does not verify general reconciliation liveness. |
| [Envoy xDS](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol) | Versioned configuration delivery with nonce/version-correlated ACK or NACK. | A receiver ACK establishes protocol acceptance, not execution of a particular hook in every downstream worker. This API source is retained because it defines the exact ACK semantics. |
| [Abstractions for Network Update, SIGCOMM '12](https://doi.org/10.1145/2342356.2342427) | Versioned network configurations and controlled packet exposure provide consistent network-update semantics. | Closest exposure concept. ECPA borrows versioned exposure, but its obligations cross host, plugin, provider, and process authorities and do not provide per-packet consistency. |
| [Kitsune, OOPSLA '12](https://doi.org/10.1145/2384616.2384635) | Dynamic update points and explicit program-state transformation update a running C program. | ECPA neither transforms live program state nor proves transformer correctness; it coordinates separately packaged extensions around restart/activation boundaries. |
| [in-toto, USENIX Security '19](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | Authorized supply-chain steps bind artifact provenance. | Authenticates how an input artifact was produced, not whether a live worker executed the planned effect. |
| [CamFlow, SoCC '17](https://doi.org/10.1145/3127479.3129249) | Kernel-level whole-system data provenance captures and streams system behavior. | Provides broader OS-level capture. ECPA uses narrower, obligation-specific receipts and must still justify semantic meaning and source authority. |
| [Leases, SOSP '89](https://doi.org/10.1145/74850.74870) | Time-bounded authority supports fault-tolerant cache consistency. | Historical basis for expiry and fencing. ECPA's process epochs and replay fence are an application of freshness ideas, not a new lease protocol. |
| [OSGi Core R8](https://docs.osgi.org/specification/osgi.core/8.0.0/) | Bundle lifecycle, module resolution, and a dynamic service registry. | Closest mature module lifecycle. Active bundle/service state does not specify the frozen inference-worker effect coverage tested by H1. |
| [dLoRA, OSDI '24](https://www.usenix.org/conference/osdi24/presentation/wu-bingyang) | Dynamically merges/unmerges LoRA adapters and migrates requests/adapters among serving replicas. | Closest recent dynamic inference-adapter mechanism. It optimizes one adapter class and request placement; it does not claim a general cross-authority activation proof for independently packaged host modifications. |
| [DistServe](https://www.usenix.org/conference/osdi24/presentation/zhong-yinmin), [Llumnix](https://www.usenix.org/conference/osdi24/presentation/sun-biao), and [Sarathi-Serve](https://www.usenix.org/conference/osdi24/presentation/agrawal), OSDI '24 | Disaggregated serving, live request migration, and chunked-prefill scheduling create real multi-process, KV, and routing surfaces. | Serving context and H4 workload controls. Their published performance gains are not ECPA gains and cannot substitute for matched manual/entry-point/ECPA runs. |

Project documentation remains appropriate only for exact API behavior such as
vLLM entry-point loading, xDS ACK/NACK, and OSGi lifecycle. Novelty comparisons
should cite the peer-reviewed mechanisms above.

## Seven-dimension mechanism comparison

“Not specified” below means absent from the cited mechanism's stated property;
it does not mean that an implementation could not be extended.

| Dimension | Loader / module lifecycle | Reconciler / ACK | Provenance | Consistent update | ECPA specified property | Current evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Target-set freeze | Package, entry point, bundle, or service identity | Desired objects and controller/receiver state | Artifact, step, data, or OS-event subjects | Packets or clients assigned to a version | Required process roles, ordinals, and epochs in an immutable plan | H1 records bind a TP2 target set; elastic membership remains untested. |
| Authority separation | Loader/registry owns load state | Controller and receiver own desired/accepted state | Authorized build actor or capture subsystem | Update controller and switches | Intent, planner, host, provider, external service, and traffic authority are distinct | A real independent HTTP authority has invocation-only qualification; formal semantic authority is unregistered. |
| Evidence freshness | Load/lifecycle event | Generation, nonce, or reconciled state | Signed step or captured event lineage | Configuration version | Plan, launch, epoch, nonce, validity interval, replay fence | H1 offline validation passes; this did not force claim revocation. |
| Exposure gating | Not specified by vLLM/OSGi loading state | Routing/readiness can gate delivery if configured | Not a serving route | Core property of consistent network update | Commit-ready should precede generation admission | Later real HTTP qualification records 503→200→503 with invocation evidence. The original H1 remains falsified; no formal semantic prevention rerun has passed. |
| Conflict ownership | Package/service resolution | Resource validity and controller ownership | Actor authorization, not extension semantics | Policy/version conflict | Typed exclusive/shared/composable resource claims | H2's independently scored four-case subset gives TP=2/TN=2/FP=FN=0; breadth, both install orders, and formal runtime qualification remain incomplete. |
| Rollback target | Prior bundle/module state | Prior desired or last accepted configuration | Prior artifact/statement | Prior configuration version | Digest-pinned predecessor plan plus failure class | H3 injected recovery and rollback results are incomplete. |
| Process coverage | No inference-worker obligation in cited loader API | Receiver/controller health is not downstream hook invocation | Capture may be broad but lacks ECPA obligation semantics | Packet path, not hook set | Per-obligation coverage of frozen process epochs | The only H1 cell measured 0.5 coverage and still claimed effective. |

## Why inference extensions are a distinct case

Generic configuration systems already address desired state, validation,
versioning, rollout, and rollback. Independently developed inference extensions
add a narrower combination that the paper must demonstrate rather than assume:

- one logical service fans out into parent, engine, and worker processes, and a
  successful import in one process does not establish hook invocation in the
  others;
- scheduler, KV, model-execution, communication, and observability extensions
  modify different lifecycle phases and can claim the same semantic host
  resource through unrelated packaging interfaces;
- provider translation and external services may be maintained by authorities
  different from the loader and host runtime; and
- dynamic worker replacement makes a process-level observation stale even when
  package and configuration identities are unchanged.

These points motivate the contract. They do not establish its effectiveness;
H1--H4 supply that evidence.

## Baseline and external-validity ledger

| Item | Current admissible status | Claim boundary |
| --- | --- | --- |
| H1 entry-point / manual / ECPA arms | One pinned partial-worker TP2 cell, three starts per arm, five lifecycle sources per start; offline validation passes | H1 prevention is falsified for this cell. Startup fields are not H4. |
| ACK + readiness + manual health alternative | Mechanistically plausible, not an executed fourth arm | Discuss as an alternative design only; do not rank it. |
| H2 real composition | Four independently scored source cases, TP=2/TN=2/FP=FN=0; one prediagnosed-report input excluded with original records retained | Finite source-case detection only; no population precision/recall, formal runtime, composition-quality, or performance claim. |
| Real HTTP authority | Invocation-only qualification, 95 raw rows and actual 503→200→503 | Real admission behavior, not formal semantic prevention. |
| Selected logical KV bytes | One independent TP2 qualification with 56 receipts, 28 layers per rank, 56 MiB selected logical bytes, 201 raw rows and a successful nonce task | No full physical-KV equivalence, native-attention correctness, full-model quality, or performance claim. |
| Native attention observation | Fresh R4 completes HTTP200/task check, 56 tensor receipts, 56 native argument completions and two worker source closures in an authenticated 261-row full prefix; original R1–R3 failures remain retained | Finite selected logical bytes and parameter-completion association only. No numerical attention correctness, continuing effectiveness, formal H3/H4, full-model quality or performance claim. |
| H3 recovery | Frozen plan; no formal results | No rollback/recovery-rate claim. |
| H4 overhead | Frozen plan; no formal results | No startup, throughput, or p99 overhead claim. |
| Cross-runtime portability | No second inference runtime | The paper is a deep single-runtime study. A second runtime is required only for a cross-framework generality claim. |

## Current evidence pointers and remaining research decision

- H1: `paper/artifacts/h1-r5/` and the paper's generated H1 evidence;
  nine formal starts, not nine successful
  prevention outcomes.
- HTTP authority: PR #144 and `experiments/exposure_gate/loopback_traffic.py`; formal semantic
  observation remains rejected in `loopback_traffic._observation_sha`.
- H2: [experiments/real_mod_composition/artifacts/h2-scoring-input-audit-20261013/](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/140a046d34ecf50bb8de3d8b19a7d70a6b0490e0/archive/mod-targeted-20261023/manager-experiments/snapshot/experiments/real_mod_composition/artifacts/h2-scoring-input-audit-20261013/);
  PR #160 excludes the prediagnosed-report consumer; PR #192 corrects the stale
  five-case detection claim.
- Selected tensor bytes: PR #193,
  [experiments/formal_campaign/artifacts/kv-selected-tensor-observation-20261014/](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/b3d2ed2692b5575b5ae77b93fc82e32c9119be8e/archive/mod-targeted-20261023/manager-formal/snapshot/experiments/formal_campaign/artifacts/kv-selected-tensor-observation-20261014/),
  and `verify_kv_selected_tensor_observation.py`. The full receiver payloads and
  source-map replay support the finite claim; PR #194 binds the paper generator
  to those inputs.
- Attention R4: PR #201 and
  [experiments/formal_campaign/artifacts/attention-source-drained-observation-20261014-r4/](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/b3d2ed2692b5575b5ae77b93fc82e32c9119be8e/archive/mod-targeted-20261023/manager-formal/snapshot/experiments/formal_campaign/artifacts/attention-source-drained-observation-20261014-r4/);
  the isolated stdlib verifier replays the full 261-row prefix and original source
  closures. PR #202 derives paper counts from that frozen archive. Original R1–R3
  failures retain their independent classifications; source closure proves a
  finite observation, not continuing semantic validity.
- Formal source policy: PR #196 does not register a semantic producer or prove
  controller-generation/lease/worker-replacement coverage. The original H3/H4
  matrices remain unqualified.

The immediate hostile-review verdict is **no-go for a paper whose headline
claim is false-effective prevention**. The next evidence must connect the real
HTTP authority to authority-owned semantic effect obligations, rerun the H1
cell under a new preregistration, and then complete H2--H4. If prevention remains
false, the work can still support an artifact or
experience-paper claim about a contract and evaluation method that exposes
false effectiveness, but it cannot present the current runtime as enforcing
the intended safety property.
