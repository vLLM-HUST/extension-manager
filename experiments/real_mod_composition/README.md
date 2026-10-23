# Real-MOD H2 source preflight

These seven **unmodified** ECPA 0.3 manifests are copied byte-for-byte from
independent MOD repositories at the exact commits, root trees and Git manifest
blobs in `sources.json`. `audit.py` verifies each Git blob before parsing
it with the current Manager. Run `python experiments/real_mod_composition/audit.py`.

This is a source-bound candidate set, **not** the H2 ownership oracle, a
clean-wheel activation test, or a host execution result. The preflight checks
declared host provider/component/version, two explicitly mapped protocol
versions, and same-spelling resource claims. A `candidate-only` result is
not ECPA admission: other API/protocol versions, package entry points,
dependencies, provider projection, external services, process ownership,
runtime effect and performance remain unverified. In particular, two
differently named claims may still own one physical resource.

The vSpec/Knorm/lifecycle-profiler triple has intersecting declared vLLM
0.23.3 version ranges and distinct resource names. BidKV/LatchMoE likewise
have overlapping 0.28.1rc1.dev319 ranges. These are candidates for independent
ownership review and, subsequently, clean-wheel execution; neither has been
run together. The profiler/BidKV case exercises a real source-declared host
version rejection. DiffSpec/vSpec is **not** a currently co-activatable
same-resource conflict. DiffSpec's host range `>=0.25.1rc1,<0.25.2` names
the `vllm-ascend` component, while its `vllm.general_plugins` protocol
requires vLLM core `>=0.28.1rc1.dev319,<0.28.2`. vSpec's host range
requires vLLM core `<0.26`. The two core ranges are disjoint. Both sources
patch the same `NPUModelRunner` methods
([DiffSpec source](https://github.com/vLLM-HUST/vllm-ascend-hust-diffspec/blob/9d9ddc9bfae2b93d03f9e66715e288b229c75e07/diffspec/ascend_patch.py#L369-L372),
[vSpec source](https://github.com/vLLM-HUST/vllm-hust-vSpec/blob/bdd919d24669f09e6eb1987157dfdb5561460f45/src/vllm_hust_vspec/adaptive/runtime.py#L3852-L3854)),
so ownership may become relevant after a future port, but that is not a real
present-day admission result.

The KVCompress/Knorm pair has intersecting declared component ranges at vLLM
core 0.23.3 and vLLM-Ascend 0.23.3. Their differently named exclusive claims
do not trigger the declared-resource checker, while both frozen sources wrap
`Scheduler.update_from_output`. `ownership_observations.json` retains the
exact-commit source excerpts and their digests. Both wrappers call the captured
predecessor, so the observation remains `unknown`: it is not an incompatibility
label. Pinned-host execution in both installation orders and independent review
of their KV-state semantics are required before scoring the case.

Do not add these results to H2 precision/recall or the paper's formal-real
table until an independent oracle, complete host/provider checks and process-
owned execution evidence exist. The 31-case synthetic corpus remains separate.

## Current TP2 active-pair preflight

`artifacts/active-mod-pair-preflight-20261013.json` binds Manager `58a2c32`,
the exact Qwen2.5-7B TP2 host wheels, three remotely reachable MOD commits,
their manifest blobs, locally rebuilt wheel bytes, Manager compatibility
checks, and both entry-point invocation orders for the two closest pairs.
The invocation probes run in disposable processes and do not start the host or
touch either NPU.

Neither pair is activation-ready.  KVCompress plus the lifecycle profiler is
blocked because the profiler's source manifest accepts vLLM `>=0.23,<0.24`,
while the exact host is `0.31.1.post1.dev163+g973d9ef5a.empty`.  KVCompress
plus KNorm is blocked because KNorm declares its implementation `import_only`,
which makes Manager correctly refuse enablement.  Direct entry-point returns
in both orders do not override either source contract.  The artifact therefore
reports zero H2-eligible pairs and zero H4-eligible pairs and contains no
performance result.

A later, separately pinned lifecycle-profiler port is recorded in
`artifacts/lifecycle-profiler-kvcompress-host-contract-20261013.json`.  It
widens the profiler source manifest to vLLM `>=0.31.1,<0.32` and verifies, in
isolated processes for both installation and entry-point orders, that the
profiler observes one synthetic typed lifecycle event while KVCompress patches
the scheduler and KV manager.  Manager also renders both extensions enabled
for the exact Host/Ascend wheel pair.  This supersedes only the earlier
*contract activation* blocker for this new source commit; it does not rewrite
the historical preflight above.

The later artifact did not start vLLM, load a model, send a workload, observe
device execution, establish an independent H2 ownership label, or measure
performance.  It is activation-ready input for a real model-serving campaign,
not a runtime-effective result or an H2/H4 score input.  Run
`python experiments/real_mod_composition/host_contract_qualification.py` to
validate its schema, byte identity, exact source/Host bindings, both orders,
and those fail-closed boundaries.

## Real TP2 two-MOD activation preflight

`artifacts/h2-real-pair-tp2-preflight-20261013.json` advances that exact
KVCompress/lifecycle-profiler pair through real Qwen2.5-14B TP2 serving on two
Ascend 910B2 devices. Both isolated installation orders reached health and a
nonempty completion, the profiler observed `request_finished`, KVCompress
reported binding its cache path, and cleanup emptied both NPU process tables.
The artifact retains the two model-fingerprint failures and the failed first
calibration attempt rather than discarding them.

This remains an activation preflight. It does not show that a compression
transaction occurred, supply an independent H2 correctness/ownership oracle,
run matched control/candidate repetitions, or measure latency or throughput.
Accordingly `formal_h2_result`, `performance_result`, and `score_eligible` are
all false. Run
`python experiments/real_mod_composition/verify_real_pair_preflight.py` to
verify the source summary's exact SHA-256, strict schema, both installation
orders, retained failure ledger, and required non-claims.

`score_admission.py` enforces that boundary mechanically. With the checked-in
artifacts it exits 2 and reports `INCOMPLETE`: all three runtime artifacts are
preflights, the independent real-MOD oracle is absent, and neither frozen
installation order has a formal-real host record. It emits no metrics while
blocked. Future admitted records must validate against
`formal-runtime-record.schema.json`, bind the exact campaign and oracle bytes,
and, for an admitted composition, carry host start, model load, workload,
process-owned observation, and cleanup evidence. This gate does not promote or
reinterpret any existing artifact.

## Formal compatible-pair runtime record

`artifacts/h2-profiler-kvcompress-formal-20261013/` preserves a separately
frozen, source-bound campaign for the lifecycle-profiler/KVCompress pair and
both real Qwen2.5-14B TP2 installation-order runs. The independent oracle and
Manager planner receipt were frozen before launch. The score gate rehashes the
planner command outputs, Manager configuration, every raw runtime artifact,
runtime receipt, and formal record. It then independently reconstructs the
unique EngineCore identity, profiler process-start and request-finished
binding, same-PID KVCompress scheduler binding, nonempty response, EngineCore
shutdown, and empty process tables for both allocated NPUs. Booleans copied
into the formal record cannot establish admission without those raw bindings.

Run the checked-in case with:

```bash
python experiments/real_mod_composition/score_admission.py \
  --campaign experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/campaign.json \
  --oracle experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/oracle.json \
  --planner-receipt experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/planner/planner-receipt.json \
  --record experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/profiler-then-kvcompress/formal-runtime-record.json \
  --receipt experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/profiler-then-kvcompress/formal-runtime-receipt.json \
  --record experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/kvcompress-then-profiler/formal-runtime-record.json \
  --receipt experiments/real_mod_composition/artifacts/h2-profiler-kvcompress-formal-20261013/kvcompress-then-profiler/formal-runtime-receipt.json
```

This command currently fails closed. The r1 planner receipt lacks an explicit
campaign digest, and the frozen served-name template is
`ecpa-h2-formal-{order_id}` while both captured requests used
`ecpa-h2-{order_id}`. These defects were found only after the runs; the frozen
campaign and planner receipt are intentionally not rewritten. A replacement
campaign and campaign-bound planner receipt must be frozen before rerunning
both orders. The captured workload also has maximum
model length 2048 while the compression threshold is 9216, so even a corrected
rerun would establish neither a compression transaction nor correctness or
performance benefit. One admitted case could not establish H2 corpus
precision/recall; rejected real cases and the remaining corpus would still be
required.

The corrected revision-2 campaign and both reruns are retained under
`artifacts/h2-profiler-kvcompress-formal-r2-20261013/`. Unlike the excluded r1
attempts, the r2 Manager planner receipt binds the frozen campaign digest before
launch, and both requests use the served name rendered from that campaign. The
gate consumes the detailed `ecpa-h2-independent-source-oracle/v2` directly. It
rehashes its independent receipt and verifier, the prior independent source
review receipt/review/verifier, and the frozen source commit/tree/blob mappings;
the compatibility wrapper is not an input.

`score-admission.json` records `ADMITTED` for this one compatible case in both
installation orders. The checked-in test reconstructs that decision from the
portable raw artifacts rather than trusting the saved score. The observed
workload still has maximum model length 2048 below the KVCompress threshold
9216. This is a real compatible host-execution and lifecycle-observation record,
not evidence of a compression transaction, compression correctness, or
performance. H2 remains incomplete until the real admit/reject corpus meets its
precision/recall target; H3 and H4 are unaffected.

## Real compression-transaction qualification

[Archived compression transaction](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/6007296ac8705e2a8feb6b211bd352ad613aa352/archive/mod-targeted-20261023/manager-experiments/snapshot/experiments/real_mod_composition/artifacts/h2-compression-transaction-20261013/) strengthens the same
compatible pair beyond the 2048-token activation record. The immutable runner
reads and validates the exact campaign, runner digest, and
planner/runtime-blind source oracle before spawning each server. The
TriAttention configuration lowers the reviewed threshold to
1152 tokens (`kv_budget=1024`, `recompute_window=128`), and the exact frozen
Qwen2.5-14B prompt contains 1201 tokenizer tokens.

Both wheel installation orders ran on two Ascend 910B2 devices. Each raw log
contains one scheduler commit from 1201 semantic tokens to 1024 physical
tokens and two identical worker acknowledgements, one from each TP rank. The
same request ID is present in an EngineCore-owned profiler epoch and in the
HTTP response. Both shutdowns left the port closed, no owned process alive,
and both allocated NPU process tables empty.

Download and export the originals using [the setup guide](../../docs/benchmark-originals.md).
Recompute the portable admission with:

```bash
python experiments/real_mod_composition/verify_h2_compression_transaction.py \
  "$VLLM_HUST_BENCHMARK_ORIGINALS/experiments/real_mod_composition/artifacts/h2-compression-transaction-20261013"
```

The verifier rehashes every raw artifact and independently parses the request,
response, configuration, scheduler commit, worker acknowledgements, process
identities, profiler records, and NPU snapshots. It rejects missing TP
acknowledgements, substituted profiler epochs, mismatched anchors, and replayed
run identities. The campaign's embedded `frozen_utc=17:48:00Z` is inaccurate:
it is later than the observed first launch even though the file itself was read
before the server subprocess. The verifier does not use that timestamp as
evidence, and copied filesystem modification time is not portable evidence.
The result is therefore retained as a real compatible-pair transaction
qualification for both installation orders, with `score_eligible=false`, not
as a formally preregistered H2 result. It is not a performance or
compression-quality result, does not increase the independently labeled corpus,
and does not complete H2, H3, or H4.

## Exact-wheel installation-order campaign

`runtime_campaign.json` freezes source commits, trees, the two locally built
wheel byte digests, exact plugin entry points, the vLLM/vLLM-Ascend 0.23.3
target, and both installation orders for the KVCompress/Knorm case. Its oracle
and all measurement fields intentionally remain unset.

Run `install_order_probe.py --wheel-dir DIR --output RESULT.json` with those
exact wheel bytes. The probe checks wheel digests and entry-point metadata,
then installs each order into a separate empty venv and observes distribution
metadata without importing either plugin. Its result is useful packaging and
order preparation only. It cannot establish static compatibility, activation
readiness, host execution, runtime effect, or an oracle label, and it is always
emitted with `score_eligible: false`.

## Executed legacy 0.23.0 source-pair preflight

`artifacts/kvcompress-knorm-legacy-0.23.0-runtime-preflight.json` records a
separate, exact case for the legacy stack that was available on 2026-10-13:
vLLM `0.23.0+empty` at `0fc695fc6d1d82e9a5ac6835ac8e4e1c83703665`
and vLLM-Ascend `0.23.0.post1` at
`1cdb8c4db6e50f36f1fb3283b3e3dd618f6821e8`. It does not replace or relabel
the frozen `0.23.3` case. The executed commits also differ from KVCompress's
documented validated legacy pair (`d0f22d2…` / `03766ac…`), which the artifact
states explicitly.

Both exact sequential wheel-install orders loaded both plugin entry points.
Calling the entry points in both orders registered both scheduler wrappers; the
record preserves which wrapper was outermost. Current Manager `646d175` planned
KVCompress as active, planned KNorm as `inspect_only`, and rejected KNorm
activation with exit code 2 because its manifest carrier is `import_only`.
Consequently, a Manager-controlled two-plugin host launch was ineligible and
was not attempted. This is real import and wrapper-registration evidence on the
pinned host process, but it is not a serving start, runtime-effective result,
semantic compatibility label, independent oracle, performance result, or H2
score input.

A second artifact,
`artifacts/kvcompress-knorm-documented-legacy-source-pair-preflight.json`,
repeats the import, entry-point call, wrapper-order, and Manager checks with
Python modules loaded from KVCompress's documented legacy source commits
`d0f22d2…` / `03766ac…`. Both orders again register both wrappers, while the
Manager gate still rejects KNorm activation. This source override did not start
the host or load a model and does not establish provenance for native extension
binaries, so it remains non-scoreable and carries no oracle label.

## Remaining H2 ownership surfaces

`artifacts/h2-remaining-surfaces-oracle-20261013/` adds one independently
reviewed external-authority case. It binds the registered Production Stack
single-writer rule, the upstream vLLM Production Stack `ScaledObject` targeting
`Deployment/default/vllm-llama3-deployment-vllm`, and pinned KEDA controller
code that creates an HPA and updates the target scale subresource. For the
frozen negative configuration, chart-side KEDA delegation is disabled. The
oracle diagnoses two replica writers, and the later Manager check rejects an
input that already contains that diagnosis in `ownership_conflicts`. The
scoring-input audit excludes this case from independent detection scores:
without the supplied report, the provider returns unknown. The original
oracle and prediction remain preserved as source-bound report-consumption
evidence. They do not establish independent ownership-conflict detection, a
Kubernetes runtime result, or performance. The upstream chart's explicit
KEDA delegation mode is a different, potentially safe configuration and is not
labeled as conflicting.

The same oracle retains an auditable exclusion ledger for the batch-admission
CLI/config surface. Pipeline Microbatch is the only frozen active bundle that
claims `vllm.batch-admission-policy.v1` and its CLI/config projection.
Scheduler Policy Lab and QoS Scheduler are `import_only` and claim different
contracts; the metadata-only `Qixin-Gaoke/kv-admission-plugin` source could not
be frozen. No synthetic competitor is substituted, so this surface remains
unresolved and H2 remains open.

Run the portable checks with:

```bash
python experiments/real_mod_composition/verify_h2_remaining_surfaces_oracle.py
python experiments/real_mod_composition/verify_h2_remaining_surface_prediction.py
PYTHONPATH=src python experiments/real_mod_composition/h2_scoring_input_audit.py
```

## Source-bound conditional scheduler pair

`artifacts/h2-pipeline-bidkv-oracle-20261013/` adds an independently scoreable case from
two independently developed active bundles.  The independent oracle was
committed before the Manager collector existed.  It binds Pipeline
Microbatch, BidKV, and vLLM-HUST `3e57b2f75c…`; that exact Host source exports
batch-admission API 1.1 and preemption-policy API 1.0 through separate
controllers and scheduler configuration fields.  The later Manager prediction
admits the pair and projects distinct `--batch-admission-policy` and
`--preemption-policy` options without a composition conflict.

After the report-consumption exclusion above, the independent definite
source-bound subset is n=4 (TP=2, TN=2, FP=0, FN=0). The historical n=5
oracle and predictions are preserved, but that total is not an independent
detection score. The corrected subset remains too small and surface-incomplete
to finish H2.  This case stops at the
pre-launch boundary: the exact Pipeline Microbatch qualification cell is
PP2+TP2 on four devices while this allocation has two.  No host was launched,
neither policy was observed running, and no runtime or performance result is
claimed.

Run the portable check with:

```bash
python experiments/real_mod_composition/verify_h2_scheduler_pair.py
```
