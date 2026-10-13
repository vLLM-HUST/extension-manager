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

`score_admission.py` enforces that boundary mechanically. With the checked-in
artifacts it exits 2 and reports `INCOMPLETE`: all three runtime artifacts are
preflights, the independent real-MOD oracle is absent, and neither frozen
installation order has a formal-real host record. It emits no metrics while
blocked. Future admitted records must validate against
`formal-runtime-record.schema.json`, bind the exact campaign and oracle bytes,
and, for an admitted composition, carry host start, model load, workload,
process-owned observation, and cleanup evidence. This gate does not promote or
reinterpret any existing artifact.

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
