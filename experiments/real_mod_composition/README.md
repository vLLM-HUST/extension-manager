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
