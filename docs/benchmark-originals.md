# Benchmark originals

## Published installation archives and source distributions

The old v0.3.0 installation wheel and sdist remain published: direct installers,
source builders and external consumers have not been proven absent. Do not
overwrite their bytes or delete them as experimental duplicates.

Historical evidence carried inside that sdist has a separate
[member-by-member benchmark binding](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/51604897aabb9a856b311fa58fc6749938d0378e/archive/mod-targeted-20261023/installation-consumers-20261024.json).
Release-specific versions are preserved in the
[original member collection](https://github.com/vLLM-HUST/vllm-hust-benchmark/tree/51604897aabb9a856b311fa58fc6749938d0378e/archive/mod-targeted-20261023/manager-release-v030/snapshot).
These are not interchangeable with newer Git-source originals. The review also
distinguishes paper examples/schemas from observations and measured results.

Future builds contain runtime sources, packaging metadata and the installation
README only. Research tools, paper sources, fixtures and tests require a source
checkout plus verified benchmark inputs; they are not the installed Manager CLI.
The package's `manual_bootstrap` helper remains part of the runtime payload.

```bash
python -m build
python scripts/check_distribution.py dist
```

Both normal CI and the existing release gate validate source/wheel/sdist byte
parity and console-entry-point presence before clean-wheel installation. The
guard does not execute archived evidence or qualify a host/device. It does not
authorize publication: the existing release-readiness and tag/version checks
remain mandatory. Package version and old Release assets are unchanged.

## Remaining composition consumers (2026-10-24)

All 149 remaining tracked members under `real_mod_composition/artifacts` are
registered in `BENCHMARK_ORIGINALS.json`. They reuse the fixed
[experiment manifest](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/140a046d34ecf50bb8de3d8b19a7d70a6b0490e0/archive/mod-targeted-20261023/manager-experiments/manifest.json);
no original bytes or historical scores are rewritten. Paper generation, scoring,
preflight checks, source-corpus evaluation and mutation tests read checked external
inputs. Negative tests still mutate their own isolated copies.

The two self-hashed oracle verifiers stay byte-for-byte unchanged. Run them via
the exporter, which checks their receipt binding and copies checked inputs into
a temporary portable tree:

```bash
python scripts/verify_composition_originals.py process-carrier
python scripts/verify_composition_originals.py remaining-surfaces
```

The two `build_h2_*` scripts and three remaining `collect_h2_*` scripts now require
`--output /absolute/external/new-output`. Builders create a fresh directory;
collectors exclusively create a fresh file. Source checkout, original-input
directory, existing destinations and symlink escapes are rejected before work.
`score_admission.py` and `install_order_probe.py` also protect explicit outputs;
their default stdout behavior is unchanged. Never use the original-input tree
as a workspace for derived outputs.

Builder outputs retain logical historical snapshot paths, allowing byte-identical
reconstruction from the frozen source bytes. For portable replay, place the new
package at that logical path in a separate export tree, not in the source checkout
or originals. Historical collectors retain their exact-commit and oracle-freeze
guards; a new output location does not authorize a new hardware run or relax those
guards. This migration does not rerun collectors or claim new performance results.

## Planner and paper consumers

[Planner/H1-r5 manifest](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/aa041953616fa170014a0c7f43fb06bf1c59b846/archive/mod-targeted-20261023/manager-paper/manifest.json)
preserves the two contract-planner results and five H1-r5 paper records. For paper generation,
research validation and the full test suite, download first and export the external directory:

```bash
python scripts/fetch_benchmark_originals.py /absolute/external/originals
export VLLM_HUST_BENCHMARK_ORIGINALS=/absolute/external/originals
python paper/scripts/generate_evidence_summary.py --check
python scripts/validate_research_matrix.py
```

The resolver checks original SHA256 and rejects missing inputs or an in-checkout directory.
Negative tests still mutate isolated fixture copies and exercise all original semantic assertions.
Schemas and the planner evaluator remain unchanged; use its explicit external `--output-dir` for
new derived results. Other experiment archives remain a separate migration queue.

This bounded collection is preserved by the benchmark repository. Original versions, failures,
negative results and diagnostic scope remain unchanged; migration is not new runtime acceptance.
Other historical collections are not declared migrated by this change.

- [Original manifest 1](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/b36edbc7698e3ca188904d0e20495ed2924a8525/archive/mod-targeted-20261023/manager/manifest.json)

Download and verify each original into an empty directory outside the source checkout:

```bash
python scripts/fetch_benchmark_originals.py /absolute/external/originals
```

The downloader checks the pinned manifest and each file's length and SHA256, rejects unsafe paths
and never executes archived code. CI repeats the readback and rejects the migrated paths returning
to Git. Fixed benchmark originals and unchanged source Git history preserve recoverability.

## Additional experiment consumers

[Experimental archive manifest](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/140a046d34ecf50bb8de3d8b19a7d70a6b0490e0/archive/mod-targeted-20261023/manager-experiments/manifest.json) preserves 208 members from the
exposure-gate, false-effective, real-MOD-composition and transaction-model collections.
The preceding batch migrated 38 verified originals: six exposure qualification/preflight
files and 32 compression-transaction members. Other archived inputs still have legacy
consumers; synthetic/reference fixtures stay local and are not serving measurements.

The same setup above serves the paper generator, invocation/semantic-gap audit, host-parent
registration reader and compression negative tests. Directory inputs verify every member and
reject unexpected files or escaping symlinks. Makefile generation explicitly verifies inputs
before rebuilding; no frozen input is executed. Missing upstream registration/semantic
producers and the inaccurate historical freeze timestamp keep their original failure boundaries.

## Formal and native challenge archives

The formal_campaign and native_challenge_candidate artifact trees now resolve
through the external originals manifest. Download using the command above and
set `VLLM_HUST_BENCHMARK_ORIGINALS` before replaying their documented commands.
Frozen portable verifier implementations and their source hashes are unchanged.
Partial, failed, nonformal, CPU-only and missing-quality identities are retained.

The quantized-KV CPU and Pipeline/BidKV source-oracle consumers also use checked
external originals. The Pipeline/BidKV collector requires a new `--output` path
outside both the checkout and the originals directory. This is not permission
to rerun hardware checks or overwrite a historical prediction.

## Paper projection inputs

The [paper projection manifest](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/5c970d6f36e42891d8365275fa6ec1b23333498b/archive/mod-targeted-20261023/manager-projections/manifest.json) preserves
the historical R4 source binding and both derived TeX summaries unchanged. Paper checks recompute
them from the original corpus and compare the archived bytes; public and anonymous builds copy
verified inputs into a fresh external directory. New generator outputs require explicit external
paths and cannot replace source or originals. Finite nonformal scope and negative results remain
unchanged; no model quality or performance acceptance is added.
