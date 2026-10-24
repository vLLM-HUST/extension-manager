# Benchmark originals

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
