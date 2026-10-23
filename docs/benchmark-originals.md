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
