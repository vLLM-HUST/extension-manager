# Strict paired tasks pass; original HTTP window remains rejected

The new optional `strict-system-copy-v1` prompt was frozen from merged source `4842bc9aa31575006b6f9501134ba170209788d0`. One fresh baseline request used canonical system/user messages, actual local tokenizer IDs of length 1201, an exact two-copy nonce oracle, no guided decoding, temperature zero, maximum 128 output tokens and a minimum completion gate of 32. Its first real TP2 execution returned the exact text: HTTP 200, 1201 prompt tokens, 75 completion tokens and `stop`.

After that baseline completed and cleaned up, an independently frozen enabled arm reused the same messages, token IDs, nonce and oracle with a new external request ID. The conditional pairing and nonce reuse were explicit before that arm's first model-producing child. It also returned the exact text with HTTP 200 / 1201 / 75 / `stop`. Observed HTTP elapsed was 17.015565s for disabled and 31.412061s for enabled. These are bounded single-request observations; execution paths differ in collector work, and this is not a performance result or causal estimate.

The enabled arm retained 156 native journal records: one start, one native API request mapping, two materialized-row projections and 152 NPU block-table uploads. The recorded authenticated post-status contains a durable prefix that the original collector source can verify; the original phase matcher observes the metadata/upload binding. However, the final two source admissions, sequences 154 and 155, occurred 4.789211ms and 12.342410ms after the recorded HTTP body read completed. The unchanged source's `kv_archive.verify` rejects the complete journal with `KV source facts lie outside the observed HTTP request window`. The runtime's original true flags, complete journal and original rejected portable result are preserved. No events are trimmed and no ACK clocks or HTTP window are rewritten.

Default CPU-only replay separates these facts:

```sh
python -m experiments.formal_campaign.verify_kv_strict_pair_partial \
  --manifest ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/kv-strict-pair-partial-20261014/manifest.json \
  --archive ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/kv-strict-pair-partial-20261014/raw.tar.gz
```

It checks both original model tasks and paired inputs, source-assigned API/worker identities, the genuine enabled Manager handoff, fixed baseline identities, actual watchdogs and terminal closure. It then reconstructs five byte-exact original stdlib modules in an isolated Python interpreter, verifies the original after-ACK prefix and metadata matcher, and requires the original HTTP-window rejection. Reading a verified durable intake prefix does not qualify the failed HTTP window. This is recorded metadata partial evidence, not formal qualification; KV tensor equivalence, attention consumption, full quality, lost/duplicate counts and the full objective remain unknown. Formal H3/H4 starts remain zero. The prospective source-clock policy is a separate version and cannot upgrade this archive.

The archive contains 239 regular files, including original raw records, source snapshots, the original portable source/asset snapshot, genuine calibration input and explicitly late independent observations. The private Triton cache contents, large original wheel archives and model tensor file streams are excluded. Their original full hashes and recorded prelaunch checks are retained, but this is not an offline serving or complete-cache bundle. Replay performs no fresh OS peer authentication, tokenization or model execution. Cleanup includes all four independent enabled sessions (owner, Manager, API and collector), source epochs, closed ports and original NPU 3/6 no-running output.
