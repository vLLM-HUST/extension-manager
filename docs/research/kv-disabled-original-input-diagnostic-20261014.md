# Original-input compression-disabled diagnostic

The original materialized-row v2 run returned HTTP 200 with 1201 prompt tokens, 81 completion tokens and `stop`, but failed its frozen exact double-nonce task. This archive preserves one compression-disabled counterfactual request with exactly the same messages, CPU token IDs, model alias, sampling settings and strict output oracle. Its new external request ID is distinct; reuse of the original challenge nonce is explicit and is not a fresh challenge qualification.

The disabled request also failed the exact task: HTTP 200,1201 prompt tokens, 119 completion tokens and `stop`, 20.815823s observed HTTP elapsed. It returned the nonce followed by an explanation rather than the frozen two-copy answer. Both strict tasks failed. This single pair does not establish compression causality, task feasibility, tensor equivalence, attention consumption, model quality, H3 recovery or H4 performance. The enabled and disabled execution paths also differ in native collector work and identity binding; their elapsed times are not a performance comparison.

Two earlier disabled attempts are retained as pre-request adaptation failures. In r2, the unmodified Manager rejected its native handoff because no bundle was enabled. In r3, the shared plugin allowlist omitted the `ascend` platform entry point and Host device inference failed. The final r4 kept the actual Ascend platform plus the three ordinary Ascend plugins and disabled the KV bundle. Source-assigned API and both worker identities were captured from actual Host invocations and kernel identities. The Manager used its unmodified empty-bundle supervision path: its baseline evidence IDs were externally preregistered, not Manager minted, and no native handoff or durable collector ACK qualification is claimed.

All three disabled attempts retain original source freezes, actual launch and terminal records. The terminal observer binds captured sessions and source epochs, closed ports and the original NPU 3/6 no-running output. Independent live and terminal observations are explicitly late, not preregistration. The enabled raw archive is the byte-exact published PR #181 artifact (SHA a201f045…), validated through its existing failed-task verifier, including its unknown final ACK status.

Run the CPU-only portable analysis from the repository:

```sh
python -m experiments.formal_campaign.verify_kv_disabled_diagnostic \
  --manifest experiments/formal_campaign/artifacts/kv-disabled-counterfactual-20261014/manifest.json \
  --archive experiments/formal_campaign/artifacts/kv-disabled-counterfactual-20261014/raw.tar.gz
```

The archive contains 173 regular files, original configuration and source snapshots, the validated 7B calibration input artifact and bounded late observations. It excludes every private Triton cache directory's contents, large original wheel files and fourteen model file byte streams. Their original full hashes and recorded prelaunch checks remain available, but this is not a complete cache or offline serving bundle. The portable command does not reexecute tokenization, model hashing, device execution or calibration validation. Clean allowlisted launch environments are included; opaque desktop session environments are omitted.

Negative checks rebuild both tar and manifest hashes and reject HTTP 503 with the same body, fake success, foreign peer/session identities, live NPU output, missing prior failure cleanup, false native mint, changed platform evidence, altered source snapshots, excess HTTP elapsed and a missing enabled archive. Formal H3/H4 starts remain 0; lost/duplicate requests and the full objective remain unknown.
