# Sealed materialized-row v2 first attempt: partial evidence

This is the original v2 first attempt, not a complete qualification or performance
result. Its immutable preserved tar SHA256 is
`3fe0c18383ec787e5f06446ac99f7360a4738c6f21c4a4f1effe880935829713`:
93 members, including 54 source snapshots that match their prelaunch hashes. The
preservation manifest and tar are copied byte for byte; no missing evidence is
backfilled from current files or later runs.

The actual request timed out under the frozen client source's legacy 30-second
socket timeout. Raw records contain one collector start, one native API mapping,
two materialized CPU projection facts and 96 GPU uploads. Each source rank has 47
later uploads matching the actual full CPU row `[11,12,13,14,15,16,17,18,19]`:
eight compression destinations plus the genuine scheduled append `[19]`.
The verifier executes the hash-pinned archived collector's pure replay predicate,
checks raw body/transaction/hash chains and mapping/effect/materialization/barrier
chronology, joins the original request/nonce/source peers and checks the observed
row index for this single-request trace. It retains all uploads; these counts do
not claim every model step, KV tensor equivalence, attention consumption or model
quality.

There are no HTTP response bytes, HTTP response metadata or post-request final
authenticated ACK seal. Durable join and the model outcome stay unknown; even a
consistent raw chain cannot replace the missing seal. The recorded Manager/API/
worker session cleanup and card-3/card-6 terminal raw are checked, but an independent
collector terminal-identity receipt is absent. Collector termination therefore
stays unknown instead of being inferred from other processes or clear cards.

The tar does not contain all tokenizer assets, eight renderer/Transformers source
bindings, model bytes, runtime wheels or calibration artifact bytes. The portable
verifier neither re-executes tokenization nor claims to rehash those absent inputs.
The frozen CPU-only oracle token IDs and hashes are checked as records, not as
HTTP usage or model output. Full semantic/quality/objective, losses and duplication
remain unknown; runner success, hardware qualification and formal result are false.
Formal admission remains closed and paper counts are unchanged.

Run from a checkout without the original machine paths:

```sh
python -m experiments.formal_campaign.verify_kv_materialized_partial \
  --manifest ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/native-kv-materialized-partial-r1-20261014/manifest.json \
  --archive ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/native-kv-materialized-partial-r1-20261014/raw.tar.gz
```

Negative tests alter actual CPU row, scheduler suffix, metadata row, effect clock,
source bytes or success/response claims. They recompute transactions, raw bodies,
full chain, tar, inventory and outer SHA as appropriate; the semantic/source/scope
checks still reject them. These tests do not manufacture new hardware evidence.
