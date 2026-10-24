# Sealed materialized-row r3: strict task-oracle failure

The original r3 runtime/source/input bytes are separately sealed in a 105-member
archive, including 55 source snapshots that match prelaunch hashes. Archive SHA256:
`a201f045f3e38422c2d7b701cbedd31421b189e2a2cb535fff5ecbec61972fd2`.
Nothing rewrites r1/r3 original files, borrows a later HTTP/ACK, or changes the
frozen two-nonce oracle. This failure is not a formal result or performance result.

The raw response is HTTP 200 with prompt usage 1201, completion usage 81 and stop.
Actual HTTP elapsed is 32.01909209 seconds, within the preregistered 180-second
socket/observed elapsed budget; the independent phase and outer watchdog records
are retained. The text contains one nonce followed by explanatory text instead
of the exact two-nonce answer. Portable verification compares actual raw content
against the source-bound frozen expected string and independently concludes
`model_task_passed=false`. A successful status and token count cannot override it.

168 original records consist of start1/map1/projection2/upload164. Each rank has
81 later uploads matching the observed nine-block CPU row: actual destinations
11..18 plus the original scheduled append19. These are observed prefix counts,
not 81 admissions completed before the HTTP response. The last two original
acceptances occur 3.803834ms and 11.506064ms after the completed HTTP read (one per
rank). Their source fact clocks are within the HTTP window, and recorded accepts
are within original phase completion. The failure-profile verifier preserves and
reports this boundary; it does not relax the success predicate or backdate clocks.

The final authenticated post-request ACK seal is absent. Durable ACK/join,
KV tensor equivalence, attention consumption, full quality/objective, loss and
duplication stay unknown; runner/hardware/formal qualification are false. Original
outer records independently cover four gone sessions including the collector,
with no cleanup error. This r3 collector evidence never fills r1's missing record.
Full tokenizer/model/wheel/stats bytes are not all in the archive, so the verifier
does not claim fresh tokenization, model execution or wheel/stat rehashing.

The r3 profile reuses r1 source/kernel/raw checks and independently reads r3's
response, budget, clocks and original outer evidence. Default r1 replay retains
its missing-HTTP and unknown-collector semantics. Rehashed response/oracle/budget/
phase-clock/source/forged-ACK/success counterfactuals are rejected; existing failure
archive tests remain applicable. Runtime experiment clients and wheels are untouched.

This single failed task does not identify a compression cause. A subsequent
disabled diagnostic also changes selected plugin/bootstrap/collector/environment
behavior; it cannot be presented as a precisely isolated algorithm comparison.
Any paired observation must disclose those differences and retain the original
oracle. No paper formal counts change.

```sh
python -m experiments.formal_campaign.verify_kv_materialized_oracle_failure \
  --manifest ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/native-kv-materialized-oracle-failure-r3-20261014/manifest.json \
  --archive ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/native-kv-materialized-oracle-failure-r3-20261014/raw.tar.gz
```
