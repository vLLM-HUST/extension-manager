# Prospective final-prefix ACK time contract

`ack_time_policy="source-fact-in-http-final-prefix-ack-v1"` is an optional KV v2
recipe field. It requires the frozen 180-second budget. The generator pins the
actual status client and this policy module's source bytes before launch. Use:

```python
make_kv_recipe(..., materialized_row=True, rpc_budget_s=180,
               prompt_variant="strict-system-copy-v1",
               ack_time_policy="source-fact-in-http-final-prefix-ack-v1")
```

The CLI exposes the same value through `--ack-time-policy`. The policy does not
alter the model task, native fact schema, response oracle, registered process
roles, or formal-producer classification.

The source collector holds its journal lock, fsyncs the complete prefix, and
then samples `issued_monotonic_ns` in its describe response. The actual client
records dispatch/completion monotonic clocks around the Unix authentication,
its process identity/boot ID, and its frozen source digest. Kernel peer,
launcher descriptor, socket inode, collector source, spec, raw status bytes,
and durable prefix must still match. Archived replay checks recorded evidence;
it does not perform fresh OS authentication and byte hashes are not signatures
against malicious archive rewriting.

Live and portable KV validation share one pure time predicate. The new policy
requires each selected fact's source timestamp within the HTTP send/read window;
acceptance at or after that fact and no more than five seconds later; membership
in the complete retained final prefix; and acceptance no later than the source
ACK issue clock. The final ACK is issued after HTTP read completion and inside
the actual client's post-request authentication window. Before-auth completion
must precede HTTP send. Both auth exchanges and HTTP share the same boot and
client process/source. The observed auth/HTTP interval must fit the frozen
180-second phase budget. The independent campaign owner still enforces its
phase and overall watchdogs and cleanup.

The default remains the original `accepted <= HTTP read completion` policy.
The strict enabled pair's original portable rejection remains a rejection;
its old status records have no source/client issue clocks and cannot qualify
under this new contract. No records are dropped, clocks backfilled, or runs
retried to win a scheduling race. A new hardware cohort needs a newly frozen
recipe, new client and collector source closures, and matching installed Host
collector bytes/wheel. It cannot borrow the old a4 collector or use old summary
booleans as native proof.

CPU tests use actual HTTP, Unix peer credentials, source-bound processes,
fsync, and measured clocks. A source-pinned CPU scheduler fixture delays status
handling while two fixture upload facts, stamped before HTTP completion, are
accepted afterwards. The legacy live/archive policy rejects this retained
sequence; the prospective policy accepts its real final-prefix clocks. These
are synthetic CPU fixture native facts, not GPU upload or model evidence.
Fully rehashed counterexamples cover a fact after HTTP, acceptance before the
fact, a five-second TTL violation, ACK issuance before final acceptance,
a future source clock, foreign peer/source, missing clocks, an over-budget
phase, an unknown policy, and removal of opt-in to try the legacy policy.
Neither these tests nor this change establish KV tensor equivalence, attention
consumption, full generation quality, formal qualification, or H4 performance.

[artifacts/final-prefix-cpu-20261014/](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/b3d2ed2692b5575b5ae77b93fc82e32c9119be8e/archive/mod-targeted-20261023/manager-formal/snapshot/experiments/native_challenge_candidate/artifacts/final-prefix-cpu-20261014) retains both actual CPU scheduling
attempts, their input/source snapshots, HTTP bytes, authenticated before/after
status clocks, native fixture raw journals, and hash inventory. These are
explicitly CPU_TIME_CONTRACT_FIXTURE_ONLY. The clocks and kernel transport are
real; the facts' device labels and block rows are CPU fixture data. The bundle
supplies no NPU result and cannot replace a new hardware qualification cohort.
