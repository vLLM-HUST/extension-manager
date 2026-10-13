# CPU review candidate: Host block-table projection

This package implements a concrete candidate producer, private durable raw-file
writer, and expectation-bound independent reader. It never registers a formal
producer or changes the closed formal gate from PR #164. No running wheel or
hardware experiment uses these files.

The hook patch applies to the exact retained KVCompress `00cc78dc` provider
source. Host `973d9ef5` block-table and evidence source bytes are also retained
with SHA-256 hashes. The hook executes after the synchronous acknowledged model
barrier and the worker's request/block-table/active-anchor mutations. It reads
those actual objects rather than accepting a successful-effect flag. Missing
request, unscheduled request, stale Host process scope, an environment-assigned
role, mismatched launch, inconsistent destination blocks or active anchors
produces no receipt. It propagates raw runtime request ID and a stable
scope/operation transaction hash, exact source hashes, Plan/launch/controller/
generation/membership, and current PID/start ticks/boot.

The operation is **worker-host-blocktable-projection-applied**. The checked
predicate concerns the Host request and CPU input-table projection, plus active
compression anchors. Host `BlockTable.add_row` updates CPU/NumPy metadata;
`commit_block_table` copies it to the accelerator later. Consequently this
receipt does not establish GPU table upload, KV tensor content or semantic
equivalence, model quality, or completion correctness. CPU tests use explicitly
fixture metadata; current PID/start/boot and file/fsync calls are real CPU acts.

`emit_worker_projection` returns true only for a writer callback returning the
literal boolean true. The callback contract requires completed exact-byte write,
file fsync, and creating-directory fsync. `write_durable_receipt` implements that
contract with exclusive private files and directory identity checks; injected
fsync failure returns false and removes the incomplete receipt. A callback
claiming true alone is not independently trusted evidence. The authority must
read bytes and compare frozen scope, request transaction, worker identity and
producer source itself. This local verifier accepts no formal/quality promotion.

The patch imports the candidate from a future Host
`vllm.plugins.semantic_evidence_candidate` module only if a Host worker has a
frozen `_ecpa_semantic_projection_context`. This package does not install that
context. Missing context is non-producing. Required next work is a source-owned
Host context installer and live independent reader, exact wheel build/source
registration, authority probe to runtime-request binding, and a newly frozen
threshold-specific real-model qualification. Host publication remains blocked
by the selected GitHub App 403. The source candidate is local and nonformal;
a successful CPU receipt cannot clear that blocker or open the existing gate.

```sh
PYTHONPATH=src:. python -m pytest tests/test_semantic_producer_candidate.py -q
```
