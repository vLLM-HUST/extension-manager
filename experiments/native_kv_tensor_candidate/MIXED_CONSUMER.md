# Selected logical KV bytes, metadata, HTTP, and final ACK

`campaign_consumer.execute_with_tensor` is the live opt-in consumer for one new
single-phase cohort. It preserves the complete mixed journal and calls the typed
archive oracle, the prospective final-prefix clock oracle, and the independent
plan/projection/upload join. It never filters tensor events into a generic proof.

Before first launch and recipe/source freeze, call `declare_tensor_recipe(recipe)`
on the new KV-v2 strict-copy recipe with budget180 and final-prefix ACK policy.
This adds the actual consumer, join, typed and clock oracle source bytes to the
preregistration. Existing recipes without this declaration are rejected. The
original payload, fresh challenge, response oracle, minimum32 completion tokens,
1201 prompt and metadata requirements remain frozen.

After launch, freeze real peer identities, installed source inventory, private
worker directories (explicit chmod0700, no special bits), collector spec and
runtime policy with all28 layers and anchors1201/1024. Use the188 typed wrapper
socket, authenticate its real launcher/kernel/source identity, then publish both
source bootstrap contexts. The consumer API is:

```python
execute_with_tensor(recipe, phase_id, output,
    socket_path=socket, descriptor=independent_launcher_descriptor,
    spec_path=spec, collector_source_path=actual_typed_wrapper_source,
    journal_path=whole_mixed_journal, policy_path=typed_runtime_policy)
```

Accept this limited observation only when `rpc_task_passed is True` and
`mixed_typed_HTTP_ACK_join is True`. Missing evidence stays unknown. An observed
wrong response is false for the bounded response task, while the full objective
remains unknown. The consumer performs one actual POST, real before/after Unix
peer authentication, records raw HTTP and both status receipts, and independently
verifies the post-status durable prefix and every selected fact clock. All four
source/gather/write/readback clocks and envelope clocks must fall inside the HTTP
window. Final ACK occurs after the response and includes the complete journal.

All56 typed receipts must share the actual plan transaction and bind each rank's
actual process, runtime request, destination blocks and anchors to that rank's
CPU projection and later matching GPU full-row prefix. Tensor and projection
transaction hashes use distinct source preimages; they are never conflated.
This proves only the recorded selected **logical** K/V bytes and metadata/upload
relation. It does not prove complete physical NPU storage or padding equivalence,
attention consumption, or full generation quality. Formal guard remains closed;
GPU qualification, attention, quality, and full objective fields remain null.
REAL_RUNTIME_UNQUALIFIED describes real runtime provenance, not formal success.

Recorded evidence can be replayed through `python -m
experiments.native_kv_tensor_candidate.campaign_consumer --recipe ... --phase ...
--output ... --descriptor ... --spec ... --journal ... --policy ...`. For relocated
source snapshots, `--source-map` is an explicit JSON mapping from original frozen
source paths to copied absolute source paths. It must include all recipe sources,
including tokenizer binding sources. Neither recipe nor clocks are rewritten.
Every declared oracle must uniquely match its original module name and both the
copied bytes and actual imported oracle bytes. Archive bytes and their external
manifest digest remain the packager's responsibility; replay does not authenticate
a currently running sender. The native spec, policy, journal, archived typed blobs,
raw RPC files and before/after status receipts must be retained in full.

The integration test runs an actual HTTP server, three independent source peers,
and an independent Unix collector. Tensor buffers are CPU bytes, model/tokenizer
and NPU metadata are explicitly fixtures. It is not a hardware or model result.
Rehashed destination forks, missing uploads/ACK, stale ACK, HTTP503, missing source
preregistration, late source envelopes and observed wrong response are tested.
