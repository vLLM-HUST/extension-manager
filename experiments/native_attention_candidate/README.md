# Actual cached attention operator source contacts

This is a **CPU_SOURCE_CANDIDATE_ONLY** implementation and reproducible source
patch, not a hardware result, registered semantic producer, or admission gate.
All existing runtime wheels, cohorts, private contexts and formal guard stay
unchanged. Future source-emitted facts use REAL_RUNTIME_UNQUALIFIED to describe
actual NPU provenance; their GPU qualification, attention consumption and full
model quality remain null.

The patch pins Ascend fcbb827 and Host c4350611 (the188 tensor-bootstrap source).
It has three real source contacts:

1. The tensor bootstrap calls `remember_acknowledged_materialization` only after
   actual private-artifact publication and its Unix kernel/source-authenticated
   ACK have returned successfully. It retains the actual archived payload hash,
   actual compression-plan transaction and layer/rank/cache storage binding.
   A local Boolean or a callback return is never a replacement for that source
   publication. Tensor and projection transaction schemas remain distinct.
2. In the real Ascend execute path, immediately after `_build_attention_metadata`,
   `bind_actual_input_batch` reads the actual active InputBatch request ID/index,
   request block IDs and group0 CPU table row. It links the actual metadata object
   to the existing acknowledged request/layer. It does not manufacture IDs from
   owner inputs, table rows or suffixes.
3. Eager PA wraps the final `torch_npu._npu_paged_attention`. A2 FIA wraps the final
   `torch_npu.npu_fused_infer_attention_score` in BaseDeviceAdaptor, after the
   large-head fallback and actual argument preparation. The observer records all
   actual native argument descriptors (including query/output/control/mask),
   native cache storage pointers, offset, dtype/device/format and supported view,
   actual block-table values and sequence lengths. It calls the original native
   operator, records its return, and synchronizes the actual current stream on
   that cache device before recording completion. Native exceptions produce no
   completed witness; publisher failures propagate.

Only eager single-request/group0 **DecodeOnly** with one actual query token is
supported. PrefillNoCache, mixed/chunked prefill, graph execution, microbatch
metadata lists, A5's separate final native branch and the large-head fallback
produce no witness. The future receiver must treat those missing obligations as
unsupported/unknown, never as consumption success. For each actual materialized
request/layer, only its first successfully published matching cached-decode call
is recorded. This bounded first-call scope does not describe all decode steps.

The pure predicate joins the original selected logical K/V materialization to
actual native argument/cache storage, destination-prefix/actual InputBatch row,
sequence extent, source ACK and causal completion clocks. It does not assert
that the native implementation mathematically consumed the selected values,
prove output quality, or recover full physical NPU storage equivalence. Native
kernel/ELF/source closure and fresh authenticated receiver evidence are also
necessary for a future runtime observation.

Generate immutable installable patches and a pre/post-byte manifest:

```sh
python -m experiments.native_attention_candidate.build_source_patch --output /new/private/patches
```

The Host patch installs `vllm.plugins.native_attention_operator_observer` and
updates the source-owned tensor callback. The Ascend patch updates only the
actual metadata builder path, eager PA and final A2 FIA contacts. Source snapshots
are gzip-compressed exact bytes with pinned hashes. Build genuine new Host/Ascend
wheels after applying the patches to those exact clean sources; the current
running c435/fcbb wheels must not be edited.

`ECPA_NATIVE_ATTENTION_OPERATOR_OBSERVER=1` is an explicit new-source opt-in.
The callback publishes through the Host source-owned native observer. The new
`collector.AttentionCollector` authenticates the actual Unix kernel worker,
epoch, command line and frozen source bytes, and checks the referenced original
typed ACK sequence/event/raw digest, archive payload, plan, layer and clocks
before appending a durable bounded OP event. The old191 collector rejects this
schema; no old runtime is silently upgraded. The formal producer guard stays
closed and no formal semantic producer is registered.

The new `attention_consumer` validates the complete three-start mixed chain,
all two-rank28-layer typed/OP receipts, actual plan→projection→later upload join,
strict raw HTTP and source/OP/readback clocks inside HTTP, and the actual final
ACK prefix. It does not filter extra OP records into a fake188/191 proof. Freeze
`declare_attention_recipe(declare_tensor_recipe(new_recipe))` before first
launch; live source paths are strict and relocated replay uses explicit copied
source byte maps without rewriting the recipe. `execute_with_attention` has the
same source/socket/spec/policy/journal arguments as191. Its bounded result gate
is `rpc_task_passed is True` and `mixed_attention_HTTP_ACK_join is True`.

At OP entry, the actual PA key/value cache or final FIA key/value view is copied
block by block through device-to-CPU and hashed as logical binary16 bytes. Only
the selected1024 tokens from the eight typed128-token destination blocks enter
this digest; the actual full native block table and sequence lengths retain the
append block. Exact4D/flattened stride and dtype are checked; unsupported layouts
are rejected. Neither the compression workspace nor an earlier hash supplies
these entry bytes. This adds selected-prefix persistence at native invocation,
not full physical storage equivalence or internal mathematical consumption.

The source wheel inventory must contain the new observer and source-bootstrap
bytes; every worker's collector preregistration must also pin the new receiver.
Build genuine new Host/Ascend wheels and freeze a fresh request/nonce/clock policy
before using the new receiver. The successful Tensor R1 remains separate,
unchanged and reproducible. This source candidate has no new NPU run.

CPU tests execute the patched pinned PA/A2-FIA Python bodies with mocked native
operators and schema-only NPU tensor/stream descriptors. They verify exact patch
application and compilation, completion order, argument preservation, finite
scope and counterexamples. They invoke no NPU operator and yield no hardware
qualification. There is no formal producer registration or new campaign result.
