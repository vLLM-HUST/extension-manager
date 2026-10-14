# Selected KV materialization source candidate

This package is **CPU_SOURCE_CANDIDATE_ONLY**. It adds an opt-in source patch and
an independent selected-byte predicate; it registers no formal producer, authenticates
no source process, and supplies no GPU, attention-consumption, or model-quality result.
The formal traffic guard remains closed. Historical archives and runtime wheels are
unchanged. No NPU was used for this package.

The patch is bound to KV commit `81e094ddcb5c3f73d064cab5ed5dd5abf280ceb9`,
Host `b1f0f3e3adbf0ef6e95c666285354930a0a1cb4c`, and Ascend
`fcbb827af84f793939bf03d01a1dfe0338a0164c`. `source/source-binding.json`
contains preimages, postimage hashes, and the exact candidate module hash.
`source/attention-source-binding.json` binds the separate source-contact snapshots.
The test applies the patch to its original bytes rather than current source lines.

## Actual source order and selected-byte predicate

`TriAttentionMethod.compress` chooses the actual `keep_indices`, expands source
and private destination block IDs, builds source/destination slots, and loops over
its actual `materialization_caches`. Binding comes from the real request ID, layer
name/index and full-attention inventory, and current native TP rank. The patch does
not fabricate phase, nonce, Manager identity, or an authority ACK.

For each actual K/V cache, the hook captures selected source physical blocks **before**
the plugin gather. It exports those blocks to CPU and independently slices bytes at
`source_blocks[i // block_size], i % block_size` for each actual keep index. The
plugin's existing contiguous `index_select` or strided advanced indexing runs
unchanged; its actual workspace bytes must match this separate reference. Existing
writes then run unchanged. After an actual stream barrier, the hook separately reads
physical destination blocks, checks destination bytes against the reference and
workspace, and checks that the exported source blocks were not changed. Destination
readback never calls the plugin gather as its oracle.

This is equality to **selected source KV**, not to the uncompressed full context.
The predicate checks unique/disjoint source and destination allocations, actual
cache extent, exact slots, dtype, shape, inner strides, gapped page strides, pointers,
storage offsets, native NPU format (when available), rank/layer inventory, and ordered
observation clocks. It rejects a wrong gather copied identically to the destination,
shared workspace overwrite, and source mutation. Snapshot exports cover selected
source blocks, not every unselected source block. Pointer/layout equality alone
cannot authenticate the process or prove the returned GPU bytes are trustworthy.

The default sink is `None`; instrumentation is a no-op until explicitly enabled.
A callback failure propagates. Callback return values, including `True`, are ignored:
no local return becomes durable publication, peer authentication, or formal evidence.

## Real CPU exercise and limits

Run the pure predicate/source tests with `pytest -q tests/test_native_kv_tensor_candidate.py`.
Run the portable source-contact check with
`python -m experiments.native_kv_tensor_candidate.source_audit`.
With an existing Torch installation, execute
`python -m experiments.native_kv_tensor_candidate.cpu_audit --output cpu-audit.json`.
The recorded audit uses actual Torch CPU float16 tensors and the patched pinned
`cache.materialize_token_slots` body, including contiguous and noncontiguous/gapped
page layouts. It exercises successful real CPU copies, wrong actual gathers followed
by the same wrong copy, actual source corruption during a private write, and callback
failure propagation. It does not execute full `compress`, all 28 real model layers,
model selection/calibration, any NPU kernel, or the full Host/Ascend pipeline.
Small request/layer/keep-index fixtures are clearly CPU test inputs.

## Actual attention contacts, still unimplemented

The pinned provider obtains each layer's actual cache through
`layer.impl._unpack_kv_cache(layer.kv_cache)` and validates its physical layout.
`compress_scheduled_requests` calls materialization after native `sample_tokens`,
then creates a pending operation. Existing metadata-v2 producer evidence occurs after
Host `_update_states` restores the real CPU row. Ascend `_prepare_inputs` then uploads
the block table. These row/upload receipts do not prove tensor materialization.

The pinned Ascend attention implementation has two relevant eager dispatch paths:

* `forward_paged_attention` calls actual `torch_npu._npu_paged_attention` with
  `self.key_cache`, `self.value_cache`, `attn_metadata.block_tables`, and
  `attn_metadata.seq_lens`.
* `forward_fused_infer_attention` derives cache/current-token inputs in
  `_get_fia_params` and calls the actual `DeviceOperator.npu_fused_infer_attention_score`
  (or other branch-specific operators). PrefillNoCache passes current K/V with no
  cache block table; that cannot discharge consumption of a compressed cache.

A future source hook must bind the actual native request/layer/rank and compressed
operation to the **selected operator branch**, actual cache storage/pointers/format,
block-table row and sequence-length parameters, followed by actual completion on
that operator's stream. Merely returning from `forward` is insufficient. Full-graph
capture/replay and hardware-dependent DeviceOperator branches require their own
instrumentation and are not covered by this candidate. No attention patch or
consumption predicate is supplied here.

## Publication gap before any new hardware qualification

For the actual 7B TP2 configuration, a selected K or V plane alone can be hundreds
of KiB, and source blocks/reference/workspace/destination exports together exceed
the current collector's **64 KiB frame** limit. This JSON fact must not be sent to
that collector, and its limit is unchanged. A future private, source-owned artifact
with exact source/process/operation scope and a bounded digest envelope requires
atomic publication, receiver verification, and an authenticated durable ACK. Such
artifact transport, registration, native producer bootstrap, per-operation authority
joining, new genuine wheels, and real NPU validation are all missing here. CPU
success does not license opening the semantic guard or replacing historical results.
