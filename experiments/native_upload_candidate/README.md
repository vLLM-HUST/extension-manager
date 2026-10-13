# Native request mapping and NPU block-table upload candidate

This is an executable source-matched hook candidate, not hardware qualification,
formal H1/H3, a performance result or a KV-correctness proof. Existing wheels and
r1/r2 records are unchanged. CPU tests simulate the interface and explicitly do
not create a device tensor.

`source-binding.json` pins the exact Host379 and Ascend873 patch preimages and
module/patch bytes. `host.patch` adds the native observer module and observes
`InputProcessor.assign_request_id` **after** the native external-to-internal
randomization. `ascend.patch` observes only the real `_prepare_inputs` upload at
`commit_block_table(num_reqs)`. The separate dummy graph upload is not evidence.

KV00cc `provider.before_update_states` rewrites request block IDs and the input
batch CPU table, updates active compression, then logs commit acknowledgement.
Its plugin wraps native update as before/provider → native update → after/provider.
That is the CPU projection boundary. Host379 `BlockTable.commit_block_table`
queues `CpuGpuBuffer.copy_to_gpu(non_blocking=True)`. Ascend873 uploads in
`_prepare_inputs` before attention metadata construction. The candidate observes
that later upload, explicitly synchronizes the current NPU stream, reads each
active device-table prefix back to CPU and compares it with its CPU source row.
It reports the physical table prefix, including native block-size expansion;
it does not replace it with logical request block IDs or the earlier projection.

The current stream barrier/readback has intentional qualification cost. Do not
use its timing as H4 or infer a production fast path. The observed table can
subsequently be transformed or replaced by attention/DCP/per-layer metadata;
this candidate does not establish that an attention kernel consumed this exact
tensor, that K/V tensor contents are equivalent, that compaction is semantically
correct, or that arbitrary model generation is correct. Those remain null in
its emitted record.

## Source-owned interfaces

The added Host module has `register_observer(callable)`; registration is single
and process-local. Unregistered hooks are no-ops and produce **no** qualification
evidence. A source-pinned bootstrap must actually register the transport callback
in the API server and both workers. This artifact does not pretend that merely
copying the module activates a collector or that the callback is authenticated.
A failed callback/ACK must raise rather than accepting a producer boolean.

Both schemas contain `process` with Host-assigned role/ordinal, PID, start ticks,
start identity, process epoch, boot ID and session; and native plan/launch plus
monotonic time. Mapping uses `ecpa-native-request-id-mapping/v1` and the **actual**
`external_request_id` and `runtime_request_id` of the EngineCoreRequest. Upload
uses `ecpa-native-block-table-upload/v1`, runtime ID, device, post-barrier time,
`uploaded_rows[{group,row,blocks}]`, and SHA-256 of canonical JSON rows. Its scope
is `NPU-block-table-prefix-readback-only`; K/V equivalence, attention consumption
and full quality fields are null. Authority phase/challenge facts are not minted
by this module.

Host379 OpenAI supports payload `request_id` and header `X-Request-Id`, constructs
`chatcmpl-<external>` for Chat, then native `assign_request_id` adds eight random
characters for the engine. Freeze one exact API recipe, one engine input and
one completion per request. Preserve native randomization. Do not remove a
suffix heuristically or set `VLLM_DISABLE_REQUEST_ID_RANDOMIZATION` to manufacture
a join.

The independent collector must hold a preregistered request/phase/challenge
registry and source/identity grants. Bind an actual API-server mapping received
with kernel peer identity to the held external request. Then join both registered
workers' native runtime ID, current epochs, expected plan/launch and uploaded row
facts. Join the independently retained backend HTTP response to the exact external
response ID and frozen completion oracle. The CPU projection producer's
transaction/runtime ID and physical row recipe must match these upload facts if
claiming a specific rewrite occurred; an ordinary unchanged upload alone cannot
establish that the MOD had an effect. Duplicate, stale, wrong-role, unmapped or
unregistered facts must not discharge that obligation. All receipt bytes must be
stored durably before the collector returns a digest-bound ACK. SO_PEERCRED and
registered source identity are a separate transport requirement, not fulfilled
by these callback unit tests.

## Reproducible CPU checks and next hardware boundary

Run `python experiments/native_upload_candidate/check_candidate.py`; it hashes
the archived exact preimages, applies both patches in private temporary trees,
and parses all changed Python. Run `pytest tests/test_native_upload_candidate.py`.
Tests cover barrier-before-readback, CPU/device mismatch, CPU-device rejection,
no-observer no-op, exact native mapping and single registration. These are CPU
contract checks, not a simulation counted as hardware evidence.

Create clean separate Host/Ascend commits and build new local wheels. Freeze
all wheel/source hashes, the native bootstrap and authenticated collector, the
new HTTP recipe and challenge schedule, both process registrations, and a full
CPU path before any NPU launch. Run a new nonformal hardware campaign through one
operator after these gates pass; never retrofit r2's source, oracle or qualification.
Formal merged-source issuer admission remains separate. Successful NPU upload
readback would establish this narrow obligation only; loss/duplicate execution,
full KV semantics, quality and the original matched recovery cell remain unknown.
