# Explicit runtime contract and executable source/wheel handoff

The new runtime policy, bootstrap, digest envelope and selected-KV fact use their
own `*-runtime-*/v1` schemas and `REAL_RUNTIME_UNQUALIFIED` classification.
This is an **unqualified attempt contract**, not a GPU success label. Successful
transport/byte joins leave GPU qualification, actual attention consumption and full
model quality null; formal registration remains false. The 64KiB frame limit is
unchanged. Existing CPU187 facts and archived source bytes are not relabelled.

The opt-in runtime policy is `ecpa-selected-KV-private-artifact-runtime-policy/v1`.
Use the exact same frozen registration/requirements/owned-directory fields as the
CPU policy, with classification `REAL_RUNTIME_UNQUALIFIED`. Bootstrap writer selects
`ecpa-selected-KV-private-artifact-runtime-bootstrap/v1` from this policy. Source
callback takes **fresh actual cache readback** from the installed source hook and
actual Host worker `_scope`, then explicitly encodes
`ecpa-selected-KV-materialization-runtime-unqualified/v1`. The fact additionally
binds `native_producer` to that actual worker role/kernel identity. The runtime
checker rejects CPU caches, missing/invalid native NPU format, mixed K/V devices,
wrong worker/rank, wrong runtime schema, and any attempt to promote quality fields.
The new CPU policy also rejects NPU views rather than mislabel a hardware attempt.
It requires actual cache views from both observation stages to name the same NPU.

The original selected-byte predicate is reused through an explicit local adapter
for its byte/layout/slot checks; that internal adapter is never an old CPU artifact,
an ACK, a runtime report or a formal source registration. Only the new typed fact is
published. Fake NPU metadata used by pure negative/contract tests is labelled
schema-only and is never hardware evidence. An actual CPU-process bootstrap with
runtime policy rejects the CPU byte buffers before any artifact write.

Collector pairs the runtime policy exclusively with the runtime envelope and exact
worker predicate, requires the new runtime module digest in each registered worker
source inventory, and records its own exact runtime dependency in the chain start.
The raw/portable analysis retains `REAL_RUNTIME_UNQUALIFIED`; both ranks/all layers
plus real authenticated ACK prefix establish only the limited observed byte/artifact
join. A model response, complete native/source/wheel closure, actual hardware and
prospective clock policy remain independently required for later qualification.
The underlying generic native registration/ACK/status retain their existing
candidate-source schemas; they are structural transport declarations, not a CPU or
GPU experiment result. Do not infer a hardware outcome from a callback return.

## Prepare and genuinely build without touching an old tuple

```
python -m experiments.native_kv_tensor_candidate.build_source_patch
python -m experiments.native_kv_tensor_candidate.build_handoff \
  --host-repository /SOURCE/host-git \
  --kv-repository /SOURCE/kv-git \
  --output /NEW/unique-source-and-wheel-root \
  --build --uv /TOOLS/uv
```

The new output path must not exist. Without `--build`, this prepares sources only.
It creates separate clean worktrees at the exact archived Host b1f0/KV81e bases,
applies the hash-bound patches, copies the **exact** merged185 collector dependency
6b3e, checks all critical source bytes, commits source with a per-command local
builder identity, and records clean commit/tree/source hashes in `handoff.json`.
It changes no shared Git config, existing checkout/env/wheel, activation or device
process. An interrupted handoff retains its partial directories/receipts and must
be retried in a new root. A partial receipt is not a complete tuple.

`--build` invokes genuine `uv build --wheel` for each new source commit using the
established `VLLM_TARGET_DEVICE=empty` Host build target, writes separate logs, and
checks every packaged Python source against its newly frozen source tree (generated
Host `_version` is explicitly excluded). It records wheel SHA/count. This is no
substitute for installed-byte/RECORD/package/ABI audits: only install in a new
independent environment, keep Ascend fcbb exact, verify the installed full source
closure and pip check, freeze actual native registration before requests, and use
a fresh cohort. Never overwrite an existing wheel or infer an NPU run from a build.

Host patch installs transport/bootstrap/unchanged witness/new runtime checker;
KV patch installs method/cache/unchanged witness and derives the transaction from
actual `CompressionRequest.plan`. Source builder manifest binds all final bytes and
existing collector dependency. Tensor actor needs **both** newly built Host and KV
packages. Metadata-only185 cohorts can continue independently and do not acquire
this runtime tensor protocol by using newer analysis code.

Actual PA/FIA operator consumer hooks and stream-completion evidence are still
missing. Neither this source/wheel handoff nor runtime materialization receipts
prove attention consumed the selected tensors or prove compression/model quality.
The formal guard remains closed and formal result counts remain zero.
