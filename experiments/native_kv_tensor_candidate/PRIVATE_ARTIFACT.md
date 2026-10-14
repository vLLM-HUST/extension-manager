# Private artifact / digest ACK source candidate

This is `CPU_SOURCE_CANDIDATE_ONLY`, not a registered semantic producer or an NPU
result. The formal guard stays closed. `attention_consumption`, GPU qualification,
and full model quality remain null. Existing wheel/environment/cohort bytes are
untouched. The 64 KiB socket frame limit is unchanged.

`artifact_transport.TensorArtifactCollector` is an opt-in subclass of the existing
native collector. The generic collector and historical verifiers are unchanged.
The separate artifact policy is immutable and bound to the exact native registration
SHA. It contains two **actual** worker PIDs mapped to separately owned private
directories with frozen device/inode, and each predeclared phase's actual layer
inventory and semantic/physical anchors. PIDs, native roles/epochs, source files,
API request mapping and physical block destinations must be obtained from real
launch/source handoff, never invented from this document.

Freeze client IDs/nonces/requirements before launch, then freeze actual native peer
registration and private directories after launch and before the first request.
Directories require exact mode0700 (including no inherited SGID), ownership and no
symlinks in any traversed path. Native bootstrap context and policy/spec are private
mode0600 O_EXCL files. The source bootstrap verifies its current kernel worker
identity, its source inventory, context inode/bytes and both registrations.
Absence of context produces no receipt and cannot qualify a request.

## Source-owned transaction and phase

The installable KV patch reads the exact `CompressionRequest.plan` object used by
`TriAttentionMethod.compress`: `semantic_anchor`, `physical_anchor`, original
scheduler `source_block_ids`, and original private `destination_block_ids`.
It records the real request ID, current TP rank/layer, expanded actual device block
IDs, and the expansion factor from those actual allocations. The common transaction
SHA is derived from real request ID and these plan fields. It has no externally
assigned transaction, phase or nonce. The pure predicate verifies exact scheduler
to device allocation expansion, source/destination mapping, expected layer inventory
and anchors, selected reference/workspace/destination bytes, and source immutability.

Collector joins the runtime ID to an already accepted **actual API peer** external
request mapping. Phase/client ID/nonce come from that preregistered mapping, never
from the provider. Both registered worker ranks and every preregistered layer must
have a receipt for the same request/actual-plan transaction to complete the limited
artifact join. No receipt count can substitute for layer/rank identity.

## Bytes and ACK order

1. The real source hook finishes its existing selected-source/workspace/destination
   comparison and stream readback barriers. No new selection algorithm is supplied.
2. Source callback writes canonical large JSON to its registered directory via
   O_EXCL/O_NOFOLLOW, drains writes, fsyncs file and directory. File name is bounded
   to a plain 64hex basename; traversal, symlinks and hardlinks are rejected.
3. Only a small digest envelope enters the existing socket. It carries actual
   Host worker process/plan/launch scope, real runtime and transaction, policy SHA,
   and file device/inode/size/hash/mtime/ctime. It carries no giant tensor JSON.
4. Collector authenticates SO_PEERCRED PID/UID/GID plus start_ticks/session/boot,
   command line and exact registered source bytes. It reopens the registered
   directory without symlinks and validates its inode. It reads the exact source
   file and hash, applies the **same pure tensor/plan/phase predicate** used by the
   portable verifier, and rejects stale/pre-mapping/readback clocks.
5. Collector creates an O_EXCL private archive copy, fsyncs file/directory, reads
   that copy back, and rechecks the producer file before appending the digest
   envelope/peer/source/phase/archive identity to its fsynced raw hash chain.
   An archive persistence failure latches failed and provides no ACK.
6. Only then does the source receive the original native ACK schema, authenticated
   by the actual collector kernel peer/socket inode/source and digest. A caller
   Boolean, raw file existence or self-supplied prefix grants no evidence.

A source file can exist before its fsync and a copied artifact can exist before
its journal ACK. Neither is accepted evidence. A later source-file change does
not alter the separately archived bytes; a changed archive copy fails the portable
hash/predicate check. Filesystem permissions authenticate the registration scope,
not mutually hostile same-UID administrators; source execution and launcher/source
byte ownership remain prerequisites for a future real experiment.

`verify_archive(..., acknowledged_prefix=...)` performs no current native PID or
sender-path reads. It independently checks chain, source inventories, actual API
mapping, identical pure tensor predicate, full rank/layer transaction coverage and
archive bytes. Original inode/clock evidence stays recorded; unpacked archive file
inodes are not expected to reproduce original kernel inodes. Its ACK prefix must
come from the independently authenticated live `probe_collector` status; a prefix
supplied by an untrusted summary does not authenticate itself. Without that
external authenticated prefix, observed raw events remain incomplete/unknown.
Existing portable source/wheel/campaign hash closure must accompany any archive.

## Executable entry points and rebuild scope

Start from frozen inputs with:

```
python -m experiments.native_kv_tensor_candidate.artifact_transport \
  --spec /PRIVATE/native-spec.json --policy /PRIVATE/artifact-policy.json \
  --journal /PRIVATE/authority/raw.jsonl --socket /PRIVATE/authority/native.sock
```

The authority directory is private mode0700. The CLI prints its actual ready
identity; launcher must independently authenticate it before writing bootstrap
contexts with `artifact_bootstrap.write_context`. Set
`ECPA_NATIVE_TENSOR_ARTIFACT_BOOTSTRAP` to a newly published context only in the
new candidate cohort. The real native Host observer supplies worker scope; tests
explicitly use CPU fixture scope and do not impersonate a native NPU producer.

`python -m experiments.native_kv_tensor_candidate.build_source_patch` reproduces
both patches from archived exact source preimages. `artifact-source/binding.json`
binds every postimage, the unchanged witness184 SHA, the actual plan dataclass
preimage and **exact existing collector dependency** SHA. The new Host patch adds
three installable modules: transport, bootstrap, and the identical pure witness.
The new KV patch modifies cache/method and installs its identical witness module.
Ascend fcbb interfaces are unchanged. Build/install a new clean Host and KV wheel,
retain the exact Ascend tuple, audit installed source/RECORD bytes, and freeze a
new cohort; do not mutate an existing wheel/env. If another collector-clock PR
changes the base dependency, regenerate this manifest against that merged source
and explicitly copy that exact version into the newly built Host.

The recorded CPU tests use four actual independent processes, real Unix sockets,
large actual CPU binary16 buffers (>64 KiB), private real files and fsync. They
cover positive full two-rank/layer joins, false prefixes, wrong source/kernel/
socket/path/inode, post-write and archived blob mutation, rehashed plan/rank/phase/
clock/source counterfactuals, source bootstrap, and injected actual archive-fsync
failure. They do not run full compression, NPU tensors, an attention operator or a
model request. Hardware/private package provenance and actual attention consumption
still require separate implementation and qualification. This source candidate
never turns generic uploaded prefixes into KV tensor or model-quality success.
