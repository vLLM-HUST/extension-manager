# Native semantic transport candidate

This executable private Unix collector receives source-native API mapping and
NPU-prefix readback facts. It does not open the formal traffic gate, register
formal producers, or prove any extension effect. A generic Host upload is not
KVCompress: that future obligation must join actual pending destination/anchor
projection with a subsequent matching GPU prefix and actual request/response.

`native_semantic_collector.py --spec SPEC --socket SOCK --journal JOURNAL` starts
an independent process. SPEC is a private 0600 frozen JSON with schema
`ecpa-native-semantic-collector-prereg/v1`, CPU_REVIEW_CANDIDATE_ONLY class,
formal_producer_registration false, native_plan_id/native_launch_id,
frozen_monotonic_ns/max_event_age_ns/max_uploads_per_rank, exact three senders,
and phases. Each sender freezes actual Host-assigned process role/ordinal/PID/
start_identity/start_ticks/boot_id/session/process_epoch/host/assignment_source,
peer_uid/peer_gid, cmdline_sha256, and source_files [{absolute path, sha256}].
Phases freeze phase_id/client_request_id/challenge_nonce/external_request_id/
expected_ranks=[0,1]. The challenge recipe precedes launch; actual PID/epochs
are bound by launcher-owned startup handoff and this spec before HTTP probes.
Do not call the PID-bearing registration a before-launch preregistration.

Facts use the exact native candidate schemas from PR #168. The source does not
claim a nonce. The collector joins its preheld external response identity to the
actual native API mapping, then accepts only registered worker facts for that
actual runtime ID. Every connection is checked with Linux SO_PEERCRED plus
PID/start ticks/boot/session, frozen argv/source bytes and raw native process
identity. Missing/changed source, role, nonce, request mapping, actual-upload
fields, stale epochs, replayed bytes or barrier times are rejected. Fresh later
uploads from the same rank are retained and ACKed within the preheld finite
bound; they do not create another completed rank or claim all-step correctness.

Framing is newline-delimited JSON, max 65536 bytes. The intake request is
{"raw_base64": BASE64_CANONICAL_NATIVE_JSON}; read-only {"op":"describe"}
returns identity/spec/source/socket/archive fields and the acknowledged prefix.
Canonical JSON uses sort_keys, separators (',',':') and allow_nan=False.
Journal sequence begins at zero, previous_sha256 at 64 zeroes; event_sha256 is
SHA-256 of the whole canonical event excluding event_sha256. Accepted envelopes
retain exact raw bytes, kernel peer, source hashes, phase join and archive inode.
Only a completed file fsync advances the ACK prefix or returns a native ACK.

The native sender client verifies the ACK's actual kernel owner, frozen socket,
source, archive identity, exact raw digest, phase and envelope hash. If raw bytes
become visible before a failed fsync, they are not durable ACK evidence. The
independent reader must obtain authenticated post-probe describe status,
failed=false and acknowledged_prefix matching the complete raw chain tail.
Without that owner seal, verify_journal reports observed raw transport only;
complete_two_rank_transport_phases is null and durable_ACK_status unverified.
A supplied prefix is trusted only after the caller authenticated its live owner;
the offline function cannot authenticate an arbitrary Python dict.

The native_semantic_bootstrap.py source-owned opt-in adapter reads immutable
private bootstrap context and registers the actual native observer callback.
It forwards native facts unchanged and never invents role, request ID or nonce.
Missing context is non-producing warmup, not qualified evidence. The source
patch targets the exact native module SHA 532b72ee...fc9a. Copy exact collector
and bootstrap modules to vllm/plugins, apply the patch in a NEW clean Host
candidate and build a NEW wheel; never mutate bb5218 or any existing wheel.
The launcher must independently check readiness/owner/source and complete
write_context before allowing a challenge. Host publication/source admission
still remains separate; local candidate and CPU tests confer no formal source.

Run CPU peer/negative checks without a device:

```sh
PYTHONPATH=src:. python -m pytest tests/test_native_semantic_collector.py -q
```

Tests use four real processes, real sockets/private files/kernel credentials and
fsync, with explicitly simulated serving/GPU payloads. They establish transport
and fail-closed behavior only. The formal guard remains closed, formal H3/H4
remain zero, and NO-GO remains.

The version-2 collector records its actual startup and per-envelope validation
monotonic time. A pure predicate in this same source file is shared by live
intake and portable raw verification, including exact fields, source process,
NPU device, scope, null quality claims, row/block types, frozen/mapping/barrier/
accept chronology and age bounds. Offline verification never reads current PIDs
or invents a receive clock. Historical version-1 source 135a3a9f remains
readable for static observations, but missing receive clocks leave chronology
unverified and complete transport qualification null, even with a prefix seal.
Runtime collector source and later analysis source hashes are reported separately.
The updated collector bytes require a new clean Host source/wheel; the old
version-1 wheel/source and sealed observations remain unchanged.
