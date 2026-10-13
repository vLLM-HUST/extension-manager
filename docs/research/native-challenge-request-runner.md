# Preregistered native request/upload challenge runner candidate

This runner is **CPU_REVIEW_CANDIDATE_ONLY**. It prepares a new campaign; it does
not retrofit the repeated-prompt r2 qualification. The CPU tests execute real HTTP
and private Unix sockets with independent processes, but their native-shaped
fixtures are not Host/GPU evidence. Formal results, hardware qualification, KV MOD
semantic effect, KV tensor equivalence, attention consumption, full quality, and
full-window loss/duplicate/objective claims are not established here.

Freeze unique public 128-bit client request IDs and challenge nonces for every
phase before launch. The body and `X-Request-Id` header use the same client ID;
the expected external response ID is `chatcmpl-<client-id>`. The single bounded
prompt requests exactly `ECPA-CHALLENGE-<nonce>` with a stop finish reason. The
existing Host source accepts that external ID but adds an internal random suffix.
The consumer obtains the actual internal ID from the native API mapper, and does
not infer it by splitting or guessing a suffix. Each challenge is POSTed once;
an ambiguous dispatch is preserved instead of replayed.

The native plan/launch IDs and actual process epochs cannot be preregistered as
external Manager identities. After native startup/handoff and before the HTTP
probe, freeze the collector spec with actual native IDs, owned Host API/worker
process identities, source bytes, and the five exact request phase fields:
`phase_id`, `client_request_id`, `challenge_nonce`, `external_request_id`, and
`expected_ranks=[0,1]`. Freeze the bounded upload cap in the collector spec.
This distinction does not claim that runtime process registration happened before
launch or before every device warmup.

The executable flow is:

1. `freeze` writes the canonical request recipe once into an owned private
   directory, mode 0600, records its digest, and binds source bytes.
2. `execute` matches the collector's preregistered phase with that recipe, then
   authenticates its actual Unix `SO_PEERCRED` kernel identity and a separately
   launcher-observed PID/start/boot/session and command fingerprint. The source,
   private spec, socket, and archive identities must match.
3. Send one real nonce request. Retain request/headers/response bytes; require the
   external response ID, model, positive generation, exact nonce content, and stop.
4. Authenticate the collector again after completion. Require failed=false and
   the fsync-acknowledged journal prefix. Recompute the authority-owned raw chain
   with that owner seal and require verified recorded intake chronology, then bind
   the actual API mapping plus both registered
   worker ranks' native upload receipts to this phase.

The explicit `rpc-only` command performs client task checking and always reports
its native join as missing. Its success cannot authorize native observations.
`execute` may report an authenticated durable **transport join**; it still leaves
`native_join_qualified=false` and KV/GPU semantic obligations unknown.

Multiple decode-step readbacks remain raw observations. The source collector
accepts fresh increasing per-rank barrier times within its frozen cap, rejects raw
replay or old time, and counts rank coverage once. The consumer retains all
accepted observations and does not pretend that a first generic GPU table prefix
proves a later KV rewrite. Closing a compression obligation would additionally
require the actual pending MOD projection's request/group/semantic and physical
anchors/destination mapping, followed by the matching later GPU prefix. The
untrusted local PublicationAck from the earlier projection prototype is not
consumed.

The native observer defaults to non-producing when no source-owned bootstrap
context is present. Correct HTTP output or a ready collector with missing native
mapping/rank receipts therefore fails the join. The final lazy callback bootstrap
must be included in newly frozen Host source/wheel bytes; the old bb wheel with
the original non-registering observer cannot be reused as if callbacks existed.
Use a new isolated venv and exact Host/Ascend/MOD/Manager/source/cache/model freeze
before any future GPU attempt. Existing r1/r2 runtime wheels and raw data stay
unchanged.

CLI:

```sh
python -m experiments.native_challenge_candidate.request_runner freeze configuration.json --output /absolute/private/recipe.json
python -m experiments.native_challenge_candidate.request_runner execute /absolute/private/recipe.json --expected-sha256 FROZEN_SHA --phase PHASE --output /absolute/private/phase-output --collector-socket /absolute/private/collector.sock --collector-launcher-descriptor /absolute/private/launcher-observation.json --collector-spec /absolute/private/spec.json --collector-source /absolute/source/native_semantic_collector.py --collector-journal /absolute/private/raw.jsonl
```

`configuration.json` has explicit `phase_targets` entries (`phase_id`, `url`,
`model`) and `sources` entries (`role`, absolute `path`, `sha256`). The target URL
must be direct loopback `/v1/chat/completions`. The launcher observation augments
the collector's ready fields with independently captured
`launcher_observed_identity` and `launcher_observed_cmdline_sha256`.

The CPU checks cover two separate real HTTP challenges, wrong nonce/response ID/
finish reason, duplicate phase/request IDs, forbidden guessed native IDs, actual
Unix kernel peer/source/socket mismatch, absent fsync prefix, full three-process
native-shaped transport with multiple decode observations, missing rank, and stale
post-request durability seal. They do not generate evidence usable as formal
Host or NPU qualification.

The source-only request-ID oracle is recorded in
`experiments/native_challenge_candidate/source_audit/host-request-id-34f6c324.json`: 
clean Host `34f6c324`, four exact serving/protocol/input-processor source digests,
and the header/body, external-prefix, and internal-randomization rules. This
source audit is not an observed client-to-worker mapping and cannot discharge
the native receipt requirement. Future exact-wheel freezes must recheck these
bytes against the installed source; the old runtime is not rebound to them.

Collector source must use the shared live/portable v2 predicate with recorded
start and accepted monotonic clocks. Legacy raw chains without intake clocks
remain unverified and cannot complete this transport join; no timestamps are
backfilled. This candidate was checked against collector source
`ee62c51444acde7b813c33ea4c2b20ab07248ea050753199cbfc79d73f1c5075`.
