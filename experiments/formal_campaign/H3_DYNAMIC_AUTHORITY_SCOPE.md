# H3 dynamic authority and source-owned carrier

This is an explicit new protocol domain. It implements actual `Popen` Manager /
Host launch, independent `/proc` observations, owned worker fault handshake,
bounded full relaunch, new membership enrollment and real HTTP forwarding.
It does not change the original 25-cell/225-start matrix, 3 arms, 3 repetitions,
thresholds, workload, or any archived qualification. Only the original
`worker-crash` and `worker-replacement` actuators are implemented here. The
protocol's original rotating arm schedule is enforced.

The workload is exactly 60 requests, concurrency 8, interval 0.2 seconds,
timeout 10 seconds, dispatch slack 0.5 seconds and single attempt. A 55-second
restart misses the 11.8-second dispatch interval. The trace is not replayed or
extended. Delivery counts cannot establish backend execution duplication:
`duplicated_requests` and `backend_execution_duplicates` remain null. The original
objective is false when its unchanged loss/recovery/action bound is measurably
violated, and unknown otherwise. No code here emits a passing original H3 result.

## Actual launch and registration

`h3_dynamic_host.py manager` delegates to the actual installed Manager CLI.
`baseline` / `managed-host` delegate to actual `runtime_activation.main`, which
loads the real vLLM CLI. Baseline flags remain independent native activation.
No mock Host or synthetic model is used by this executable.

`h3_dynamic_registration.py` issues only a new-domain receipt after unchanged
full-tuple source admission: published commits, clean exact source checkouts,
Manager/Host merged-main, exact new protocol bytes in the Manager commit,
actual imported SDK bytes equal that commit, every installed MOD payload equal
its explicit plugin source owner, and source-admitted full contracts. Compiled
native payloads require a separate build proof and fail closed here. An old
NONFORMAL campaign or receipt cannot be promoted by renaming its schema.

`h3_dynamic_bindings.py` derives a typed execution Plan from an explicitly new
uncompiled intent, all actual installed bundles and full source contracts.
PluginIdentity comes from actual distribution payload bytes, metadata,
manifest and installed entry-point ownership. Bare policy plugin/entrypoint
labels are insufficient. Duplicate entry points / obligations and cross-MOD
substitution are rejected; all actual MODs must have their own obligations.
Semantic/non-invoked contracts fail closed, without dropping obligations.

Actual Manager default lifecycle Plan IDs differ from typed execution Plan IDs.
`native_plan_bindings` explicitly joins the actual installed bundle-derived
`runtime_evidence.launch_environment` ID to the contract-derived execution Plan.
Host events retain their actual native ID. `--semantic-launch-spec` cannot be
downscoped to this lifecycle carrier. Such cells still require the real semantic
producer and admission chain.

The campaign schema freezes nine start-specific policy and recipe-template
references. Templates contain `authority.process_identity: null`, never a future
PID. A source-admitted independent runner launches the exact authority command,
observes the actual authority kernel and Unix peer, and materializes only that
kernel field in a fresh runtime recipe. All other fields must equal the static
template. It does not edit old campaign, authority.start, receipt or client spec.

The original source campaign remains a content-addressed input. Its original
cell, model/workload identity, fault, objectives and functional response oracle
are retained. No old unsupported cell is replaced with an easier new hypothesis.

## Authority and raw checks

The new journal domain is `ecpa-h3-dynamic-authority-journal/v1`. The authority
CAS-closes before enrollment; independently checks actual API listener ownership,
exact API argv, actual source files, real Host role events from the private
journal, distinct API/TP2 worker kernels and every worker's PPID chain to this API.
Dead API/launch identities cannot reenroll. The new generation stays closed until
all declared source-owned invoked obligations are observed. Source/observer,
process, listener, lease or fencing loss closes and revokes that membership.

Native Manager owns each fresh launch UUID. The static policy freezes private
handoff roots; the authority derives `UUID.events.jsonl` only after observing the
actual canonical UUID4. Baselines use exact frozen evidence paths. No future UUID
or PID is guessed. Evidence files must be private, canonical and source owned.

`RegisteredAuthority` verifies exact full argv and script prefix, actual
PID/start/boot, source bytes and the private Unix socket/directory inode before
and after IO. It verifies SO_PEERCRED PID/UID/GID immediately after connect,
before sending the grant. A same-UID socket replacement receives no grant bytes.

HTTP forwarding connects TCP without writing HTTP bytes, then under the control
lock independently joins the TCP four-tuple and server accepted FD to the
admitted API kernel; it rechecks generation/membership/source before sending.
A closed replacement API on the same port receives no body. Old-request errors
cannot revoke a newer pending enrollment.

`h3_dynamic_client.py` reads the unchanged client generator's real raw trace and
the new journal directly. Exactly one authority.start, ordered close/enroll/open,
unique live generations, actual enrollment membership, pre-send peer proof,
request ID/method/body hash, response bytes, original schedule and
client.send <= admit < peer < complete <= client.finish are checked. The old
static verifier is never taught to trust a self-reported replacement PID.

The installed binding proof is derived from actual discovery/compiler outputs.
The live BindingGuard rehashes every underlying payload, contract, Plan,
registration artifact, RECORD, relevant optional metadata and global entry-point
metadata, and checks distribution-directory inventory on each use. It caches
pure derivation, never a stat/mtime-only freshness assertion.

## Executable commands after source publication

Run from the admitted Manager checkout with the selected runtime Python and
`PYTHONPATH` containing the admitted checkout root and the selected CANN/TBE
paths. The Manager SDK itself must import from the admitted installed wheel,
so do not prepend the checkout `src` directory. Every path below must be a fresh, real deployment input.
Missing references or absent source publication reject before Host launch.

```bash
export PYTHONPATH="$PWD:/usr/local/Ascend/cann-9.1.0/python/site-packages:/usr/local/Ascend/cann-9.1.0/opp/built-in/op_impl/ai_core/tbe"
PY=/root/ecpa-workspace/environments/ecpa-selected-kv-attention-candidate-venv-20261014-r4/bin/python

# Derive actual multi-MOD bindings from complete source-owned contracts.
"$PY" -m experiments.formal_campaign.h3_dynamic_bindings \
  --base-template /absolute/new-uncompiled-intent.json \
  --bundle-id ACTUAL_BUNDLE_A --contract /absolute/admitted-contract-A.json \
  --bundle-id ACTUAL_BUNDLE_B --contract /absolute/admitted-contract-B.json \
  --output-dir /absolute/fresh-derived-binding

# The campaign must satisfy h3-dynamic-campaign.schema.json. Each of its nine
# policies must satisfy h3-dynamic-policy.schema.json, with exact native bindings
# and recipe-template refs. There is no automatic reuse of NONFORMAL inputs.
"$PY" -m experiments.formal_campaign.h3_dynamic_registration \
  --campaign /absolute/fresh-dynamic-campaign.json \
  --output /absolute/fresh-dynamic-deployment-receipt.json

# Execute one original cell/start; order for repetitions 2/3 rotates per protocol.
"$PY" -m experiments.formal_campaign.h3_dynamic_runner \
  --campaign /absolute/fresh-dynamic-campaign.json \
  --receipt /absolute/fresh-dynamic-deployment-receipt.json \
  --start-id worker-crash-r1-vanilla-vllm-entry-points \
  --output-dir /absolute/fresh-start-output
```

The runner owns authority, carrier and descendants, retaining all raw starts.
An early real Popen failure first produces prospective-unverified provenance,
not a formal record. New intake independently validates receipt/source/actual
observations and reports `source-admitted-actual-start`; missing live observations
remain launched-unverified. Preflight rejection is separate. Existing aggregate
analyzer and old static record domains are unchanged. CPU protocol tests are
never counted as model/NPU formal starts; publication and actual fresh registered
model runs remain prerequisites.


## Full native domain

For selected-KV semantic contracts use `h3_native_registration` and the runner's
explicit `--native-domain`. The invoked-only registration above continues to
reject those contracts. Native admission recompiles the complete original KV
Plan and consumes the unchanged global tensor/OP/drain archive before each
public 200. Private readiness uses only GET `/health`; a positive model response
is not a prerequisite for starting the fault experiment.

```bash
"$PY" -m experiments.formal_campaign.h3_native_registration \
  --campaign /absolute/fresh-native-campaign.json \
  --output /absolute/fresh-native-receipt.json
"$PY" -m experiments.formal_campaign.h3_dynamic_runner --native-domain \
  --campaign /absolute/fresh-native-campaign.json \
  --receipt /absolute/fresh-native-receipt.json \
  --start-id worker-crash-r1-vanilla-vllm-entry-points \
  --output-dir /absolute/registered-start-directory
```

Every declared native peer spec must pass the original 65536-byte Host reader
limit before Popen; source scope retains the complete worker dependency union.
A late replacement, 503, timeout or incomplete original traffic coverage is
recorded as a failure after independently admitted launch/fault observations.
Invalid source/schema/proof joins remain intake rejections. Unknown lost counts
and backend duplication remain null. CPU fixtures and functional qualifications
are not formal experiment results.

`formal_start_validated: true` with `evidence_class: formal-real` is a validated
start for the original campaign denominator, including a measured failed start.
The separate `formal_result: false` field does not withdraw that start: it states
that this observation does not establish the complete H3 hypothesis. Read
`objective_met` and coverage separately; the 225-start aggregator must explicitly
consume these source-independent native-domain observations.
