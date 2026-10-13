# Three-arm real TP2 worker crash / full relaunch qualification

The new r2 cohort completes six real backend starts and three actual owned-worker
SIGKILL faults: vanilla entry points, explicit manual hooks, and native Manager
activation each launch, return the frozen exact marker, lose worker ordinal 0,
clean up the entire old session, and launch the same backend command with fresh
Host worker identities/epochs. Each of the six direct model RPCs returns
`ECPA-WORKER-READY`, `finish_reason=stop`, and nine completion tokens. This is a
supplementary **QUALIFIED_NONFORMAL** result.

The earlier r1 cohort also completes six generation RPC starts and three worker
faults, but all six responses fail the requested marker task. Its legacy runner
accepted HTTP/model/token/choice readiness. The independent analysis reports
`task_oracle_failed`; it preserves the original source, raw response bytes, cache
warnings, failed preflight script, and aborted wrapper attempt. The wrapper
attempt has no backend-start evidence and contributes no startup count.

| Cohort | Real generation starts | Worker faults | Exact requested marker / stop | Scope |
|---|---:|---:|---:|---|
| r1 | 6 | 3 | 0/6 | RPC lifecycle only; task failed |
| r2 | 6 | 3 | 6/6 | Frozen per-launch task oracle and worker relaunch |

The original manager-crash-after-prepare matrix remains incomplete. The common
external full-relaunch policy is not an ECPA recovery injection into baselines or
a substitute for that cell. Each arm has two starts here; these are not formal
H3 qualification counts. Full-window request loss, duplicate requests, objective
satisfaction, and performance remain unknown. Formal H3/H4 stay zero and NO-GO
is unchanged.

## Exact runtime and environment

Both cohorts use the new isolated Manager wheel built from
`0a6fdbc7784a0db0a92fc50615f5ca3efbf5f966`, SHA-256
`0498efa84fa0739abc924f9680764ec3ba88c0ab9eaf5574906038cb0a1f2358`.
The venv is an independent copy; the previously qualified shared venv is not
modified. Host is `379a0ad35e9de6928e3481d375692204b0dee6e4`, Ascend is
`873584026`, KV MOD is `e343fc5ce6b4c64611a79df5d797b3db12cd6dac`, with CANN
9.1.0, the recorded Torch/Torch-NPU/Triton wheels, and 14 hashed model files from
Qwen2.5-7B-Instruct. The preflight compares installed Python bytes with all seven
wheel archives. This does not close the unmerged Host or formal capability gates.
Physical devices 3 and 6 map to runtime ordinals 0 and 1; visibility override is
unset. The arms execute sequentially on the assigned two devices.

The r2 runner is frozen separately at
`aef46c09b6c574ad42945f331a0dc68f9a19b2f2` (PR #163, CI 322; merged as
`86043ef405741866b53cae763dae0ea3776a2aa0`). The installed Manager runtime remains
0a6; the run is not retrospectively rebound to later main. The campaign digest is
`b7221a6aa1026366780c5eaf5cc40d981069e28c2ed9a73d4e5d6d514cd28e2e`.

The previous r4 model driver inherited the session environment while its input
summary filtered keys. r1 constructed a clean environment from that filtered
summary and omitted HOME, locale, ATB, and other original runtime values. r2
explicitly freezes a safe allowlist, preserves HOME `/root`, sets TRITON_HOME to
that original home, and assigns a private mode-0700 initially empty cache to each
arm. Initial launch is cold; the same-arm relaunch reuses that cache; different
arms do not share caches. Directory UID/device/inode and terminal cache file
hashes are retained. Compiled cache binaries remain private and are not claimed
as publicly archived bytes. The missing-root and async-launch warnings disappear
and the task oracle passes after environment closure, but these observations are
not an ablation proving a single cause of the r1 incorrect generation.

Baseline IDs are frozen per phase. ECPA freezes only private handoff paths and
protocol/source identities, then records actual Manager-minted IDs. Its two native
launch UUIDs differ and its plan remains the same. Private Unix SO_PEERCRED,
actual parent/child identity, source digests, and raw handoff body/receipt binding
remain intact; external native reserved-environment injection remains rejected.

## Recompute and limits

Run from the repository with a Python interpreter:

```sh
python -m experiments.formal_campaign.verify_h3_worker_real experiments/formal_campaign/artifacts/h3-worker-real-20261013/r1-manifest.json
python -m experiments.formal_campaign.verify_h3_worker_real experiments/formal_campaign/artifacts/h3-worker-real-20261013/r2-manifest.json
```

The verifier reads actual final Host journals and original response bytes, rather
than trusting the summary verdict. It binds same-phase plan/launch IDs, the KV MOD
entry point and both Host-assigned TP2 worker ordinals, PID/start/epoch uniqueness,
selected fault target, event order, source snapshots, exact launch argv, baseline
activation flags, and ECPA raw canonical handoff body plus owned Manager/session.
Early worker snapshots must be prefixes of final journals. It binds a late actual
terminal `/proc` audit to every final journal, all 30 original Host/Manager process
identities, all eight captured sessions, and the latest timestamp across all six
journals; both devices and all arm ports are clean after each terminal cohort.
These late observations are explicitly not preregistered crash-window observers.

The task predicate was frozen before r2 GPU use: exact message text after the
specified whitespace rule and `finish_reason=stop`. A wrong completed RPC fails
immediately and retains its bytes. Transport readiness may poll. Actual installed
Manager CLI three-arm CPU HTTP fixtures passed the same predicate and complete
process kill/relaunch/cleanup path before GPU use; their fixture protocol remains
CPU-only and cannot become Host/model evidence.

The repeated short prompt contains no per-phase nonce. Phase RPC attribution
trusts the frozen runner's serial direct HTTP probes and Host chronology. API
`created` seconds provide a limited phase-clock consistency check that detects
accidental response swaps under the API server's clock. This is neither an
independent client completion timestamp nor a challenge-bound authority receipt;
rewritten/replayed response metadata cannot establish an exactly-once result.
The qualification proves six bounded task responses, not crash-window traffic
continuity or recovery correctness.

Independent late `/proc` samples confirm recorded Manager or launcher parent
inputs where captured. Host children derive environment changes, including cv2
library prefixes and the explicit manual bootstrap path/plugin filtering. Those
samples preserve the actual differences; parent environment is not asserted equal
to child environment. Vanilla historical live environment was not captured and
is not reconstructed as an actual observation.

The public r1 archive has 97 files, SHA-256
`c192cbf3d3d93744d742882013452720ca14bfd765f795b2d6d0da0fbad6df6c`.
Its original CPU campaign contains opaque session infrastructure fields and is
retained privately. The archive explicitly excludes that file, records its
original digest and exclusion provenance, and states that the public archive is
not the complete original directory. No opaque environment values or recovery
mapping are published. The r2 archive has 175 files, SHA-256
`5202308dfe08cae258e222d60b527c8c0840872f218f26fb72d49bf3dc032173`,
including the safe explicit-allowlist CPU records and bounded independent late
observations. Public archive digests remain unchanged while analysis is hardened.

Negative tests include wrong-phase rank 1 despite valid rank 0, a forked receipt
publisher despite a matching raw-body hash, a fully rehashed nonowned publisher,
wrong model/text/stop reason, response order and clock inconsistency, warm or
changed cache identity, omitted/live terminal process claims, and a late record
in an earlier arm despite rewritten journal hashes. Raw content and final journals
remain necessary even if a report claims success.
