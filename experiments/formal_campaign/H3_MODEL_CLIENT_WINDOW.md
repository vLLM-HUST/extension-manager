# Real model finite client-window qualification

This retained `QUALIFIED_NONFORMAL` experiment runs two independent live
Qwen2.5-7B TP2 backends on NPU 3 and 6 and observes 60 frozen model requests
through an independent authority during an actual native coordinator crash.
Runtime Manager source is clean merged `3a55952299655d8319c49f34efa59946fc30d63f`;
the complete CPU path used immutable PR #154 head `394d4dd0491dc0d29f10d5a10e754cd0230cc891`.
All 43 relevant runtime/helper files are byte-equal across those exact commits.
Later portable analysis uses the current mainline helpers, including the
missing-evidence rules from PR #156. These analysis changes do not rewrite the
frozen runtime, preregister a formal experiment, or promote its qualification.

The exact instruct prompt was generated before any model launch by the audited
Qwen tokenizer's `apply_chat_template` with recorded input messages and options.
It is 179 bytes, SHA-256
`2065e474377b8b47df5df5af710809068983cfd4f0b101ed4f662a9c63705764`.
The frozen `/v1/completions` oracle requires exactly `ECPA-H3-WINDOW-OK` and stop
termination. The runner freezes 60 IDs, a 0.2-second schedule, 8 concurrent
attempts, 10-second deadlines, 0.5-second dispatch slack and no retries. Actual
backend PID/start/boot/launch/model descriptors and the authority identity are
frozen before the client starts. The independently owned authority checks the
registered backend's actual live listening socket and records full response
bytes; headers are only join keys.

The coordinator commits its native SQLite close intent and pauses before the
external effect. The continuous client starts first; after at least two seconds
the operator sends SIGKILL to that coordinator. Both model backends remain live.
After at least three seconds a new coordinator reconciles the same database and
restores the exact predecessor control route. Client arrivals continue for more
than two seconds after observed recovery. Native SQLite rows, process epochs,
fault/recovery markers and the independent route chain substantiate the actual
fault and recovery separately from the client timestamps.

For this finite set, all 60 model responses satisfy the exact frozen oracle and
were delivered by their individual deadlines. Observed deadline delivery loss
is 0/60, duplicate authority admissions 0, and reused successful response IDs 0.
Backend execution duplicates, duplicated requests/side effects and the full
research objective remain unknown. Only predecessor generation 0 serves the
client window; the live candidate is independently sampled by seven separate
phase markers and is never exposed. This establishes native coordinator/control
route recovery with a continuously live predecessor model backend. It does not
establish backend restart, replacement-generation correctness, rollback after
candidate exposure, full Host effectiveness, matched baseline recovery,
performance/quality or formal H3. Formal H3/H4 counts remain zero.

The full two-CPU-backend/native-coordinator/authority/client path was run first
without NPU or model qualification. Its initial chat-shaped response fixture
failed the frozen completions oracle and is retained as a separate failure.
A new correctly frozen completions fixture passed before the model launch. No
running inputs or failed evidence were edited into success. Runtime source
snapshots were extracted from the frozen commit after execution and are marked
as such. Local hashes establish byte integrity, not signatures against an
adversary rewriting every artifact.

Recompute the portable retained model evidence:

```sh
PYTHONPATH=src:. python -m experiments.formal_campaign.h3_model_client_window \
  experiments/formal_campaign/artifacts/h3-model-client-window-20261013/raw.tar.gz
```

The verifier checks frozen input/model/wheel/source bytes, both Host worker
pairs, actual SQLite recovery, exact predecessor binding, all seven phase
markers, the continuous client's schedule and raw authority response joins,
actual registered backend epochs, fault/recovery timing and final reclamation
of all 12 owned PIDs and three listening ports. Incomplete window evidence
retains unknown counts and cannot pass this qualification. It does not trust
`result.json` or the coordinator's functional-correctness summary.
