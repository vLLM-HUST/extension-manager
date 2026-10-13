# Shared worker crash and external full relaunch

`h3_worker_relaunch.py` is an executable, supplementary qualification runner.
It never calls `run_h3.py`, changes the manager-crash cell, uses a native prepare
barrier, or adds ECPA recovery to either baseline. The independent source oracle
in `H3_BASELINE_NATIVE_SUPPORT.md` shows that native Host worker death shuts down
the executor; the common recovery action here is an experiment-controlled full
launch restart, not native transactional recovery.

The frozen JSON schema identifier is
`ecpa-h3-worker-relaunch-qualification/v1`. `classification` must be
`QUALIFIED_NONFORMAL` for actual Host events, or `CPU_PREFLIGHT_ONLY` for CPU
process fixtures. `formal_result` and `original_manager_cell_completed` must
both be false; `recovery_action` is `common-external-full-relaunch`.

One campaign retains all three named arms. Each has its own exact `argv`, absolute
`cwd`, complete `env` (ambient environment is not inherited), `plan_id`, worker
`target_ordinal`, and two phase objects with distinct `launch_id` and absolute,
fresh `evidence_path`. These six launch IDs and evidence paths cannot overlap
across arms. `activation_contract` is `entry-points-unmanaged`,
`explicit-manual-hooks`, or `manager-controlled-activation` respectively.
Actual baseline argv must select exactly `--disable-ecpa-manager` plus
`--enable-entrypoints` or `--manual-hooks`; ECPA must select none of those
baseline flags. The original ECPA launcher must remain independently source
reviewed: the flag check alone does not establish Manager control semantics.
The frozen launcher must honor the phase binding variables; a launcher that
replaces them produces rejected stale/unbound evidence.

Each arm freezes three `sources` (`launcher`, `host`, `mod`) with concrete path,
SHA-256 and, for actual Host qualification, exact 40-character `revision`.
The launcher source must be one of the executed first two argv entries, such
as a console script invoked by an absolute Python executable. The runner verifies
all bytes before each launch and retains source copies. These bindings do not
prove merged-source admission, installed wheel equivalence or authenticity
against coordinated artifact rewriting; those formal gates remain separate.

All arms share one `policy`: `signal: SIGKILL`, `relaunches: 1`, and bounded
`ready_timeout_s`, `exit_timeout_s`, `cleanup_timeout_s`, `probe_poll_s` and
`request_timeout_s`. No arm can override that policy. Before the first signal
and after relaunch, the actual Host path requires a frozen `probe` containing
a direct loopback URL and OpenAI completion `payload`. The runner retains
request and response bytes and every failed readiness attempt, and accepts
only an HTTP 200 with the requested model and positive completion tokens.
This is direct-backend completion readiness; it establishes no independent
traffic-authority admission, model correctness, quality or crash-window coverage.
CPU fixtures instead freeze `probe_command`; its success never counts as a model
completion. The same argv/cwd/env is reused, with only the explicitly fresh phase
launch identity and evidence path changed.

For actual Host mode, `evidence_protocol` is `vllm-host-worker-event/v1` and the
frozen environment must arrange the real Host sink, for example
`VLLM_ECPA_EVIDENCE_SINK=vllm_hust_ext.runtime_evidence:record_event` with its
exact source/package binding. The runner sets `VLLM_ECPA_PLAN_ID`,
`VLLM_ECPA_LAUNCH_ID`, `VLLM_HUST_EXT_EVIDENCE_PATH` and the arm activation
contract. It parses actual Host event bytes, accepts only `invoked` records with
Host-assigned worker role/ordinal, requires fresh launch/plan/time and a unique
live PID/start ticks/process epoch, and verifies that the worker belongs to the
launcher ancestry and the exact live session leaders captured from that tree.
This supports the actual Manager process supervisor, which creates a nested SUT
session. Declared arbitrary session IDs are never sufficient. It retains the
journal bytes before each probe.

The fault is delivered through a Linux pidfd after rechecking the exact live
PID/start ticks/boot ID/session. The runner records signal delivery and target
exit, completely reclaims the original launch session, then relaunches and
requires a new worker identity and process epoch. Finally it reclaims every
owned session (including captured nested supervisor sessions) on success and
failure and retains all errors. It refuses unowned
workers, stale identities, ambiguous records, reused launch/evidence paths and
source mutation. Any failed probe, fault, fresh-epoch or cleanup check yields a
failed qualification with raw logs; it cannot be aggregated as native recovery.

Run a separately frozen arm from the repository root with the intended exact
Python environment:

```sh
PYTHONPATH=src:. python -m experiments.formal_campaign.h3_worker_relaunch \
  /absolute/campaign.json --expected-sha256 FROZEN_SHA256 \
  --arm manual-integration --output /absolute/fresh-output
```

The CLI checks the externally recorded input digest. Before launching, the
runner retains its campaign bytes/digest and exact source copies. Every phase
retains stdout/stderr, observed worker identity/epoch and probe artifacts; result
records include terminal cleanup failures. Output directories must be fresh.

The tests execute real CPU parent/worker processes and SIGKILL/full relaunch
for all three labels, reject stale or unowned live worker identities without
signalling them, and exercise raw HTTP fixture response retention. Fixture
protocol `cpu-fixture-worker/v1` is accepted only as `CPU_PREFLIGHT_ONLY`;
fixtures provide no Host/model, NPU, formal H3 or baseline recovery result.
This runner has no deployment receipt/issuer integration and is deliberately
ineligible for formal intake. Whole-window loss, duplication and recovery
objective remain null. Original H3 requirements remain open and formal starts
remain zero. Next actual use requires independently frozen per-arm source,
installed stack, owned port/backend bindings and model commands; it cannot reuse
historical H1 commands as current qualification or claim the original cell done.


## Opt-in native Manager phase handoff

The original prototype inherited reserved plan/launch/evidence variables and
could not run the actual Manager `run` path: `launch_environment` correctly
rejects those caller values. Its three-label CPU fixture runs therefore remain
CPU-only, with no claim that three actual model arms have run.

An opt-in `vllm-hust-ext run --phase-binding-socket PRIVATE_SOCKET -- COMMAND`
now invokes the original native mint, then transfers its generated binding
through a private Unix stream socket. Default `run` behavior is unchanged.
Enabled bundle discovery, compatibility checks and provider plans remain the
normal CLI inputs; the new option does not bypass them or the reserved-variable
rejection. A receiver cannot supply plan/launch IDs or select the evidence file:
Manager chooses its UUID and a fresh private evidence file before supervision.
Both endpoints verify kernel SO_PEERCRED: publisher is the exact live Manager
child, receiver is its actual parent. Canonical private directory/socket inode,
PID/start ticks/boot/session, timestamp and exact Manager source digests bind
the handoff. Manager waits for a digest-bound acknowledgement before invoking
the existing process supervisor, which creates the actual nested SUT session.

For an ECPA common-worker arm, freeze
`binding_protocol: ecpa-manager-native-phase-handoff/v1`, exact
`manager_source_sha256` for `cli.py`, `runtime_evidence.py` and
`runtime_phase_handoff.py`, `process_supervisor.py`, and two phase objects containing only
`handoff_path`. Native `plan_id`, `launch_id` and `evidence_path` are not frozen
external identities: they are received after startup and before fault, then
retained in separate phase receipts. Actual IDs must follow Manager generation;
these receipts are not retroactive formal registration. Freeze the command's
single `@native_phase_socket@` argument in the position of
`--phase-binding-socket`; only that frozen path is substituted per phase.
Baseline fixed environment contracts remain unchanged. Actual ECPA Host mode
requires the native protocol and rejects externally supplied reserved variables.

The CPU integration traverses the real Manager CLI parser, native mint,
source-bound handoff, acknowledgement and process supervisor, then actually
kills/relaunches a nested CPU worker and checks cleanup. Its bundle discovery,
provider plan/compatibility input and worker protocol are explicitly fixtures;
no fake Host event is emitted. Reserved-variable, wrong process identity,
non-owned publisher, source mismatch, public directory and wrong-ack negatives
stop before worker supervision or fault. Raw unvalidated handoff bytes remain
failure evidence, not accepted receipts. All of this is CPU_PREFLIGHT_ONLY.

A new exact Manager wheel/source freeze is needed before actual model use;
the earlier r4/runtime source does not acquire this API retroactively. Actual
three-arm model experiments, owned port/backend bindings, formal Host admission,
the original manager-crash cell and whole-window loss/dup/objective remain open.
Formal H3 remains zero. The source hashes bind bytes and the trusted native code
path; they are not signatures against an actor rewriting every artifact.
