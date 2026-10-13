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
