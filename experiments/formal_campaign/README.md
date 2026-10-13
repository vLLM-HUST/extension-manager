# H3/H4 formal campaign intake

This directory freezes the analysis contract for the H3 recovery campaign and
the H4 matched-cost campaign.  It contains no formal result.  `protocol.json`
is `planned`, and the analyzer reports `incomplete` until every required cell,
arm, and independent start is present.

Run the intake before using any number in the paper:

```bash
python3 experiments/formal_campaign/analyze.py \
  --campaign-spec /absolute/path/to/frozen-h4-campaign.json \
  --records /absolute/path/to/records.jsonl \
  --artifact-root /absolute/path/to/raw-artifacts \
  --output /absolute/path/to/validated-summary.json
```

Each JSONL record must be `formal-real`, bind a registered deployment receipt,
use the frozen Latin-square order, and provide SHA-256 bindings for the
registered deployment receipt, raw log, request results, process snapshot, and
cleanup report. The receipt bytes must match the digest in the record and must
contain an admissible, registered deployment. Records from
preflight, simulation, fixtures, or an unregistered deployment are rejected.
For H4, every start must also bind a named `ecpa-h4-deployment-receipt/v1`
receipt and a unique `ecpa-h4-raw-measurement/v1` artifact. The gate checks the
campaign, cell, arm, workload, receipt, process epoch, and child artifact
bindings. It recomputes startup phases, throughput, and latency quantiles from
raw monotonic timestamps; copied summary metrics are never authoritative.
The analyzer verifies artifact bytes and exact cross-arm identity equality. It
retains failed starts and keeps the overall campaign incomplete when only one
nine-start cell is complete, while emitting that cell's independently labeled
formal result.

After an exact three-arm deployment receipt exists, execute the frozen Latin
square with:

```bash
python3 experiments/formal_campaign/run_h4.py \
  --campaign /absolute/path/to/campaign.json \
  --deployment-receipt /absolute/path/to/deployment-receipt.json \
  --launch-spec /absolute/path/to/launch-spec.json \
  --output-root /absolute/path/to/h4-runs
```

The receipt is issued by the repository transition, not authored by hand:

```bash
python3 experiments/formal_campaign/h4_registration.py \
  --campaign /absolute/path/to/campaign.json \
  --launch-spec /absolute/path/to/launch-spec.json \
  --manager-repo /absolute/path/to/extension-manager \
  --host-repo /absolute/path/to/vllm-hust \
  --output /absolute/path/to/deployment-receipt.json
```

Issuance fetches both remote `main` branches, requires the frozen Manager and
Host commits to be ancestors of those heads, verifies the historical protocol
bytes named by the campaign, validates the complete campaign/launch shape, and
atomically creates a new receipt. It refuses to replace an existing receipt.
A local Host commit, a pull-request ref, or a functional preflight cannot issue
the receipt. Receipt issuance starts no server and produces no H4 result.

`run_h4.py` records `CLOCK_MONOTONIC_RAW` phase and request timestamps, every
response outcome, process identity, CPU/RSS/NPU memory samples, evidence
counts, and process/port/device cleanup. `--validate-only` checks all frozen
bindings without launching a server.

H4 pairs ECPA with the manual-integration arm by cell and repetition.  It
reports paired startup, throughput, and p99 effects with a deterministic 95%
bootstrap interval.  The frozen hypothesis thresholds remain 5% **or** 250 ms
for startup (the hypothesis is falsified only when both are exceeded), 1% for
throughput regression, and 2% for p99 latency regression.  Vanilla entry-point
loading is reported as a separate comparison and is never substituted for the
manual cost baseline.

H3 requires an exact-stack cell campaign and a deployment receipt that binds
the campaign digest, exact software/model/workload identity, parent-process
registration, and the authority-owned exposure gate. Each start must carry a
unique `raw_recovery` event chain. The analyzer binds the fault target by
PID, `/proc` start ticks, and boot ID; checks event order; and recomputes loss,
duplication, recovery time, route, predecessor preservation, correctness, and
rollback classification. It rejects edited metrics and artifacts replayed
between starts. `run_h3.py` executes one process-crash cell from frozen launch,
PID-file, HTTP-probe, authority state-probe, and cleanup-probe commands. Fixture
output is test evidence only and cannot satisfy a production deployment receipt.

Create that receipt only through `h3_registration.py`. The transition fetches
the Manager and Host remote `main` branches, checks that both frozen commits are
ancestors, rehashes the historical protocol, all three launch commands, the
fault descriptor, state and cleanup probes, and a reviewed nine-start authority
registration. Each start owns a distinct loopback-proxy run directory and an
exact source/argv registration. The runner requires the authority bytes again
and binds its start-specific proxy identity into raw evidence. The issuer writes
once with an atomic rename and refuses replacement:

```bash
python3 experiments/formal_campaign/h3_registration.py \
  --campaign /absolute/path/to/h3-campaign.json \
  --authority-registration /absolute/path/to/h3-authority.json \
  --manager-repo /absolute/path/to/extension-manager \
  --host-repo /absolute/path/to/vllm-hust \
  --output /absolute/path/to/h3-deployment-receipt.json
```

A local-only Host candidate, a hand-authored receipt, duplicate start identity,
changed command, changed endpoint, changed proxy source, or receipt replacement
fails before the model server starts.

H3 evaluates every injected failure, including failed runs.  Unsupported
tuples serving traffic or loss of the predecessor plan falsifies H3 directly;
otherwise at least 95% of injections must meet the preregistered automatic
recovery or bounded-operator-action objective.

H3 HTTP probes use a frozen JSON POST `request_payload` and a
`response_expectation.text_equals` task oracle. The runner retains the request
payload digest and complete response body; the analyzer independently checks
model, choice index, finish reason, exact text, and response digest. A nonempty
body or a caller-provided correctness boolean is insufficient. Fault PIDs must
belong to the current launcher's process session. These checks do not establish
a transaction prepare barrier: `manager-crash-after-prepare` still requires an
actual coordinator journal and a verified barrier before the signal is sent.

H4 arm definitions may freeze `unset_environment` for inherited variables that
must be absent. It is applied before all phase and server commands; assigning
and unsetting the same variable is rejected. In a container exposing physical
NPU nodes 3 and 6 as logical devices 0 and 1, do not set
`ASCEND_RT_VISIBLE_DEVICES=3,6`: first record a real initialization/allocation
probe and freeze the successful environment. A prelaunch dry-run cannot prove
that device initialization succeeds.
