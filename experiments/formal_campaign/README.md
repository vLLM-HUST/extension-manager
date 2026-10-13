# H3/H4 formal campaign intake

This directory freezes the analysis contract for the H3 recovery campaign and
the H4 matched-cost campaign.  It contains no formal result.  `protocol.json`
is `planned`, and the analyzer reports `incomplete` until every required cell,
arm, and independent start is present.

Run the intake before using any number in the paper:

```bash
python3 experiments/formal_campaign/analyze.py \
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
The analyzer verifies artifact bytes and exact cross-arm identity equality. It
retains failed starts and refuses to emit metrics for an incomplete campaign.

H4 pairs ECPA with the manual-integration arm by cell and repetition.  It
reports paired startup, throughput, and p99 effects with a deterministic 95%
bootstrap interval.  The frozen hypothesis thresholds remain 5% **or** 250 ms
for startup (the hypothesis is falsified only when both are exceeded), 1% for
throughput regression, and 2% for p99 latency regression.  Vanilla entry-point
loading is reported as a separate comparison and is never substituted for the
manual cost baseline.

H3 evaluates every injected failure, including failed runs.  Unsupported
tuples serving traffic or loss of the predecessor plan falsifies H3 directly;
otherwise at least 95% of injections must meet the preregistered automatic
recovery or bounded-operator-action objective.
