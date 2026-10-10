# Qualification and performance policy

ECPA release qualification and MOD performance qualification are independent.
This separation is normative for the `0.3` development and prerelease line.

## Manager release qualification

A Manager prerelease requires stable schemas, fail-closed compatibility and
conflict handling, clean-wheel lifecycle evidence, process-owned runtime
evidence, deterministic stop/rollback/uninstall behavior, and an accurate
support matrix. These gates establish that ECPA manages declared intent safely;
they do not establish that a MOD improves throughput, latency, memory, quality,
or cost.

## MOD availability and recommendation

Functional correctness and recovery evidence determine whether a MOD can be
listed as qualified and available. A negative matched performance result does
not erase correct functionality: it remains available but is labeled
`not-recommended-for-tested-cell`. Unverified function or recovery remains
preview/inspect-only and cannot become enableable from a benchmark result.

Every effect is scoped to its exact model, workload, hardware, topology,
versions, commits, configuration, and repetitions. No historical, simulated,
smoke, or single-cell result becomes a general performance claim.

## Research and production cost gates

The H4 overhead bounds in `docs/evaluation-plan.md` remain required for the
corresponding formal study and any production-readiness claim. They are not an
alpha API-publication gate. Publishing an ECPA prerelease therefore cannot be
described as completing H4 or proving performance benefit.

`check`, `status`, `plan`, and `render` report contract and lifecycle state;
they are not benchmark tools. Benchmark execution and result audit remain the
experiment harness's responsibility.
