# ECPA recovery task plan

Date: 2026-09-28 (UTC)

1. Audit local state, authoritative remotes, open PR heads, CI, and overlap with merged PRs #8-#14.
2. Re-implement the still-required PR #5 contract on `origin/main`, with deterministic activation, fail-closed compatibility, and consistent CLI surfaces.
3. Run unit, lint, type, build, and clean-wheel checks; publish a narrow replacement or update PR #5, merge only with passing evidence, and verify `origin/main`.
4. Rebase and validate vLLM-HUST PR #20 against its latest main.
5. Rebase and validate KV materialization PR #23 against its latest main (including merged PR #25), update dependency pins, and execute clean-wheel end-to-end lifecycle checks.
6. Update documentation/support claims to match evidence; preserve compatibility freeze unless every release gate is proven.

Safety constraints: no unknown service/process mutation; no NPU use unless CPU/fixture/contract checks require escalation and assigned devices/processes are audited first; no modification of unrelated dirty workspaces.

## PR #53 research-diagram migration (2026-10-06)

1. Preserve the two useful authored commits from archived research PR #53 on
   current organization `main` in an isolated worktree.
2. Remove `.DS_Store` and correct source references, Plan/inventory ownership,
   and provider-health versus runtime-effect evidence semantics.
3. Add source-contract regression coverage; run Ruff, full pytest, evidence
   checks, paper build, package build, and clean-wheel validation.
4. Publish a narrow `vLLM-HUST/extension-manager` PR and verify remote CI.

## Organization-wide follow-up (2026-10-02)

- Base: `origin/main` at `ff144b469ad8cf7a1109610b3a6a4e3528bc40ee`.
- Branch: `codex/ecpa-bundle-dependencies`.
- Tracking issue: `vLLM-HUST/extension-manager#25`.
- Add fail-closed Bundle dependency composition, rerun the full suite and
  clean-wheel organization matrix, merge a narrow PR, and keep release frozen.

## Inspect-only convergence (2026-10-07)

1. Replace the Request Lifecycle Profiler's historical-only carrier with a
   current-host EventBus v1 sink and callback-owned runtime evidence.
2. Expose only Quality-Bounded Inference's behavior-preserving request observer;
   keep adaptive policy mechanisms unqualified and fail closed.
3. Remove the Cost Pricing Model's misleading in-process marker and serving
   launcher; classify it as an offline, user-owned CLI.
4. Re-run repository, host-contract, wheel, ECPA lifecycle and supervised-stop
   checks; merge only after dual-Python CI and verify merged-main CI.
5. Reconcile the Manager support matrix and public plugin catalog without
   claiming NPU execution, quality, performance, or alpha readiness.
