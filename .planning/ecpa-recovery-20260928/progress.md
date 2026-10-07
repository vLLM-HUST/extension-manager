# ECPA recovery progress

- [x] Verified requested local checkout was absent.
- [x] Verified authoritative remote heads for all three repositories and target PRs.
- [x] Created clean clone, isolated worktree, and requested branch from latest Manager main.
- [x] Captured PR #5 diff for overlap review.
- [x] Modernize and validate Manager plugin activation contract.
- [x] Add CI for Python 3.10/3.12 tests, Ruff, strict mypy, build, and clean-wheel CLI.
- [x] Replaced PR #5 with PR #15, passed CI, merged, and verified remote main.
- [x] Reconciled host PR #20 with latest main, passed pre-commit/contract tests,
  merged, and verified remote main at `6baa026f602fd221dc7db64362730305048a8b87`.
- [x] Reconciled KV plugin PR #23 with PR #25, passed dual-Python CI, merged,
  and verified remote main at `6d31843458bf7c75322f60c5715ae598c6ed4cde`.
- [x] Passed clean-wheel discover/check/enable/plan/render/run-observer/
  disable/rollback/forget/uninstall validation without NPU use or residual
  Manager-owned processes.
- [x] Updated support claims and kept compatibility freeze for remaining
  native-NPU, failure-degradation, and broader support-matrix gates.
- [x] Merged ECPA 0.3 capability/resource contracts (Manager #18, host #44),
  live-only observer evidence (Manager #19, host #45), and the real plugin
  migration (#27); verified exact remote main commits and dual-Python CI.
- [x] Isolated invalid Bundle registrations in `extension list` while preserving
  strict selected operations, with unit and mixed clean-wheel regression tests.
- [x] Routed confirmed MOD packaging gaps to repository issues, reusing existing
  pluginization issues and using the organization tracker where Tricard disables
  repository issues.
- [x] Re-audited the tracked MOD repositories and isolated selected external
  Provider loading so one broken Provider cannot deny unrelated ECPA operations;
  also reject activation entry points whose target module is absent from the
  declaring wheel/editable distribution.

## Organization-wide follow-up (2026-10-02)

- [x] Enumerated and classified all 71 organization repositories.
- [x] Built and co-installed all 26 ECPA distributions.
- [x] Routed newly found Mod-owned gaps to owner repositories.
- [x] Implemented and unit-tested ECPA Bundle dependency admission.
- [x] Rebuild and rerun final clean-wheel validation.
- [x] Open, merge, and remotely verify Manager PR #26 at
  `031cbb13ae1dc9deebb09d55dc85a1918cd33dc0`.
- [x] Remove temporary organization-audit artifacts and worktree.

## Request-lifecycle follow-up (2026-10-02)

- [x] Modernize host PR #6 on current main, publish the versioned
  `vllm.request-lifecycle-events` capability, pass pre-commit and focused
  scheduler tests, merge, and verify main at
  `7620b23ab6d91230ff1c3f65f2dc4727fdec90c9`.
- [x] Repair canonical CLM package protocol naming and default-off activation,
  pass Python 3.10/3.12/3.14 CI plus clean-wheel lifecycle checks, merge PR #2,
  and verify main at `efaae1052a672ba4df7f6139ad2d1eabda80abea`.
- [x] Keep compatibility freeze: no current-head NPU, live observer receipt, or
  performance evidence was produced by this follow-up.

## Research PR #53 migration (2026-10-06)

- [x] Verify organization and archived-research `main` trees are identical and
  confirm PR #53's two commits were not merged.
- [x] Preserve the original author commits on an isolated organization branch.
- [x] Remove `.DS_Store` and correct the evidence-authority diagram and caption.
- [x] Pass local Ruff lint, changed-file format, mypy, 601 pytest tests,
  research/evidence/result validation, Tectonic, package build, and clean-wheel
  CLI validation.
- [x] Open organization PR #29 from `codex/port-pr53-system-overview`.
- [x] Verify Python 3.10/3.12 plus wheel CI and mark PR #29 ready to merge.

## Inspect-only convergence (2026-10-07)

- [x] Manager PR #36 merged as `26511210709ccfa711c6a150acab81771669f49d`;
  manifest-declared activation entry points are now eligible for verified
  process-owned runtime evidence. Python 3.10/3.12 and wheel CI passed on PR and
  merged main.
- [x] Request Lifecycle Profiler PR #31 merged as
  `7c6155b75840ee046a9547489628ca31df773334`; its active carrier is a current
  EventBus v1 sink, not the historical KV-recovery adapter.
- [x] Quality-Bounded Inference PR #6 merged as
  `b2ed0136f0a399fa919287fb334946f71d6a9ac7`; only its behavior-preserving
  full-fidelity request observer is activated.
- [x] Cost Pricing Model PR #2 merged as
  `1559df80e40172299231f7cee381f41738720ce2`; it is now explicitly an offline
  process-isolated CLI with no vLLM activation entry point.
- [x] Clean-wheel discovery/check/enable/plan/render and supervised runtime
  evidence were validated for both active carriers. SIGTERM removed each
  Manager-owned child and live status evidence; disable/forget/uninstall paths
  passed. No NPU or external service was used.
- [x] Profiler merged-main CPU/ECPA runs `37615868408`/`37615868432`, Quality
  run `37615878450`, and Cost run `37615720840` passed. Manager support-matrix
  PR #37 merged as `907469c2228f5d18ea1141548b79dce1b1571464`; its merged-main
  Python 3.10/3.12 and wheel run `37617138670` passed.
- [x] Public catalog PR #364 merged as
  `83c446d4cdfcaa4b7aa4286662d3109f3e9b730e`; merged-main validation/browser
  run `37617151581` and Pages deployment `37617150954` passed. Profiler and
  Quality are listed as experimental observers, while Cost remains an
  inspect-only offline tool.
