# Progress

## 2026-10-07

- Created isolated worktree and branch from exact `origin/main` commit
  `98903e416bdb593186b8245fd95180dafde995b9`.
- Re-audited organization repositories, current open PRs, CI state, and known
  owner issues.
- Began modernizing `vllm-hust-knorm` PR #4: Manifest 0.3, explicit
  dependencies/resource ownership/general-plugin declaration, inspect-only
  safety gate, accurate documentation, and discoverable GitHub Actions CI.
- Pending: local tests, build, clean-wheel ECPA validation, push/CI/PR decision;
  then continue through the priority queue and update this record with exact
  commits and results.

- KNorm PR #4 merged as main `563173e1`; Manifest 0.3 remains deliberately
  inspect-only pending correctness issue #3. Remote Python 3.10/3.12/3.14 CI
  passed.
- PyramidKV PR #4 merged as main `84c7ecb1`; Manifest 0.3 now encodes its
  KVCompress Bundle dependency and exclusive method registration. Remote Python
  3.10/3.11/3.12 CI passed.
- DLA PR #3 merged as main `da504dc7`; Manifest 0.3 exclusively claims the
  scheduler preemption policy and clean-wheel lifecycle stays fail closed on an
  unknown host. Remote Python 3.10/3.12/3.14 CI passed.
- SliceGPT PR #2 merged as main `fc157ab2`; existing Manifest 0.3 boundaries
  were rerun against current Manager, with runtime-wheel Python 3.10/3.12 and
  toolkit Python 3.11 CI passing.
- No hardware was used. No runtime-effective or performance claim was inferred
  from discovery, import, enablement, CI, or historical smoke evidence.
- Manager verification after the documentation reconciliation: Ruff lint
  passed, strict mypy passed, 601 pytest tests passed, and sdist/wheel build
  passed. `ruff format --check` with newly released Ruff 0.16.10 reports four
  pre-existing formatting drifts unchanged from `origin/main`; CI does not
  currently configure that check, so unrelated research files were not
  reformatted in this documentation PR.
- Prefix Router clean-wheel validation exposed a provider-neutral inconsistency:
  an `import_only` Production Stack extension could be rejected by `enable`
  while still rendering Helm-oriented actions. The Manager Core now converts
  every manifest activation blocker into the same non-mutating `inspect_only`
  plan and renders only `inspection-plan.json`, independent of provider.
- The Core fix passed focused CLI/provider tests (81), the complete suite (602),
  Ruff, strict mypy, and sdist/wheel construction. No cluster, service, or NPU
  operation was performed.
- KV Tiering clean-wheel validation then demonstrated that a third-party
  provider could bypass the unknown-host launch gate even though it injects
  trusted code into the vLLM process. The run gate is now based on
  `trusted_in_process` isolation rather than a hard-coded provider allowlist;
  a dedicated third-party-provider regression test passes.
- Manager PR #30 merged as `00618621` after Python 3.10/3.12 and wheel CI;
  follow-up PR #31 merged as `7bcfe556` after the same CI and 603 local tests.
- Prefix Router PR #2 merged to main as `8115ed50`; vSpec PR #3 merged to main
  as `a0bf4203`. KV Tiering PR #3 first merged to its declared
  `pluginize-v1` base as `9da2bdbb`; ancestry verification caught that this was
  not main, so convergence PR #4 reran three-Python CI and merged to main as
  `03f17227`. The obsolete conflicting vSpec PR #2 was closed with a
  supersession record.
- Tricard PR #2 merged as `1d141da1`; Python 3.10/3.11/3.12 clean-wheel CI
  passed on the PR and merged main. Organization issue #42 was closed.
- Cost Pricing Model PR #1 merged as `0dbebad7`; Quality-Bounded PR #5 merged
  as `3e321aef`; both passed Python 3.10/3.12 clean-wheel CI again on merged
  main. Their packaging issues were closed while their marker-only carriers
  remain inspect-only.
- Request Lifecycle Profiler PR #30 merged as `63af34ef`; 238 CPU tests passed
  with 9 skips, and both its existing CPU CI and new ECPA matrix passed on
  merged main. Issue #29 was closed without claiming native-sink activation.
- Added typed Worker carrier projection and conflict tests to Manager. Focused
  Provider/CLI tests passed (86); the complete Manager suite passed (607), as
  did Ruff, strict mypy, sdist and wheel builds. Documentation now records the
  exact 35-distribution/38-Bundle inventory and the remaining BetterScale and
  FreshKV owner gates.
- A clean synthetic Worker-carrier wheel passed list/inspect/check/enable/
  plan/render, rendered the exact `--worker-cls` value, rejected an unknown
  trusted host at `run --dry-run`, and passed disable/forget/pip-uninstall with
  no residual Bundle discovery.
