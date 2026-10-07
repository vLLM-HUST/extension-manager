# Findings

- Organization enumeration found 71 repositories and 45 runtime/plugin/provider
  candidates in the current audit.
- 26 distributions expose ECPA bundles; 29 registrations were found and 28 are
  valid. The known invalid registration is the Pegaflow split package.
- 14 bundles are activation-ready and 14 intentionally fail closed as
  inspect-only. Only KV materialization currently has clean-wheel lifecycle plus
  live process-owned observer evidence.
- KNorm PR #4 declares a real general plugin, but correctness issue #3 remains
  open. Its safe Manifest 0.3 posture is therefore `import_only` with an
  exclusive `vllm.kv-cache.compression-policy` process resource claim.
- KNorm's CI file was under `.github/extension-ci.yml`, so GitHub Actions did not
  discover it. The active CI belongs under `.github/workflows/` while its release
  workflow must remain inactive until release gates pass.
- Current release decision: compatibility freeze remains in force.
- After the 2026-10-07 merges, current organization main branches contain 28
  ECPA distributions, 31 registrations and 30 valid Bundles. Seventeen are
  activation-ready and thirteen are inspect-only; Pegaflow remains the sole
  invalid split registration.
- The subsequent Prefix Router and KV Tiering merges raise the current totals
  to 30 ECPA distributions, 33 registrations and 32 valid Bundles. Eighteen
  are activation-ready and fourteen are inspect-only. vSpec moved from 0.2 to
  0.3 without changing the registration count.
- Manager `7bcfe556` closes two cross-provider gaps found by those real wheels:
  blockers are inspect-only in plan/render and visible as degraded check/status
  evidence, and unknown compatibility rejects every trusted in-process provider
  rather than only hard-coded built-ins.
- Final re-audit added five valid main-branch distributions: ADM, Tricard,
  Cost Pricing Model, Quality-Bounded Inference, and Request Lifecycle
  Profiler. The exact additive inventory is now 35 distributions, 38
  registrations, and 38 valid Bundles: 21 activation-intent and 17
  inspect-only.
- Tricard and canonical CLM previously shared the entry-point name
  `clm_lifecycle`; co-installation could therefore activate both from one
  allowlist item. Tricard now owns the distinct `tricard_clm_lifecycle` name.
- The current request-lifecycle host exports EventBus 1.0, but the profiler
  still imports a historical KV-recovery ABI and registers no native sink.
  Its truthful posture is descriptor-only, not runtime-effective.
- BetterScale exposed a Manager-owned gap: typed Worker carriers were not
  projected to native `--worker-cls`. The vLLM Provider now supports one
  `vllm.worker-class.v1` component with pre-launch conflict rejection. The MOD
  itself remains blocked by old host pins, out-of-tree native release payloads,
  missing observer evidence, and owner-controlled publication.
- Inspect-only convergence PRs then changed two existing registrations without
  changing the 35-distribution/38-registration total: Request Lifecycle
  Profiler `7c6155b7` and Quality-Bounded Inference `b2ed0136` now expose narrow
  active host-contract observers, while Cost Pricing Model `1559df80` remains
  inspect-only as an explicit offline CLI. The resulting composition count is
  23 activation-intent and 15 inspect-only Bundles.
