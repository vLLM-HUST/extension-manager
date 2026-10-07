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
