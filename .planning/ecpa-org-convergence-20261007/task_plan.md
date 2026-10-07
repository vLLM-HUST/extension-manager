# ECPA organization convergence — 2026-10-07

Base: `vLLM-HUST/extension-manager@98903e416bdb593186b8245fd95180dafde995b9`

1. Re-audit every vLLM-HUST runtime/plugin/provider candidate against Manifest
   0.3 and classify it as activation-ready, inspect-only, or not packaged.
2. Fix manager defects in this repository. Fix small packaging, manifest,
   resource-claim, dependency, and CI defects in the owning MOD repository.
3. Preserve fail-closed boundaries: installed is not enabled, enabled is not
   runtime-effective, and runtime-effective is not performance-qualified.
4. Validate each changed MOD from clean wheels with ECPA discovery and lifecycle
   commands; require owned observer evidence for runtime-effective claims.
5. Merge only reviewable, green changes; leave owner-facing issues for algorithm,
   hardware, or product decisions that cannot safely be made here.
6. Update the support matrix and keep the compatibility freeze until all release
   gates have evidence.

Initial priority queue: KNorm PR #4 (inspect-only correctness gate), then the
clean/green PyramidKV #4, DLA #3, and SliceGPT #2 PRs; repair vSpec #2 only after
its current conflict and package-CI failure are understood.
