# ECPA task-local source bundle (2026-10-13)

This bundle preserves the only uncommitted source diff found in ECPA-named
worktrees during the 2026-10-13 audit. It is **not** applied to Extension
Manager, qualified as a runtime dependency, or included in a formal H1 result.

The archived `triton-ascend-h1-clean-stack-candidate.patch.gz` expands to a
byte-for-byte
`git diff --binary` from the task-owned worktree
`/root/triton-ascend-worktrees/ecpa-h1-clean-stack-candidate` at base commit
`702d89caf04cbaf202afbdb0e93debad4c0dbb86` (tree
`ca147c3d6de30c402645a9cbd48c0f780d6a3238`). It changes 17 tracked
Triton Ascend files and has SHA-256
`a9154e66a09c7c7dfa0bf1909d6739e0649f00d8b967ea9e670bcf4ead9d7d5f`.
The deterministic gzip artifact has SHA-256
`1ed60a55139e04feca501c4031f0cd0ef5d7525f35f4dfe668b12a815a3c729f`.
The worktree is intentionally left untouched, preserving the original diff.
The patch has not passed code review or tests. Do not apply it to production
or count it as ECPA functionality merely because it is archived here.

The base commit combines the already-uploaded upstream changes
[triton-ascend #2526](https://github.com/triton-lang/triton-ascend/pull/2526)
and [#2527](https://github.com/triton-lang/triton-ascend/pull/2527). Their
local worktrees are clean; the PR heads match their local commits. The vLLM-HUST
host, Extension Manager, KV MOD, and Ascend PR #50 task worktrees are likewise
clean, with their source commits uploaded. The Ascend PR #54 worktree is clean
and matches its remote PR head. No unrelated `/root` workspace was copied.

To inspect the archived patch against its exact base in an isolated checkout,
download this bundle and use the patch's downloaded path:

```sh
git worktree add --detach /path/to/isolated-triton 702d89caf04cbaf202afbdb0e93debad4c0dbb86
gzip -dc /path/to/downloaded/triton-ascend-h1-clean-stack-candidate.patch.gz | git -C /path/to/isolated-triton apply --check -
```

`artifact-manifest.json` records hashes of the wheel artifacts used by the
real TP2 pre-admission pilot. These rebuildable binaries and the 2.8 GB test
venv are not committed into the source repository. The installed environment
and model snapshots are independently fingerprinted in
`experiments/false_effective/deployment-candidates/`.

The only live follow-up tracker is
[Extension Manager #66](https://github.com/vLLM-HUST/extension-manager/issues/66).
