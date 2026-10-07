# Progress

- Created isolated Manager worktree and branch `codex/ecpa-pegaflow-clean-wheel` from current `origin/main`.
- Revalidated both repositories are clean and exactly at their remote main commits.
- Built Manager and provider wheels plus the Pegaflow Ascend runtime wheel.
- Installed all three into an isolated CPython 3.11 environment and passed list, inspect, validate, configure, check, plan, render, enable, status, disable, forget, and uninstall verification.
- Verified absent external service fails closed before host process creation; no port or process residue was observed.
- Updated the current support-matrix counts from 32/33 valid to 33/33 valid and added exact Pegaflow evidence without widening runtime or performance claims.
- Manager full suite passed: 603 tests. Ruff lint, strict mypy, sdist and wheel build passed. A direct latest-Ruff format check reports four pre-existing formatting differences outside this documentation-only change; no unrelated files were rewritten.
- Added a separate Pegaflow CI change that pins current Manager and builds/installs the actual Ascend runtime wheel before exercising the fail-closed clean-wheel lifecycle; local YAML parsing, nine focused tests and Ruff passed.
- Manager PR #33 merged after its PR checks passed; the post-merge Python 3.10
  result and its follow-up are recorded below.
- Pegaflow PR #32 merged as `ac1b2d3e943c27e9344a9dba9115ad31f4791d43`.
  GitHub x86 CI validates metadata with an explicitly CI-only link placeholder;
  the real Ascend wheel evidence remains local to the allocated container.
- Website PR #362 merged as `96b8f453f0976718f484f844bf17fec4738d3b13`;
  the deployed catalog and plugin page now advertise the verified Manifest 0.3
  contract while preserving external-operator and runtime-evidence boundaries.

# Post-merge CI follow-up

- Extension Manager PR #33 merged as `2270ac6d6fdbe6369ea0f1cb72c29271c6e1288f`.
- Its post-merge Python 3.10 job exposed a controlled-fixture startup race: the
  SUT could finish shutdown before the observer script captured `/proc` identity,
  yielding an empty observer pipe.
- The follow-up removes retry masking and adds an explicit, fixture-only SUT and
  observer readiness handshake. It does not alter the formal-real host observer
  contract or infer runtime effectiveness.
- Local verification passed under Python 3.10 and 3.12 (603 tests each), plus
  20 consecutive reproducer runs under Python 3.10, repository-wide Ruff,
  strict mypy, sdist/wheel build, and clean-wheel CLI installation.

