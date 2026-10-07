# Progress

- Created isolated Manager worktree and branch `codex/ecpa-pegaflow-clean-wheel` from current `origin/main`.
- Revalidated both repositories are clean and exactly at their remote main commits.
- Built Manager and provider wheels plus the Pegaflow Ascend runtime wheel.
- Installed all three into an isolated CPython 3.11 environment and passed list, inspect, validate, configure, check, plan, render, enable, status, disable, forget, and uninstall verification.
- Verified absent external service fails closed before host process creation; no port or process residue was observed.
- Updated the current support-matrix counts from 32/33 valid to 33/33 valid and added exact Pegaflow evidence without widening runtime or performance claims.
- Manager full suite passed: 603 tests. Ruff lint, strict mypy, sdist and wheel build passed. A direct latest-Ruff format check reports four pre-existing formatting differences outside this documentation-only change; no unrelated files were rewritten.
- Added a separate Pegaflow CI change that pins current Manager and builds/installs the actual Ascend runtime wheel before exercising the fail-closed clean-wheel lifecycle; local YAML parsing, nine focused tests and Ruff passed.
- Manager PR #33 Python 3.10 and wheel CI passed; Python 3.12 exposed the controlled-fixture race. The bounded retry fix passed Ruff, all 117 formal-harness tests, and the complete 603-test suite locally; a new CI run is pending.
- Pegaflow PR #32 showed that GitHub-hosted x86 runners cannot link the Ascend wheel without `libascendcl`; the remote job is being narrowed to explicitly metadata-only packaging while the real Ascend wheel evidence remains local to the allocated container.
- Public catalog PR and deployment verification remain pending.

