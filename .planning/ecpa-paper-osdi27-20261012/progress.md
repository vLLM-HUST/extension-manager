# Progress

## 2026-10-12

- Selected OSDI '27 Research track as the target.
- Replaced the historical OSDI '26 baseline with the current OSDI '27 venue
  contract, deadlines, format, track decision, evidence gates, and anonymity
  procedure.
- Updated the paper README to distinguish the public working draft from the
  eventual double-blind submission artifact.
- Built the paper with Tectonic and validated the evidence summary, research
  matrix, and example result schema. The PDF is 14 pages with exactly 12 body
  pages and References beginning on page 13.
- Next critical path: admit and run the matched formal-real study; prose and
  formatting work cannot substitute for those measurements.
- The paper build policy is now Tectonic-only. Both the default `make` target
  and the explicit `make tectonic` target resolve to the same Tectonic build;
  cleanup no longer requires `latexmk`.
- Began issue #59 by re-auditing the formal study's producer dependency against
  vLLM-HUST PR #27. Updated its immutable final head, tree, base, merge commit,
  and human-review facts in both preregistration artifacts. The experiment
  remains pre-admission with three truthful blockers; no formal result has been
  claimed or synthesized.
- Verification after the producer refresh: 637 pytest cases passed; Ruff and
  mypy passed; release readiness, manifest 0.3 conformance, and the executable
  failure/permission matrix passed; sdist and wheel built; a clean virtualenv
  installed the wheel and ran CLI version/help; the research matrix and paper
  evidence summary passed; Tectonic rebuilt the paper successfully.
- PR #67 merged as `475830ca62fbbcf440865ededdced2abbf3f307c` with Python
  3.10, Python 3.12, and wheel CI green. Audited the remaining deployment gate:
  the historical eight-device candidate is blocked, and the current container
  exposes two devices with no Docker CLI. Corrected the stale producer wording
  in the formal adapter ADR and lifecycle-source design note.
