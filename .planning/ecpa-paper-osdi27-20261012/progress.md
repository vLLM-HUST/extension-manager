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
