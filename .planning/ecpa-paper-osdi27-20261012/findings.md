# Findings

## 2026-10-12 venue audit

- OSDI '27 explicitly includes systems for machine learning, secure and
  reliable systems, and management/troubleshooting of complex systems.
- ECPA's systems mechanism fits the Research track. Current evidence does not
  establish the deployment scale or operational experience expected by the
  Operational Systems track.
- Abstract registration is due 2026-12-01 22:59 UTC and the full paper is due
  2026-12-08 22:59 UTC.
- The submission body limit is 12 pages plus unlimited references.
- A preliminary first-pages review may be introduced; USENIX will decide at
  least one month before the deadline.
- Because ECPA and its draft are public, the submitted paper must use a
  different, unpublicized system name and remove searchable release/repository
  identifiers. An anonymous author line alone is insufficient.
- The public draft still reports the matched formal experiment and H1--H4 as
  incomplete. The pinned Ascend run is lifecycle qualification, not the
  formal comparison and not a performance result.
- The 2026-10-12 Tectonic build produced 14 PDF pages. The body occupies pages
  1--12 and References starts on page 13, so the current draft exactly meets
  the OSDI '27 submission page boundary but has no body-page slack.
- Research-matrix validation reports 4 claims, 5 experiments, a first study in
  pre-admission with 9 planned starts, and an unregistered deployment. This is
  the primary submission blocker.
- vLLM-HUST PR #27 was merged as
  `b326fafe5405b9996db9c9f0d7758536148ecc9b`; its final head and tree are
  `f3eb4b09ba91a1720c4e35de41a91e6dc351fd5b` and
  `bcdb8c810b60c11e77cb8af2002bd9039600b808`. APei-520 completed an
  affirmative line review before merge. The historical PR check still records
  a Buildkite test-tethering failure; current host `main` subsequently wires
  the evidence test, so this audit records the merge/review facts without
  describing the historical PR CI as green.
- Retiring those two stale producer blockers does not admit the experiment.
  The verified adapter registry is empty, the deployment identity is not
  frozen, and deployment commands have not been reviewed.

Official source:
<https://www.usenix.org/conference/osdi27/call-for-papers>
