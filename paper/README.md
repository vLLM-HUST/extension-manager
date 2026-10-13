# Paper build and evidence contract

Paper lead and accountable owner: `ShuhaoZhangTony` (张书豪). Research,
artifact, and submission decisions are PI-led/self-driven; student
contributions are optional and non-blocking.

This is the public working draft for an OSDI '27 Research-track submission.
The venue and format contract is recorded in [`venue/osdi.md`](venue/osdi.md).
The checked-in draft deliberately retains the public ECPA name; it is not the
double-blind submission artifact. OSDI '27 requires a different anonymized
system name for a project already public under this name, so the final review
PDF must be produced from a private, untracked anonymity overlay and audited
for textual and metadata leaks.

## Current evidence snapshot

The draft now reflects ECPA 0.3.0 and stable Manifest 0.3. The checked release
inventory and the pinned Ascend lifecycle qualification are generated from
`docs/release-readiness.json` and
`docs/evidence/native-current-npu-qualification-2026-10-11.md`. The lifecycle
qualification establishes one clean-wheel, process-owned observer and cleanup
path; it is not inserted into the preregistered formal-real aggregate and makes
no performance claim.  The separate authoritative r5 campaign now supplies
the first H1 formal cell: nine validator-approved starts over three arms and
three repetitions.  All arms, including ECPA, retained an effective claim at
0.5 evidence coverage, so the tested H1 prevention claim is falsified.  H2--H4
and the real ExposureGate remain incomplete.

Build:

```bash
cd paper
make
make validate-results
make check-evidence-summary
```

All paper builds use Tectonic's XeTeX engine and integrated BibTeX pass;
`make` and `make tectonic` are equivalent. Do not add a parallel `latexmk`,
`pdflatex`, or system-TeX build path. The vendored USENIX style selects only
engine-supported `microtype`, `inputenc`, and `breakurl` behavior. Override the
executable with `TECTONIC=/path` when needed. Set `PYTHON=/path/to/venv/bin/python`
to run evidence validation and PDF auditing in a specific environment.
`main.pdf` and intermediate files are ignored by Git.

Evidence rules:

- Observed values must point to a raw artifact and exact code/runtime identity.
- Planned cells use JSON `null` and `status: "planned"`; they are never encoded
  as zero.
- Failed runs remain records with failure class and phase.
- Formal cells use at least three independent service starts and record arm
  order, process topology, warm/cold state, model/workload, hardware, and every
  model/API call.
- Aggregates may not hide a failed provider, process topology, or version tuple.
- A figure/table generator must reject mixed identities and missing required
  provenance before producing a paper result.
- Artifact-backed counts and modeled metrics in `main.tex` come from the
  checked-in `generated/evidence-summary.tex`. Regenerate it with `make
  evidence-summary`; `make check-evidence-summary` fails if it is stale or if
  the corpus, planner, formal-status, adapter-registry, release-readiness, and
  native-qualification inputs disagree.
- `../docs/research/claims-to-experiment-matrix.json` separates each paper
  claim from its falsifier, evidence authority, and experiment. The first
  formal-real preregistration is
  `../experiments/false_effective/first-formal-real-study.json`; validation
  keeps it pre-admission while the adapter registry and frozen deployment
  registration are absent. The host producer has been reviewed and merged.
- `../experiments/false_effective/first-formal-real-deployment.json` is the
  separate registration-review packet. It must bind all three arms, all five
  lifecycle sources, producer admission, deployment identity, and review gates
  before admission; it does not replace the runtime adapter registry.

Alignment:

| Governance item | Paper location |
|---|---|
| Research charter | Sections 1--3 |
| Issue #2 / M0 taxonomy and failure model | Sections 2, 3, 7 |
| Issue #4 / M1 capability and conflict planner | Sections 4.2--4.4, H2 |
| Issue #3 / M2 lifecycle, runtime evidence, rollback | Sections 4.5--4.8, H1/H3 |
| Issue #5 / program, two-week gate, stop-loss | Sections 1, 7, 9 |
| M3 cost gate | H4 and Section 7 |

`artifacts/results.schema.json` is the machine contract. The example is planned,
not a measured result. Run `make validate-results` before admitting artifacts.
The ECPA interoperability contract is versioned under `../spec/`; the Manager
is a reference implementation rather than the standard itself.

Open scientific and evaluation decisions that must not be silently promoted to
claims are tracked in [`OPEN-QUESTIONS.md`](OPEN-QUESTIONS.md).

The paper must be rebuilt and audited after every results edit.  The prior
checkpoint was 12 pages total, with body text ending on page 11 before
References began. This fixed the earlier body-page violation by removing
duplicated corpus inventory and architecture/status visuals while keeping the
source-bound inventory in `../docs/corpus/`. It is still a working draft: the
H2--H4 results are missing, and the recovered space must be budgeted for
measured tables and analysis. Recheck the body/reference boundary after every
substantive edit; page count alone does not certify submission readiness.
Install the optional `paper` dependency from the repository root, then run
`make -C paper audit-pdf` after every Tectonic build. The audit checks page
geometry, body/reference boundary, page numbers, embedded fonts, nominal
10-point body type, and two-column extraction. Run
`python3 paper/scripts/audit_pdf.py paper/main.pdf --anonymous` on the private
submission rendering; the public draft is expected to fail its identity scan.
Leading, exact text-block dimensions, grayscale legibility, and implication-
based identity leaks still need human review.

A provisional anonymous review copy can be rendered outside the repository:

```bash
python3 paper/scripts/render_anonymous.py \
  --output /absolute/private/review-directory \
  --alias ExampleOnlyChangeMe \
  --title 'A New Nonidentifying Paper Title'
```

Replace the example alias and title with private, unpublished values. The
command refuses an in-repository or existing output directory, checks the
generated evidence summary, compiles only with Tectonic, and runs the PDF
identity audit. Keep the alias and output private. The transform is mechanical:
it does **not** remove identity by implication from distinctive incidents,
release numbers, corpus counts, citations, or figure content. Human authors
must review and edit that private copy before treating it as a submission PDF;
it must never be committed as a purportedly anonymous artifact.
