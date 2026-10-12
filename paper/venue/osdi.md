# OSDI '27 submission target

Checked on 2026-10-12 against the official
[OSDI '27 Call for Papers](https://www.usenix.org/conference/osdi27/call-for-papers).
This is the target-venue contract for the ECPA paper, not a statement that the
current draft is submission-ready.

## Venue decision

Target the **Research track**. ECPA proposes a new systems abstraction and
runtime protocol for composing, activating, observing, and rolling back LLM
inference extensions. That is a systems-for-ML contribution and matches OSDI's
scope better than a resource, demo, or Web paper.

Do not select the Operational Systems track without new evidence of a
meaningful real-world deployment. The current clean-wheel Ascend lifecycle
qualification proves one pinned activation and cleanup path; it is not
large-scale operational experience.

## Hard dates

- Abstract registration: **2026-12-01 22:59 UTC**.
- Complete paper: **2026-12-08 22:59 UTC**.
- Notification: **2027-03-16**.
- Final paper: **2027-06-03**.

The abstract registration must be substantive. A placeholder abstract can be
desk-rejected and thereby prevent the full-paper submission.

## Format and review contract

- US letter, two columns, 10-point type on 12-point leading.
- Text block 7 by 9 inches.
- Submission limit: 12 pages including figures and tables, with unlimited
  additional pages for references.
- Accepted-paper limit: 14 pages plus references.
- Page numbers are required; figures and tables must remain legible in black
  and white without magnification.
- Separate supplementary material is allowed, but the paper must stand alone;
  reviewers are not required to read it.
- Research-track review is double blind. Author and institution identity must
  be removed.

`main.tex` uses the official `usenix2019_v3.sty` and does not add custom page
geometry. Before submission, validate the produced PDF rather than assuming
that use of the style file proves compliance.

## Public-name and anonymity rule

The project and this draft are public under the name ECPA. OSDI '27 permits
public preprints and technical reports, but requires the submission to use an
anonymized project/system name different from the public name. Therefore:

- keep ECPA in the public research repository and working draft;
- produce the submission PDF from a private, untracked anonymity overlay;
- replace the system name, repository URLs, organization names, release tags,
  issue/PR identifiers, and self-identifying artifact paths in that overlay;
- do not commit the anonymous alias to this public repository before review;
- run a PDF text and metadata audit before submission.

Changing only the author line is not sufficient for this paper because its
release and repository evidence is publicly searchable.

## OSDI readiness gates

The paper is not submission-ready until all of the following hold:

- [ ] The matched formal-real study is admitted before execution and reports
      measured H1--H4 results rather than planned cells.
- [ ] The three activation arms use genuinely different paths under identical
      model, workload, topology, version, and injected-fault conditions.
- [ ] Results cover correct activation, false-effective detection, conflicts,
      worker/process skew, stale evidence, crash recovery, stop, and rollback.
- [ ] Runtime overhead includes activation latency, steady-state throughput and
      latency, evidence traffic/storage, and recovery cost with uncertainty.
- [ ] Baselines engage systems and ML-serving prior work; the paper explains
      what new systems challenge independently developed inference extensions
      introduce.
- [ ] At least one real extension crosses parent/engine/worker boundaries and
      produces authority-owned effect evidence; fixtures and successful import
      are not counted as runtime effect.
- [ ] Claims remain bounded to the tested host, accelerator, versions, process
      topology, and extension classes.
- [ ] The first pages state the problem, failure consequence, key mechanism,
      and quantitative result clearly enough to survive a possible preliminary
      review based only on those pages.
- [ ] The submission body is at most 12 pages before references, is internally
      self-contained, and passes a clean Tectonic/LaTeX build.
- [ ] A private anonymity audit finds no ECPA name, organization, repository,
      author/institution hint, PDF metadata leak, or searchable public alias.
- [ ] The final author list, conflicts, prior/concurrent-submission disclosures,
      authorship eligibility, and presentation commitment are checked.

## Policy checks near the deadline

Recheck the CFP no later than 2026-11-08. OSDI '27 may add a preliminary review
process at least one month before the paper deadline. Also recheck the detailed
submission requirements and submission site when USENIX publishes them.

Do not submit the same work concurrently to another archival venue. In
particular, the CFP explicitly treats NSDI '27 Fall as conflicting with OSDI
'27. If the work was previously rejected by a conference or journal, prepare
the required revision summary. A related workshop version requires the prior
paper and an explanation of the new material.
