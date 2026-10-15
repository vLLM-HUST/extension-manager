# Distributed predicates and source closure: issue #64 follow-up

Audit date: 2026-10-15. This is a literature and argument audit, not an
experiment, formal qualification, external review, or submission approval.
It supplements `paper/related-work-audit.md` and the 2026-10-13 internal hostile
review. Those documents already discuss typed obligations, Acto/Anvil,
provenance, leases, consistent updates, and a competent controller plus proxy;
repeating those comparisons would not close the gap identified here.

## One concrete improvement

Compare ECPA directly with **distributed predicate checking plus an admission
controller**, and explain precisely why a closed, epoch-scoped observation
does not establish continuing semantic effectiveness. This is a closer and
stronger alternative than a loader, a readiness bit, or an ACK alone.

The missing primary comparison is [D3S, NSDI 2008, official proceedings
page](https://www.usenix.org/conference/nsdi-08/presentation/d3s-debugging-deployed-distributed-systems).
Its [full paper, Sections 2 and 3](https://www.usenix.org/legacy/event/nsdi08/tech/full_papers/liu_xuezheng/liu_xuezheng_html/index.html)
describes instrumented state exposure, predicates over global snapshots,
logical-clock ordering, verifier recovery, and membership under failure.
Consequently, ECPA cannot claim novelty merely for gathering process-local
facts, checking a distributed condition, or replaying a deterministic checker.
Its discussion of failed-member removal makes the target-set comparison
particularly relevant; a frozen activation obligation must not silently become
true merely because a required worker disappeared.

The historical boundary is [Chandy and Lamport, TOCS 1985, author publication
page](https://www.microsoft.com/en-us/research/publication/distributed-snapshots-determining-global-states-distributed-system/).
The [Caltech author repository record](https://authors.library.caltech.edu/records/4chat-vem22)
also supplies the journal, pages, and DOI used below.
That work establishes distributed snapshots and their use for detecting
stable properties. ECPA should cite the foundation while explicitly declining
to claim that a receiver-prefix ACK implements the complete snapshot algorithm.
The application-specific conditions below are our audit inference, not a
reported result of either cited work.

## Proposed insertion for Related Work

> Distributed predicate checkers already collect process-local states and
> evaluate cross-process properties. D3S constructs global snapshots, orders
> exposed states, and handles verifier and monitored-process failures.
> ECPA does not introduce distributed predicate checking. Its proposed boundary
> is compiling extension declarations into fixed, authority-specific activation
> obligations and binding their satisfaction to generation admission. Whether
> that boundary improves on a competent predicate checker with the same inputs
> and a routing controller remains an evaluation question.

Suggested bibliography entries, to verify against the official pages when
integrating:

```bibtex
@inproceedings{d3s,
  author = {Xuezheng Liu and Zhenyu Guo and Xi Wang and Feibo Chen and
            Xiaochen Lian and Jian Tang and Ming Wu and M. Frans Kaashoek
            and Zheng Zhang},
  title = {{D3S}: Debugging Deployed Distributed Systems},
  booktitle = {5th USENIX Symposium on Networked Systems Design and Implementation},
  year = {2008},
  url = {https://www.usenix.org/conference/nsdi-08/presentation/d3s-debugging-deployed-distributed-systems}
}
@article{chandy-lamport-snapshot,
  author = {K. Mani Chandy and Leslie Lamport},
  title = {Distributed Snapshots: Determining Global States of Distributed Systems},
  journal = {ACM Transactions on Computer Systems},
  volume = {3}, number = {1}, pages = {63--75}, year = {1985},
  doi = {10.1145/214451.214456}
}
```

## Source closure is a finite observation boundary

For a declared request and source epoch, define a source-issued terminal
sequence `close(s)`. A receiver ACK `ack` can discharge a finite collection
obligation only if every required source is closed, every sequence through
its closure is accounted for, and all closures and associated records lie in
the acknowledged receiver prefix. The source must stop producing facts for
that declared scope before issuing its closure. These are proposed reasoning
conditions; do not infer them solely from the field name `closed`.

Three separate assertions require separate witnesses:

| Assertion | Necessary witness | Does not establish |
| --- | --- | --- |
| Selected collection is closed | Required source epochs, source terminal markers, gap-free sequence accounting, receiver ACK containing those markers | A globally consistent snapshot over uninstrumented channels |
| A declared finite semantic predicate holds | The closure above plus the effect-specific reference and actual observed arguments/bytes | Numerical attention correctness, complete physical KV ownership, or full quality |
| Generation admission remains safe | Live authority over the route, generation/epoch fencing, and an explicit invalidation or bounded-validity policy | Permanent validity of a historical observation |

The current R4 publication records 261 rows, 56 native argument completions,
and two worker closures. Its finite replay is useful evidence for the selected
observation contract. It is not a live membership service, continuous numerical
monitor, or formal prevention result. R3's HTTP success with a rejected final
ACK remains a failure of that older evidence contract; R4 must not retroactively
qualify it. Do not turn a collector's lack of new messages into a source
completion witness. A hash checks byte integrity, not effect truth.

The integration should make this distinction in the Safety Argument and the
Reference ExposureGate discussion, rather than adding further raw counts to
the abstract. A sufficient improvement today is a precise claim boundary and
the missing related-work comparison; it does not require another NPU launch.

## Strong alternative that can actually discriminate a contribution

This is a proposed future comparison, not a fourth measured H1 arm and not a
claim that the historical D3S implementation runs on the current stack.
Call a new implementation a *predicate-monitor baseline*, not “D3S,” unless
the actual system is ported and its behavior verified.

1. Freeze the same obligations, observer sources, process epochs, closure
   contract, workload, fault actuator, route authority, and expiry policy.
2. Give a conventional predicate monitor the exact same raw observations as
   ECPA. Connect its decision to the same fail-closed generation gate. Do not
   weaken it by removing freshness, epoch checks, or worker coverage.
3. Measure unsafe admissions and useful successful admissions, as well as
   diagnosis and integration effort only where these have an independently
   specified scoring rule. Keeping both systems permanently closed is not a
   successful availability result.
4. Separately ablate contract compilation: hand-written, frozen obligations
   versus manifest-derived obligations. If admission decisions are identical
   with equivalent information, report that result. The potential benefit is
   then reusable obligation construction and ownership checking, not a new
   admission-safety principle.

There is no logical reason that a fully informed baseline using the same
predicate and route enforcement must be less safe. A claim of superiority
requires a measured difference or a clearly restricted property; it cannot
follow from naming the alternative a readiness check.

## Acceptance delta and scientific status

This audit supplies two missing mechanism comparisons and a concrete
comparison design. It does not satisfy #64's faithful, pinned baseline
implementation criterion. It also does not alter the existing H1 falsification,
the partial H2 subset, formal H3/H4 counts, source-admission gates, or NO-GO.
The follow-up integration updates public `paper/main.tex`, `references.bib`,
and the related-work ledger. Generated result macros and historical experiment
artifacts remain unchanged. Only Tectonic is used for the public PDF build.
