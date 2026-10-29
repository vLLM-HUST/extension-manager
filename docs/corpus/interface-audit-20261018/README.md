# Real MOD interfaces, hidden dependencies, and composition

This is a new **source audit**, not a native execution result. The frozen
24-MOD population in `../workshop-mods.json` remains unchanged. Its historical
package/CPU counts are not counts of this audit. `population-screen.json`
lists all 24 entries and explicitly marks unfinished deep audits. This pass
also obtained all 24 README files and 21 root project files; see
[the complete packaging screen](population-source-screen.md). The three root
404s are recorded, not interpreted as runtime failure. New source
revisions are recorded separately from the original page snapshot.

The question is whether ECPA can turn heterogeneous, partly implicit extension
requirements into a composition that preserves each MOD's intended effect.
Manifests and adapters are inputs whose accuracy and cost must be evaluated.
Reading ECPA-added declarations alone does not establish that the original
MODs expose a common interface.

## Source-to-system mapping

`root-findings.json` contains exact commits, Git blobs, full-file SHA-256s,
copied source files, line excerpts, and six findings from four repositories.
Every captured file was byte-checked against both its checkout and Git object.
[The additional deep audit](deep-interface-findings.md) adds ten observations
and 33 verified source excerpts. Together these cover eight MOD repositories;
backend/Manager sources and two KV revisions are additional source subjects,
not extra MOD population members. All source excerpts are verified and copied
as `.snapshot` files to avoid executing them as repository code.

| Real source observation | What ECPA already offers | What remains to implement or verify |
|---|---|---|
| KNorm's package dependency list is empty; activation needs seven private host surfaces and refuses an in-tree duplicate. | Host/protocol requirements, version constraints, explicit rejection. | Actual symbol/ABI verification and contract acquisition. The compiler does not discover private dependencies automatically. |
| KNorm registers patches but only compresses when enabled, ratio is below one, and prefix caching is off. | Separate intent, loading, invocation, and effect obligations. | Real above-threshold effect and representation checks; HTTP200 or patch registration is insufficient. |
| KNorm wraps `Scheduler.update_from_output` and rebinds already-imported registration aliases. | Declared ownership, resource aliases, explicit ordering. | Hidden wrappers, alias coverage, order effects, and shared KV-state semantics. A shared method is a risk surface, not a proven conflict. |
| Frozen QoS exposes an import-only policy and proposed host protocols, with no activation entry point. | Inspect-only handling and missing-capability decisions. | The actual API/scheduler adapter; installing the descriptor does not implement it. |
| Frozen Split-batch is a pure planner requiring graph pools, scoped context and an executor, with feature exclusions. | Capability requirements and declared ownership/exclusions. | Executable host integration and graph/buffer invariants. |
| Frozen Unified Communication exposes an import-only registry/strategy and reserves communicator ownership to the host. | Lifecycle authority and resource constraints. | Native backend integration and real group/collective lifetime validation. |

These observations include deliberate restrictions and good defensive guards;
they are not all bugs. The audit separates an original implementation limit,
a missing declaration, a missing ECPA adapter, and an actual composition fault.
Only the last requires independently observed failure of the frozen composition.

## Evidence and adaptation boundaries

- `source-observed`: the pinned code establishes a prerequisite or integration surface.
- `runtime-observed`: independently retained execution establishes a bounded behavior.
- `hypothesis/unknown`: source suggests a risk, but composition behavior is unmeasured.

Original MOD source, ECPA-added descriptor, adapter, algorithm port, and host
modification are separate subjects. Manual and ECPA arms use the same algorithm
and host binaries when comparing orchestration. Costs include the adapter and
host work; unavailable historical labor hours remain unknown.

The original four definite H2 cases, the excluded report-consumption case,
the 31 modeled cases, and the negative H1 result retain their original scope.
The [prospective H2 design](../../research/h2-real-mod-redesign.md) and
[candidate plan](../../../experiments/real_mod_composition/h2-real-mod-redesign-plan.json)
add no measured outcomes and do not rewrite historical protocols.

## Expanded discovery beyond the original24

[The expanded source inventory](expanded-population/README.md) distinguishes49
declared extension/control repository boundaries (33 public,16 restricted) from
algorithms and runtime qualification. Its old24 intersection is21;28 lie outside
that frozen cohort. Four additional public source audits and exact portable
snapshots cover GDN and three StateAxis mechanisms. The fifth internal case and
private source remain local; no original population label or runtime result is
changed. Adaptation work estimates are explicitly unmeasured.
