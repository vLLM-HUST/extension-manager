# OSDI related-work and baseline audit

Status: superseded short-form inventory. The source-checked mechanism matrix,
hostile review, and current evidence ledger live in
[`paper/related-work-audit.md`](../../paper/related-work-audit.md). One H1
formal-real cell is now complete and falsifies the tested prevention property;
H2--H4 remain incomplete.

The closest mechanism comparison is about the authority needed to certify an
extension's effect. A baseline is eligible for a measured comparison only when
it can run the same model, workload, host, plugin behavior, process topology,
and fault. The table identifies which mechanism each source actually specifies;
"not specified" is not an assertion that an implementation cannot be extended.

| System or mechanism | Specified decision and observable | Relationship to ECPA's H1 comparison |
|---|---|---|
| [vLLM Plugin System](https://docs.vllm.ai/en/latest/design/plugin_system/) | Python entry-point discovery, filtering, and loading | The vanilla arm uses this loader. Loading alone is not a process-wide effect receipt. |
| [Envoy xDS](https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol) | Versioned resource delivery and ACK/NACK | Useful configuration acceptance baseline; an ACK does not encode the inference hook's process coverage. |
| [OSGi Core](https://docs.osgi.org/specification/osgi.core/8.0.0/) | Bundle and service lifecycle | Close module-lifecycle design, but the ECPA experiment needs a host-owned worker effect boundary. |
| [Consistent network updates](https://doi.org/10.1145/2342356.2342427) | Coordinated network configuration exposure | Foundational exposure principle; packet-level update consistency is outside ECPA's claim. |
| [Acto, SOSP '23](https://doi.org/10.1145/3600006.3613161) | End-to-end operation testing against desired-state oracles | Closest testing analogue; its state oracle does not assign every inference effect to a distinct producer authority. |
| [Anvil, OSDI '24](https://www.usenix.org/conference/osdi24/presentation/sun-xudong) | Verified eventual stable reconciliation for cluster controllers | Stronger reconciliation-liveness result; ECPA specifies a narrower process-effect/exposure property. |
| [dLoRA, OSDI '24](https://www.usenix.org/conference/osdi24/presentation/wu-bingyang) | Dynamic placement, merge/unmerge, and migration of LoRA adapters | Closest dynamic inference-adapter mechanism; it does not claim general cross-authority activation evidence. |
| [CamFlow, SoCC '17](https://doi.org/10.1145/3127479.3129249) | Whole-system provenance capture at the OS boundary | Broader event capture; ECPA still needs obligation semantics and the correct effect authority. |
| [AlpaServe, OSDI '23](https://www.usenix.org/conference/osdi23/presentation/li-zhouhan) | Placement and model parallelism for serving latency under burstiness | Performance context for H4, not an activation-safety substitute. |

The preregistered H1 arms are vanilla entry points, manual integration, and
ECPA. Manual integration must implement the same extension behavior without
silently inheriting ECPA's evidence gate. H1 compares false-effective outcomes
under the same fault and frozen target set; H4 compares overhead under the
same model and workload. One partial-worker-coverage TP2 cell now has three
starts per arm and five lifecycle sources per start. All records pass offline
validation, but every ECPA repetition retained an effective claim at 0.5
coverage. This falsifies H1 prevention for the tested implementation. The
startup fields are not H4 results.

The strongest current novelty statement is a falsifiable protocol that binds
an immutable extension plan, authority-owned evidence, frozen process epochs,
and a traffic exposure decision. The current runtime does not yet enforce that
last decision at a real traffic authority. Prevention requires an implementation
fix and fresh H1 evidence; H2--H4 also remain incomplete. A second inference
runtime is not required
to establish the tested vLLM-HUST cell, but cross-framework portability remains
unmeasured and cannot support a generality claim.
