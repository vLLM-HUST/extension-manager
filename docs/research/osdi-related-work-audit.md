# OSDI related-work and baseline audit

Status: argument inventory; no experimental result.

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
| [AlpaServe, OSDI '23](https://www.usenix.org/conference/osdi23/presentation/li-zhouhan) | Placement and model parallelism for serving latency under burstiness | Performance context for H4, not an activation-safety substitute. |

The preregistered H1 arms are vanilla entry points, manual integration, and
ECPA. Manual integration must implement the same extension behavior without
silently inheriting ECPA's evidence gate. H1 compares false-effective outcomes
under the same fault and frozen target set; H4 compares overhead under the
same model and workload. The current matrix has zero completed formal-real
cells, so no baseline has yet been measured or ranked.

The strongest current novelty statement is a proposed transaction that binds
an immutable extension plan, authority-owned evidence, frozen process epochs,
and a traffic exposure decision. Its runtime advantage is a hypothesis until
the formal H1 and H3 studies finish. A second inference runtime is not required
to establish the tested vLLM-HUST cell, but cross-framework portability remains
unmeasured and cannot support a generality claim.
