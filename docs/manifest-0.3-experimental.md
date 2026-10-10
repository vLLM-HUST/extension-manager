# Extension Manifest 0.3 — compatibility alias

The stable Manifest 0.3 shape is now documented in
[`manifest-0.3.md`](manifest-0.3.md) and uses `"schema_version": "0.3"`.
`0.3-experimental` remains readable with the same shape for existing wheels but
must not be used for new migrations. This file is retained as historical design
context.

Manifest 0.3 is the first composition-oriented ECPA schema. It retains every
0.2 field and adds `resource_claims` and `requires_extensions` so conflicts and
incomplete activation graphs are rejected before a host process starts.

```json
{
  "schema_version": "0.3-experimental",
  "requires_extensions": [
    {
      "extension_id": "org.vllm-hust.ascend-kvcompress",
      "version_range": ">=0.9,<0.10"
    }
  ],
  "resource_claims": [
    {
      "resource": "vllm.scheduler.preemption-policy",
      "scope": "vllm-process",
      "mode": "exclusive"
    },
    {
      "resource": "vllm.runtime.observer",
      "scope": "vllm-process",
      "mode": "shared"
    }
  ]
}
```

`resource` and `scope` are extensible lowercase identifiers. ECPA does not
maintain a closed list of MOD names. Providers and host contracts define the
meaning of a resource. `mode` is one of:

- `exclusive`: another claim for the same `(scope, resource)` is rejected,
  including an otherwise identical exclusive claim;
- `shared`: multiple shared claims may coexist, but they conflict with an
  exclusive claim for the same resource.

Typical exclusive resources include scheduler policies, KV connectors,
process carriers, network ports, and device partitions. Observer and telemetry
fan-out are typical shared resources. Resource claims do not grant lifecycle
ownership, device access, or permission to mutate an external service.

`requires_extensions` declares Bundle identity and a PEP 440 version range.
Every dependency must be installed, compatible, and explicitly enabled in the
same activation set. ECPA never auto-enables it. Missing, disabled,
version-incompatible, or cyclic dependencies fail before plan/render/run.
Disabling or forgetting a dependency is rejected while an enabled dependent
still refers to it. This is enable-intent composition, not runtime evidence or
lifecycle ownership.

## Host capability discovery

Current vLLM-HUST hosts export a side-effect-free snapshot from
`vllm.plugins.extension_capabilities.get_extension_capabilities()`:

```json
{
  "schema_version": "vllm.extension-capabilities/v1",
  "host_api_version": "1.0",
  "protocols": {
    "vllm.preemption-policy": "1.0"
  }
}
```

ECPA consumes that registry instead of importing one implementation module per
MOD. An unknown schema, malformed version, invalid protocol entry, or failing
registry is rejected without falling back to optimistic compatibility.
Legacy module probes are used only when the registry module is absent.

## Migration from 0.2

0.2 manifests remain readable and receive empty resource-claim and extension-
dependency sets. They must not add `resource_claims` or `requires_extensions`
without changing `schema_version` to `0.3`. Migrating a MOD requires identifying every resource it
owns and every Bundle whose carrier must be enabled; absence of a declaration
is not evidence that a combination is safe.

The `0.3-experimental` identifier is not a stable promise. The stable `0.3`
identifier is frozen by the schema and conformance vectors; Manager publication
and MOD runtime qualification remain separate release gates.

## Explicit vLLM process carriers

An active component with contract `vllm.worker-class.v1` asks the vLLM Provider
to project its `module:object` implementation as the native `--worker-cls`
launch option. Exactly one such component may appear in a Bundle. Core rejects
a different user-supplied Worker before launch, and an exclusive claim such as
`vllm.process-carrier.worker` prevents two enabled Bundles from competing for
the same process carrier.

The contract only describes launch intent. A MOD must still pin a truthful
host range, keep installation inert, define restart-based rollback, and obtain
process-owned observer evidence before reporting `runtime_effective`. ECPA does
not install donor runtimes, choose devices, or qualify performance through the
presence of `--worker-cls`.
