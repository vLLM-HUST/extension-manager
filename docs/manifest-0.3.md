# Extension Manifest 0.3

Manifest 0.3 is ECPA's stable composition-oriented manifest shape. It retains
the 0.2 fields and adds `resource_claims` and `requires_extensions`, allowing
Core to reject conflicts and incomplete activation graphs before a host process
starts. The normative schema and conformance corpus live in
[`spec/manifest-0.3`](../spec/manifest-0.3/README.md).

New manifests use:

```json
{
  "schema_version": "0.3",
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
    }
  ]
}
```

An `exclusive` claim conflicts with every other claim for the same
`(scope, resource)`. Multiple `shared` claims may coexist, but conflict with an
exclusive claim. Claims do not grant permission, device access, or lifecycle
authority.

Every `requires_extensions` dependency must be installed, version-compatible,
and explicitly enabled in the same activation set. ECPA never auto-enables a
dependency. Missing, disabled, incompatible, or cyclic dependencies fail before
plan/render/run. Dependency satisfaction is not runtime evidence.

Current vLLM-HUST hosts advertise protocols through the side-effect-free
`vllm.extension-capabilities/v1` registry. Unknown schemas, malformed versions,
invalid protocols, and registry failures fail closed. Legacy probes apply only
when the registry module is absent.

## Compatibility

`0.3-experimental` is retained as a read-only compatibility alias with the same
field shape so existing wheels remain discoverable. New or migrated wheels
should use `0.3`. Unknown revisions such as `0.3.1` are rejected; compatible
future additions require an explicitly reviewed schema identifier.

0.2 remains readable with empty resource/dependency sets. Migration is not
inferred: an owner must audit claims and dependencies, change the identifier,
and test the resulting activation graph. Rollback disables dependents first,
restores the exact 0.2 document, and then re-enables in dependency order. The
checked vectors are in `spec/manifest-0.3/migration-vectors.json`.

## Runtime boundary

The manifest expresses intent and ownership conflicts. Installation, discovery,
compatibility, enablement, runtime effectiveness, and performance remain
separate states. Only a live owning-process observer can establish
`runtime_effective`; external services remain operator-owned.
