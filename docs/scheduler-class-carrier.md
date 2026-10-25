# Native scheduler class carrier (development)

`0.3.1.dev1` can deliver an installed Python scheduler through vLLM's existing
`--scheduler-cls` selector. ECPA `0.3.0` cannot render this selector. The component
contract `vllm.scheduler-class.v1` versions this Manager projection only: it does
not promise a stable vLLM SchedulerInterface, worker/model-runner ABI, typed core
materializer, accelerator behavior, or performance. In particular, current vLLM
still warns that its custom scheduler interface is not public.

Use Manifest `0.3`, with an active `python_module` implementation and one component:

```json
{
  "component_id": "scheduler",
  "contracts": ["vllm.scheduler-class.v1"],
  "execution_planes": ["scheduler"],
  "isolation": "trusted_in_process",
  "implementation_ref": "example.scheduler:Scheduler",
  "permissions": []
}
```

The owning Bundle must declare `lifecycle_owner: "vllm"`, runtime isolation
`trusted_in_process`, and this resource claim:

```json
{
  "resource": "vllm.process-carrier.scheduler",
  "scope": "vllm-process-tree",
  "mode": "exclusive"
}
```

Missing/shared/wrong-scope claims, multiple scheduler components, or another
execution plane fail before launch. Two enabled Bundles claiming this resource
conflict even if their implementation classes are identical. This resource claim
does not reserve physical devices or grant additional process authority.

A Bundle may additionally declare its existing `vllm.worker-class.v1` component
and exclusive `vllm.process-carrier.worker` claim, plus a batch-admission policy.
The existing worker behavior is unchanged. Manager renders all selected native
options together; it never imports the scheduler implementation to plan/render.
Every supplied occurrence of a managed scalar option must match the generated
value. A later conflicting duplicate, missing value, or managed option after `--`
is rejected, including vLLM's underscore spelling. Abbreviated managed selectors
are rejected rather than resolved without the host parser. Newly generated
options are inserted before `--` when present.

Package the one manifest as wheel package data and register its directory under
`vllm_hust.extension_bundles`. A normal package import/install must not activate
runtime code. Do not use an `import_only` carrier or a no-op general plugin as a
substitute for selecting the scheduler. Consumers must pin a Manager wheel/build
containing this capability; the older release does not acquire it from metadata.

Qualification must separately cover installed-wheel discovery, configure/enable,
render and `run --dry-run`, incompatible-host and conflicting-option rejection,
actual scheduler/worker use, request completion/cancellation, bounded shutdown,
and next-start rollback. Host/protocol versions and private runtime APIs require
exact source qualification, particularly for paired scheduler/worker MODs. Do not
invent a host capability protocol that the host registry does not advertise.

Disable saved intent, stop the operator-owned old instance, then launch a fresh
instance without the selected classes to roll back. Disable does not mutate a
running scheduler. Forget saved state before uninstalling if stale re-enable
intent must not survive a reinstall. Static compatibility or successful render
is not live runtime-effect evidence.

For direct module carriers, a supervised launch writes a separate
`vllm-hust-module-launch/0.1` binding containing the selected manifest bytes,
component contracts/references and Manager process birth identity. After real
successful work, each selected carrier calls `emit_module_effective` with its
actual loaded class, role and positive output counts. The resulting
`vllm-hust-module-evidence/0.1` receipt has no fabricated plugin entry point.
Status requires every declared class-carrier component (including a paired
admission policy) from the latest launch and all observed process identities to
remain live. A new launch, changed manifest or exited observed process revokes
the match. This is trusted in-process reporting, not protection from malicious
same-user journal writes, an independent accelerator trace or an all-rank check.

The current development release is intentionally `no-go` for stable publication.
The published 0.3.0 release decision remains historical evidence, not qualification
of this new carrier or any MOD using it. Previously passed gates retained in the
development readiness record refer to that historical qualification; the new
carrier qualification remains a separate required blocker.
