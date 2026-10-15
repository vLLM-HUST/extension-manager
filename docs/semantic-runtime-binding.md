# Fresh semantic runtime binding

`run --semantic-launch-spec /canonical/private/spec.json -- HOST ...` binds the
actual enabled wheel payloads to a prospectively compiled semantic execution
Plan before launching Host. The default `run` path remains unchanged. This
feature binds identity and intent; an independent live producer and authority
must still establish the bounded semantic effect before opening public traffic.

The owner uses `semantic_runtime_binding.installed_plugin_identities(bundles)`
to obtain `(plugins, snapshots)` from installed distributions. Construct a base
Plan using those exact PluginIdentity values, compile explicit provided native
contracts with `compile_native_semantic_plan` (runtime/all/worker TP2), and write
private base Plan, compiled Plan, binding receipt, contract and plugin map files.
The plugin map keys must be actual enabled bundle IDs; their values are the
corresponding actual PluginIdentity IDs. Every Plan plugin must match one enabled
bundle, including real distribution name/version, manifest hash, and sorted
per-file payload hashes. The manager reads each installed file; RECORD hashes
and caller summaries are not evidence. Bytecode, installation receipts and
installer-generated console wrappers are excluded; editable installs fail closed.

`make_semantic_launch_spec(bundles, base_plan_path=..., plan_path=...,
binding_path=..., contract_paths=[...], plugin_map_path=...,
controller_instance="controller:...", candidate_generation=1,
membership_epoch=0)` returns the spec object. Persist it privately before launch;
`validate_semantic_launch_spec(path, bundles)` is the same admission check used
by `launch_environment(bundles, semantic_launch_spec=path)`. All referenced
artifacts must be canonical absolute, owned regular files with mode 0600/0400.
The binding receipt is recomputed from the base Plan and contracts and compared
exactly, rather than trusted as a producer assertion.

Schema `ecpa-native-semantic-launch-spec/v1` has exactly these fields:

- `schema`, `base_plan`, `plan`, `binding`, `contracts`, `plugin_map`.
- `enabled_bundles`, `execution_plan_id`, `native_plan_id`.
- `controller_instance`, `candidate_generation`, `membership_epoch`.

Each artifact reference is `{ "path": "/canonical/private/file", "sha256":
"64 lowercase hex" }`; `contracts` is a list of these references. The snapshot
list comes from the helper. `native_plan_id` is the 64 hexadecimal SHA256 suffix
of the canonical execution Plan ID, preserving the unchanged native v1 handoff.
A changed semantic Plan cannot reuse the old native Plan identity. Launch IDs
remain fresh Manager-generated UUID4s.

`semantic_context_environment(spec_path, validated_spec)` provides the separate
`ECPA_SEMANTIC_LAUNCH_SPEC`, `ECPA_SEMANTIC_EXECUTION_PLAN_ID`, `ECPA_SEMANTIC_CONTROLLER_INSTANCE`,
`ECPA_SEMANTIC_CANDIDATE_GENERATION`, and `ECPA_SEMANTIC_MEMBERSHIP_EPOCH` fields. These are added
outside the unchanged five-field v1 handshake. Inherited values are rejected.
Membership process identities must subsequently be obtained from real source
registrations; a frozen epoch number is not proof of actual membership. A new
cohort requires new challenge and raw live evidence. Historical R4 evidence
cannot satisfy this Plan's fresh obligations. This path does not waive source
publication admission or declare a formal H3/H4 result.
