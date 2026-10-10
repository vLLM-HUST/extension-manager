# Versioning and migration

The source package is `0.3.0.dev0`; compatibility remains frozen and no alpha
release is authorized. The version change identifies the active development
line and does not stabilize the manifest, Provider, host-hook, or catalog
contracts. Passing unit or host-contract tests does not authorize publication.

`docs/release-readiness.json` is the machine-readable release decision. Its
package version must match both `pyproject.toml` and
`vllm_hust_ext.__version__`; required blocked gates force a `no-go`. A release
operator must run both of these commands before creating a tag:

```bash
python scripts/check_release_readiness.py --require-authorized
vllm-hust-ext --version
```

The first command intentionally fails while the compatibility freeze remains.

## Persisted configuration

- Schema 2 stores each extension's `enabled` intent separately from its
  provider configuration.
- Schema 1's `enabled` list is accepted as a one-way migration input. The next
  saved state writes schema 2.
- Unknown schemas and malformed fields are rejected. Operators should retain a
  copy of the previous configuration before migration; rollback is restoring
  that copy while no Manager command is writing it.

## Manifest 0.2 to 0.3

Manifest `0.3` freezes the composition data shape first exercised by
`0.3-experimental`. The experimental identifier remains readable for existing
wheels, but new migrations emit `0.3`. A 0.2 manifest is still readable and has
neither resource claims nor extension dependencies. It cannot declare
`resource_claims` or `requires_extensions` until its author audits ownership
and dependencies and changes the manifest version. There is no automatic
inference from flags, environment variables, package dependencies, or
implementation names.

Downgrading a 0.3 manifest to 0.2 discards conflict and dependency information
and is not automatic. Operators must first disable dependents, disable the
dependency, replace the package, inspect the 0.2 plan, and re-enable in
dependency order. Saved enable intent does not bypass this migration check.
The normative positive, negative, migration, and exact-rollback vectors are in
[`spec/manifest-0.3`](../spec/manifest-0.3/README.md) and run in CI.

## Runtime rollback

For an in-process vLLM plugin, disable the extension and restart the
Manager-owned host process. Then verify the plugin observer no longer reports
invocations before forgetting state or uninstalling the distribution. A
successful import, an environment variable, or saved enabled intent is never
`runtime_effective` evidence. Bound observer receipts remain in an audit log,
but status stops projecting the state as soon as the exact reporting PID/start
identity is no longer live.

External KV services and Kubernetes workloads keep their existing operator
lifecycle. Manager disable, forget, and package uninstall do not stop, roll
back, or delete those resources.

## Release gate

The freeze remains until the latest vLLM-HUST contract and at least one real
plugin pass clean-wheel activation, incompatible-version rejection,
process-owned runtime observation, failure degradation, stop, disable,
rollback, forget, and uninstall. Support-matrix entries must cite the exact
host/plugin commits and must distinguish historical compatibility adapters from
native-host NPU validation.

Moving from `0.3.0.dev0` to an alpha, release candidate, or stable version is a
separate reviewed change. It must update the machine-readable decision and all
version sources in the same commit. A tag alone never changes release status.
