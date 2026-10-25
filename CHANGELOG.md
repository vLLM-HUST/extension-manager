# Changelog

## 0.3.1.dev1 - unreleased

- Add explicit native `--scheduler-cls` projection for one trusted, vLLM-owned
  scheduler carrier with an exclusive process-tree resource claim.
- Validate every occurrence of managed scalar launch options, including mixed
  `--name value` / `--name=value` duplicates, underscore aliases, and the
  end-of-options boundary; reject abbreviated managed selectors.
- Bind successful module-carrier work to the latest supervised launch and live
  process identities, separately from entry-point observations and device proof.
- Keep Manifest 0.3 unchanged and require separate host/accelerator qualification;
  the development build does not inherit 0.3.0 stable publication authorization.

## 0.3.0 - 2026-10-11

First formally published ECPA release.

- Freezes Manifest 0.3 composition, resource-claim, dependency, and migration
  semantics while retaining the experimental manifest identifiers as migration
  aliases.
- Separates package discovery, saved enable intent, compatibility, rendered
  launch configuration, live process-owned runtime effect, and performance
  evidence.
- Adds provider-neutral discovery, inspection, check, plan, render, supervised
  run, status, disable, restart rollback, forget, and package-operator uninstall
  guidance.
- Preserves user `VLLM_PLUGINS`, the built-in `ascend` platform plugin, and
  deterministic de-duplicated plugin activation; conflicts and unknown
  host/protocol versions fail closed before launch.
- Adds strict composition claims, Bundle dependencies, external-controller and
  production-stack provider boundaries, failure/permission matrices, and a
  catalog contract for the MOD page.
- Qualifies one pinned clean-wheel native NPU lifecycle with the current
  vLLM-HUST host, vLLM-Ascend-HUST compatibility patch, and KV materialization
  plugin. This is lifecycle evidence, not a performance or universal MOD
  support claim.

See `docs/release-readiness.json`, `docs/support-matrix.md`, and
`docs/versioning-and-migration.md` for the exact evidence and rollback boundary.
