# Extension Manifest 0.2 — experimental

This schema replaces the single-Python-Bundle assumption during architecture
validation. It is deliberately marked `0.2-experimental`; it is not a stable
compatibility contract.

Every manifest declares:

- `kind`: the domain role, such as `scheduler_policy`, `kv_service_adapter`, or
  `control_plane_extension`;
- `host`: Provider identity plus host and host-API compatibility ranges;
- `runtime`: Python, external service, OCI, Kubernetes, or composite runtime,
  with process scope and isolation;
- `lifecycle_owner`: the system or operator that is authorized to change the
  runtime lifecycle;
- `protocols`: explicit protocol compatibility ranges;
- `implementation`: one or more carriers, including Python entry points,
  host-builtins, external services, OCI images, Helm values, Kubernetes
  manifests, CRDs, and controllers;
- `requires_services`: service identity, protocol range, configuration key for
  its endpoint, and whether it is optional; and
- optional typed components and activation declarations.

The old Bundle v1 shape remains readable only as an experimental migration
input. It must not be advertised as stable and receives no forward
compatibility promise.
