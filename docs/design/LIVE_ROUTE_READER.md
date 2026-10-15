# Actual controller reads and exact cell inputs

`live_route_reader` is a read-only adapter, not source registration or a route
opener. No existing runner, producer, compiler, legacy gate, or authority changes.

Before issuing a fresh permit, run `audit_cell_inputs(config_path, recipe_path)`
in the actual pinned runtime interpreter. It checks the seven genuine archives,
wheel metadata and installed Python/native payload (including additional modules),
14 model files, exact tokenizer assets and runtime source binding, and calibration
bytes. The model identity is SHA256 of the canonical path→digest inventory. The
tokenizer identity hashes the complete phase tokenization object, observed Host
sources, and implementation inventory. The calibration identity is its file hash.
File inode/mode/uid/size/mtime/ctime snapshots prevent reusing an audit after an
ordinary file replacement; these are not attestation against a root attacker.
Weights are hashed once, never on each public request. This does not establish
which model bytes executed on the accelerator or any quality result.

An independent issuer must trust the audit digest itself. Pass that trust set to
`controller_cell_binding(issuer, permit, handoff, inputs,
trusted_input_audits=...)`. This validates the issuer's original authenticated
Manager exchange and source-admission tuple against the exact wheel revisions,
profile/request, recipe, model/tokenizer/calibration identities. Preserve the
original handoff; do not receive it twice or synthesize it from environment JSON.

A future controller must put that returned object in its actual RouteState
snapshot as `semantic_cell`, with `execution_plan_id`, `native_launch_id`,
`controller_instance`, and `membership_epoch` beside it. `LiveRouteReader.read`
only accepts real current candidate routes. It authenticates controller kernel
epoch, command bytes, source files and Unix socket identity/SO_PEERCRED. It reads
`query → lease_valid → query` from the existing authority used by HTTP forwarding,
rejecting scope changes and missing cell binding. The original lease grant must
name the controller. Its conservative monotonic expiry is anchored once and
cannot renew on a repeated query. The audited input file state is checked again.
Register `LiveRouteReader.read` as the exact route callback, not a static dict.

This reader deliberately rejects the cached authority's ready/status interface,
which has no route generation/fence/lease, and closed/predecessor routes. It
cannot solve admission bootstrap: opening a public candidate before binding and
verifying a deployment would be unsafe. A separate staged controller must keep
public exposure closed while it owns a prepared candidate scope/fence/fixed
lease, then verify typed evidence and current state before atomic bounded commit.
The producer's fixed proof expiry must not be renewed. The legacy formal gate
stays closed. No historical cohort receives new qualification from this code.

Required trust still includes independently captured source-admission and input
audits, actual deployed controller source/argv pins, single-owner control socket,
and non-reused controller/generation/fences on restart. Two queries are current
state observations, not a durable transaction history or an ABA-prevention proof.
The later controller must enforce that lifecycle. The new CPU tests exercise the
existing authority's real socket and HTTP forwarding, with explicitly synthetic
cell semantics; they do not issue formal or NPU evidence.
