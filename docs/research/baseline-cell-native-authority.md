# Baseline native cell authority

`baseline_cell_issuer.py` and `baseline_cached_controller.py` provide a separate
baseline-origin path for the selected-KV entrypoint and explicit-callable arms.
They do not accept a Manager permit, Plan, handoff, deployment, quote or ticket.
The original Manager registry/controller and native drain algorithms are unchanged.
This is local same-UID administrative verification, not attestation against a
malicious administrator with Python memory or filesystem access.

## Owner integration

1. Freeze one identical canonical `phase.payload` for all matched arms. Independently
   audit the seven installed wheels, model, tokenizer, calibration and source closure
   with `live_route_reader.audit_cell_inputs`; independently admit the exact source
   tuple. Keep both trusted digest sets in the owner, outside producer registration.
2. Before Host spawn, write the `BaselineNativeScope`, activation profile and common
   query. Launch with the real `HostObserver` and scope environment. Capture the
   stock Host-assigned API/worker roles and current kernels. Use the unchanged
   `baseline_native_scope.write_contexts` adapter and real native collector.
3. Issue `BaselineCellIssuer.issue_permit(cell, baseline_scope_reference=...,
   activation_profile_reference=..., recipe=..., fixed=..., policy=...,
   source_observation=..., inputs=...)`. `cell` has exactly `CELL_FIELDS`; protocol
   roles are `producer`, `issuer`, `verifier`, `controller`, `input_audit`. The verifier
   pin is `drain_consumer.verify_observation`; the controller pin is
   `BaselineCachedController.read_route`. Callable pins include `callable` as well
   as exact `path` and `sha256`. All native/protocol files must appear in the
   independently trusted input audit. The profile calibration must match that audit.
4. Write a fresh private baseline producer registration and launch its independent
   process under the owner. Construct `BaselineCachedController(issuer, permit,
   recipe=recipe, journal_path=fresh_private_path, public_port=...)`; public HTTP
   begins CLOSED. Call `bind_and_commit_cached(controller, producer_kernel=...,
   artifacts=..., observation_arguments=...)` within the outer owner watchdog.
   Artifact roles are `registration`, `recipe`, `spec`, `policy`, `drain_policy`.
   Arguments are the original drain verifier's exact recipe/phase/output/descriptor
   and four native policy/journal/spec paths. Always close the controller in cleanup.
5. Exercise the exact frozen public request and actual registered worker fault
   within the original deadline. Preserve all raw failure/success evidence and
   independently audit before classifying any experiment.

The owner, API server, worker 0, worker 1 and producer must be five distinct current
kernel epochs; the collector is another independent process. Host launcher epochs
and ancestry are also checked. The owner reads its actual prepared controller
state through the pinned bound method. There is no declared synthetic Manager.

## Native predicate and fixed lifetime

The independent verifier burns each nonce even on failure, authenticates the
collector and final acknowledged prefix before and after the unchanged full drain
verification, and reconstructs 56 tensor receipts, 56 operator receipts and two
worker closures from the entire raw journal. It compares the canonical observation,
raw response and journal digests, all current source/Host/configuration/process
bindings, and the producer's original durable completion record.

The original completion expiry is exactly its initial monotonic issuance plus
30 seconds. Per-query issuance may advance; expiry and every other proof field
cannot. Neither first observation, preparation, deployment, ticket issuance nor a
later challenge restarts that deadline. Verification and response journal fsyncs
are followed by an expiry check. Late source/epoch/prefix/raw-input loss permanently
revokes the controller. CLOSED/PREPARED/VERIFYING requests return HTTP 503 without
waiting behind full verification.

A successful ticket authorizes only the exact frozen request's cached verified
bytes. It does not authorize a new inference, arbitrary HTTP request, general model
quality claim, performance result, or formal H3/H4 qualification. All schemas retain
`formal_result: false`. CPU tests exercise administrative boundaries only; actual
native effects require a fresh frozen real TP2 run and independent evidence audit.
