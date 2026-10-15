# Fresh bounded cached-cell integration

This is a prospective, nonformal owner integration. It neither opens the legacy
formal gate nor changes compiler registration/human-review flags. It does not
forward new model requests or establish numerical/full-KV/quality/H3/H4 results.

The new owner keeps its existing source/model/epoch/watchdog/cleanup checks and
calls `live_route_reader.audit_cell_inputs(config_path, recipe_path)` before
launch, in the actual runtime. The config's `sources` must include the new
`live_route_reader.py`, `staged_cell_controller.py`, and `staged_cell_cohort.py`
plus the existing registry, verifier dependencies and original required sources.
The audit now checks those exact source bytes as well as the seven wheels,
installed code/ELFs, model, tokenizer and calibration; no extra installed payload
is allowed. Independently trust the observed audit digest, not a producer claim.

Issue the exact single-cell permit before Manager launch using that audit's
`profile_id`, model/tokenizer/calibration and wheel digests, canonical recipe and
request hashes, actual native source inventory, original Manager handoff sources,
and exact protocol references. The verifier reference is
`drain_consumer.verify_observation`. The route-reader reference is
`staged_cell_controller.PreparedCandidateReader.read`. Keep all unrelated cells
unverified. Fresh exact source admission still applies; unpublished or non-main
Manager/Host commits cannot be made eligible by supplying a callback hash.

Replace the old owner receive with this one receive, which saves **actual wire
bytes**, preserves the original returned record, and seals the authenticated
exchange under the permit:

```python
from experiments.native_attention_candidate import staged_cell_cohort
sealed = staged_cell_cohort.capture_owner_handoff(
    issuer, permit, listener=listener, path=phase_socket, manager=owner,
    launched_wall_ns=launched, raw_record_path=out / "handoff-raw.json")
receipt = sealed["body"]["record"]
write(out / "native-binding.json", receipt)
write(out / "cell-authenticated-manager-handoff.json", sealed)
native_env = receipt["environment"]
```

Do not call `accept_native_binding` or `issuer.accept_handoff` again. Inside the
existing whole-phase RPC watchdog, replace only the old cohort call:

```python
rpc = staged_cell_cohort.execute(
    config, recipe, native_env=native_env, peers=peers, manager=owner,
    descriptor=ready, spec_path=spec_path, journal_path=raw,
    policy_path=policy_path, drain_policy_path=drain_policy_path,
    issuer=issuer, permit=permit, sealed_handoff=sealed, inputs=inputs,
    trusted_input_audits={sha(canonical(inputs))})
```

`inputs` is the independently observed audit above. The issuer owns its MAC key
and independent source-admission/audit trust sets. The output directory must be
fresh/private. Preserve the original exact seven wheel pins, complete model,
tokenizer, calibration and native epoch registrations. The wrapper starts only
the existing independent producer subprocess and an owner-local controller; it
does not launch NPU workers or change who owns device cleanup.

The controller starts with real public HTTP 503 and a private read-only Unix
control endpoint. It waits for the real producer, then uses a preliminary quote
only to bound a prepared candidate's expiry. It never treats that quote as
verified. The prepared scope/fence/original proof expiry are fixed. The actual
prepared UDS reader feeds deployment binding while public stays closed. A full
independent `QuoteVerifier.verify` recomputes typed evidence once; successful,
still-current verification yields an issuer-MAC ticket tied to cell/deployment,
proof identity, immutable raw/response file states and the same fixed expiry.
Commit never renews the lease or changes the deployment's fence/scope. Public
requests arriving during PREPARED/VERIFYING immediately get 503.

Each public admission is only the exact frozen POST path, payload, known headers
and X-ECPA-Request-ID, returning the exact verified cached bytes. It rechecks a
fresh nonce/actual Unix peer, current kernel epochs, source bytes, prepared state,
raw/response file states, and unchanged proof contents/expiry. Only the fresh
producer issuance timestamp may vary. It does not rerun the expensive semantic
verification or mint another 30 seconds. Drift/fault/expiry revokes permanently.
This ticket is an in-process administrative capability, not public attestation
or crash-persistent replay protection. Restart needs a fresh controller and run.

The wrapper retains real wrong-request 503 and registered-worker SIGTERM→503
with a still-valid original lease, exact response comparison, and subprocess
cleanup. A 20+ second full verification plus worker shutdown may exhaust the
original 30 seconds; that must fail and preserve the attempt, never increase TTL
or count an expired denial as an epoch-loss result. The CPU tests exercise real
sockets/HTTP, actual child epochs and original Manager wire exchange with declared
synthetic semantic data. They are not evidence that this new path has run on NPU.
