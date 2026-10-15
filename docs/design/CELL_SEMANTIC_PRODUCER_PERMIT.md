# Cell-scoped semantic producer permits

`experiments.native_attention_candidate.semantic_producer_registry` is an
unwired, local permission and verification layer. It does not install software,
launch models, mutate routes, admit formal runs, or modify the compiler's
`formal_producer_registration=false`. Existing formal gates stay closed.

The independent authority owns `CellIssuer`'s private MAC key and the trusted
digests returned by independently executed full-tuple source admission. Neither
comes from producer JSON. This is a local administrative capability, not public
attestation or protection against a same-user administrator. Permit issuance
also requires the exact execution Plan, complete recipe, seven wheel hashes,
model/tokenizer/calibration identities, path-specific native sources, and exact
producer/verifier/route-reader/registry sources. Verifier callbacks additionally
bind their qualified function names. No human-review flag is invented.

The integration order is:

1. Before launch, call `issue_permit(cell, execution_plan=..., recipe=...,
   fixed=..., policy=..., source_observation=...)`. Compute `profile_id` with
   `recipe_profile_id(recipe)`. Only one explicit TP2 obligation and one plugin
   cell are supported. Other cells and compositions remain unverified.
2. Replace the owner's original handoff receive with `accept_handoff(permit,
   listener=..., path=..., manager=..., launched_wall_ns=...)`. It performs the
   real existing Manager exchange and returns a MAC witness; its `body.record`
   retains the original native receipt. Do not call both receive functions.
3. After actual source/producer registration, call `bind_deployment` with that
   witness, exact kernel identities, the connected producer Unix socket,
   `recipe/spec/policy/drain_policy/registration` artifact references, and a
   source-pinned independent `route_reader`. The route query must report current
   Plan, launch, generation, membership epoch, controller, fence and lease expiry. This helper
   does not supply a route implementation or synthesize its query.
4. The authority generates a fresh nonce, calls `QuoteVerifier.expect`, obtains
   the producer's existing typed quote, and calls `verify`. Supply the exact
   registered observation verifier, such as `drain_consumer.verify_observation`,
   and its actual deployment arguments. It executes that verifier; a claimed
   count or invocation cannot substitute for the full typed/OP/source-drain
   result. Failed challenges are consumed, proof leases cannot renew, and OS,
   source, artifact, socket and route checks repeat after verification.

The returned bounded verdict discharges only the named observation obligation.
It does not establish whole-Plan effectiveness, numerical attention, complete
physical KV, future-request effects, formal source registration across classes,
or H3/H4 results. Nonce and lease state live in the verifier process; replacing
that process requires a fresh controller/generation and deployment binding in
the future durable authority adapter. No persistent replay/fence mechanism is
claimed here. A public forwarding adapter and its formal runner integration
remain separate work; this module does not change the cached-response profile.

Tests use real CPU child processes, Manager handoff and Unix peer credentials,
with explicitly synthetic source-admission and semantic fixtures. They are not
official source publication observations or NPU qualification.
