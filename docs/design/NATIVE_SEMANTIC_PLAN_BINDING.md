# Prospective native completion obligations

`vllm-hust-ext compile-semantic-plan` compiles an explicit draft contract into a
fresh content-addressed execution Plan. It never launches a host or opens a
traffic route. It preserves the base Plan and adds a distinct obligation with
`event=selected-kv-native-arguments-completed`, `role=worker`, runtime authority
and all-worker completion. The current profile supports only explicit TP2
ordinals 0 and 1. The semantic capability must be provided by the same extension;
a consumer cannot attest a different selected provider through `requires`.
Optional, quorum, partial-worker and non-runtime claims fail.

The event's bounded meaning is selected logical KV reference/gather/destination
association with native-entry parameter completion. It is not a claim about
full physical KV storage, numerical attention correctness, model quality,
performance, or continued effectiveness after the observation expires.

```sh
vllm-hust-ext compile-semantic-plan \
  --base-plan /absolute/base-plan.json \
  --contract /absolute/explicit-native-contract.json \
  --plugin-map /absolute/extension-plugin-map.json \
  --output-directory /absolute/new-plan-directory
```

The contract uses `ecpa-manifest/0.1-draft` and must explicitly declare the new
event in both its process obligation and matching runtime authority grant.
`extension-plugin-map.json` maps every semantic contract extension ID to an
exact `PluginIdentity.id` already in the base Plan. Missing, extraneous,
ambiguous, duplicate-JSON or many-to-one mappings are rejected. Contract and
artifact versions and the compiled host tuple must agree. The compiler
rechecks the complete ContractPlan against its original ordered contracts.

The new directory contains mode-0400 `plan.json` and `binding.json`, inside a
mode-0700 directory. Existing output directories are never overwritten. Both
identities bind the contract manifest digest, compiled obligation, compiled
contract plan, exact plugin artifact, base Plan and required worker set.
Changing any of those identities produces a different semantic obligation and
execution Plan. Existing Plan artifacts and historical runs are not rewritten.

Invocation evidence cannot discharge the added obligation. The current
invocation-only Host observer rejects the new Plan instead of upgrading its
receipts. The binding receipt explicitly reports
`formal_producer_registration=false`. The formal semantic ExposureGate remains
closed: this change does not implement the registered live producer, independent
response association, generation/lease invalidation or ongoing membership
fencing required before formal admission.

R4 is an immutable historical observation under its original Plan, not a run of
this new Plan. A future deployment must register and source-admit the exact
producer, freeze a fresh Plan/recipe and validate live evidence before serving.
Original H1/H3/H4 results and matrices retain their classifications. Unit tests
of the compiler and reference model are CPU checks, not NPU qualification.
