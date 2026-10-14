# Frozen nonformal KV HTTP budget

KV v2 recipes may preregister `rpc_budget_s` per phase using
`--materialized-row-v2 --rpc-budget-s 180`. It must be a finite positive number
at most 600 seconds; booleans, NaN, infinity and other types are rejected. An
absent field retains the legacy 30-second default. Old recipes and raw archives
are not rewritten. The budget applies only to the nonformal qualification RPC;
it does not change performance workloads, model/nonce/token-count oracles,
compression predicates, source-peer admission or durable ACK requirements.

The frozen value is passed to the actual standard-library HTTP call. urllib's
socket timeout limits blocking socket operations, not the absolute duration of a
response delivered in many chunks. This field therefore means **socket timeout
and observed HTTP elapsed gate**, not an end-to-end hard deadline. The owner must
also retain its independently frozen total process/cohort watchdog. No request is
retried after an ambiguous timeout.

For a budget-bearing phase, response receipt v2 records the source-owned dispatch
and completed-read monotonic clocks, raw request/response hashes, kernel client
identity, client source hash, frozen budget and exact semantics. Client execution
and portable archive verification independently require measured HTTP elapsed
<= the frozen budget. They do not trust the result-summary success flag. A server
that trickles bytes below each socket timeout but exceeds total budget is rejected
after the read; it cannot become a qualified join. Failure results retain actual
dispatch/completion clocks and budget; a timeout is not evidence of no execution.

CPU tests use real HTTP servers and short source-injected budgets: legacy socket
failure, success with a larger frozen phase budget, and a complete valid response
whose trickled total elapsed exceeds the budget. These are timing/transport tests,
not hardware, compression-quality or formal results. Existing actual three-peer
HTTP/Unix pipeline tests also replay the new receipt through the portable verifier.
A new source freeze, recipe, nonce and owner cohort are required for the next NPU
run. Host/KV wheels are unchanged because these modules are experiment clients.
