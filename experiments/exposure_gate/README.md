# Loopback traffic authority integration slice

`loopback_traffic.py` is a bounded research adapter for the reference
ExposureGate. It runs in a process separate from the gate, owns one loopback
HTTP port, and forwards each admitted request to a predecessor or candidate
loopback backend according to its current route. The gate can inspect that
route only through a private Unix control socket. A route-query failure
prevents request admission; failed rollback queries are classified as safety
unknown. SIGINT/SIGTERM stops the owned proxy and removes its socket. Backend
services remain owned by their original operator or test harness.

The traffic process also requires a new `--journal` file in a private
directory. It fsyncs canonical, sequence- and hash-chain-bound records for
its PID/start-time identity, route transitions, and each admitted or rejected
HTTP request. An open/restore record is durable before the route becomes
visible to request handlers; admission is durable before forwarding. If the
journal cannot be written, the proxy closes its route and returns 503 rather
than forwarding without a traffic-side record. `read_traffic_journal` checks
the integration trace's canonical bytes and chain; it is not a formal source
receipt or protection against a malicious same-UID experiment process.

Optional `--observer-config` mode (contract:
[`host-authorization.schema.json`](host-authorization.schema.json)) freezes
one canonical execution-plan path,
host-journal directory identity, launch/controller identity, entry-point
bindings, candidate generation, membership epoch, a digest of the canonical
fixed target set, and every required process epoch at proxy startup. The traffic
process independently reads the host journal and live Linux identities before
opening a candidate route. It rechecks them on candidate route queries and
before every external request; loss of coverage or lease closes the route and
rejects the request. Opening records the observation digest, and every
candidate admission records the independently refreshed digest. A caller's
plan ID, environment variables, import success, or fabricated `OpenProof`
digest alone cannot make this mode admit a request.

`observe_gate_transitions` is an offline reader for the authority-owned hash
chain. It emits gate-open only when a durable applied record immediately
follows an intent bound to plan, launch, controller, generation, membership
epoch and target-set digest; it also emits close/restore facts. Its schema is
explicitly classified `real-loopback-integration-preflight`, with both formal
and performance result flags false. These are independent traffic-boundary
facts, not SUT effect claims.

The new CPU integration test exercises a real separate proxy and external
HTTP clients against a live *fixture* process: missing evidence, an old epoch,
and a cross-launch, generation, membership-epoch or target-set snapshot keep
the predecessor route; a matching fixture event permits the candidate.
Replacing that process and publishing evidence for a new process epoch
invalidates the frozen old coverage and closes the route while both externally
owned backends remain alive. Observer exceptions and query-time observation
loss also close or preserve the predecessor without opening the candidate.
The fixture's event is test-
generated, **not** a vLLM-HUST worker event or a formal runtime-effective
receipt. The same-UID experiment threat model still trusts the host journal
writer; a malicious same-UID actor could forge its bytes. A real host-owned
issuer and reviewed process membership are necessary for #60.

The original integration test exercises real external HTTP requests before close,
during candidate preparation, after open, after rollback, and after fail-safe
closure. It also injects journal loss and proves the route fails closed without
stopping either separately owned backend. The adapter accepts bounded
non-streaming GET/POST only. It is not a
production proxy: the same-UID process boundary follows the repository's
trusted experiment threat model, and the reference gate's open proof remains
synthetic.
Neither the HTTP response nor a controller ACK is evidence that vLLM workers
executed an extension. The adapter is not registered for the H1 formal-real
matrix; its test results must not enter the paper aggregate.

To complete issue #60, the optional observer mode must be exercised against
real vLLM-HUST parent/engine/worker events and a reviewed target-set epoch,
with an independent route observation outside this integration slice,
lease/crash cases, and the real three-arm runner. Until those bindings are
registered and reviewed, this slice demonstrates the external request path,
host-journal validation mechanics, and cleanup behavior only.
