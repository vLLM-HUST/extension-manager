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

The integration test exercises real external HTTP requests before close,
during candidate preparation, after open, after rollback, and after fail-safe
closure. It also injects journal loss and proves the route fails closed without
stopping either separately owned backend. The adapter accepts bounded
non-streaming GET/POST only. It is not a
production proxy: the same-UID process boundary follows the repository's
trusted experiment threat model, and the current open proof is synthetic.
Neither the HTTP response nor a controller ACK is evidence that vLLM workers
executed an extension. The adapter is not registered for the H1 formal-real
matrix; its test results must not enter the paper aggregate.

To complete issue #60, the traffic authority must be bound to host-owned
process and invocation evidence, a frozen target-set epoch, an independent
route observation outside this integration slice, lease/crash cases, and the
real three-arm runner. Until
those bindings are registered and reviewed, this slice demonstrates only the
external request path and cleanup behavior.
