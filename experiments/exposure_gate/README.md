# Loopback traffic authority integration slice

Sealed invocation/preflight originals now live in benchmark; follow
[the external-input setup](../../docs/benchmark-originals.md) before running
readers or tests. Synthetic reference fixtures remain local.

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

Each authorization is also bound to its absolute input path. The authority
atomically creates and fsyncs a private claim containing the authorization
digest, file identity, and its own PID/start ticks before opening any socket.
An existing claim rejects a second authority, while copying the authorization
to another path fails the path binding. This makes missing, stale, replayed,
cross-launch, and partial-coverage inputs fail closed within the declared
same-UID experiment trust boundary.

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

`formal_proxy.py` and the formal runner now provide the fail-closed execution
path for that run. The runner rewrites the registered SUT endpoint from public
port 8187 to its separately registered backend port, freezes the post-launch
process transition, and only then writes a new
`ecpa-loopback-formal-host-authorization/v1` input only when retained host
bytes contain canonical, host-assigned `api-server`, `engine-core-scheduler`,
and `worker` identities. It checks an automated-independent registration of
the exact proxy source, argv, public/backend/predecessor ports, lease, and
review receipt. The independently launched proxy re-reads journal bytes and
live Linux identities before opening and before each phase; loss of the proxy,
observer, route, or membership fails the start. Its authorization, journal,
offline observation, stdout/stderr, process identity, and cleanup outcome are
bound into the runner command and receipt. Readiness and workload sources keep
their registered port 8187 URLs, so successful requests necessarily cross the
proxy rather than reaching the backend directly.

This is an enabling path, not a new formal result. A candidate must add a
`formal_proxy_registrations` map to each arm's runner arguments after
regenerating the backend-port SUT command fingerprints. The map has one entry
per deterministic start ID because private authorization, socket, and journal
paths differ across starts. `formal_proxy_command_material` produces each
exact argv digest for independent review. A requested map with a missing start
entry fails before launch. Fixture and same-UID tests cover only fail-closed
mechanics and remain ineligible.

An audit of the retained H1 r5 process transitions finds real host-assigned
engine and worker identities, but no host-assigned `api-server` identity. All
nine therefore fail this new gate with `formal proxy membership lacks
host-owned roles: api-server`; none may be relabeled as an exposure result.
The latest Host preflight binds all three process layers, but that Host commit
and the exact backend-port/proxy commands still need upstream qualification and
deployment registration before any run can enter the formal aggregate.

The source-bound
[`proxy-parent-membership-preflight-20261013.json`](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/140a046d34ecf50bb8de3d8b19a7d70a6b0490e0/archive/mod-targeted-20261023/manager-experiments/snapshot/experiments/exposure_gate/artifacts/proxy-parent-membership-preflight-20261013.json)
records the first real TP2 functional preflight in which the Host emitted all
three host-assigned process layers. It is explicitly unregistered and does not
count as a formal traffic-boundary or performance result.

The content-addressed
[`host-parent-registration-candidate-20261013.json`](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/140a046d34ecf50bb8de3d8b19a7d70a6b0490e0/archive/mod-targeted-20261023/manager-experiments/snapshot/experiments/exposure_gate/artifacts/host-parent-registration-candidate-20261013.json)
binds that preflight to Host candidate `379a0ad35`, its two changed source
blobs, wheel `a850a238...d551`, and the Manager review context at `32cebf7`.
The Host commit is present only in the local checkout: `git ls-remote` found no
matching remote ref and remote `main` remained at `973d9ef5`. The automated
review therefore records `BLOCKED`; the candidate cannot become a formal
producer registration until the exact Host commit is repository-reachable and
merged. Uploading a different commit or retaining only the wheel does not clear
the source-provenance gate.

The formal authorization path now **fails closed for semantic admission**. The
current `observe_bound_invocations` implementation accepts only Plan events
`invoked`; a complete worker set proves entry-point invocation coverage, not a
plugin's required runtime effect. Formal registration, live process identities,
and a caller-supplied semantic-success flag cannot upgrade this observer.
The ordinary nonformal v1 path remains available for bounded invocation/route
qualification, including sealed historical evidence. This does not change H1's
historical 9/9 starts or its falsified prevention result.

Run the concrete retained-evidence gap audit without a device:

```sh
PYTHONPATH=src:. python -m experiments.exposure_gate.semantic_obligation_gap
```

It verifies the original real-model archive and returns explicit
`source-bound-worker-invocation-only`, semantic status `unverified`, runtime
effectiveness `null`, and formal traffic admission `false`. It lists missing
edges: a registered live source-owned semantic producer; an operation/effect
predicate; authority probe to Host runtime request identity; operation to worker
PID/start-ticks/boot/membership epoch; operation to Plan/launch/controller/
generation; and per-worker semantic outcome to the observed response.
The separate real H2 compression archive already binds scheduler commit,
TP0/TP1 acknowledgement, runtime request, response and profiler completion.
Those offline stdout/profiler bytes belong to a threshold-specific workload;
they are not a registered live producer consumed by this gate and cannot open
it. Implementing and independently qualifying that producer remains necessary.
The added fixture negative test reproduces the former formal authorization
acceptance before the fix, then rejects it after the fix; fixtures do not become
formal evidence. Formal H3/H4 counts and NO-GO are unchanged.
