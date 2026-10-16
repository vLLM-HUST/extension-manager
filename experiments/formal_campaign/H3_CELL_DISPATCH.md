# Original H3 cell execution dispatch

This source change adds no formal start. The original 25 cells, three arms,
three repetitions, objective thresholds and H4 workload remain unchanged.

`h3_cell_dispatch.py` is shared by registration, runner and analyzer. Only
`manager-crash-after-prepare` uses the existing durable-before-effect prepare
and predecessor-restore verifier. Its baseline arms still require their own
native protocol; ECPA prepare cannot be injected into them. Missing support is
now rejected before creating an output directory or launching any process.
`manager-crash-before-prepare` is not an alias of after-prepare.

`worker-crash` and `worker-replacement` select the separate worker carrier.
Unsupported plugin/API tuples select a distinct pre-serving-rejection policy,
but remain unavailable until that source-owned actuator and independent
never-served oracle exist. Every other original cell remains explicit
`unimplemented-actuator`; none falls through to a generic SIGKILL experiment.

## Worker adapter interface

An actual future implementation is registered through campaign
`cell_execution`, validated against `h3-worker-carrier.schema.json`. It supplies
one exact Python argv and a Manager-repository-relative source path/digest.
The runner rehashes that file and requires identical bytes in the admitted
Manager commit before it spawns anything. It also requires the explicit
`ecpa-h3-owned-worker-handshake/v1` interface in that source. The existing
`h3_worker_relaunch.py` qualification CLI does not implement this interface and
is not automatically promoted.

The carrier's nine original start entries retain the original client schedule:
60 single-attempt requests, concurrency 8, interval 0.2 seconds, timeout
10 seconds. Request bytes and functional oracle must equal the campaign probe.
Each spec also needs actual independent authority and backend registrations;
no future PID or process epoch is synthesized.

The admitted adapter is invoked with the existing campaign/arm/repetition/
order/output/receipt/authority arguments and
`--kernel-observer-handshake ecpa-h3-owned-worker-handshake/v1`. It owns the
actual Host launch and native recovery interface. A baseline must supply its
own independent native relaunch, or explicitly freeze
`bounded-operator-full-relaunch`, which counts one operator action. It must
not invent a Manager handoff or durable prepare barrier.

1. The adapter launches the real Host privately, starts the original client
   window and publishes an atomic `carrier-before.json` containing real
   parent/worker Host events, kernel identities and route generation. The parent
   role is the Host contract `api-server`, not `api`.
2. The independent runner reads actual `/proc` identities and captured ancestry
   sessions, walks actual worker PPIDs through any EngineCore intermediates to
   this phase's exact API parent and rechecks every PID/start identity and PPID,
   parses the source-owned Host role events, and writes
   `runner-before-ack.json`. The adapter must use this observation in raw data.
3. After its real client is ready, the adapter publishes
   `carrier-fault-ready.json` with exactly `{"target": observed_worker}`.
   The runner sends the frozen signal through a checked pidfd, writes
   `runner-fault.json`, independently observes that kernel's death and writes
   `runner-worker-dead.json`. The adapter does not supply those observations.
4. The adapter performs the declared native recovery or bounded action and
   publishes `carrier-after.json`. A new real worker identity, Host launch ID,
   process epoch and authority generation are required. The runner repeats the
   live API-parent-to-worker ancestry/Host checks and writes `kernel-observations.json` before
   `runner-after-ack.json`. The adapter retains the whole finite client window
   and emits its raw artifacts/record, then exits. Owned sessions are reclaimed
   by the runner; external processes are not cleanup targets.
5. The runner and analyzer independently validate the worker raw schema,
   registration/record/artifact hashes, kernel observations, Host epochs,
   actual authority journal and exact request/response joins through
   `h3_client_trace.verify_window`. Caller-supplied metrics are recomputed.

The worker raw format is `ecpa-h3-worker-raw-recovery/v1`, separate from legacy
prepare v2. It cannot accept native-prepare bytes as worker evidence. Complete
finite-window delivery counts still do not prove backend execution duplication.
`duplicated_requests` and `objective_met` remain null; this patch does not turn
unknown into a pass or mark the original hypothesis complete.

## Remaining real carriers

No published adapter currently implements the handshake. The current proxy's
registered semantic path still rejects unverified semantic obligations. Real
replacement membership enrollment, generation/lease/public admission, actual
three-arm recovery adapters, predecessor preservation and an execution oracle
remain explicit prerequisites. The static backend-registration profile cannot
guess a replacement process identity before it exists; an admitted dynamic
membership carrier is needed where the actual replacement is created later.

The H4 lifecycle-only protocol does not itself require selected-KV native
completion for every obligation. It may independently use a genuine matched
MOD pair with exactly its declared lifecycle obligations; effect or invocation
claims require their corresponding evidence. Profiler EventBus `effective`
receipts cannot be relabeled `invoked` or native-completion receipts.
