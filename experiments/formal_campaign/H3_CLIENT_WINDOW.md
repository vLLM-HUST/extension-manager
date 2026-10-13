# Finite crash-window client trace

`h3_client_trace.py` is an executable continuous client and an independent raw
trace verifier. It is qualification tooling; it does not admit formal H3 runs,
complete the original three-arm matrix, or supply backend exactly-once evidence.
The existing formal runner continues to report missing crash-window coverage
until a preregistered deployment explicitly integrates this client and its own
native recovery/Host/traffic proof.

Freeze a `ecpa-h3-client-window-spec/v1` object before starting the client:

- `start_id`, explicit loopback `request_url`, `payload`, frozen
  `response_expectation: {text_equals: ...}`;
- `request_count`, `interval_s`, `timeout_s`, `dispatch_slack_s`, `concurrency`;
- `retry_policy: single-attempt-no-retry`;
- `authority_registration_sha256`, actual `authority_process_identity`
  (`pid`, `start_ticks`, `boot_id`);
- `backend_registration`, keyed by decimal backend port, each with
  `process_identity`, `generation`, `model`, and a distinct backend `launch_id`.

The backend registration file is also passed to the independent authority with
`--backend-registration`. The authority freezes its digest at startup, forwards
unique request and admission IDs, records admitted request hashes and the full
upstream response bytes/status/endpoint, and independently checks that the
registered live PID/start ticks/boot owns that endpoint's listening socket.
A response is bound to the registered process, route generation, model and
backend response ID. This is process/endpoint provenance, not complete Host
worker invocation or effectiveness evidence. A replacement backend requires a
new independently registered epoch; the tool must not reuse the old identity.

Start before the actual fault and allow the frozen schedule to run after the
actual recovery observation. Record fault/recovery monotonic markers with their
separate native fault/recovery evidence. The verifier requires requests before,
during, and after that finite window, every expected request start/finish, and
an end marker. It checks actual dispatch skew against the frozen bound. Marker
values alone do not prove that an actual fault or recovery occurred.

```sh
python experiments/formal_campaign/h3_client_trace.py \
  --spec /absolute/frozen-client-spec.json \
  --trace /absolute/client.jsonl --ready /absolute/client-ready.json
python experiments/formal_campaign/h3_client_trace.py --verify \
  --spec /absolute/frozen-client-spec.json --trace /absolute/client.jsonl \
  --authority-trace /absolute/authority.jsonl \
  --client-identity /absolute/independently-recorded-client-identity.json \
  --fault-ns FAULT_MONOTONIC_NS --recovery-ns RECOVERY_MONOTONIC_NS
```

One logical request has exactly one attempted POST; the client never retries.
`lost_requests` means no successful delivery by that attempt's frozen deadline,
within this bounded request set. A timeout is delivery loss even if the backend
later completes; it does not prove nonexecution. A delayed successful response
arriving after the deadline also counts as delivery loss. This excludes arrivals
outside the frozen finite schedule and is not an unbounded production loss rate.

`duplicate_admissions` and `reused_successful_response_ids` are separate raw
observations. Neither proves duplicate backend execution or side effects.
`duplicated_requests` and `backend_execution_duplicates` remain unknown/null
without an independent execution oracle. Truncated traces, absent final markers,
missing request attempts, uncovered fault/recovery boundaries, or excess dispatch
skew leave coverage incomplete and counts unknown. Corrupt hashes, cross-launch
or process-epoch evidence, and successful responses without matching independent
authority bytes are rejected. Headers are only join keys, never the evidence.

The CPU regression starts real independent authority/backend/client processes,
sends 60 continuous requests, SIGSTOPs/SIGCONTs the backend within the window,
and verifies real deadline loss alongside successful traffic before and after.
It retains ambiguous execution as unknown and tests truncated/forged joins.
The CPU backend is a fixture, not a model. Formal H3 remains zero.
