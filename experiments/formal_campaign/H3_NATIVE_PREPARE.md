# H3 native durable prepare adapter

`h3_native_prepare.py` implements only the ECPA coordinator's SQLite
`close.before_effect` barrier. It uses a separately owned live traffic authority;
no HTTP health result establishes prepare. The coordinator commits the native
close intent, reads it back, confirms the predecessor route, records its live
PID/start ticks/boot/session and launch ID, and pauses before the external effect.

A frozen ECPA arm may declare `phase_barrier` with `support: supported`, protocol
`ecpa-native-close-prepare-barrier/v1`, exact `barrier_path`, exact `journal_path`,
`timeout_s`, and a concrete `reason`. Set the native spec `launch_id` to the exact
start ID (`<cell>-r<repetition>-ecpa`). Freeze each start's own paths and launch
command. The runner validates the current native journal and authority route
before sending the frozen signal. Raw recovery embeds the native rows and state,
barrier, session identity and verification timestamp; the analyzer recomputes
intent hashes, identity and phase ordering. `prepare-proof.json` retains the
same observed proof for inspection.

The vanilla and manual arms have no implemented equivalent native transaction
adapter. Declare them `unsupported` or `not-applicable` with a reason, retaining
all three arms. The runner emits failed records with empty metrics and no fault
when prepare is unsupported. The issuer rejects missing support declarations and
forbids declaring the ECPA adapter on either baseline. Those records remain in
intake, are listed as failed, and cannot complete a cell. Baseline recovery must
be implemented from each baseline's own source and semantics.

The CPU integration test starts a real independent authority and coordinator,
reads the actual SQLite intent, kills the coordinator, restarts it and checks the
actual authority route restored with a new process identity. Negative checks
cover replayed launch, stale timestamp, health-only evidence, intent/hash
mutation and wrong predecessor route. Another live test kills a launcher first
and verifies cleanup still reclaims its child session. These are nonformal CPU
qualifications; they provide no model, Host invocation, two-card, throughput,
quality or three-arm H3 result. The remote Host merged-source admission gate
remains required. H3 formal starts remain zero.

This adapter does not yet bind a model launcher to coordinator recovery or
independently recompute the full post-recovery authority hash chain. A pure
`state_command` report is insufficient to establish those remaining claims.

Post-recovery intake now independently recomputes the traffic authority's full
hash chain. The authority start binds the exact launch and proxy registration;
every row binds its PID, start ticks, boot ID and monotonic timestamp. Restoration
requires one adjacent restore intent/effect pair after the new coordinator
starts, the same prepared predecessor generation/fence/snapshot, and no later
route change before completion. The retained SQLite journal must extend the
prepared prefix with an ordered, operation-bound native rollback receipt while
leaving the before-effect close uncompleted. A state command or recovery summary
cannot establish route restoration. The protocol issuer binds the new verifier
bytes and the native adapter state probe no longer emits authoritative labels.

The current client sends requests only after restart. Therefore lost requests,
duplicate requests and whole-crash objective are unknown (`null`), with explicit
`crash_window_coverage: missing`. These starts remain incomplete in aggregation;
unknown does not count as a recovery success or falsification. The observed
post-recovery loss count is derived from HTTP status and has that limited scope.
A frozen independent client trace spanning the fault remains required. This
change and its real CPU SIGKILL/SQLite/authority test provide no formal H3 starts,
model performance, matched baseline recovery or Host admission.
