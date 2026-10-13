# Common worker relaunch: RPC readiness and response correctness

The separately frozen worker-crash/full-relaunch qualification remains supplementary
and nonformal. It does not complete the original manager-crash-after-prepare cell,
prove a crash-window authority chain, or establish lost/duplicate-request or objective
bounds.

The runner's legacy HTTP predicate proves only a completed direct backend RPC with
matching model, positive completion-token count, and a choice. It cannot establish
that the requested task was performed. In the private 2026-10-13 r1 run, all three
arms completed two real TP2 backend launches and a worker SIGKILL/full relaunch;
the returned message content did not match the requested marker. Record RPC
lifecycle success separately from `task_oracle_failed` / semantic correctness
unqualified. The r1 source and original response bytes must remain unchanged.

A new campaign can freeze a `probe.response_oracle` object:

```json
{"type":"exact-message-content","expected":"ECPA-WORKER-READY","strip_outer_whitespace":true,"finish_reason":"stop"}
```

A completed RPC must satisfy both the content oracle and stop reason. A mismatch
writes the original response bytes and an explicit failed oracle attempt, then
fails immediately. Transport readiness may still poll according to the frozen
policy. CPU HTTP fixtures use this same response path; their classification and
worker protocol remain CPU-only.

Environment closure is an input, not a reconstruction from a filtered summary.
The previous model qualification launcher inherited the session environment,
while its published input summary filtered environment keys. Reusing that summary
as an entire clean environment omitted the original HOME, locale, ATB, and other
runtime values. Triton's C++ async launch loader requires an explicit cache/home
root even where Python's user-directory resolution can fall back to passwd data.
The r1 missing-cache/async-launch warnings remain raw failure evidence; this does
not independently establish the full cause of the incorrect generated content.

Any rerun must use new paths and freeze an explicit safe environment allowlist,
the original HOME value, CANN/ATB/locale values, a private per-campaign Triton cache
path, directory ownership/device/inode, and the cold/warm cache policy shared by
all arms. Freeze the exact response oracle before GPU use. Preserve private CPU
campaigns that contain session infrastructure fields; public redacted copies must
state that their bytes changed and must not expose opaque session values.
