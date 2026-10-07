# Findings

- Manager baseline: `4be9d2c502f8a41797bb068993eb91add29f3401` (`origin/main`, clean).
- Pegaflow baseline: `14ca1d461580b4fc5069707fe615eee224c093eb` (`origin/main`, clean).
- Pegaflow PR #31 moved Bundle ownership to `pegaflow-llm-npu`, the distribution that also owns `vllm.general_plugins:pegaflow`.
- `vllm-hust-pegaflow-provider` now exposes only `vllm_hust_ext.providers:pegaflow`; it no longer makes a false activation claim.
- The Bundle declares an external-operator lifecycle and an exclusive primary KV-connector resource. ECPA must not start or stop Pegaflow services.
- The current Manager support matrix predates PR #31 and still records Pegaflow as the sole invalid distribution split.
- A CPython 3.11 Ascend runtime wheel built successfully with `maturin --release --no-default-features --features ascend`; the default CUDA build is not applicable in this Ascend container.
- In a clean environment, the runtime wheel and provider wheel produced exactly one valid, activation-ready Bundle and no duplicate or invalid registration.
- With explicit connector configuration and an intentionally absent local service, `check`/`status` reported `compatible,configured,degraded`; `run` and dry-run both refused before launching a child.
- Enabled environment rendering preserved and de-duplicated the caller's `ascend,user_plugin` selection and appended `pegaflow` deterministically.
- Disable, forget, runtime-wheel uninstall, and provider-wheel uninstall removed intent, configuration, Bundle discovery, and provider discovery. Ports 50055 and 19091 remained closed and no Pegaflow process existed.
- This is packaging, compatibility, and fail-closed lifecycle evidence only. It is not runtime-effective, NPU connector, correctness, recovery, device-release, or performance evidence.
- Manager CI exposed excessive controlled-fixture process churn: tests that needed one valid record repeatedly generated a full nine-start Latin square, amplifying transient pipe startup failures. Single-record tests now request one record; the two matrix/manifest paths retain all nine. A failed controlled start is retried at most twice in separate artifact roots and still fails after three consecutive incomplete starts. The production runner remains fail closed.
- A Python 3.12 full run also exposed two independent hermeticity defects: `urllib` can wrap the SIGALRM `TimeoutError` inside `URLError`, and a Mooncake provider test inherited an unrelated installed runtime distribution. Deadline classification now unwraps the timeout, and the unit test explicitly fixes its distribution inventory.

