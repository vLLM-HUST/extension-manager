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

