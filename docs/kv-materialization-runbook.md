# KV materialization ECPA runbook

This runbook covers the pinned native-contract lane only:

- Extension Manager tag `v0.3.0`;
- vLLM-HUST `fa6f7d29db99d5350e1b2b9c2742c9b621b22b25`;
- vLLM-Ascend-HUST PR #46 qualification source
  `95334cc38a3938406fe24caf748030cf4ece5917`; and
- arrival-control plugin `e343fc5ce6b4c64611a79df5d797b3db12cd6dac`.

Install Manager and plugin wheels into an isolated environment, then run:

```bash
vllm-hust-ext extension list
vllm-hust-ext extension inspect \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension check \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension enable \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension plan \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext extension render \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext run --dry-run -- vllm serve MODEL
vllm-hust-ext run -- vllm serve MODEL
vllm-hust-ext extension status \
  org.vllm-hust.kv-materialization-arrival-control
```

Before describing the plugin as runtime-effective, require an observer receipt
emitted by the running host after an actual KV lookup or commit outcome. Saved
enable intent, `VLLM_PLUGINS`, entry-point resolution, import success, and a
controller decision are insufficient. Performance qualification is a separate
benchmark-harness result and is never inferred by `check`, `status`, or `plan`.

Stop the `vllm-hust-ext run` process and verify its API/worker descendants,
ports, and assigned device processes have exited. Do not stop external
operator-owned KV services. Roll back the in-process plugin on the next host
start:

```bash
vllm-hust-ext extension disable \
  org.vllm-hust.kv-materialization-arrival-control
vllm-hust-ext run --dry-run -- vllm serve MODEL
vllm-hust-ext extension forget \
  org.vllm-hust.kv-materialization-arrival-control
python -m pip uninstall vllm-kv-materialization
```

The disabled dry-run must omit `kv_materialization` and the bundle ID. After
uninstall, `extension list` must not discover the bundle. Exact dependency
hashes, observer receipts, and resource-release boundaries are recorded in
[`evidence/native-current-npu-qualification-2026-10-11.md`](evidence/native-current-npu-qualification-2026-10-11.md).
The historical vLLM 0.23 Ascend record validates only the version-scoped
compatibility adapter.
