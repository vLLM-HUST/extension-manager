# Quantized KV + KVCompress: bounded CPU provider observation

This independent source pair adds a CPU check of two real MOD manifests. It adds **no H2 scored case**: the combined cache-format/block-replacement runtime oracle remains unknown, and the current definite subset remains n4. No MOD activation, model request, NPU experiment, installation-order execution, performance measurement, or paper change occurred.

QuantizedKV source `2f0b37b63dc1aba25f035a0dbf620f4abb73b2b3` and KVCompress source `00cc78dc7f3491eecbc79c5068e29aed9f59afc3` were clean and their manifest/implementation snapshots matched Git blobs. Before provider execution, freeze `1605caf2dd2ebcd8ace5bba00a85c47588ebe6412799dc7afad6ba67af304e85` recorded an independent **unknown** oracle: actual quantized-backend dispatch is cache-dtype-gated; actual KVCompress materializes/replaces cache blocks. Their combined indexing/layout and ordering behavior has no independent runtime observation. This source review does not label their coexistence as a conflict or as safe.

The executable used the existing read-only qualified interpreter with actual installed Host `379a0ad35` / Ascend `873584026` / Manager `0.3.0`. It constructed Manager source-bundle carriers from the two frozen real manifests and called the real `VllmProvider.check`, `status_for` (the API called by CLI `check`), `plan_for`, and `reject_conflicting_plans`. The source MOD carriers were not newly installed distributions. It supplied empty configuration, no compatibility hints, synthetic capability registry, conflict report, or boundary seed. Both declared member orders were checked; runtime plugin installation order was not executed.

Attempt 1 retained actual unknown/degraded results after Host capability import failed and terminated with SIGSEGV (-11). Its output JSON is **not a successful qualification**. Attempt 2 separately froze an allowlisted environment adding actual CANN paths and normal process termination (exit 0). Actual Host discovery returned seven registered protocols; both member provider checks returned compatible/configured, and both plan orders returned no declared plan conflict. This is a plan-surface observation only. The environment change is not an isolated causal experiment identifying the SIGSEGV mechanism. A missing compiler PATH warning remains in raw stderr; no Triton compiler or device kernel was executed by this check.

`PYTHONDONTWRITEBYTECODE=1` and separate cache/TMP paths preserved the old environment. All originally frozen Manager source files and the Host capability file are archived. Two additional actually imported Host plugin files (`vllm.plugins` and `vllm.plugins.evidence`) were identified only during postrun import auditing and retained with an explicit **postrun** provenance record. Prelaunch imported-source closure is therefore partial; these snapshots are not backdated to preregistration.

The portable archive retains both attempts, runner bytes, exact allowlisted environments, execution freezes/terminal exit codes, stdout/stderr, actual distribution versions/capability receipts/import-source hashes, two-order plans, frozen oracle/source bytes, and the postrun limitation. It omits executable caches and unrelated session environment. File hashes provide byte integrity and source binding, not signatures against a malicious archive publisher.

Reproduce from the repository root:

```sh
python experiments/real_mod_composition/verify_h2_quantized_kvcompress_cpu.py \
  --manifest experiments/real_mod_composition/artifacts/h2-quantized-kvcompress-cpu-20261013/manifest.json \
  --archive experiments/real_mod_composition/artifacts/h2-quantized-kvcompress-cpu-20261013/raw.tar.gz
```

The replay reads archived observations; it does not rerun the original environment or upgrade a source declaration to runtime effectiveness. Unknown oracle, not-scoreable status, retained failed attempt, partial preregistration, and existing n4 are checked explicitly.
