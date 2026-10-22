# vLLM Ascend PyramidKV HUST

Owner-maintained extraction of the PyramidKV provider work preserved in the
archived vLLM-HUST and vLLM-Ascend-HUST repositories.

**Status: installable migration baseline, not a runnable alpha.**

The package is discoverable as `org.vllm-hust.ascend-pyramidkv`, but its
Manifest 0.2 carrier is deliberately marked `import_only`. Extension Manager
inspection works and enablement fails closed until current vLLM-HUST Core and
Ascend hosts expose a reviewed, provider-neutral transactional KV-compression
contract. Importing the package never patches or activates vLLM.

The target remains an in-process Ascend KV-compression provider/method
extension. This baseline restores the legacy provider code, schema-v1 values,
configuration validation, fail-closed capability matrix, request state, and
CPU-testable selection semantics without claiming current-host compatibility.

## Inspect the migration package

```bash
python -m pip install \
  "vllm-hust-ext @ git+https://github.com/vLLM-HUST/extension-manager.git@9fb467447e95d753f7002b28575d6802f4347181"
python -m pip install .
vllm-hust-ext extension inspect org.vllm-hust.ascend-pyramidkv
```

The descriptor is intentionally not enableable. For offline provider tests,
install the test extra in an environment with a host-compatible PyTorch build:

```bash
python -m pip install -e ".[test]"
pytest -q
```

Do not install a generic PyTorch wheel over an existing torch-npu environment.
Use the matched PyTorch supplied by the Ascend host and install this package
with `--no-deps` when appropriate.

## Current boundary

- No `vllm.general_plugins` entry point is registered.
- No import-time monkey patching is performed.
- No current vLLM or vLLM Ascend version is advertised as runnable.
- Historical NPU, LongBench, and performance results are supporting evidence,
  not measurements of this repository's current head.
- The first active alpha requires current-host integration tests plus exact-head
  real-device correctness, rollback, quality, capacity, and performance
  evidence.

See:

- [provenance](PROVENANCE.md)
- [maintainers](MAINTAINERS.md)
- [support matrix](docs/support-matrix.md)
- [host contract](docs/host-contract.md)
- [install and rollback](docs/install-and-rollback.md)
- [legacy evidence inventory](evidence/legacy/README.md)
- [public historical Ascend 910B2 result](evidence/legacy/2026-08-13-ascend910b2/README.md)
