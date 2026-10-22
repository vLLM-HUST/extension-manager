# Activation Sparsity for vLLM-HUST

Owner-led research carrier for TEAL and LaRoSA activation sparsity. The source PR was not merged; no sparse-kernel, quality, model, or hardware support is claimed.

**Status: fail-closed TEAL/La RoSA configuration and compatibility validation are installable and tested; model/kernel attachment remains blocked until `HOST_CONTRACT.md` is implemented.**

Technical ownership belongs to @llxler. Source extraction must preserve exact authorship, license, tests, constraints, and evidence before activation is considered.

See [MAINTAINERS.md](MAINTAINERS.md) and [PROVENANCE.md](PROVENANCE.md).

## Extension framework

Extension ID: `org.vllm-hust.activation-sparsity`

This repository follows the vLLM-HUST Extension Template. The current package
is deliberately `import_only`: it can be built, installed, discovered, and
inspected, but Extension Manager must refuse enablement until the maintainers
land a real host contract, implementation, compatibility evidence, and tests.

```bash
python -m pip install "vllm-hust-ext @ git+https://github.com/vLLM-HUST/extension-manager.git@main"
python -m pip install -e ".[test]"
vllm-hust-ext extension inspect org.vllm-hust.activation-sparsity
vllm-hust-ext extension check org.vllm-hust.activation-sparsity
pytest -q
```

The static Manifest 0.2 descriptor lives inside the Python distribution under
`src/`. Installation alone changes no vLLM behavior.
