# vLLM Ascend Adaptive Quantized KV

English | [Simplified Chinese](README.zh.md)

Independent vLLM-HUST extension for the Adaptive Quantized KV research
project on Ascend.

Repository:
[`vLLM-HUST/vllm-ascend-adaptive-quantized-kv-hust`](https://github.com/vLLM-HUST/vllm-ascend-adaptive-quantized-kv-hust)

## Current scope

This repository is at package stage P1. It provides:

- a static experimental 0.2 manifest discoverable by `vllm-hust-ext` without importing
  implementation modules;
- fail-closed host-contract compatibility receipts;
- typed validation of the retained ACL graph reset and recapture receipts;
- the proposed generic host-contract boundary for continuing-prefill
  observation and ACL graph lifecycle control;
- an explicitly imported CPU-only paged INT8 attention reference, adapted from
  archived advisor PR #19 in the research repository.

It does not yet activate runtime behavior, patch vLLM or vLLM Ascend, launch a
model service, or make a performance claim. The current host baselines do not
yet expose the reviewed contracts required by this extension. Installing the
package is therefore inert.

## Delivery policy

This organization plugin is the project implementation carrier. The project
does not submit optimization commits or PRs directly to `vllm-hust` or
`vllm-ascend-hust`. Missing generic host interfaces are reviewed in this
repository and must be delivered by the host owner or another explicitly
approved route. Reproducible workload contracts remain in the research carrier
with its fixed `intellistream/llm-serving-workloads` gitlink.

## Identity

| Layer | Identifier |
| --- | --- |
| Distribution | `vllm-ascend-adaptive-quantized-kv-hust` |
| Python package | `vllm_ascend_adaptive_quantized_kv` |
| Extension ID | `org.vllm-hust.ascend-adaptive-quantized-kv` |
| Component | `continuing-prefill-profiler` |
| Proposed contract | `vllm.ascend.continuing-prefill.observer.v1` |

## Validation

```bash
uv venv --python 3.12
uv pip install -e ".[test]"
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build
.venv/bin/python scripts/validate_distribution.py --dist dist
```

Install the resulting wheel together with `vllm-hust-ext` in a clean environment,
then run:

```bash
vllm-hust-ext extension list
vllm-hust-ext extension inspect org.vllm-hust.ascend-adaptive-quantized-kv
vllm-hust-ext extension validate org.vllm-hust.ascend-adaptive-quantized-kv
vllm-hust-ext extension check org.vllm-hust.ascend-adaptive-quantized-kv
```

Validation proves package discovery and metadata only. It is not a runtime or
NPU result.

The repository CI runs the tests on Python 3.10, 3.12, and 3.14. Python 3.12
also builds the wheel and sdist, validates the inert extension boundary, and
retains the validated distributions for 14 days. CI does not publish to PyPI.

## Offline component reference

The optional reference validates causal suffix attention with explicit 5D NZ
INT8 pages, per-channel scales, grouped query heads and variable sequence
lengths. It dequantizes one KV page at a time and tiles queries; these are
source-level temporary-shape bounds, not measured HBM savings. Online softmax
avoids a full-cache floating K/V copy but may reread pages for each query tile.
It is ordinary Torch CPU code, not a fused Ascend operator or a runtime adapter.

Use Python 3.12 for the tested component environment (the default inert package
also supports the other Python versions in CI):

```bash
uv pip install -e ".[test,component]"
.venv/bin/python -m pytest -q tests/test_reference.py
```

The explicit module is `vllm_ascend_adaptive_quantized_kv.reference`, exposing
`paged_int8_attention_reference`. Its docstring specifies the input contract;
`tests/test_reference.py` supplies executable input and dense-oracle examples.
CPU FP64/FP32/FP16/BF16 agreement does not establish bitwise FIA equivalence,
NPU correctness, graph safety, quality or end-to-end performance. Default
discovery imports neither Torch nor the reference; the manifest remains inert.
A separate Python 3.12 CI job requires CPU Torch and runs the component tests.

For offline host-shaped fixtures only,
`vllm_ascend_adaptive_quantized_kv.snapshot_reference` converts declared packed
NZ storage, cumulative query ends, and decode/prefill metadata into reference
inputs. It rejects ambiguous storage and unsupported semantics. It is not an
NPU exporter or runtime adapter; see
[`docs/HOST_EXECUTION_AUDIT_20260905.md`](docs/HOST_EXECUTION_AUDIT_20260905.md).
That document links the retained read-only source-audit receipt and its exact
host revisions; `scripts/audit_host_execution.py` reproduces it without
importing host modules or starting a device runtime.

Source attribution, reproduced old-code defects, and remaining integration
decisions are tracked in [the takeover control](docs/PR19_TAKEOVER_CONTROL_20260904.md).

## Research evidence

Experiment contracts, raw evidence, runners, and claims remain in
[`intellistream/ascend-adaptive-quantized-kv`](https://github.com/intellistream/ascend-adaptive-quantized-kv).
They are not copied into the runtime package.

The exact legacy Ascend source drafts retained for host-contract design are
listed in
[`docs/LEGACY_CONTRACT_EVIDENCE.md`](docs/LEGACY_CONTRACT_EVIDENCE.md). Those
references are boundary evidence only and do not activate the extension or
support a performance claim.

The historical 910B2 paged-INT8 continuing-prefill capability probes and the
later V2 compatibility audit are mapped, with exact commits and hashes, in
[`docs/PAGED_INT8_OPERATOR_EVIDENCE.md`](docs/PAGED_INT8_OPERATOR_EVIDENCE.md).
The underlying experiments remain in the research carrier. Their narrow
diagnostic failures prevent repeating known unsupported calls but do not prove
universal CANN or hardware incapability. The linked record is reproduced by
`scripts/audit_parent_operator_evidence.py`, which reads only the frozen parent
commits and fails closed on hash or semantic drift.

## Security and release

- Installation never enables the extension.
- While the manifest remains `import_only`, `vllm-hust-ext extension enable`
  refuses it. Runtime activation requires both an accepted host contract and a
  later manifest revision that declares an active implementation.
- PyPI publication should use Trusted Publishing.
- Passwords, 2FA codes, recovery codes, and long-lived API tokens must not be
  stored in this repository or CI configuration.
