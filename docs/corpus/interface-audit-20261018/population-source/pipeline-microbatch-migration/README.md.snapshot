# Pipeline Microbatch Scheduling for vLLM-HUST

Owner-led research carrier for calibrated pipeline-parallel microbatch scheduling. The work crosses scheduler, executor, communication, KV, worker, and benchmark boundaries and requires neutral host contracts.

**Status: migrated to the vLLM-HUST batch-admission policy API without monkey
patching. Qwen3.8-27B is functionally and recoverably qualified on Ascend
PP2+TP2 graph mode. It remains available, but the measured balanced profile is
not recommended for this tested cell because it regressed matched performance.**

Technical ownership belongs to @xsun2001. Source extraction must preserve exact authorship, license, tests, constraints, and evidence before activation is considered.

See [MAINTAINERS.md](MAINTAINERS.md) and [PROVENANCE.md](PROVENANCE.md).

## Extension framework

Extension ID: `org.vllm-hust.pipeline-microbatch`

This repository follows the vLLM-HUST Extension Template. Installation alone
does not activate scheduling. Extension Manager requires host-API, functional,
and recovery qualification before enablement. Performance evidence controls the
scenario recommendation, not functional availability.

```bash
python -m pip install "vllm-hust-ext @ git+https://github.com/vLLM-HUST/extension-manager.git@main"
python -m pip install -e ".[test]"
vllm-hust-ext extension inspect org.vllm-hust.pipeline-microbatch
vllm-hust-ext extension check org.vllm-hust.pipeline-microbatch
pytest -q
```

The active policy is
`vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy`. vLLM expects
that dotted qualname on `--batch-admission-policy`; the manifest continues to
use `module:object` syntax and Extension Manager performs the conversion.

## Compatibility boundary

- Qwen3.8-27B / TP4 / graph: **Not Applicable** because PP=1 has no pipeline
  bubbles or concurrent pipeline microbatches to optimize.
- Qwen3.8-27B / PP2+TP2 / graph: functional, cancellation, concurrency and
  runtime-effectiveness checks pass, so the cell is compatible and available.
  The tested balanced profile is **not recommended for this cell**: the
  balanced policy loses 9.05% completion throughput at C4, 4.37% at C8, and
  26.33% on the fixed-work mixed-length C8 matrix; mixed P95 is 80.16% higher.
- Qwen3-32B and Qwen3-235B-A22B / PP4+TP2: historical legacy evidence only.
  They remain unverified on the current Core/Ascend baseline.

See `docs/evidence/sage-mate-20260905-qwen38-pp2tp2-graph.md`. Do not reuse
historical rank coefficients across model, PP partition, device generation, or
runtime commit.
