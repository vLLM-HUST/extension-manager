# LMCache-Ascend 0.4.3 pinned evidence — server 91

This record audits an existing real-model run from 2026-08-26 on server 91.
The artifacts were rechecked on 2026-09-01 without restarting the stopped test
containers or consuming NPU capacity.

## Scope and provenance

- host architecture: `aarch64`;
- accelerator: eight Ascend 910B2 (A2) devices;
- serving image:
  `sha256:f4c89c293e076453e9eef9edb5fb9669740dccbd3c48619a9f976d775fc29b81`
  (`quay.io/ascend/vllm-ascend:v0.23.0rc1-openeuler`);
- CANN path recorded by the containers: `cann-9.0.1`;
- model: `Qwen/Qwen3-0.6B`, snapshot
  `c1899de289a04d12100db370d81485cdf75e47ca`;
- benchmark worktree commit: `eacba9b3147435f5db43b863b545e5b60b143765`;
- vLLM source commit: `72a7f33695081a410c0e04bab665a3da5c5e15a7`;
- vLLM-Ascend source commit:
  `a66dc5310149dda2240ea0f58944a3a5c3c0e4a9`;
- LMCache: tag `v0.4.3`, commit
  `7f326118a2f1afc7801988dd02e3055bdf21ef6b`;
- LMCache-Ascend: commit
  `c86fa99a9986669e8cf310ba80972a98715b8cc2`, described as
  `v0.4.3-4-gc86fa99`.

The LMCache-Ascend source is **not** an unmodified upstream `v0.4.3` checkout.
The four additional commits pin CANN 9-compatible KV-cache operations and add
a vLLM 0.21 preemption-metadata compatibility guard. This is pinned fork
evidence, not a general upstream release claim.

## Observed connector data path

The producer and consumer were separate vLLM-Ascend processes using the
LMCache-Ascend in-process adapter and a shared filesystem backend. The two
requests completed successfully:

| Observation | Request 1 | Request 2 | Total |
| --- | ---: | ---: | ---: |
| producer stored tokens | 1228 | 1008 | 2236 |
| consumer LMCache-hit tokens | 1228 | 1008 | 2236 |
| consumer retrieved tokens | 1228 | 1008 | 2236 |
| failed requests | 0 | 0 | 0 |

The consumer logs report `Inference Engine computed tokens: 0` for both
prompts, followed by complete retrieval from LMCache. The request CSV records
two successful 96-output-token completions. Cache artifacts were materialized
under the shared filesystem backend, so this is a real connector store/hit/load
path rather than package-import or HTTP-liveness evidence.

## Known degradation and failed attempts

The passing logs also contain three warnings that prevent a broad support
claim:

1. vLLM reports `KVConnectorBase_V1` as experimental.
2. LMCache falls back to the builtin hash and warns that this can be
   inconsistent in distributed caching. The pinned producer/consumer did
   match, but the warning still requires a deterministic cross-process gate.
3. LMCache reports a duplicate Prometheus logger with different metadata.

Runs r1, r2, and r4 failed before the successful r5 run because of provenance
binding, missing management-script, and startup failures respectively. They are
useful packaging/operation failure evidence, but they do not yet constitute a
controlled storage-backend outage and recovery test.

## Manager projection

This exact result may be represented as:

```json
{
  "mode": "vllm_ascend_in_process",
  "model": "Qwen/Qwen3-0.6B",
  "backend": "fs",
  "stored_tokens": 2236,
  "hit_tokens": 2236,
  "retrieved_tokens": 2236,
  "failed_requests": 0
}
```

It must not be reused for `LMCacheMPConnector`: upstream Ascend MP support is a
separate, unfinished capability. It also does not satisfy the controlled
backend-unreachable, recompute/fail policy, and recovery acceptance gate. Alpha
therefore remains **NO-GO**.
