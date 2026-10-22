# KV Materialization Arrival Control

Maintainer: [Wei He (`healer-positive`)](https://github.com/healer-positive).
This repository is a vLLM-HUST MOD exposed through the
`vllm.general_plugins` entry-point interface.

This repository studies the request-arrival decision among full reuse,
block-aligned partial reuse, and recomputation. It is distinct from
`intellistream/kv-materialization-scheduling`, which studies cross-request
resource coordination and scheduling.

This repository studies one narrow control point in vLLM serving: arrival-time
KV materialization decisions.

For an incoming request with reusable prefix or KV state already available, the
controller chooses exactly one action:

- `full_reuse`
- `partial_reuse`
- `recompute`

Everything in this repository should stay subordinate to that question. This is
not a general admission-control repository, not an online memory-evolution
repository, and not a generic state-management repository.

## Reference Paper

- Short label: `LEAP / SIGMOD 2024`
- Full paper: `Predictive and Near-Optimal Sampling for View Materialization in Video Databases`

Chinese guidance for student follow-up:

- 学这篇的地方：把 materialization 写成一个有成本约束的 selective decision problem，强调“现在值不值得物化”而不是泛化成所有状态管理都归这个仓库。
- 不要直接照搬的地方：LEAP 面向视频数据库 view materialization；当前仓库面向 arrival-time KV materialization，动作集合是 `full_reuse / partial_reuse / recompute`。
- 写作时更适合继承的是：选择性物化的决策逻辑、收益与代价的平衡表达、以及“部分物化当前为什么还只停在 boundary”这种边界诚实写法。

## Scope

This artifact studies:

- whether reusable state should be fully materialized, partially materialized,
  or ignored at request arrival
- how that three-action decision surface behaves across shared workload
  families with different overlap geometry and startup-latency pressure
- how much of that decision surface is currently realizable through the current
  out-of-tree vLLM runtime seam

This artifact does not study:

- general admission or queue-gating policy
- online memory evolution, writeback, or long-horizon state lifecycle control
- a broad scheduler or placement redesign

## Truthfulness Boundary

This repository keeps two evidence layers separate.

- `decision-study`: offline, workload-grounded analysis of the three-action
  arrival-time decision surface
- `runtime-boundary-live`: live execution against a vLLM-compatible endpoint to
  show what the current runtime seam can and cannot realize online

The offline study supports claims about decision structure, sensitivity, and
workload coverage. It does not imply deployed runtime gains.

The live path is truthfulness-safe only when described as a runtime realization
boundary:

- `full_reuse` is realized through anchor-scoped prefix-cache reuse
- `recompute` is realized through request-scoped prefix-cache bypass
- `partial_reuse` is realized only at hash-block granularity on the current
  prefix-cache path; the current carrier seam now isolates the recomputed tail
  in a request-scoped segmented hash namespace, but exact token-level
  materialization is still not available

## Partial Reuse Boundary

`partial_reuse` is the key action for this artifact, so its boundary stays
explicit.

Offline meaning:

- choose a profitable cut point, reuse the high-confidence prefix segment, and
  recompute the remaining suffix
- recompute the remaining suffix
- compare that hybrid action against `full_reuse` and `recompute`

Current offline evaluator semantics:

- `partial_reuse` is no longer modeled as a fixed half-prefix proxy
- the evaluator estimates a confidence-aware reuse frontier and discounts the
  value of low-confidence tail tokens
- the policy and oracle both optimize the partial cut point against that same
  cost model, so `partial_reuse` now means "reuse up to the best boundary" and
  not simply "reuse some arbitrary fraction"

Current live-path taxonomy:

- observed decision: `partial_reuse`
- runtime support tier:
  `native_runtime_action` for block-aligned partial reuse, otherwise
  `fallback_to_supported_runtime_action`
- fallback reason taxonomy:
  `partial_reuse_cut_point_realigned_to_runtime_hash_blocks` when the offline
  cut point is rounded down to a realizable full-block boundary,
  `block_aligned_partial_reuse_dominated_by_full_reuse` when that realizable
  boundary is no longer better than `full_reuse`, and
  `block_aligned_partial_reuse_collapses_to_recompute` when it is no longer
  better than `recompute`
- effective live action: block-aligned `partial_reuse`, anchor-scoped
  `full_reuse`, or request-scoped `recompute`, depending on the best
  realizable runtime action after block alignment
- the live control seam preserves the offline cut point inside a dedicated
  materialization-control `extra_args` payload, then aligns it to the runtime
  hash-block boundary before the carrier runtime applies the corresponding
  prefix-cache policy
- on the current carrier seam, effective `partial_reuse` now caps both
  prefix-cache lookup and shared-cache commit at the aligned reuse boundary,
  so the recomputed tail is executed for the current request but is not
  materialized back into the shared prefix-cache namespace
- carrier-side segmented hashing now also resets the tail hash chain at the
  aligned reuse boundary under a request-scoped `segmented_tail_cache_salt`,
  so the recomputed suffix no longer inherits the shared prefix hash chain
- a true connector-backed KV transfer/materialization path still requires an
  explicit global `kv_transfer_config`; request-local control metadata alone
  does not create a `KVConnector`
- carrier-side runtime changes live only in the `vendor/vllm` submodule; the
  pinned feature branch contains the segmented runtime seam: aligned
  prefix-cache lookup,
  aligned cache-write capping, and request-scoped tail hash isolation derived
  from `target_reuse_tokens`

The live paper matrix now has four cells for the two representative workloads:
old seam + baseline knobs, old seam + tuned knobs, new segmented seam +
baseline knobs, and new segmented seam + tuned knobs.

- `shared_scenario_multi_turn_knowledge_service`
  old baseline: mean `3289.302 ms`, p95 `3641.928 ms`, throughput `1.209 rps`
  old tuned: mean `3860.692 ms`, p95 `4170.369 ms`, throughput `1.031 rps`
  new segmented baseline: mean `3054.712 ms`, p95 `3383.972 ms`, throughput `1.303 rps`
  new segmented tuned: mean `2980.648 ms`, p95 `3214.822 ms`, throughput `1.335 rps`
- `shared_tool_scaffold_agent`
  old baseline: mean `8856.437 ms`, p95 `10627.872 ms`, throughput `0.896 rps`
  old tuned: mean `11068.224 ms`, p95 `12187.492 ms`, throughput `0.717 rps`
  new segmented baseline: mean `9362.399 ms`, p95 `10302.383 ms`, throughput `0.848 rps`
  new segmented tuned: mean `9186.471 ms`, p95 `10182.569 ms`, throughput `0.865 rps`

M1 supports a descriptive runtime-realization claim, not a stable seam gain:
three independent restart blocks show seam main effects close to zero on both
workloads, so the unchanged protocol stopped at its 5% minimum meaningful
effect.

M2 then compared `always_recompute`, `always_full_reuse`, and the controller in
18 matched independent lifecycles (576/576 successful requests). The controller
did not beat the best fixed policy: matched mean TTFT regressed by `9.24%` on
tool scaffold and `6.60%` on knowledge service, while `always_full_reuse` won
all six matched rounds. Cost-model and online winners agreed in `6/6` rounds.
The preregistered verdict is therefore `stop_mechanism_direction`; the project
does not continue per-workload controller tuning.

The verdict is fixed in the M2 issue #3 closure summary and the paper boundary.
The 39 in-repo raw-bundle lifecycles are also archived in release
`m2-issue3-closure-evidence-20260811`
(<https://github.com/vLLM-HUST/vllm-hust-kv-materialization-arrival-control/releases/tag/m2-issue3-closure-evidence-20260811>,
asset `m2_raw_bundles_39_lifecycles.tar.gz`); the other 102 M2 lifecycles
remain aggregate-only supporting evidence, and the 39/102 reproducibility
boundary is kept until those raw bundles are archived to a persistent,
content-addressed location.

The action accounting remains a useful systems result. For example, the tool
controller's median lifecycle applied mix was `8/8/16`
recompute/partial/full, while engine realization was `16/16/0`. Requested or
effective `partial_reuse` is never reported as realized reuse without the
scheduler-owned token counters.

That fallback is a real limitation of the current runtime path and should be
described as such, not widened into a generic “state-management” claim.

## Workload Source Of Truth

All workload-driven paths must enter through `llm-serving-workloads`. This
repository should not grow a second local workload catalog or a repo-local
default case subset.

The default arrival-time decision matrix now follows the shared benchmark case
order exported by the sibling workload repository. In other words, this
repository's default decision-study workload set is whatever
`llm-serving-workloads` currently exposes as its default shared benchmark case
catalog, rather than a second hardcoded list carried locally.

## Canonical Paths

Preferred bootstrap:

```bash
make bootstrap-env
```

Canonical repository-local entrypoints:

```bash
make decision-study
make runtime-boundary-live MODEL=/path/to/shared-models/Qwen2.5-7B-Instruct \
  WORKLOAD_CASE=shared_prefix_multi_tenant_assistant
make pdf
```

Compatibility aliases remain available:

- `make study-experiment`
- `make experiment`
- `make shared-workloads-offline`
- `make live-benchmark`
- `make shared-workloads-live`
- `make optimization-live`

Preferred workload-entry wrapper from `llm-serving-workloads`:

```bash
cd /path/to/llm-serving-workloads
make kv-materialization-study
make kv-materialization-live \
  BASE_URL=https://<openai-compatible-endpoint>/v1 \
  OPENAI_API_KEY=<token> \
  MODEL=/path/to/shared-models/Qwen2.5-7B-Instruct \
  WORKLOAD_CASE=shared_prefix_multi_tenant_assistant
```

## Ownership And Transfer

- current student owner: `Wei He` (`healer-positive`)
- current organization: `vLLM-HUST`
- status: maintained as a vLLM-HUST MOD by `healer-positive`
- transfer readiness: keep repository docs and scripts free of user-specific
  absolute paths and source-organization hardcoding

For graduate-student takeover and paper-oriented follow-up, start from
`HANDOFF.md`.

## Common Commands

```bash
make help
make install-dev
make smoke
make test
make shared-workloads-smoke
make shared-workloads-test
make offline-experiment
make decision-study
make runtime-boundary-live MODEL=/path/to/shared-models/Qwen2.5-7B-Instruct
make pdf
make build
```

`shared-workloads-smoke` writes the standardized compatibility report under
`.benchmarks/results`.

## Usage

Run vLLM with the plugin enabled through the wrapper launcher:

```bash
vllm-kv-materialization-serve serve --model <model>
```

Run the toy policy harness:

```bash
vllm-kv-materialization-offline --policy heuristic
```

When launching a local vLLM server through
`paper/kv_materialization_control/experiments/launch_vllm_kv_materialization_server.sh`,
leave `MAX_MODEL_LEN` unset if you want the launcher to derive the serving
window from `llm-serving-workloads` via `WORKLOAD_CASE`.

That launcher always resolves the repo-local `vendor/vllm` runtime from the
parent repository, activates `vllm-kv-materialization-exp`, and uses writable
repo-local cache roots. Override `CONDA_SH`, `ENV_NAME`,
`VLLM_KV_MATERIALIZATION_XDG_CACHE_HOME`, or
`VLLM_KV_MATERIALIZATION_HF_HOME` when you need a different local setup.

For OpenAI-compatible endpoints, `BASE_URL` may be either the server root or a
path that already ends with `/v1`. The live driver normalizes both forms and
forwards `OPENAI_API_KEY` plus `OPENAI_HTTP_USER_AGENT` when present.

## Paper And Experiments

Paper assets live under:

- `paper/kv_materialization_control/`
- `paper/kv_materialization_control/experiments/`
- `paper/related_works/`

The decision-study pipeline emits paper-facing summaries under
`paper/kv_materialization_control/experiments/results/latest/`.

The runtime-boundary live path writes endpoint summaries under
`paper/kv_materialization_control/experiments/results/live/`.

## Reproducible Runtime Carrier

`vendor/vllm` is the only runtime carrier. It is a regular, in-repository
submodule (not a symlink) with:

- URL: `https://github.com/vLLM-HUST/vllm-hust.git`
- branch: `feature/kv-materialization-runtime-integration`
- pinned carrier commit: `68b8be04493d39d5706f3d0d18f465f5eab947c4`
- base: vLLM-HUST `main` at `e4ce33646f2ef1781289e6dc651fad0d00177c55`

Fresh-checkout CPU validation:

```bash
git clone --recurse-submodules https://github.com/vLLM-HUST/vllm-hust-kv-materialization-arrival-control.git
cd kv-materialization-arrival-control
bash scripts/setup_repo_env.sh
make test
```

For an existing checkout:

```bash
git submodule sync --recursive
git submodule update --init --recursive
```

This repository exists because vLLM supports out-of-tree plugins through
`vllm.general_plugins`. That seam is the right place to study arrival-time
materialization decisions without turning this repo into an upstream fork.


Run A/B with only plugin-owned environment variables changed between baseline and experiment. Record command shape, devices, model, graph config, prompt, max tokens, output length, TTFT, TPOT, throughput, result paths, confirmed facts, hypotheses, rejected directions, and the next experiment. If startup fails, stop through the same manager and record the failure; do not switch to manual Docker startup.
