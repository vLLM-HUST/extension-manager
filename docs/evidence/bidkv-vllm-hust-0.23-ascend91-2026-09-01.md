# BidKV typed scheduler policy online gate on Ascend 91

Date: 2026-09-01  
Host: `ascend91-host`, one idle Ascend 910B2  
Result: online policy selection and next-process rollback passed

## Pinned inputs

- vLLM-HUST core commit: `5c994cdc0` (typed scheduler policy host seam)
- Extension Manager commit: `e71d7cf`
- BidKV commit: `d0a7b20`
- container image:
  `local/vllm-ascend-hust@sha256:f86a810132b152f93579ad993eb8d1b3202fd901d664b1dc468385d18acc313f`
- installed distributions: vLLM `0.23.0+empty`, vLLM Ascend `0.23.0rc1`,
  `vllm-hust-ext 0.2.0.dev0`, and BidKV `0.1.1`
- model: local Qwen3-0.6B checkpoint
- service: loopback-only `127.0.0.1:18091`

The existing 0.23 image predates the current scheduler file. The test copied
the new typed admission modules and victim-selector implementation into an
isolated container, then applied only the generic selector construction and
preemption-selection calls to that image's native scheduler. It did not copy
the newer scheduler wholesale or modify any persistent host installation.

## Enabled path

Manager discovered BidKV, projected
`installed + discovered + compatible + configured + enabled`, rendered a
host-native schema 1.0 manifest, and selected
`org.vllm-hust.bidkv/victim-selector`. EngineCore reported:

```text
Loaded typed victim selector component=org.vllm-hust.bidkv/victim-selector
source=.../bidkv/adapters/vllm_hust/selector.py api_version=1
```

With `max_model_len=2048` and a 2,560-token KV cache, three concurrent
1,400-token generations forced real KV pressure. BidKV was called three times
at `kv_util=1.00`; representative events selected victims from three and two
running requests:

```text
[BidKV] UTILITY_ACTIVE ... r=769 tok ... running=3
[BidKV] UTILITY_ACTIVE ... r=1152 tok ... running=2
[BidKV] UTILITY_ACTIVE ... r=1407 tok ... preemptions=1 ... running=2
```

All three requests completed with 1,422 total tokens and `finish_reason=length`.

## Disable and next-process rollback

After `extension disable`, Manager preserved installed/discovered/compatible/
configured state but removed enabled intent. The next Manager dry run contained
no native extension manifests and no additional selector configuration. The
replacement service started as `builtin-qwen`, returned a successful real
completion, and its complete log contained zero typed-selector load lines and
zero `[BidKV]` lines. The process environment had neither
`VLLM_EXTENSION_MANIFESTS` nor `VLLM_EXTENSION_BUNDLES`.

Raw logs retained by the task workspace:

- enabled log SHA-256:
  `cbb8c86438633e7c48ad66fdfdc06a970f89f0a4f48bea31835bfcdb8925b4c9`
- built-in rollback log SHA-256:
  `aeeeebf7d924b936103a5a6658d219318d2e5fd0a32d5b8c1fe2632c04b5dc38`

The isolated container and remote staging directory were removed. A final
`npu-smi` check reported no processes on all eight devices.

The run also exposed a non-fatal naming warning: the Manager diagnostic
variable used the reserved-looking `VLLM_` prefix. It was renamed to
`VLLMHUST_EXT_ENABLED_BUNDLES` after this run so future launches do not present
it as an unknown vLLM-owned setting.

## Remaining release boundary

This closes the online load, policy-call, request-completion, disable, and
next-process fallback behavior gate. It does not turn the overlay into a
release artifact. Alpha still requires the same result from a clean image and
wheel built from the pushed commits, plus the remaining cross-host release
matrix.
