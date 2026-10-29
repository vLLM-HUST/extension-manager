# Fixed-population interface screen

All 24 README files were read from their exact frozen commits in this pass. Root `pyproject.toml` was obtained for 21; three root paths returned404. This is a packaging/documentation screen, not a claim of deep semantic review or native support. Newer-revision deep findings are in separate files.

| MOD | Root project | Declared entry-point groups | Runtime package dependencies |
|---|---|---|---|
| bidkv | 200 | vllm_hust.extension_bundles | empty |
| diffspec | 200 | vllm.general_plugins, vllm_hust.extension_bundles | vllm>=0.28.1rc1.dev319,<0.28.2, vllm-ascend>=0.25.1rc1,<0.25.2 |
| vspec | 200 | vllm.general_plugins, vllm_hust.extension_bundles | empty |
| latchmoe | 200 | vllm.general_plugins, vllm_hust.extension_bundles | empty |
| ascend-adaptive-quantized-kv | 200 | vllm_hust.extension_bundles | empty |
| ascend-quant-runtime-descriptor | 404 | none observed | unknown |
| kvcompress-ascend | 200 | vllm.general_plugins, vllm_hust.extension_bundles | empty |
| kv-tiering-migration | 404 | none observed | unknown |
| knorm-migration | 404 | none observed | unknown |
| pyramidkv-ascend-migration | 200 | vllm_hust.extension_bundles | empty |
| quantized-kv-cache-migration | 200 | vllm.general_plugins | empty |
| simllm-migration | 200 | vllm_hust.extension_bundles | empty |
| unified-communication-migration | 200 | vllm_hust.extension_bundles | empty |
| split-batch-full-graph-migration | 200 | vllm_hust.extension_bundles | empty |
| kv-transfer-observability-migration | 200 | vllm_hust.extension_bundles | empty |
| layered-prefill-migration | 200 | vllm_hust.extension_bundles | empty |
| activation-sparsity-migration | 200 | vllm_hust.extension_bundles | empty |
| pipeline-microbatch-migration | 200 | vllm_hust.extension_bundles | empty |
| qos-scheduler-migration | 200 | vllm_hust.extension_bundles | empty |
| betterscale | 200 | none observed | empty |
| request-lifecycle-profiler | 200 | vllm.general_plugins | empty |
| kv-materialization-arrival-control | 200 | vllm.general_plugins | llm-serving-workloads @ git+https://github.com/vLLM-HUST/llm-serving-workloads.git@ceef92d52e0c49f26ba1efc6706edd1f6df5d913 |
| dla | 200 | vllm.extension_bundles, vllm.victim_selector | empty |
| traceloom | 200 | none observed | traceloom-vllm-context==0.1.0 |

Root404 does not prove the repository has no package: nested packaging and source-only deliveries require their own inspection. README keyword matches are not proof of actual defaults or host compatibility. Entry-point groups can overlap, so their counts are not disjoint integration classes.

Original population counts remain in `../workshop-mods.json`; do not replace them with this narrower root-file parser.
