# vllmhust

`vllmhust` is the small, framework-facing lifecycle manager for vLLM-HUST
extension bundles. The vLLM and vLLM Ascend forks remain close to their
upstreams; installation state, enablement policy, diagnostics, and launch-time
activation live here.

```bash
pip install vllmhust
pip install bidkv

vllmhust plugin list
vllmhust plugin enable org.vllm-hust.bidkv
vllmhust run -- vllm serve MODEL
```

Installing a plugin only makes it discoverable. Enabling is explicit and stored
in the user configuration. Discovery reads installed distribution metadata and
the static bundle manifest without importing plugin implementation modules.

