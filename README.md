# vLLM-HUST Extension Manager

`vllm-hust-ext` discovers, validates, activates, and diagnoses installable
vLLM-HUST extension bundles. The vLLM and vLLM Ascend forks remain close to
their upstreams; extension enablement policy and launch-time activation live
here.

An extension bundle can declare one or more typed components, such as an
in-process vLLM plugin, a KV connector adapter, or a bridge to an external
service. The manager does not relabel Mooncake, LMCache, or a control plane as
plugins, and it does not own their service lifecycle.

```bash
pip install vllm-hust-ext
pip install bidkv

vllm-hust-ext extension list
vllm-hust-ext extension enable org.vllm-hust.bidkv
vllm-hust-ext run -- vllm serve MODEL
```

Installing an extension distribution only makes it discoverable. Enabling is
explicit and stored in the user configuration. Discovery reads installed
distribution metadata and the static bundle manifest without importing its
implementation modules.

