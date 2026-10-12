# Two-card H1 model snapshot candidate

Captured on 2026-10-12 from `/models/Qwen2.5-7B-Instruct` in the
180-evaluation container. Every Hugging Face download metadata file for the
14 files in the adjacent SHA-256 list reports revision
`a09a35458c702b33eeacc393d103063234e8bc28` for
`Qwen/Qwen2.5-7B-Instruct`. The local snapshot has four BF16 safetensors
shards, one index, and tokenizer/configuration files. The model directory is
not a Git checkout; the revision is the downloader's recorded source
identity, while the hashes bind the actual local bytes.

Verify the same bytes before a run:

```sh
cd /models/Qwen2.5-7B-Instruct
sha256sum -c /root/extension-manager/experiments/false_effective/deployment-candidates/qwen2.5-7b-instruct-a09a3545.sha256
```

This is a **candidate input**, not a registered H1 deployment or model-serving
result. The runtime/plugin wheels, container or environment digest, workload,
commands, process topology, and formal adapter registry remain unfrozen. The
container exposes physical NPU IDs 0 and 7, but TorchNPU sees two logical
devices when `ASCEND_RT_VISIBLE_DEVICES` is unset; setting it to `0,7` in this
container yields only one. Recheck that mapping and active processes before
any TP=2 launch. Two cards support the matched H1 partial-worker-coverage
experiment, not an eight-card scaling claim.
