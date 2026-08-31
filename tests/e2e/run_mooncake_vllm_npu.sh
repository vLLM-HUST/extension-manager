#!/usr/bin/env bash
set -euo pipefail

mooncake_master \
  --rpc_port=50054 \
  --enable_http_metadata_server=true \
  --http_metadata_server_host=127.0.0.1 \
  --http_metadata_server_port=50055 \
  --metrics_port=50056 \
  --logtostderr=true \
  >/tmp/mooncake-master.log 2>&1 &

sleep 3
kill -0 "$!"

cd /workspace/vllm-hust
exec /usr/local/python3.12.13/bin/vllm serve /model \
  --served-model-name Qwen3-0.6B \
  --host 127.0.0.1 \
  --port 18084 \
  --tensor-parallel-size 1 \
  --max-model-len 2048 \
  --max-num-batched-tokens 1024 \
  --max-num-seqs 2 \
  --gpu-memory-utilization 0.25 \
  --dtype bfloat16 \
  --no-enable-prefix-caching \
  --kv-transfer-config '{"kv_connector":"MooncakeStoreConnector","kv_role":"kv_both","kv_connector_extra_config":{"load_async":true,"lookup_async":false,"cache_prefix":"vllmhust-e2e-20260901"}}'
