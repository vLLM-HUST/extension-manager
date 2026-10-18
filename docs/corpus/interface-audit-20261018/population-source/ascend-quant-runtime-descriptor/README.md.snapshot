# vllm-ascend-quant-hust

## Description 

An offline toolkit for post-training quantization on Ascend NPUs, supporting
8-bit, 4-bit, and mixed-precision quantization for large language models.

This repository has two deliberately separate deliverables:

- the scripts in the repository root prepare quantized model artifacts offline;
- `runtime-extension/` is an independently packaged, currently inert runtime
  compatibility extension for the vLLM-HUST Extension Manager.

Installing the offline toolkit does not modify or extend vLLM. The runtime
extension remains `import_only` until vLLM Ascend exposes the versioned loader
and operator-selection protocols declared in its manifest.

## Authors

Hongkun Wang, Xuedong Jiang, Chaiyu Gui, Xiang Xiang (HAIV Lab, https://github.com/HAIV-Lab)

## Usage

### Environment setup

```bash
conda activate vllm-hust-dev
pip install -r requirements.txt
```

### W8A8 quantization

W8A8 quantization run command：

```bash
msmodelslim quant \
  --model_path /root/models/Qwen2.5-7B-Instruct \
  --save_path /root/models/Qwen2.5-7B-Instruct-w8a8-test \
  --device npu \
  --model_type Qwen2.5 \
  --config_path /root/workspace1/vllm-ascend-quant-hust/qwen_w8a8.yaml \
  --trust_remote_code True
```

Note: replace root with real root.

### W4A4 quantization

W4A4 quantization run command：


```bash
  python3 qwen3_w4a4.py 
  --model_path /root/models/Qwen3-8B \
  --save_directory /root/models/Qwen3-8B-w4a4 \
  --calib_file common/qwen_qwen3_cot_w4a4.json \
  --trust_remote_code True \
  --batch_size 1
```
Note: replace root with real root. This supports Qwen3 models.


```bash
  python3 qwen2.5_w4a4.py 
  --model_path /root/models/Qwen2.5-14B-Instruct \
  --save_directory /root/models/Qwen2.5-14B-Instruct-w4a4 \
  --calib_file common/qwen_qwen3_cot_w4a4.json \
  --trust_remote_code True \
  --batch_size 1
```

Note: replace root with real root. This supports Qwen2.5 models, such as Qwen2.5-7B and Qwen2.5-14B.


### PPL evaluation

PPL evaluation run command：

```bash
python test_ppl.py --model_path /root/models/Qwen2.5-7B-w8a8-Instruct-smooth
```

Note: run this command in a free npu.
