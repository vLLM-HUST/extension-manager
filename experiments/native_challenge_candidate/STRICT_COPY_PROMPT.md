# Strict copy prompt feasibility candidate

The original enabled KV run and the compression-disabled diagnostic both failed
that input's exact two-nonce oracle. Their recipes and results remain unchanged.
`strict-system-copy-v1` is a new, optional KV v2 input variant for testing task
feasibility. It has no GPU result and cannot establish compression quality,
formal qualification, or performance.

`make_kv_recipe(..., materialized_row=True, rpc_budget_s=180,
prompt_variant="strict-system-copy-v1")` freezes a canonical system instruction
and user message directing the model to copy all of the text inside `<answer>`.
That text remains exactly two copies of one fresh nonce separated by one space.
The actual local chat tokenizer searches padding counts for exactly 1201 input
tokens. The one sampled nonce's expected output must encode to 32–128 tokens;
a short sample fails on CPU without resampling. The receipt records the actual
expected token IDs, count, digest, source-bound tokenizer implementation and
assets. These are input preconditions, not an observed model completion.

The variant retains temperature 0, n=1, max_tokens=128, the minimum observed
completion count of 32, stop finish reason, and the exact existing oracle.
It forbids extra payload keys such as guided decoding or regex constraints.
There is no response rewriting. Omitting `prompt_variant` preserves the legacy
single-message recipe and its archived validation semantics. Unknown variants,
changed canonical messages, changed predicates, and malformed expected-token
receipts fail validation. The shared runner and archive call `validate_kv`, so
this optional variant uses the existing v2 schema through both paths.

The CLI accepts `--materialized-row-v2 --rpc-budget-s 180 --prompt-variant
strict-system-copy-v1`. Its output parent must be owned mode 0700 including
cleared special bits. The explicit real local tokenizer test is:

```sh
ECPA_REAL_TOKENIZER_MODEL=/models/Qwen2.5-7B-Instruct python -m pytest -q \
  tests/test_native_kv_strict_copy.py -k actual_local
```

CI tests the validation and existing CPU transport/archive paths; the real
local tokenizer test is explicitly skipped when its assets are unavailable.
Local real-tokenizer preflight is CPU-only and its nonce must not be recycled
as a hardware challenge. Hardware feasibility needs a separately frozen fresh
baseline request. An enabled request sharing that baseline nonce is an
explicit paired diagnostic with a new request ID, not a fresh qualification
challenge. Neither a single pass nor a paired result supplies a full quality
or causal compression claim. Authority-held runtime mapping, both actual rank
receipts, durable post-request publication, and cleanup remain independently
required for any finite native evidence classification.

The retained local CPU CLI records are under
`artifacts/strict-copy-cpu-20261014/`: the first attempt rejected its inherited
2700 output parent; a fresh owned 0700 second attempt exited 0 with actual
padding count 1013, 1201 prompt IDs, and 74 expected output IDs. Both attempts
retain their command, stdout, and stderr. The successful input recipe and
hash inventory are included; model assets and installed Host source bytes are
not included. This is a CPU source candidate record, not a portable hardware
qualification. Its sampled nonce is explicitly unavailable for hardware reuse.
