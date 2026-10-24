# One real selected logical KV byte observation

A new independently frozen TP2 cohort now passes the strict model task and the
mixed typed HTTP/final-ACK predicate from PR #191. The observation covers both
ranks and all 28 Qwen2.5-7B layers. This is `REAL_RUNTIME_UNQUALIFIED`: formal
H3/H4, complete physical-storage equivalence, attention consumption, full
quality, lost/duplicate requests and the overall objective remain unqualified
or unknown. This is not an H4 performance measurement.

Runtime sources were frozen at immutable head
`0666cf001db4f2a6247f6da6b2c12ad0b97e5560` before launch; its exact merge is
`db887cc2e160dab815c5cac0ca0e7dcf71b6afde`. Source-pinned consumer/helper
bytes were explicitly declared in the new recipe before launch. A genuine
new Host `c4350611` wheel (SHA256 `42f5f436…5e40ec`) and KV `5256d4b0` wheel
(`28a61431…35b22`) were installed in a separately copied venv, leaving old
qualified environments untouched. Seven package byte audits, 70 operator
source files, 39 unique native source files, fourteen complete model-file hashes
and the separately validated 7B stats artifact were frozen. The calibration
wrapper failure remains a failure; its model-matched stats are an input.

The new strict-copy challenge has actual CPU prompt count 1201 and a standalone
68-token oracle precondition. Original HTTP 200 evidence reports 1201 prompt
and 69 completion tokens, `stop`, and the exact two-nonce response. The observed
HTTP elapsed time is 51.540227549 seconds; this single instrumented request is
not a performance result. The 180-second phase and 1200-second overall watchdogs
did not fire. All actual owner, Manager, API and collector sessions, registered
source epochs and backend port 29504 were closed. Original NPU reports show
allocated physical devices 3 and 6 have no running processes.

All 201 original mixed journal rows are retained: two distinct starts, one
actual native API map, two materialized-row projections, 56 typed tensor
receipts and 140 actual NPU upload receipts. For each rank, all 28 recorded
`model.layers.{index}.self_attn.attn` names and distinct observed K/V virtual
pointers match the fixed corpus. Pointers are observations within one process;
they do not prove complete physical-storage coverage or uniqueness across
processes. The typed reference fixes selected source blocks before the actual
gather, checks actual workspace bytes, and independently reads actual
destinations after the write. The whole 56 MiB of selected logical K/V bytes
joins to the actual request/plan and the two same-process projections, then
69 later matching full-prefix uploads per rank.

The two final intakes remain in the original journal, including their original
source/accept clocks. The preregistered source-fact HTTP and source-issued
final-prefix ACK contract passes without filtering typed rows, moving clocks
or changing the old metadata archives. The original generic RPC-only missing
native-evidence flags remain in `result.json`; the new typed predicate records
its own finite join. No generic qualified flag was manufactured.

`verify_kv_selected_tensor_observation` restores ten exact frozen pure-stdlib
modules in a private isolated `-I -S` interpreter. Its complete source map
includes real tokenizer/render source assets. It independently recomputes
HTTP/source/epoch, both-rank/all-layer tensor byte witnesses, projection and
later-upload bindings, recorded final ACK clocks, and owned cleanup. Offline
replay performs no fresh OS-peer authentication or original model execution.
Late independent kernel/source/terminal reports remain late observations.

```sh
python -m experiments.formal_campaign.verify_kv_selected_tensor_observation \
  --manifest ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/kv-selected-tensor-observation-20261014/manifest.json \
  --archive-directory ${VLLM_HUST_BENCHMARK_ORIGINALS}/experiments/formal_campaign/artifacts/kv-selected-tensor-observation-20261014
```

The original complete 76,364,712-byte `tar.xz` is published as thirteen ordered
byte parts of at most 6 MiB. Concatenation restores the original XZ byte-for-byte
(SHA256 `f704e8d1e7bd35d99ecf0ebfbe6671d2e8baf8133a326b5df5dc935447846548`).
The manifest checks every part, the whole compressed stream, the additional
source archive, and all 279 member hashes/sizes. All 56 original receiver JSON
payloads remain fully included. The source-extra archive preserves tokenizer
and renderer assets plus the late fixed-layer audit. Tensor values were not
replaced by digests or summaries.

Private Triton cache contents, duplicate worker publication originals and
large original wheel/model tensor files are excluded. Receiver payload bytes
and source original descriptor/SHA bindings remain complete; this is not a
full cache archive or offline serving bundle. Only explicitly allowed launch
variables are public, with no opaque desktop-session environment payload.
