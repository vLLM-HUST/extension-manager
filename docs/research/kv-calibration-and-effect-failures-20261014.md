# Real 7B calibration input and failed KV effect attempts

This archive preserves failures. It does not add a formal H3/H4 start, a KV
semantic positive, a quality result, or a performance measurement. Formal
qualification remains closed and the submission decision remains NO-GO.

The standalone calibration CLI performed an actual Qwen2.5-7B model forward on
logical NPU0, with 4096 actual input tokens. It produced the fresh 655,783-byte
stats artifact `d8cc47fbdae931785fcbed403fcc688d1b12000cee76e591622c7d70e3b254d7`.
The original wrapper then exited 1: its clean PATH could not resolve `npu-smi`
in the final diagnostic. The original traceback and missing `run/result.json`
remain unchanged. No independently persisted leaf exit status exists, and the
live generator was not independently observed. The source control flow and
saved output do not create a new raw exit-status record. A separately labeled
late diagnostic used `/usr/local/sbin/npu-smi` and found physical NPUs3/6 clean.
This was single-device HF calibration, not TP2 calibration or text generation.

The artifact is a usable, separately checked future input. CPU loading uses
`weights_only=True` and `map_location='cpu'`; the original frozen
`CalibrationStats.validate` checks the 7B geometry (28 layers, 28 query heads,
4 KV heads, head/rotary dimension128). Metadata matches the model path,
4096-token text input, and original local-manifest fingerprint. That fingerprint
covers recognized file names, sizes and mtimes; it is not a weight-content hash.
The original freeze separately records all14 model-file full SHA256 digests.
The portable check replays those records and the copied model configuration;
it does not rehash omitted model weights on the verifier machine. Structural
validation does not change the original wrapper failure or establish quality.

The effect tuple used Host89ee8c074, Ascendfcbb827af and KVCompressd30e956a,
with exact wheel digests and installed source audits. Frozen launch environments
select the three Ascend core entry points; Manager activates only
`org.vllm-hust.ascend-kvcompress`. The original Host journal confirms
`ascend_kvcompress` was invoked on the API server and both workers, without
old `kv_materialization` or `arctic_inference` invocation. Each new recipe
froze a fresh nonce and an actual local chat-template input of1201 tokens,
with budget1024, threshold1152, block128 and minimum configured output16.

* Effect r3 started actual Manager/API/two-rank processes. Its frozen native
  source list contained duplicate plugin/provider paths; the actual frozen
  collector source digest guard rejected them. The owner was stopped through
  its verified kernel PID/start/boot/session before a request, and its original
  finally cleanup completed. The resulting `/proc` race failure and original
  result remain preserved alongside the controlled-stop/duplicate diagnostics.
* Effect r4 passed the real unique-source CPU gate, started actual TP2 and sent
  one frozen POST. It returned500. Both workers raised `KeyError` in
  `native_kv_projection_observer.py` when the callback read an InputBatch row
  before the original Host update restored that row. This is a concrete
  producer placement failure. It must be fixed in a new source/wheel tuple;
  no synthetic row or relaxed operation predicate can repair this archive.
* R4's four raw collector rows contain start, one native API request-ID mapping,
  and two initial generic GPU uploads. There is no KV projection or later
  destination-prefix witness. The post-request authenticated ACK status was
  never saved. Raw presence does not prove durable ACK or a KV effect. The
  verifier reports the join unknown and the attempt failed.

Original terminal records bind both Manager/API sessions, all three source
PID/start/boot identities, the closed backend port29494, and the actual no-running
NPU3/6 output. A separately labeled late kernel observation also confirms the
collector epoch gone. Late independent audits are supplementary observations,
not prelaunch registrations. The archive includes all original run records,
source snapshots whose bytes match prelaunch hashes, model/wheel provenance,
input token IDs, the stats artifact, and failure diagnostics. Snapshot collection
occurred after the attempts and is explicitly labeled. Large wheel/model bytes
and private Triton cache binaries are excluded; this is not an offline serving
reproduction bundle or a claim to archive a complete cache directory. Public
JSON launch environments are explicit allowlists; the reported key-pattern
scan is not a complete secret-detection guarantee.

The 234 regular-file archive SHA256 is
`ca45a44ffcda123d0960a8833db3736c1b3954e38ffb091780c352ab230d8d5b`.
A prior 233-file packaging candidate was retained privately before the late
collector cleanup supplement; it is not the published archive.

```sh
python -m experiments.formal_campaign.verify_kv_failures \
  --manifest experiments/formal_campaign/artifacts/kv-failures-20261014/manifest.json \
  --archive experiments/formal_campaign/artifacts/kv-failures-20261014/raw.tar.gz
```

The default portable failure proof is standard-library-only and returns artifact
structural validation as unknown. Run the separate CPU artifact check with an
installed CPU-capable Torch runtime (no native device execution):

```sh
TORCH_DEVICE_BACKEND_AUTOLOAD=0 python -m experiments.formal_campaign.verify_kv_failures \
  --manifest experiments/formal_campaign/artifacts/kv-failures-20261014/manifest.json \
  --archive experiments/formal_campaign/artifacts/kv-failures-20261014/raw.tar.gz \
  --validate-stats
```

Only the frozen base/stats modules are loaded for the shape check; package
initializers that register serving methods are bypassed. Original source bytes
remain unchanged. Archive counterfactual tests rebuild the tar and every digest
before verification: promoting a failed result, changing HTTP status, omitting
wrapper failure, inventing leaf status, replacing peer identities, changing
owned session cleanup or adding a live NPU process is rejected.
