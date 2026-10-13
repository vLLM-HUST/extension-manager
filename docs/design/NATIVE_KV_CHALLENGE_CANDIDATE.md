# New KV metadata/upload request cohort

The generic v1 recipe and default consumer remain unchanged. The explicit
`ecpa-native-kv-challenge-campaign/v1` recipe instead requires the KV opt-in
collector schema and exact phase requirements from #172. An ordinary two-rank
upload, an upload before projection, or a different destination cannot pass.
Aggregate success from another phase cannot discharge this request: both actual
projections must join the selected phase's mapped runtime ID and later uploads.

Freeze a new recipe before any new model launch. The builder uses the actual
local AutoTokenizer and chat template, with `add_generation_prompt=True` and
`enable_thinking=False` and explicit `return_dict=False`, to search for exactly
1201 prompt tokens. Failure to
reach exactly 1201 is unsupported; no token count is guessed. It archives the
actual IDs, their hash, messages hash, template policy, class and tokenizer asset
byte bindings. The actual Transformers version, apply_chat_template implementation
file hash and eight installed Host renderer/tokenization/input processor file
hashes are recorded and archived. New nonce/request IDs are minted by the existing client recipe
builder, never native process/launch IDs. The required semantic/physical anchors
are 1201/1024, threshold 1152, group 0, block size 128 and eight destination blocks.

The response task asks for two copies of the fresh nonce challenge, with
max_tokens=128. The observed response must stop with the exact frozen text,
actual usage prompt_tokens=1201, and completion_tokens at least 32. This provides
a bounded decode window, while actual post-projection upload receipts remain
mandatory: extra decode alone does not prove an effect. The current old short
nonce protocol or a prior artifact cannot substitute for this new recipe.

With an explicit owned 0700 directory (including cleared SGID/SUID/sticky bits),
run the builder from the isolated new KV environment:

```sh
python -m experiments.native_challenge_candidate.kv_request_runner \
  --configuration CONFIG.json --model-directory LOCAL_MODEL \
  --output /absolute/private/new-recipe.json
```

Configuration uses the existing `phase_targets` and `sources` format. Pin all
actual helper/client/collector/provider/Host sources and tokenizer assets. The
builder loads local assets only, with remote code disabled. Execute through the
existing request runner's `execute` command with the frozen recipe SHA and an
independently observed new collector descriptor. Register the selected phase's
six-field `kv_requirements` in the KV collector, after actual native identity
minting and before HTTP. The registered native API mapping supplies phase/nonce;
provider facts never supply or guess them. Use a new native launch/plan and new
wheel tuple; keep the current generic run frozen.

For a complete observation, `kv_archive.seal` copies the raw request, headers,
response body, observed HTTP metadata, before/after recorded peer ACK statuses,
launcher descriptor, spec, full raw journal and frozen source snapshots. Its
returned manifest digest must be preserved independently. The portable CLI
requires that externally held digest:

```sh
python -m experiments.native_challenge_candidate.kv_archive ARCHIVE \
  --expected-manifest-sha256 DIGEST --phase PHASE
```

Replay verifies bytes, source snapshots, recorded peer/launcher/spec/socket/ACK
bindings, the complete hash chain, selected-phase native mapping and both later
same-worker destination-prefix joins, then independently parses the raw nonce
response and actual usage counts. Facts must lie after HTTP dispatch and before
response receipt in the same recorded boot epoch. Original source paths can be
gone: replay uses archived bytes. It does not authenticate a new live OS peer,
re-execute tokenization from archived assets, or trust a success summary.
Unsupported collector source/version, missing ACK/HTTP/source evidence and
counterfactuals fail closed. It reuses the exact #172 collector predicate.

The result is only a finite observed KVCompress Host metadata-to-upload binding.
KV tensor equivalence, attention consumption, full generation quality, all-step
stability and the full objective remain unknown. Formal producer registration
and the real formal traffic guard remain closed. Every CPU test labels its
model/tokenizer/native/GPU metadata as fixtures and cannot qualify real hardware.
One owner must freeze and run the future NPU cohort with the new clean wheels;
this change launches no NPU process and provides no new model result.
