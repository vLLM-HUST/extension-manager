# KV metadata receipt after native Host row materialization

The sealed r4 single POST failed with HTTP 500. The v1 provider called the receipt
hook in `before_update_states`, where a scheduled cached request existed in
`runner.requests` but was absent from `InputBatch.req_id_to_index`. That source
already skipped `add_row` when the row was missing. The old failure and v1 source
remain immutable; this candidate has no NPU result and does not register a formal
semantic producer.

The exact d30 provider patch captures the actual pending compression destination,
active semantic/physical anchors, scheduler cached-request append tuple, and real
metadata-effect clock after the request mutation. It emits nothing at that point.
The existing plugin calls original Host `_update_states` between provider before
and after hooks. The pinned Host appends native cached new blocks, calls actual
`InputBatch.add_request`, condenses/reorders, and refreshes metadata. The new
provider after hook then reads the actual row index, table width and CPU table,
request block IDs and active anchors. Ascend executes this before `_prepare_inputs`
and the unchanged fcbb real block-table H2D commit/upload observer.

Receipt schema `ecpa-native-kv-blocktable-projection/v2` requires the observed full
CPU row to equal the compression destinations plus the previously captured actual
scheduler append. For the diagnosed eight-destination / append `[19]` sequence,
the row is nine blocks. An absent row, wrong CPU table, substituted append, wrong
row, changed anchors, or rejected durable callback fails. Nothing guesses a row,
substitutes request metadata for an observed table, or backdates a receipt.

The opt-in recipe/spec are `ecpa-native-kv-challenge-campaign/v2` and
`ecpa-native-kv-semantic-collector-prereg/v2` (`--materialized-row-v2` when freezing
the recipe). Default generic and KV v1 protocols keep their existing semantics;
v2 intake is explicitly version 3. Live intake and portable replay share the same
pure field/source/chronology predicate: actual API mapping time <= metadata effect
time <= materialized receipt time <= collector accept time. A later upload must
come from the same registered worker/request/epoch and match the entire observed
CPU row prefix, including the genuine appended suffix. Pre-projection uploads
cannot discharge the obligation. All actual upload records remain in the raw chain.

The frozen source manifest includes exact provider pre/postimage hashes and pinned
Host method regions with their full-source and region hashes. CPU tests execute
those actual Host bodies using symbolic list storage, including the native cached
append branch and actual InputBatch/BlockTable add methods. These are partial
source-control-flow tests, not a full Host worker, GPU simulation or model oracle.
Actual HTTP plus three Unix peer processes exercise v1 and v2 positive/negative
transport paths. A new source commit, genuine Host/KV wheels, installed-byte audit,
new nonce/recipe and cohort are required before any subsequent hardware run.

The claim is limited to compression CPU metadata and subsequent uploaded block-ID
prefix binding. KV tensor equivalence, attention consumption, full generation
quality and the formal objective remain unknown; formal admission stays closed.
