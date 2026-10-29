# First native H2 study block, 19 October 2026

This packet contains real model execution, with actual Manager admission, Host
processes, TP2 workers and Qwen2.5-7B requests. It is a first bounded study block,
not a completed three-method/three-repeat H2 comparison, a held-out qualification,
a numerical-equivalence result, or a performance measurement. Absolute local
paths and device/process identities are retained; this is not the anonymous
submission artifact. Historical H1/H3/H4 results and the four-case H2 score are
unchanged.

Each of KVCompress alone, Profiler alone, KV→Profiler and Profiler→KV executed
both a 4-token prompt and a 1201-token prompt, generating 32 tokens per request.
Both actual callback orders were observed independently for the API, scheduler
and two TP worker epochs. The fifth group is the same Host without either MOD. Its common observer did
not activate: the study hook was installed after general-plugin callbacks,
whereas this group has only the Ascend platform callback. Its HTTP data remain
valid, but matched Host counter/mapping coverage is UNKNOWN. No missing events
are reconstructed. A common unconditional bootstrap hook needs a new cohort.
See summary.json for original HTTP/usage and cleanup fields; these are runner
measurements, not oracle labels.

For KV-bearing groups, the long request has original scheduler/worker commit
logs at semantic=1201, physical=1024, destination_blocks=8. Independent original
Host/NPU facts show both ranks' block-table prefix widths changing from 10 to 9:
eight destination blocks plus one scheduled decode block. Host finished and
reclaimed counters report 9 at the same lifecycle boundary. The latter two
counters share a source variable and are not two independent measurements;
NPU stream-synchronized readback supplies the separate physical-table evidence.
This does not establish KV tensor or attention-output equivalence.

Profiler-bearing groups have actual finished/reclaimed trace events joined to
original request IDs, Host timestamps and launch/process subjects. Its complete
loss-free close remains UNKNOWN: the original plugin registers writer.close
through atexit, while the actual Host shutdown sends SIGTERM and force kills
EngineCore/workers. The scheduler shard retains request events but lacks its
process summary. This is an observed lifecycle-interface mismatch, not proof
that request events were lost, and not a completed compatibility PASS.
The independently source-bound analysis is included in independent-reader/.

The independent rule and pure tokenizer input bytes precede first launch.
Reader implementations were developed after some raw results were available;
that timing is explicitly disclosed in their freeze records. They read raw
observations rather than ECPA pass/fail decisions. The oracle remains unknown
where original facts are missing. Rank-local transaction hashes include local
clocks and need not equal across ranks. The native local callback is not an
authenticated ACK or a formal phase-drain receipt.

The successful KV singleton is from r3. The remaining groups are from r4, using
distinct ports after r3's four remaining cases failed before Host launch due to
TIME_WAIT port probes. Original r1 spawn-entrypoint and r2 logical-device-number
failures, their cleanup and administrative cancellations remain separate.
Selected original attempt records are included; complete failure archives remain
at their manifest-bound local roots. None are reclassified as MOD conflicts.

The exact existing official runtime was reused without algorithm edits or new
product builds. Actual order is controlled by explicit shared study
instrumentation, not inferred automatically by production ECPA. The current
shared runner/observer totals 318 physical lines (213+105), with immutable
per-cohort source hashes. Historical ports and human labor are unknown, not zero.
See provenance/actual-r3-r4-study-adaptation-cost.json and the original wheel
source/installed-byte verification. Instrumentation includes NPU synchronizations;
request elapsed times in raw records must not be presented as clean performance.

The scripts and raw files are retained for inspection. Some readers reference
original absolute source locations; they are not claimed to be a portable
standalone artifact. manifest.json hashes every copied original byte. New
lifecycle fixes require new source/wheel/cohort identity and a real rerun; they
cannot repair these original records retroactively.

Byte-preserved Python sources use `.py.snapshot`, following the source-audit
convention, so archival reader revisions are not treated as maintained project
modules by lint/import discovery. Restore the `.py` suffix when inspecting or
reconstructing their original environment; hashes bind the original bytes.
