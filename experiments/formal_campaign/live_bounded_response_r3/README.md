# Recorded live bounded-response release, r3

This is a lossless content-addressed package of the real 2026-10-15 r3 run, classified `REAL_LIVE_BOUNDED_RESPONSE_RELEASE_NONFORMAL`. It is historical replay, not fresh OS peer authentication, formal H1/H3/H4 qualification, model quality, or a performance result.

The original raw archive remains unchanged: 244,769,640 bytes, SHA-256 `76d68e7417479e9306955447842d910d79cbe6db54607ff70ae6ad170c565360`. All 1,102 original regular members (875,520,077 bytes) are retained with original paths, byte sizes and SHA-256 hashes in `origin-inventory.json` and `manifest.json`. Full byte comparison during packaging verified duplicate-content identity. The 1,022 unique contents compress to 76,412,184 bytes, split into thirteen parts no larger than 6 MiB. Joining the parts reconstructs the content-addressed container, not a claim of byte-identical reproduction of the original compressed tar stream.

Thirteen software/tokenizer dependencies pinned in the original recipe were omitted from the original raw archive. `replay-assets.json` identifies their separate late packaging recovery; `replay-assets.tar.xz` supplies their exact original pinned bytes. These files are not represented as original raw members or additional runtime evidence.

The complete payload is published on the independent [artifact snapshot](https://github.com/vLLM-HUST/extension-manager/tree/246d3983a6b6274b4b566debdfbfbc31245ae020), commit `246d3983a6b6274b4b566debdfbfbc31245ae020`. Its binary data is outside main ancestry. Download that directory, retaining `parts/`, then run with Python 3.12 and the standard library only:

```sh
python3 -I -S assemble_live_r3.py --bundle .
python3 -I -S verify_live_bounded_observation.py --bundle .
```

To reconstruct every original regular member without modifying the original archive:

```sh
python3 -I -S assemble_live_r3.py --bundle . --extract-members /tmp/ecpa-r3-members
```

The verifier checks the original member inventory, all object hashes, frozen executed sources, request and retained probe response bytes, complete 265-record native prefix, complete source ACK closures, 704-record authority hashchain, 699 paired client observations, scope and original fixed lease. It runs the captured standard-library consumer in an isolated subprocess and requires its result to match the original observation SHA exactly. The record shows one successful frozen public request, a different request rejected with 503, and the original request rejected after the recorded SIGTERM of the registered worker identity while 23,761,395,371 ns remained on the original lease.

The original journal retained quote hashes but omitted complete producer quotes/nonces. Public clients retained response hashes, not all actual response bodies. The successful release hash matches the retained probe response; control-body hashes are checked against deterministic reconstruction. These checks do not reconstruct missing authentication transcripts or prove fresh kernel state. The archived fault intent and executed cohort source are retained; no later fault-observed marker has been backfilled. Failed r1/r2 archives remain separate and are not promoted to successful cohorts.

Keep this artifact branch separate from the main development branch. The small verifier/manifest change may reference this immutable commit; the binary payload must not be merged into main ancestry.
