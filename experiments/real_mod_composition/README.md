# Real-MOD H2 source preflight

These six **unmodified** ECPA 0.3 manifests are copied byte-for-byte from
independent MOD repositories at the exact commits, root trees and Git manifest
blobs in `sources.json`. `audit.py` verifies each Git blob before parsing
it with the current Manager. Run `python experiments/real_mod_composition/audit.py`.

This is a source-bound candidate set, **not** the H2 ownership oracle, a
clean-wheel activation test, or a host execution result. The preflight checks
only exact host provider/name/version and same-spelling resource claims. A
`candidate-only` result is not ECPA admission: API/protocol versions, package
entry points, dependencies, provider projection, external services, process
ownership, runtime effect and performance remain unverified. In particular,
two differently named claims may still own one physical resource.

The vSpec/Knorm/lifecycle-profiler triple has intersecting declared vLLM
0.23.3 version ranges and distinct resource names. BidKV/LatchMoE likewise
have overlapping 0.28.1rc1.dev319 ranges. These are candidates for independent
ownership review and, subsequently, clean-wheel execution; neither has been
run together. The profiler/BidKV case exercises a real source-declared host
version rejection. DiffSpec/vSpec is a **review question**, not a scored
conflict: their version ranges overlap and both modify speculative-decoding
paths, but their manifest host names and resource names differ. The physical
ownership and method-dependent interaction require separate source review.

Do not add these results to H2 precision/recall or the paper's formal-real
table until an independent oracle, complete host/provider checks and process-
owned execution evidence exist. The 31-case synthetic corpus remains separate.
