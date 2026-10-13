# H1 exact Host/Ascend support candidate — 2026-10-13

The exact exercised tuple is a bounded functional candidate for
Qwen2.5-7B-Instruct at revision `a09a3545`, eager single-host TP2 on two
Ascend 910B2 devices, with the KV materialization MOD. It is not a general
Host/Ascend compatibility claim, a formal H1 result, or a performance result.

The source tuple is Host `b093ae009`, Ascend `fd70a5c81`, Manager wheel source
`9f075f8e7`, and KV MOD `9728ccd9d`. Manager `main` is now `5b046c915`, and
`9f075f8e7` is its ancestor, so the earlier Manager merge blocker is resolved.
Remote-ref checks on 2026-10-13 found no branch or pull-request ref for the
Host, Ascend candidate, or MOD commits. Ascend PR #50 remains open at
`54d31aaf2`; `fd70a5c81` is one local commit after that head and is not PR #50.

The bounded source contract covers the explicit general-plugin callable in
the Host, the exact `vllm.general_plugins` registration in the MOD, and lazy
`fla_npu` loading for this non-GDN model in the Ascend plugin. The three live
TP2 arms are unregistered functional preflights and still contribute 0/9
formal starts.

The selected contract subset passed 175 tests with one skip. The full CPU
suite failed and stopped at 50 failures after 1,985 passes and 12 skips. The
failure distribution is 1 for 310P sharded loading, 1 for MLA/DCP, 5 for
Dyntra recompute, 33 for the Dyntra scheduler, and 10 for the profiling-chunk
scheduler. Those failures are retained as qualification evidence; the bounded
scope does not reinterpret them as passes.

Run the local source and evidence check with:

```console
python experiments/false_effective/check_h1_exact_pair.py \
  --host-repo /root/vllm-hust-h1 \
  --ascend-repo /root/vllm-ascend-hust-h1-lazy \
  --manager-repo /root/extension-manager-main-5b046 \
  --mod-repo /root/ecpa-kv-mod-rebuild \
  --evidence-root /root/ecpa-audit-20261013
```

This command verifies immutable commits, trees, source-contract tokens, the
Manager ancestor relation, evidence digests, and fail-closed qualification
invariants. A successful check means the local candidate inputs match. It does
not make the tuple formally eligible. Repository reachability, bounded
support-matrix review, registration, CANN dependency metadata, and independent
reviews remain blockers.
