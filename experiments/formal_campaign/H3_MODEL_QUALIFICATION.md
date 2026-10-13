# ECPA two-live-backend recovery qualification

This is a retained `QUALIFIED_NONFORMAL` ECPA-only experiment. It does not
complete H3, supply matched vanilla/manual results, admit the unmerged Host
candidate, measure throughput/quality, or establish request loss/duplication
rates. The original three-arm and formal campaign requirements remain open.

The audited stack uses Host candidate `379a0ad35`, Ascend `873584026`,
KV materialization `e343` wheel bytes, Torch `2.13.0+cpu`, torch-npu
`2.13.0rc1`, Triton Ascend `92513dba`, and CANN 9.1.0. Wheel SHA-256,
installed Python byte comparisons and all model file SHA-256 are retained.
The Host candidate is unmerged, so these bytes do not satisfy formal admission.

The frozen runner launches two independent Qwen2.5-7B-Instruct TP2 services on
the allocated Ascend910B2 devices 3 and 6, each with eager execution and
`gpu_memory_utilization=0.25`. Predecessor and candidate use independent ports,
launch IDs, workers and Host invocation journals. The native coordinator has
its own process session. A separate authority serves the predecessor route.
The coordinator commits its real SQLite `close` intent and pauses before the
external effect. The operator verifies that durable barrier, sends SIGKILL,
checks both backends through actual completions during the controller outage,
and starts a new coordinator process against the same database. Native SQLite
rollback records and the independently owned, chained authority journal must
prove restoration of the exact predecessor route before the post-recovery
proxy completion. The operator finally cleans up the externally owned services.

Seven frozen marker requests cover direct readiness, both backends during the
controller outage, and the recovered proxy/candidate. These establish only the
observed marker task. They are not a complete crash-window client trace, and
lost/duplicated requests and the broader objective remain unknown. The candidate
is live but never becomes the exposed generation in this before-effect crash.
Thus this experiment does not establish rollback after candidate exposure,
in-flight request transfer, or model-generation replacement correctness.

The first attempt failed for a real vendor networking reason: HCCL EI0020 said
192.168.2.196:16666 was already bound. The complete failed run is retained. The
second attempt freezes separate NPU socket ranges 60000-60099 and 60100-60199,
and separate host ranges 61000-61099 and 61100-61199 before either service starts.
[CANN 9.1 HCCL documentation](https://www.hiascend.com/document/detail/en/CANNCommunityEdition/910/commlib/hcclug/docs/en/user_guide/hccl_env/HCCL_NPU_SOCKET_PORT_RANGE.md)
describes the default 16666 and non-overlapping ranges for concurrent services.
The first attempt was fully reclaimed before the second started.

The second attempt's input audit records two untracked offline verifier/test
files. It then failed the authority's private-directory check despite both
backends completing actual requests. The third was deliberately interrupted
before model loading to run the full native CPU path first. Those failures and
the interruption are retained. A separately labeled `CPU_PREFLIGHT_ONLY` run
then verified the exact authority CLI, private directory policy, native durable
prepare, kill/restart and independent restoration chain. Its raw bytes were
frozen into the final model attempt. The final attempt checks private ownership
and permissions plus fresh journal/socket/database paths before launching any
backend. Its source audit records clean commit
`7c0b2d7e9aa4b94312c61e1295c886df953e73e5`; launch/runtime source derives from
the retained b57 authority change on Manager e7b8f3c. Later independent analysis
uses the mainline PR #149/#150 APIs. Neither the later verifier nor CPU preflight
is a retroactive formal preregistration. Runtime Manager source is supplied by
the explicitly frozen PYTHONPATH; installed Manager distribution metadata and
that source override are both recorded.

To recompute from the retained archive:

```sh
PYTHONPATH=src:. python -m experiments.formal_campaign.h3_model_qualification \
  experiments/formal_campaign/artifacts/h3-model-qualification-20261013/raw.tar.gz
```

The verifier hashes frozen inputs, parses the retained Host event bytes and
Linux start identity, checks two distinct worker pairs, reads actual SQLite
records, checks SIGKILL/restart timing and exact marker responses, recomputes the
traffic-owned authority chain and validates cleanup. The local hash chain establishes byte integrity and source binding; it is not
a signature against an adversary rewriting every artifact. It does not trust the
coordinator's reported final route or functional-correctness summary.
