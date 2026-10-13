# H1 reachable-stack machine candidate — 2026-10-13

This packet binds exact repository-reachable source commits and the exact wheel
set used by three real two-card functional qualification runs. It remains
**unregistered**, is not a formal H1 start, and contains no performance result.

## Qualified source and wheel tuple

| Component | Commit | Tree | Reachable ref |
| --- | --- | --- | --- |
| vLLM-HUST Host | `973d9ef5acd2b9beb03e399dec1511a41fc941b5` | `9bc1a9a7dceab8bf1002a5ec5f735e5b454f11af` | `refs/heads/main` |
| vLLM-Ascend-HUST | `873584026f8a683ac73523f15127569e9f6ab34b` | `3a21eb6bec128786be61d3739268b93fda1095ac` | `refs/pull/54/head` |
| Extension Manager | `b734a923a566f3d1b07b22e087fdbab796b3b1d9` | `62d3cf4899dff86661a9debb78fa1257cb029775` | `refs/heads/main` |
| KV materialization MOD | `e343fc5ce6b4c64611a79df5d797b3db12cd6dac` | `9c64ec82cbd8c1751433131bacbbe506101e8d42` | `refs/heads/main` |

The content-addressed qualification receipt is
`h1-reachable-stack-tp2-qualification-20261013.json`. It freezes environment
digest `sha256:50ad1f54bc29cd29ddd0c4ff27b00e4eb123f4b5710bb547aea533672f51547d`
and the Ascend wheel SHA-256
`16438dc60e86c7bc4741a3520d80d5f9de54676daabe2035ebff0d6b2dceefcf`.

Vanilla and manual arms passed through `ecpa-host-launch`; their result digests
start `ae6d3dd8` and `6018755b`. The ECPA arm passed when `formal-run` launched
the exact venv Python ELF with `-m vllm.entrypoints.cli.main`; its result digest
starts `06dcd5cf`. All three reached health 200, produced a nonempty completion,
retained live PID/start-tick identities, and proved cleanup.

The earlier ECPA attempt that targeted the `ecpa-host-launch` Python console
script is retained as a failed qualification attempt. Multiprocessing spawn
treated the Manager's fd 3 launch pipe as its main-path preparation channel and
deadlocked before service health. Cleanup passed. The formal candidate therefore
uses the direct Python ELF only for ECPA, while the two baseline arms keep the
Manager-owned launch wrapper.

## Qualification boundary

This evidence qualifies only the named Qwen2.5-7B-Instruct, single-host Ascend
910B2, eager TP2, KV-materialization functional profile. It contributes zero
formal H1 starts and no latency, throughput, or other performance conclusion.
The old `b093`/`fd70`/`9f075`/`9728` preflight hashes remain historical and do
not qualify this tuple.

## Remaining admission blocker

Automated-independent command, activation-path, observer, and retention review
is separately content-addressed. Exact environment freezing and bounded
Host/Ascend qualification are complete. Producer admission and the atomic
official study/deployment/registry transition remain outstanding.

The official deployment, study, and adapter registry files are unchanged. H1
remains 0/9.
