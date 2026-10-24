# H3 baseline native-phase audit

The source-bound oracle in [artifacts/h3-baseline-native-oracle-20261013](https://github.com/vLLM-HUST/vllm-hust-benchmark/blob/b3d2ed2692b5575b5ae77b93fc82e32c9119be8e/archive/mod-targeted-20261023/manager-formal/snapshot/experiments/formal_campaign/artifacts/h3-baseline-native-oracle-20261013)
was frozen independently of planner and runner output. It retains exact Git
source bytes, SHA-256, revisions, and the historical H1 baseline launch argv.
Those historical commands identify activation semantics only; they are neither
new H3 launches nor admission for the current candidate wheel combination.

Both baseline commands select `ecpa-host-launch` with `--disable-ecpa-manager`.
`runtime_activation.py:parse_activation` resolves unmanaged entry points or
explicit manual hooks. `main` calls the vLLM CLI in the same process after
configuring plugin activation. Manual `install_manual_activation` invokes the
same MOD callable explicitly. The MOD registers request processing and KV
runtime hooks. None of these activation contracts creates a Manager coordinator,
durable close-intent, coordinator process or restart journal. Therefore
`manager-crash-afterprepare` is **not applicable** to either exact baseline,
rather than a health-ready phase waiting to be renamed prepare.

For ECPA, `ExposureGate.close` commits an intent before `close.before_effect`.
The existing native adapter binds that actual SQLite transaction, predecessor
route and live coordinator identity. This is source support, not a formal
model recovery result. It still requires model binding and merged Host admission.

The original cell remains incomplete with all three arms retained. Its baselines
must not receive the ECPA coordinator or its journal/recovery behavior. An
unsupported result has no recovery metric, and cannot complete the H3 matrix.

The shortest shared fault is a Host TP worker crash. The cited
`MultiprocExecutor.start_worker_monitor` watches worker sentinels and, on death,
sets `is_failed`, shuts down the executor and invokes the failure callback.
It does not replace a worker in place. A supplementary `worker-crash-full-relaunch`
cell can consequently apply one frozen external full-relaunch policy equally
to all arms, retaining worker identity and actual process death/rebirth plus
request and independent authority evidence. Its result must be described as
experiment-controlled relaunch. It cannot replace the manager-crash cell,
claim native baseline transactional recovery, or complete the original matrix.

The oracle lists the required binding, preregistration and admission evidence.
No new model start, NPU experiment or formal H3 result was performed by this audit.
The concrete next execution step is to freeze baseline launch artifacts and an
identical common worker-kill/full-relaunch policy. The runner currently assumes
an ECPA close barrier for its supported prepare path; adding a shared worker
fault requires a distinct phase/identity protocol and authority preregistration,
not merely changing its `support` string.
