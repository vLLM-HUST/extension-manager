# Actual KV + profiler pair (prospective)

This extension has its own pair input audit and source-owned carrier guard.
It does not normalize a two-plugin source tuple into the legacy singleton
request permit. A successful check does not itself authorize a public response.

`compile_pair_plan` uses both actual installed noneditable distribution snapshots
and two distinct `PluginIdentity` values. It first recompiles the original KV
contract from the independently trusted KV base, then adds the profiler's
separate loader obligations and recompiles the pair. It preserves every original
base obligation and the KV provided capability, runtime authority, all-TP2
completion, selected-native event, scope and ordinals. It never edits an executed
KV Plan. New identities and obligations generate a new content-addressed Plan.

`audit_pair_inputs` retains the complete original seven-wheel native input audit
and adds both plugin source revisions, exact wheel hashes, actual installed
runtime bytes and full static bundle snapshots (including manifests and entry
points). `PairSourceAuthority.source_current` verifies independent source/audit
trust, the complete five-component source policy, all current installed payloads
and a freshly recomputed pair Plan. These are fresh reads, not validity caches.

`PairEpochGuard.validate_current(enrollment, host_journal)` is the native carrier
interface. Original Manager handoff/Host sink trust must be independently
established. The guard verifies live kernel epochs before and after reading that
same original sink. Loader coverage is each extension × each required slot;
one plugin's receipt cannot fill the other's slot. The native enrollment must
retain its original API + two worker sender roster. Additional scheduler Host
membership is independently included in the pair roster, not forged into the
native tensor sender list. The carrier must additionally retain its generation,
membership, route lease, original completion deadline and one-use release checks.

`verify_request_pair` invokes the original full-global-prefix native consumer
without accepting a caller verdict, then joins the consumer's actual runtime
request id to the original profiler finished callback from an authority-owned
Host snapshot. The callback remains `effective` / `runtime_effective`; it never
satisfies `invoked`. It returns an observation with `public_route_authorized`
false. Public200 requires the separate live carrier's original final release.

After the root has installed the officially merged profiler wheel and audited
both installed distributions, the following command produces actual installed
pair compilation inputs, without launching, installing or issuing receipts:

```sh
PYTHONPATH=/root/ecpa-workspace/worktrees/ecpa-manager-formal-semantic-obligation-bridge \
/root/ecpa-workspace/environments/ecpa-selected-kv-attention-candidate-venv-20261014-r4/bin/python \
-m experiments.pair_semantic_candidate.prepare \
--kv-base-plan /root/ecpa-workspace/evidence/ecpa-request-semantic-tp2-20261016-r11/preparation/semantic-base-plan.json \
--kv-contract /root/ecpa-workspace/evidence/ecpa-request-semantic-tp2-20261016-r11/preparation/semantic-contract.json \
--output /root/ecpa-workspace/management/actual-installed-pair-plan-r1
```

The declared profiler slots are `api-server/0` and `engine-core-scheduler/0`.
The latter is the role explicitly bound by actual Host47
`EngineCoreProc.__init__`; only live original Host receipts and independent
kernel identities prove either slot exists in a particular launch.

For a real qualification the root must freshly freeze the pair configuration,
source policy/observation, both wheel artifacts, Manager launch/handoff, actual
roster, and native collector recipe. Its two Manager configuration entries must
include the unchanged selected-KV calibration/configuration and enabled profiler.
The Host environment must retain the Ascend platform plugin, KV plugin and
profiler entry point. A source-owned native carrier must call the pair guard,
retain every original tensor/OP/ACK/global-prefix predicate, observe the raw
profiler callback, and release and save a real nonempty public200. Missing source,
Plan, role, callback, native proof, clock or release remains a failed gate.

The original H4 protocol retains four cells, each with the original balanced
three-arm Latin square and nine independent starts. The arms remain vanilla
entry points, manual integration and ECPA. Lifecycle-only is its own original
cost scope; it cannot erase KV semantic obligations from an already declared
Plan. A qualification does not count as one of the 36 formal starts. Formal
registration must freshly bind this published implementation, matched model,
workload, topology, exact versions and warm state before starting a cohort.
