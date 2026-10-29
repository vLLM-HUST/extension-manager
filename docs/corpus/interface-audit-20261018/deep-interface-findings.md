# 真实 MOD 接口与组合面源码深审

本次核对10条具体接口事实。最直接的结论：**Pipeline 与现有 KVCompress 的 PP 约束无共同可行配置；BidKV legacy 与 KV 类级 patch 存在可构造的顺序敏感面；Ascend153535→Host66 已有真实 CPU import 失败。** 前两类不是新增设备冲突 oracle，第三类也不是 NPU 资格结果。

ECPA 现有代码能校验已声明的 Host 版本并裁决同一 canonical URI 的 exclusive ownership；不能自动从 Python monkeypatch、import graph 或物理缓存 alias 中发现完整冲突。下面的“需适配”是现实缺口，不是已实现承诺。

| ID | 源码问题 | 证据类别 | ECPA 当前边界 |
|---|---|---|---|
| MOD-01 | 安装发现不等于可调用策略；Pipeline 原生于 HUST 定制 ABI，而非通用 vLLM 插件 | observed_source | Host 自有 factory/callsite 与实际 invocation 证据 |
| MOD-02 | Pipeline 与 KV compression 的 PP 约束明确不相交 | source_derived_incompatibility_not_runtime_oracle | 从源提取并认证 PP/TP/并行模式约束 |
| MOD-03 | BidKV 功能调用与压力下产生 utility effect 是不同命题 | observed_source | Host 验证后 accepted-victim 与原控制 query 的身份连接 |
| MOD-04 | BidKV legacy monkeypatch 与 KV 类级 hook 存在具体顺序敏感面 | source_derived_order_counterexample_not_executed | 实际 class/instance method owner、链头/原方法及卸载所有权检查 |
| MOD-05 | KVCompress 的真实 ABI 是私有 runner/cache 结构，不是版本范围一个字段 | observed_source | 具体 ABI shape 与 source owner 校验、精确可维护的版本适配 |
| MOD-06 | KV compression 与 preemption/APC 共享的是物理缓存状态而非单个插件名称 | observed_source_with_unverified_pair_hypothesis | 把真实 block pool/request 生命周期依赖投影为可信共同资源与 obligations |
| MOD-07 | 兼容 shim 会改变进程共享命名空间，幂等 marker 不等于可组合 | observed_source | 默认值/类属性原像与后像、配置一致性、变更撤销所有权 |
| MOD-08 | Ascend 到 Host 的隐式 import 边已经产生真实 CPU 反例 | actual_runtime_CPU_counterexample_not_NPU | 正确源码 backport 或严格 Host/Ascend API 迁移 |
| MOD-09 | Profiler 依赖 HUST EventBus ABI 和逐进程注册，非标准 HTTP 日志采样 | observed_source | 每进程 actual EventBus 注册与原事件身份联结 |
| MOD-10 | Profiler fail-open 与原完整性验收必须分开 | observed_source | 按原 loss intervals、producer sequence、terminal summary 验证完整性 |

仓库快照均为本次只读观察时的精确 HEAD/tree，状态记录在 JSON。KV 使用真实 d409 source；另列2f H4采样分支，未借其声明替换当前源。Ascend 使用真实153535 checkout，而非其他54d/8735本地分支。

## MOD-01 — 安装发现不等于可调用策略；Pipeline 原生于 HUST 定制 ABI，而非通用 vLLM 插件

Pipeline 主包仅导出 extension_bundles 与 from_config/admit_batch；读取 BatchAdmissionContext、max_concurrent_batches 和 PP 拓扑。没有 general_plugins 自动启用入口。

加载 manifest 或安装 wheel 不能证明 Host 调度器构造并调用策略；必须绑定实际 factory、Host callsite 和返回后的验证。planner 以 p0..p5、request/context length 与每rank layer数预测 worst-rank cost；另一MOD改变上下文或计算成本后，原系数有效性是待测假设，预测本身不是性能实测。

来源/新增适配边界：当前 narrow dev19 声明及 _manager_runtime_qualification 是本次研究新增发布声明，policy/planner 算法没有因声明而新增。HUST batch-admission 不是这里证明的上游公共 API。

当前可处理：声明发现、版本/协议筛选、显式 activation artifact 绑定。需适配：Host 自有 factory/callsite 与实际 invocation 证据。未解决：当前审计没有新的 PP2TP1 功能/效果实测。

- [`pyproject.toml:17`](sources/deep-pipeline/pyproject.toml.snapshot#L17)，commit `4b8bafda91d2db6d8cf5f689a03eb13734bfa510`；精确Git blob `0dda3c3ef5989215dc0b1e255ff5349176f90da3`，行17–21（逐行代码/文件SHA见JSON）。
- [`src/vllm_hust_pipeline_microbatch/policy.py:43`](sources/deep-pipeline/src/vllm_hust_pipeline_microbatch/policy.py.snapshot#L43)，commit `4b8bafda91d2db6d8cf5f689a03eb13734bfa510`；精确Git blob `df8a9ba1f51aaa5629a82527406d8699a5f00340`，行43–62（逐行代码/文件SHA见JSON）。
- [`src/vllm_hust_pipeline_microbatch/policy.py:83`](sources/deep-pipeline/src/vllm_hust_pipeline_microbatch/policy.py.snapshot#L83)，commit `4b8bafda91d2db6d8cf5f689a03eb13734bfa510`；精确Git blob `df8a9ba1f51aaa5629a82527406d8699a5f00340`，行83–92（逐行代码/文件SHA见JSON）。
- [`docs/conditional-host031-unqualified-release.md:1`](sources/deep-pipeline/docs/conditional-host031-unqualified-release.md.snapshot#L1)，commit `4b8bafda91d2db6d8cf5f689a03eb13734bfa510`；精确Git blob `f8be2291341d82caa04b0378807314ce80e8cb03`，行1–7（逐行代码/文件SHA见JSON）。

- [`planner.py:20`](sources/deep-pipeline/src/vllm_hust_pipeline_microbatch/planner.py.snapshot#L20)，同Pipeline精确commit；rank-local公式/最差rank选择与完整源码片段见JSON（20–34、61–87行）。

## MOD-02 — Pipeline 与 KV compression 的 PP 约束明确不相交

Pipeline 要求 pipeline_parallel_size>1；当前 d409 KV stateful Host 验证要求 pipeline/data/prefill-context/decode-context parallel size 均为1。

同一进程配置下二者的 PP 可行域为空。不能靠禁用其中一个仍称 pair compatible，也不能把 Pipeline+BidKV 候选混成 Pipeline+KVCompress。两者 manifest 的 host 身份不同，不能直接比较版本字符串得出此结论。

来源/新增适配边界：这是原策略/状态协调代码的约束，不是本次构造的 compatibility 标签。

当前可处理：将真实拓扑谓词纳入 adapter/contract 后在启动前拒绝该组合。需适配：从源提取并认证 PP/TP/并行模式约束。未解决：不应放宽 KV 算法的 PP 支持来获得一个正标签。

- [`src/vllm_hust_pipeline_microbatch/policy.py:49`](sources/deep-pipeline/src/vllm_hust_pipeline_microbatch/policy.py.snapshot#L49)，commit `4b8bafda91d2db6d8cf5f689a03eb13734bfa510`；精确Git blob `df8a9ba1f51aaa5629a82527406d8699a5f00340`，行49–62（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/stateful.py:221`](sources/deep-kv/src/vllm_ascend_kvcompress/stateful.py.snapshot#L221)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `3142c55ce11d0f0e01be8fbb02740d98aff3435f`，行221–230（逐行代码/文件SHA见JSON）。

## MOD-03 — BidKV 功能调用与压力下产生 utility effect 是不同命题

原策略从 context.candidates/kv_cache_usage/now 选择 victim；running 为空拒绝，utility gate 会因 running 数、缺失/不足 KV utilization、cooldown 而返回 false；实例保留最近选择与 preemption 历史。

正常 HTTP 输出、已构造策略或全候选 fallback 不证明发生 BidKV utility preemption。maxseq1/无压力下 effects 可缺失；缺失必须保留 unknown/negative，不能前置为插件未安装，也不能当32个效果通过。

来源/新增适配边界：这些 gate 与统计来自实际 BidKV 算法。研究的32选择/typed qualification/record bridge 是另外新增的测量与管理层。

当前可处理：绑定条件声明、原请求/策略调用、功能与 effect 两级结果。需适配：Host 验证后 accepted-victim 与原控制 query 的身份连接。未解决：无运行压力证据时不能证明 pair 的条件成立。

- [`src/bidkv/adapters/vllm_hust/selector.py:273`](sources/deep-bidkv/src/bidkv/adapters/vllm_hust/selector.py.snapshot#L273)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `2d79dd5a683414498df474e86f5c1598b2378ed1`，行273–295（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm_hust/selector.py:318`](sources/deep-bidkv/src/bidkv/adapters/vllm_hust/selector.py.snapshot#L318)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `2d79dd5a683414498df474e86f5c1598b2378ed1`，行318–342（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm_hust/selector.py:682`](sources/deep-bidkv/src/bidkv/adapters/vllm_hust/selector.py.snapshot#L682)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `2d79dd5a683414498df474e86f5c1598b2378ed1`，行682–705（逐行代码/文件SHA见JSON）。

## MOD-04 — BidKV legacy monkeypatch 与 KV 类级 hook 存在具体顺序敏感面

BidKV legacy 包单独提供 general plugin，主包不注册；legacy 模式包裹 Scheduler.__init__，再把 schedule/update_from_output/_free_request/_preempt_request 写到实例。KVCompress 则保存并替换 Scheduler 类的 __init__/schedule/update_from_output。

若一个已被 BidKV 实例级覆盖的 Scheduler 之后才安装 KV 类级 schedule wrapper，Python 实例属性优先于类方法，已有实例仍可绕过新类 wrapper。相反，KV 类 hook 先装、BidKV 后从已包裹实例捕获原方法，是另一条组合链。这是可构造源级反例，不是本机已测冲突。

来源/新增适配边界：必须区分 BidKV 明确标注 legacy 实验路径与 native PreemptionPolicy 路径；不能用 legacy 的冲突证据给 native pair 自动贴标签。

当前可处理：若真实声明同一调度方法的 exclusive ownership，可拒绝；可固定激活顺序并记录 scope。需适配：实际 class/instance method owner、链头/原方法及卸载所有权检查。未解决：当前逻辑资源 URI 不自动发现 Python 属性别名/覆盖关系。

- [`src/bidkv/adapters/vllm/plugin.py:1`](sources/deep-bidkv/src/bidkv/adapters/vllm/plugin.py.snapshot#L1)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `d214a3629310976687e3b2d7a573c958684ec6e4`，行1–17（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm/plugin.py:75`](sources/deep-bidkv/src/bidkv/adapters/vllm/plugin.py.snapshot#L75)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `d214a3629310976687e3b2d7a573c958684ec6e4`，行75–100（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm/scheduler_hook.py:57`](sources/deep-bidkv/src/bidkv/adapters/vllm/scheduler_hook.py.snapshot#L57)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `dd3664f30722ce1bf7138be13df0e1ec17bb1b87`，行57–77（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm/scheduler_hook.py:114`](sources/deep-bidkv/src/bidkv/adapters/vllm/scheduler_hook.py.snapshot#L114)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `dd3664f30722ce1bf7138be13df0e1ec17bb1b87`，行114–134（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/stateful.py:580`](sources/deep-kv/src/vllm_ascend_kvcompress/stateful.py.snapshot#L580)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `3142c55ce11d0f0e01be8fbb02740d98aff3435f`，行580–619（逐行代码/文件SHA见JSON）。

## MOD-05 — KVCompress 的真实 ABI 是私有 runner/cache 结构，不是版本范围一个字段

显式 register 后安装 meta_path finder 包裹 vllm_ascend.worker.model_runner_v1 loader；读取 NPUModelRunner 的 initialize_kv_cache/load_model/_update_states/_build_attention_metadata/sample_tokens。状态侧还验证 scheduler 类型、balance、speculative、KV transfer 和 APC 方法。

即使 metadata 版本匹配，任一字段/签名/结构迁移仍会使 load 或执行失败。当前 narrow supported tuple 不能外推到所有0.31；同一 Host 名字也不保证实际 Ascend concrete BlockTable。

来源/新增适配边界：该插件自身已含 host_compat 兼容层；不能把它注入的旧字段和类型当成上游 Host 原有 API。

当前可处理：绑定真实版本/源/轮闭包及明确声明的需求。需适配：具体 ABI shape 与 source owner 校验、精确可维护的版本适配。未解决：不能仅凭 manifest 推导代码级接口兼容。

- [`src/vllm_ascend_kvcompress/plugin.py:74`](sources/deep-kv/src/vllm_ascend_kvcompress/plugin.py.snapshot#L74)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `53110d8570eed4d0cd438d9cf5a37e4bfba05d33`，行74–112（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/plugin.py:115`](sources/deep-kv/src/vllm_ascend_kvcompress/plugin.py.snapshot#L115)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `53110d8570eed4d0cd438d9cf5a37e4bfba05d33`，行115–150（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/stateful.py:193`](sources/deep-kv/src/vllm_ascend_kvcompress/stateful.py.snapshot#L193)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `3142c55ce11d0f0e01be8fbb02740d98aff3435f`，行193–220（逐行代码/文件SHA见JSON）。

## MOD-06 — KV compression 与 preemption/APC 共享的是物理缓存状态而非单个插件名称

KV 状态协调持有 coordinator/single_type_managers/block_pool，提交 pending 压缩与延迟释放；manager.free wrapper 清理 offsets/pending 并归还 reserved blocks。runner 的 slot_mapping hook 在实际 Ascend table 上把 positions 转物理位置。

BidKV 选择 victim 后由 Host 真正 preempt/free，因此潜在相互作用涉及 request ID、reserved blocks、semantic/physical lengths 和释放时序。仅不同 entrypoint/不同资源字符串不能证明二者互不干扰。

来源/新增适配边界：物理 slot/table 适配属于现有 KV 插件自己实现；研究 native tensor/OP/ACK 观察用于证明执行，不是该缓存语义的原始接口。

当前可处理：有同一 canonical resource 声明时进行所有权/排他裁决。需适配：把真实 block pool/request 生命周期依赖投影为可信共同资源与 obligations。未解决：尚无此 pair 的实际 preemption+compression 双顺序 native 反例或正例。

- [`src/vllm_ascend_kvcompress/stateful.py:301`](sources/deep-kv/src/vllm_ascend_kvcompress/stateful.py.snapshot#L301)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `3142c55ce11d0f0e01be8fbb02740d98aff3435f`，行301–324（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/stateful.py:622`](sources/deep-kv/src/vllm_ascend_kvcompress/stateful.py.snapshot#L622)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `3142c55ce11d0f0e01be8fbb02740d98aff3435f`，行622–638（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/plugin.py:463`](sources/deep-kv/src/vllm_ascend_kvcompress/plugin.py.snapshot#L463)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `53110d8570eed4d0cd438d9cf5a37e4bfba05d33`，行463–505（逐行代码/文件SHA见JSON）。
- [`src/bidkv/adapters/vllm_hust/selector.py:318`](sources/deep-bidkv/src/bidkv/adapters/vllm_hust/selector.py.snapshot#L318)，commit `3d7fdc9f7e8ba6cb7076811b15065862d8675440`；精确Git blob `2d79dd5a683414498df474e86f5c1598b2378ed1`，行318–342（逐行代码/文件SHA见JSON）。

## MOD-07 — 兼容 shim 会改变进程共享命名空间，幂等 marker 不等于可组合

KV 插件在 loader/runner 初始化时补缺失的 routed-experts/输出字段/DCP/FP32 alias；另按环境改写 MessageQueue.__init__.__defaults__ 的 chunk 大小，并用类 marker 跳过后续安装。

另一个 MOD 若依赖相同类默认值或不同旧字段语义，安装顺序及第一配置会影响后续调用。marker 证明“装过”，不证明“当前拥有者/配置与请求一致”或可安全卸载。

来源/新增适配边界：这些均是插件仓里真实兼容代码，不能表述为 upstream 仍保证的稳定 API；源码具体 owner 必须包括这个适配层。

当前可处理：显式声明进程全局变更资源及互斥。需适配：默认值/类属性原像与后像、配置一致性、变更撤销所有权。未解决：没有自动发现和证明任意 monkeypatch 可交换的能力。

- [`src/vllm_ascend_kvcompress/plugin.py:122`](sources/deep-kv/src/vllm_ascend_kvcompress/plugin.py.snapshot#L122)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `53110d8570eed4d0cd438d9cf5a37e4bfba05d33`，行122–145（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/plugin.py:438`](sources/deep-kv/src/vllm_ascend_kvcompress/plugin.py.snapshot#L438)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `53110d8570eed4d0cd438d9cf5a37e4bfba05d33`，行438–456（逐行代码/文件SHA见JSON）。
- [`src/vllm_ascend_kvcompress/host_compat.py:248`](sources/deep-kv/src/vllm_ascend_kvcompress/host_compat.py.snapshot#L248)，commit `d4090a888f971ea50e874cdf86bf63a8e22e647f`；精确Git blob `bedda47252ea48ca9b0b49e644a42904dbce0695`，行248–274（逐行代码/文件SHA见JSON）。

## MOD-08 — Ascend 到 Host 的隐式 import 边已经产生真实 CPU 反例

Ascend153535 global patch 由 connector/model-loader entrypoints 触发；模型 runner 的 attention import 链到 DeepSeek compressor，并无条件 import Host DeepseekV4Config。

新 Host66 dev414 的 metadata/已安装 manifest 范围能通过，但实际导入 Ascend model_runner_v1 因移除的 vllm.transformers_utils.configs.deepseek_v4 失败。老731确有此模块。这是一个无关当前Qwen模型也会触发的隐式 import 依赖，不能通过扩大版本声明修复。

来源/新增适配边界：Ascend _ensure_global_patch 和 plugin 中的补丁不是 Manager 原生生命周期接口；Host66 main55 演进与我们新增 H3 probe 叠加的源码应分别记账。

当前可处理：管理侧独立 CPU ABI 预检已经捕获该失败；这不证明 ECPA compiler 自动发现了隐式 import 依赖。需适配：正确源码 backport 或严格 Host/Ascend API 迁移。未解决：版本范围/逻辑资源声明本身未发现这个 import graph 缺边。

- [`vllm_ascend/__init__.py:42`](sources/deep-ascend/vllm_ascend/__init__.py.snapshot#L42)，commit `153535b32417b3ad8fb10dad2f564ddf4dcab1ef`；精确Git blob `a00d44e437d1860b5e77cdd63474aff33909ab49`，行42–62（逐行代码/文件SHA见JSON）。
- [`vllm_ascend/__init__.py:65`](sources/deep-ascend/vllm_ascend/__init__.py.snapshot#L65)，commit `153535b32417b3ad8fb10dad2f564ddf4dcab1ef`；精确Git blob `a00d44e437d1860b5e77cdd63474aff33909ab49`，行65–82（逐行代码/文件SHA见JSON）。
- [`vllm_ascend/models/deepseek_v4/compressor.py:31`](sources/deep-ascend/vllm_ascend/models/deepseek_v4/compressor.py.snapshot#L31)，commit `153535b32417b3ad8fb10dad2f564ddf4dcab1ef`；精确Git blob `0aec2bc8928f147804366d959a7ebe039faa1f63`，行31–38（逐行代码/文件SHA见JSON）。

真实CPU原件：[actual-CPU-ABI.json](/root/ecpa-workspace/management/h3-new-host66-private-runtime-next-20261018-r1/actual-CPU-ABI.json)；错误 `ModuleNotFoundError: No module named 'vllm.transformers_utils.configs.deepseek_v4'`。

## MOD-09 — Profiler 依赖 HUST EventBus ABI 和逐进程注册，非标准 HTTP 日志采样

register_plugin 强要求 vllm.v1.events 的 EventBus、RequestFinished/Preempted/KvReclaimed 与 API_VERSION==1.0；以 PID 保护重复注册，fork 后注销继承 sink 再创建新 sink，run_id 可取真实 launch ID。

一个进程注册成功不能覆盖 API/scheduler 其他进程；HTTP request ID 也不能代替 EventBus 原 runtimeID/epoch。组合证据必须绑定产生事件的具体进程与真实 request_finished。

来源/新增适配边界：request-lifecycle-events 明确是 vLLM-HUST 提供的 ABI。研究新 H4 opaque-ID/profiler join 是新增验收桥，不能称上游官方通用能力。

当前可处理：为已声明的 role/epoch 约束建立 evidence obligations。需适配：每进程 actual EventBus 注册与原事件身份联结。未解决：安装/entrypoint 发现不证明各实际进程有效订阅。

- [`src/vllm_request_lifecycle_profiler/plugin.py:23`](sources/deep-profiler/src/vllm_request_lifecycle_profiler/plugin.py.snapshot#L23)，commit `23caefeaf2e61f3f0f9f8d3599314b6732eb2a8f`；精确Git blob `aee8c1f52c5bdbcebf54f2b23851e75c1f26e478`，行23–53（逐行代码/文件SHA见JSON）。
- [`src/vllm_request_lifecycle_profiler/plugin.py:61`](sources/deep-profiler/src/vllm_request_lifecycle_profiler/plugin.py.snapshot#L61)，commit `23caefeaf2e61f3f0f9f8d3599314b6732eb2a8f`；精确Git blob `aee8c1f52c5bdbcebf54f2b23851e75c1f26e478`，行61–76（逐行代码/文件SHA见JSON）。

## MOD-10 — Profiler fail-open 与原完整性验收必须分开

runtime_hooks 在序列化失败/队列溢出时记 loss/drop 并返回None，使 serving fail-open；可选 KV recovery observer 注册失败仅记录 exception。

服务200可以与缺失 profiler facts 共存，因此不能把200当完整观测，更不能把“shared observer resource”当零影响/无丢失证明。反之，observability 缺证不自动证明原模型功能失败，应分功能、完整性和统计可用性。

来源/新增适配边界：这是原 profiler 的故障语义；研究的强 evidence gate/failed-slot 分类与其 fail-open serving 行为不是同一协议。

当前可处理：明确 obligation 未满足/数据不可用，并保留功能结果与 loss facts。需适配：按原 loss intervals、producer sequence、terminal summary 验证完整性。未解决：Manager 不能以启动成功消除 bounded queue 的实际丢失风险。

- [`src/vllm_request_lifecycle_profiler/runtime_hooks.py:387`](sources/deep-profiler/src/vllm_request_lifecycle_profiler/runtime_hooks.py.snapshot#L387)，commit `23caefeaf2e61f3f0f9f8d3599314b6732eb2a8f`；精确Git blob `0d1c67f1969f598442574c216958cf0b01445fb5`，行387–411（逐行代码/文件SHA见JSON）。
- [`src/vllm_request_lifecycle_profiler/plugin.py:94`](sources/deep-profiler/src/vllm_request_lifecycle_profiler/plugin.py.snapshot#L94)，commit `23caefeaf2e61f3f0f9f8d3599314b6732eb2a8f`；精确Git blob `aee8c1f52c5bdbcebf54f2b23851e75c1f26e478`，行94–107（逐行代码/文件SHA见JSON）。

## 可直接用于正文的短摘要

真实插件边界比 entrypoint 和版本范围更深：Pipeline 调度策略消费 HUST 私有 batch-admission 上下文并要求 PP>1，而 KV 压缩状态机要求 PP=1；BidKV 的 legacy 路径覆写实例调度方法，KV 插件同时覆写类级调度和缓存方法，激活顺序影响实际调用链。BidKV native utility 还依赖运行队列、KV 压力与 cooldown，功能可用不能替代效果已发生。Ascend 的无条件模型导入边在一次真实 CPU 检查中越过了 manifest 版本接受，却因 Host 移除配置模块失败；Profiler 的 bounded fail-open 出口则允许服务成功和观测缺失同时出现。上述事实支持对“依赖与资源模型需要真实接口适配”的论证，但本次源码审计没有制造新的运行兼容 oracle。

该材料与历史 H2 24项人口清点独立，不重分类历史标签；未执行新组合实验，未修改产品源/当前SDK/runtime/实验或其他总稿。

“原/既有实现”仅指上述精确插件Git源的算法与接口，未将vLLM-HUST fork ABI冒称上游vLLM公共ABI。源码约束、源级可构造顺序反例、真实CPU反例、待测性能/并发假设分别标注；没有新兼容/冲突标签。
