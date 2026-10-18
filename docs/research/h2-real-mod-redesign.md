# H2 重设计：真实 MOD 接口、隐式依赖与组合冲突

日期：2026-10-18。本文只做源级设计审计，未运行测试、安装、模型推理或设备任务，未修改产品源码、历史记录或 preregistration。H3 backport 和新增 fault cohort 不属于本次工作。

建议把新实验问题写成：**面对独立开发的真实 MOD，在准确版本和运行条件下，ECPA 能否以可接受的适配成本，发现实际接口/资源依赖，拒绝真实不安全组合，同时保留可以正确运行的组合？** “manifest 一致”“两个 entry point 都返回”“health 200”分别只是较低层观察，不能替代这个问题。

## 1. 历史边界与本次审计发现

历史四个独立 definite case 仍为 TP=2、TN=2、FP=FN=0；不改标签、分母、原件或原 H2 precision/recall ≥0.95 要求。旧 n=3、旧 n=5 的索引是不同修订的历史记录，不能拿其中一个覆盖当前纠偏后的 n=4。31 个 modeled case 仍单列为 modeled corpus，不作为新增真实 MOD、真实失败或设备成功。新实验应有新 cohort、独立 source inventory 和预注册，不把重做结果回填旧记录。

| 已读源码证据 | 对重设计的具体约束 |
|---|---|
| [h2_scoring_input_audit.py:72](../../experiments/real_mod_composition/h2_scoring_input_audit.py#L72) 固定保留纠偏后的四例；[H2_SCORING_INPUT_AUDIT.md:3](../../experiments/real_mod_composition/H2_SCORING_INPUT_AUDIT.md#L3) 解释 report-consumption 排除。 | 四例是历史小样本，不是新方法的发现集或最终总体证明。 |
| [collect_h2_remaining_surface_prediction.py:103](../../experiments/real_mod_composition/collect_h2_remaining_surface_prediction.py#L103) 把已诊断的 `ownership_conflicts` 输入 provider。 | 旧 external-writer match 不能证明独立发现冲突；新 predictor 输入不能含 oracle verdict、预写冲突字符串或根据标签生成的 owner 结论。 |
| [evaluate_h2_source_corpus.py:44](../../experiments/real_mod_composition/evaluate_h2_source_corpus.py#L44) 读取 oracle；116–119 行根据 `case["oracle_decision"]` 决定 `prediction="excluded"`。 | 这是旧 source-corpus evaluator 的标签可见路径；不得直接把该脚本当新 blinded predictor。这个发现不追溯改判历史四例。 |
| [audit.py:145](../../experiments/real_mod_composition/audit.py#L145) 按 `(scope, resource)` 同名检查；[ownership_observations.json:6](../../experiments/real_mod_composition/ownership_observations.json#L6) 记录 KVCompress/KNorm 两种不同 claim 名字指向同一 `Scheduler.update_from_output`。 | 声明名不同不表示物理资源不同；同一符号也不自动等于冲突。原观察明确 label=null、status=unknown，两个 wrapper 都保留 predecessor；必须核真实状态语义和顺序。 |
| [README.md:159](../../experiments/real_mod_composition/README.md#L159) 的兼容执行 workload 最大长度2048，低于9216压缩阈值；[README.md:170](../../experiments/real_mod_composition/README.md#L170) 的后续真实压缩事务因 freeze 时间问题仍为非 scoreable qualification。 | 兼容 Host 执行、事务发生、事务正确、正式 prereg、性能分别记录；不能靠一项替换另一项。 |
| [contract_planner/README.md:64](../../experiments/contract_planner/README.md#L64) 记录31 modeled decisions及 reject-all 对照。 | 保留为工程回归，不将 modeled 数量加进真实 MOD 样本数。 |

现有新 surface 候选可复用的部分也有明确边界：

- external-writer r2 从具体 Deployment/ScaledObject/HPA desired objects 推导实际目标，能合并 KEDA parent 与其 HPA，避免重复计 writer；见 [replica_writers.py:40](/root/ecpa-workspace/management/h2-external-writer-registration-candidate-r2/src/vllm_hust_ext/providers/replica_writers.py:40)、[replica_writers.py:121](/root/ecpa-workspace/management/h2-external-writer-registration-candidate-r2/src/vllm_hust_ext/providers/replica_writers.py:121)。但“no-conflict-in-declared-inventory”明确不是 global admit；[h2_external_writer_case.py:43](/root/ecpa-workspace/management/h2-external-writer-registration-candidate-r2/experiments/real_mod_composition/h2_external_writer_case.py:43) 非 conflict 仍输出 unknown。它适合新的负例检测 surface，不能凭一个安全 inventory 充当全局兼容正例，也没有证明真实集群存在这些 controller。
- scheduler pair 的独立旧 oracle 只认准确 Host 的 batch API1.1、preemption API1.0、不同 CLI/config 入口；[verify_h2_scheduler_pair.py:69](../../experiments/real_mod_composition/verify_h2_scheduler_pair.py#L69) 和100–105行明确无 Host launch。新真实 producer 只能作为采集工具，不能用自身 decision/accepted 汇总给自身充当 ground truth。
- 量化 KV CPU 候选明确为 `CPU_PLAN_SURFACE_QUALIFICATION_ONLY`、runtime oracle unknown、score_eligible=false；见 [verify_h2_quantized_kvcompress_cpu.py:30](../../experiments/real_mod_composition/verify_h2_quantized_kvcompress_cpu.py#L30)。process-carrier 候选两例同样保留 abstain；见 [verify_h2_process_carrier_predictions.py:45](../../experiments/real_mod_composition/verify_h2_process_carrier_predictions.py#L45)。已有记录不能因新设计需要更多 negative 而改标签。

## 2. Oracle 的独立性：谁可以看到什么

分成独立的源审阅与 source-blinded 运行 oracle，不能声称既不看任何 MOD 源码、又已从源码证明隐式依赖。

1. **原始源审阅者**读取准确 upstream MOD/Host 源码、构建依赖、官方配置说明和直接调用点；不看 ECPA manifest、provider/adapter 实现、planner 输出、预测或历史 match。先写物理资源/调用者/被调者/前置条件/原始证据位置，不先给出“应该被 ECPA 拒绝”的标签。独立审阅可以由隔离的工具或智能体完成，不新增人工审批门；分歧无法用原始证据解决时记录 unknown。源 reviewer 不兼任该 case 的 ECPA adapter 作者。
2. **运行 oracle**只消费独立采集的原始 Host/API/worker/设备或控制平面状态，case/method 用匿名 ID；不读取 MOD/ECPA 源码、manifest claims、planner 决策、MOD 自报 `passed` 或被测 hook 的自报成功。其判定程序和触发条件先冻结。必要的 Host 观察 hook 必须对各 arm 相同、只读、单独审阅；“同一 hook 发事件，另一个 reader 数事件”不构成两个独立证据源。
3. **ECPA/各 baseline 的预测者**可看到真实构建产物、版本、用户期望配置和允许的原始环境事实，不能看到 oracle 文件内容、verdict、评分字段或人造 conflict 字符串。仅使用无标签 input inventory；若必须绑定 oracle 完整性，只给 opaque commitment ID，由独立 scorer 连接。新 predictor 不复用上述读 `oracle_decision` 的旧 evaluator。
4. 按 input/source freeze → oracle规则及独立预期 freeze → 各方法代码/适配/config freeze → 原始预测留存 → 运行 → oracle重放 → 揭盲评分的顺序留证。对不能在运行前定性的行为，预先冻结**判定规则**而不是编造结果，结果运行后由独立 reader 得出。运行现象不符源审阅时保留两者分歧；不能用 planner 决定谁“正确”。

oracle label 必须带作用域：`declared-unsupported`、`definite-composition-conflict`、`compatible-under-frozen-condition`、`unknown`；源码版本不支持与真实同资源冲突分层报告。运行缺失 effect 的条件 case 是 `not-triggered/unknown-effect`，不是证明兼容或证明冲突。

## 3. 原 MOD 与 ECPA 适配的边界

每个 MOD 保存两份可比较的 source subject：ECPA 适配前的原始发布/commit，以及适配分支。不能只选已写好 ECPA0.3 manifest 的项目，便将“读自己的新声明”表述为处理现存混乱 MOD。保留 upstream entry point、monkey patch、环境变量、动态 import、wrapper predecessor、全局状态、外部服务、进程/线程/通信依赖与版本约束的逐项登记。

允许的 ECPA adapter 工作是事实提取、声明/配置投影、Host ABI bridge 和编排。每一项算法、状态语义、默认行为或 Host 内部 API 修改都单列为 port；需要移植时，为 manual 与 ECPA 提供**同一算法/Host二进制**，另比较编排，不能让 ECPA 使用修好的 MOD、baseline 使用原始坏版本。原生未适配结果另保留，显示“原来能否工作”。原 MOD 本身不支持当前模型/Host，不自动证明存在组合冲突；只放宽 manifest 版本也不证明支持成立。

这一区分会实际影响配置：Pipeline 的 [policy.py:50](/root/ecpa-workspace/worktrees/ecpa-conditional-pipeline-source/src/vllm_hust_pipeline_microbatch/policy.py:50) 要求 PP>1，并核准确 PP/TP、model profile 和 microbatch 数；源码不是“必须四卡”的算法条件。其历史 PP2×TP2 资格不能借给 PP2×TP1。BidKV 的 [selector.py:66](/root/ecpa-workspace/worktrees/ecpa-conditional-bidkv-source/src/bidkv/adapters/vllm_hust/selector.py:66) 默认不开 utility、受环境变量/kill switch 等控制；成功安装或构造对象不足以证明实际选择过 victim。

## 4. 数据集与 heldout：不再围绕四例挑题

基本单位是 `MOD源集合 × Host/设备插件/依赖版本集合 × 模型/拓扑 × 用户配置/触发条件`，附安装顺序和激活顺序。一次 case 的两个顺序、多个请求和重复运行不是多个独立 MOD 样本。跨版本、同一 fork、相同 adapter/源文件衍生的 case 在统计中按 family 聚类，避免复制相近版本扩大 n。

先冻结真实项目发现规则、可检索的仓库/发布日期范围和所有候选清单，再看 ECPA 结果；至少覆盖包/import、CLI/config、wrapper/共享状态、scheduler ownership、worker/通信、外部 controller 六类 surface。每个候选保留 included/excluded/unknown 的原始理由：拿不到源、缺外部服务、无共同 Host、算法本不支持目标模型、只有 inspect/import carrier，均不能静默删除。新发现 MOD 可追加新 cohort，不能在已有 holdout 评分后重选同一批容易项目。

建议有限首轮：约24个不同 source-tuple composition 单位，拟按冻结的 surface/家族分层安排12 discovery、12 heldout；这只是资源预算建议，最终数量在实际 inventory 后冻结，不能预填正负标签。所有已有四例及已反复调试过的组合只作为 legacy/development controls，不能充当从未看过的 heldout。未知数量也纳入总表，凑不足真实可定性 case 就报告不足，绝不用31 modeled补足。

holdout 至少分别报告：已见 MOD 的未见组合/顺序，与未参与 discovery 的 MOD 家族/版本。相邻版本或同一 fork 不跨两边制造“新家族”。适配者可读 upstream 源码，但看不到 sealed oracle/实际结果；core方法、规则和 adapter 在揭盲前冻结。若揭盲后加专门规则/port，原失败保留，该 case 转 development，方法的新版本只在新的未见 holdout 上评估。不能把 adapter 作者用同一个预期 verdict 写出的两个 JSON 称为独立 oracle。

## 5. 三层测量与真实运行矩阵

| 层 | 单 MOD 与组合都必须记录的原始证据 | 不能据此推出 |
|---|---|---|
| 安装/构建 | 准确 commit/tree、官方构建、wheel完整成员/RECORD、resolver/dependency 状态、实际 installed files；两个干净安装顺序；失败尝试与残留文件。 | import成功、可启动、资源语义正确。 |
| import/激活 | 独立进程的实际 import/entrypoint、最终 symbol/wrapper 链与 predecessor、配置/env真实投影、owner进程、禁用/abstain/fallback和异常；激活顺序与安装顺序分开。 | 算法在真实请求被调用、目标条件触发或产生正确实效。 |
| 运行实效/兼容 | 真实模型请求、原服务 model/RID、实际目标 API 调用及 Host 验证后 outcome、实际缓存/调度/worker/设备状态与效果不变量、所有 owned process/端口/设备 cleanup。 | 性能收益、模型质量不变、未测试版本/模型也兼容。 |

对二元组运行 `Host-only、A-only、B-only、A→B、B→A`；安装次序与调用/激活次序不等价时先做2×2矩阵。三元组仅从真实 inventory 中预选少量高风险项，含三个 singles、所有 pairs及六种激活排列，不能由 pairwise 全通过推导 triple 通过。每个单元先写触发条件、预算和终止规则；设备层每个方法至少3次独立启动建议为 prospective 新设计，按固定轮换顺序配对，失败启动照计。它不是回溯修改旧 prereg 的重复数。

对必须触发的 MOD，同时设阈值下/阈值上或压力低/压力足的 workload；前者是“不应触发”的负控，后者应由独立原始状态证明确实满足条件。若压力未达、不曾进入 selector、全走 fallback，兼容的 HTTP 请求可记 functional pass，但 effect=unknown/not-triggered，不能叫该 MOD 已起效。运行方法/原生 carrier 的额外失败、OOM、错误模型、重复 RID、迟到、cleanup失败都完整留存；不靠一次成功覆盖前次失败。

## 6. 真模型/两张设备先做哪三组

沿用已在本机实际使用的 Qwen2.5-14B 类模型文件，重新绑定准确 tokenizer/模型/source/wheel tuple；不为扩题先下载模型。两张 Ascend 910B2 由 root 分配，以下均为将来独立窗口的优先级，不代表已有新资格。

| 优先组 | 真正要测什么 | 首个设备单元与条件 | 当前不能借用的结论 |
|---|---|---|---|
| 1. KVCompress + lifecycle-profiler | 最快取得独立正控：算法与纯观察者是否共同正确工作；同时复核 implicit process/API/version 依赖。 | TP2，Host-only、各single、两顺序；短请求低于阈值，加准确 tokenizer 长请求跨越实际配置的 compression阈值。独立核 scheduler anchor/物理 block状态、两rank实际执行与原请求，profiler只证明其真实观察链。 | 历史2048长度的 formal compatible记录不能当压缩effect；历史事务qualification不回填新cohort。 |
| 2. Pipeline Microbatch + BidKV | 不同接口是否真能共同使用，配置/env隐式依赖是否改变实效；preemption的called/accepted/abstained/fallback必须分开。 | 新 PP2×TP1 固定 tuple、模型profile和实际两个controller consumer；在支持的配置下预先校准并冻结能达到真实 pressure 的请求组，再做两single和pair/顺序。Host真实验证后 admission、in-flight集合、victim合法性与实际释放/继续进展由独立reader核。 | 历史四设备PP2×TP2只是已验证范围；两卡源码可行不等于两卡资格，新的插件wheel/声明/CI也不等于运行。压力不够时保留unknown，不编造preemption。 |
| 3. KVCompress + KNorm | 优先研究最有价值的混乱 surface：不同声明名、同一scheduler wrapper、KV状态和score routing的交互及顺序。 | 先核各single原生算法可运行、准确共用Host/模型；再 TP2 两顺序真实state/worker消费与输出不变量。旧source excerpts证明值得调查，不预判冲突。 | KNorm目前冻结manifest为import_only，Manager拒激活必须保留；源码见 [source_manifests/knorm.json:32](../../experiments/real_mod_composition/source_manifests/knorm.json#L32)。若需active carrier/ABI port，先单列新source和成本、统一给manual/ECPA，未完成时该组设备cell为blocked，不强启或改标签。 |

组3若因真实 active-carrier 缺口暂不可执行，设备继续跑组1/2缺失的single/顺序/压力单元；并行做 external-writer 的真实对象/独立controller证据，无需让卡等待 oracle 文书。DiffSpec+KVCompress、DiffSpec+vSpec保留为后续未见组合/版本 surface：目前 source范围和共享Host/模型未证明时不得直接顶替成已支持TP2 cell。外部 controller 不需要模型推理，不为了“设备利用率”硬绑NPU。

## 7. 正负、unknown 与 anti-reject-all

原 H2 定义仍以 admit 为正类。报告 admit/reject 两类 precision、recall 与原≥0.95目标，同时给完整 `oracle(admit/reject/unknown) × prediction(admit/reject/unknown)` 表、总注册数、每类已判定率、每surface结果和所有被排除理由。不能只画正确 definite 子集，也不能把 unknown 当安全 admit、把 import失败改叫已检测资源冲突。

对 oracle已定性的 case，预测unknown是 abstention：原历史二分类分数若按原规则单列则照旧保留，但新主报告必须同时给全known-case分母下的覆盖/正确诊断率；例如真实admit上的成功诊断率=`predicted-admit / all-oracle-admit`，不能删去unknown再声称高recall。oracle未知本身不强行填真值。新增主报告定义/coverage要求在新cohort前登记，不偷改旧prereg。

正例应覆盖不同物理资源、合法共享/委托、正确wrapper链、可接受版本；负例分别覆盖真实同资源互斥、错误controller/通信owner、明确ABI/版本/配置冲突。合法KEDA委托不能标冲突；碰到同一symbol但两wrapper均链式调用，也不能直接标TN。必须能区分“拒绝正确”与“拒绝原因正确”：输出需包含准确owner、物理resource、触发条件及可验证修复方向，不得只用宽版本范围拒绝所有难组合。

保留 reject-all、admit-all 两个负面对照。reject-all的admit recall应为0，admit-all会在真实冲突上失败；精度的零分母记undefined，不填1。报告每个family、每个surface和两个方向的最差项，给按family聚类的不确定性/样本数。四例全对不支持总体0.95；若要声称总体下界≥0.95，应另行前置样本量/区间设计，不能把原point threshold事后解释为已达到置信下界。

## 8. Baselines、ablation 与适配成本

baseline至少包括：原MOD官方原生入口/推荐组合方式；专家manual integration；ECPA同算法/Host二进制；manifest版本与同名claim检查。各方法拿到同一无标签输入、实际环境事实和时间预算，原生与manual不得提前拿oracle诊断。原生MOD没有声明时保留“缺声明”的现实结果，不能悄悄给它ECPA adapter。专家完成修复所需的工作也计成本，不能只计最终启动命令。

在已冻结的raw输入上做有限ablation：去掉隐式dependency提取、只按claim同名判owner、去掉实际版本/协议验证、只检查install/import而不核effect。每项预测先留存再揭盲；危险ablation不通过关闭真实设备安全guard来实现，可在离线真实raw/计划投影中测诊断差异，明确该项无设备执行。去掉oracle verdict字段不是ablation，它是所有方法应满足的独立性前提。

逐MOD/tuple记录适配总成本：新增或修改生产代码与manifest的语义行数、Host/API改动、专用规则数、涉及仓库/版本数、测试与采集hook、构建/安装/资格的CPU及wall时间、人工实际操作时间、失败/返工次数、对原MOD算法行为的变化。纯format churn单列；无法观测的历史人时记unknown，不从commit时间推算。共同算法port、source审计和oracle采集成本分别披露，不能只向baseline收费或把ECPA前置port藏在“统一接口”之外。当前Pipeline/BidKV的manifest/profile/ABI bridge即使算法不变，也有真实适配成本，不能写成零。

## 9. 下一步的有限交付边界

先产出不含label的真实MOD inventory与安装/import/效果surface表、独立oracle规则、source/adapter差异和prospective cohort计划。随后冻结发现/heldout划分与全部方法输入，再安排上述三组的真实single/pair/顺序设备单元；失败、unknown、没触发及缺模型/依赖都留在总表。模型和设备执行与oracle审阅可以并行准备，不以原H3/H4全部格完成作为本次H2实验前提。

完成标准应是：独立ground truth、可复核的适配成本、真实single与组合差异、至少一种真实允许和真实拒绝、明确的运行effect与失败分母，并在前置定义的数据集上检验原0.95目标。现四例、31 modeled以及已有真实activation/transaction资格仍按各自历史范围保留。本文没有把任何新surface候选、CI、构建或成功import升级成H2实验结果。

## 本轮执行状态

本设计为 prospective draft，未签发 preregistration，未封存 heldout，未采集新 H2 实验结果。已读过源码或历史标签的组合只能进入 development/legacy controls；真正的 heldout 需要在方法冻结后另外选定和封存。当前主体是源码审计，不再把故障启动作为主线。
