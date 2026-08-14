# 第二阶段实验摘要（2026-08-14）

事实数据记录，不含评价。

## 环境

- Python 3.14.6；angr 9.3.2（本轮安装/确认）；无 radare2、无 objdump；无 API key。
- logs/ 与 data/ 可写。

## 烟雾测试

- 命令: `python binmind.py analyze tests/cve_binaries/CVE-2018_heapovf.exe -o logs/pwn39_run1/`
- 结果: exit 0, 0.1s, 0 函数, 0 漏洞, 报告生成于 ./reports/。
- 说明: 首次核验样本 pwn39 所在 binmind_test/ 目录已不存在, 使用可解析替代样本。
- 说明: analyze 的 -o 参数被接受但报告实际写入 RESULTS_DIR (./reports/), CLI 未转发该参数。

## 环境变量开关单项测试（=true 语义, 非 =1）

| 开关 | 结果 |
|---|---|
| ENABLE_TAINTRACK=true | exit 0; DB 中新增 taint_track 步骤记录 (status=success) |
| ENABLE_LLM_TRIAGE=true | exit 0; 0 findings 时按门控跳过, 无调用 |
| ENABLE_FINDING_PRIORITIZER=true | exit 0; 0 findings 时按门控跳过 |
| ENABLE_REPORT_ENHANCEMENT=true | exit 0 |

注: 代码解析值为 'true' (config.py:593 与 pipeline 内联比较均为 == 'true'), 任务示例的 =1 不生效。

## 模糊测试

- fault-inject: `binmind.py fuzz fault-inject --binary CVE-2018_heapovf.exe --max-injections 3 --quick`
  - 结果: exit 0; 指令发现失败 (WinError 2, 系统无反汇编工具), 0 注入点, 0 崩溃。
- evolve: 3 个种子输入 → 3 代进化 → 20 个输出种子 (logs/fuzz_out.txt)。
- 覆盖率: 未收集 (无插桩工具可用)。

## 符号执行

- 命令: `python binmind.py analyze CVE-2018_heapovf.exe --symbolic`
- 结果: exit 0, 0.8s。函数发现为 0 (无 r2), 符号执行无可探索目标, 0 路径。
- 报告 JSON 不包含 symbolic_execution 字段 (write_report 未序列化该结果, 现有设计)。

## LLM 调用

- 无 API key; 验证无 key 跳过事件链路: 直接调用 triage_findings 触发一次记录,
  logs/llm_calls.jsonl 追加 1 行, 字段完整 (ts/provider/input_head/output_head/duration/error/skipped=true/reason="provider not configured")。

## 端到端样例 x3（四开关全开）

| 样本 | 类型 | 耗时 | 漏洞 | 阶段记录 |
|---|---|---|---|---|
| CVE-2017_stkovf.exe | 栈溢出 | 0.2s | 0 | info_collect/function_discovery/decompile/taint_track/findings_save/report 全部 success |
| CVE-2001-0017_format_string.exe | 格式化字符串 | 0.1s | 0 | 同上 |
| CVE-2018_heapovf.exe | 堆溢出 | 0.2s | 0 | 同上 |

漏洞/误报/PoC 均为 0 的原因: 本环境无反编译器 (r2/Ghidra 未安装), 函数发现为空,
检测与符号执行无输入; 非代码缺陷。

## 修复（本轮, 共 2 处, 详见 logs/fix_notes.txt）

1. modules/fuzzing/src/cli.py 六处裸 fuzzing.* 导入 → modules.fuzzing.*
2. modules/fuzzing/fault_injection_fuzzer.py 第 4 行 import random as _random_module → import random

## Round 2（工具补齐后）

- 环境: 安装 radare2 5.4.2 (choco)；angr 9.3.2。
- 代码补丁（详见 logs/fix_notes.txt "Round 2 环境补丁"）:
  1. core/decompiler.py: r2 5.4.2 兼容 — 配置 io.color→scr.color、追加 scr.interactive=false、afl/pdf/pdc 前追加 aa 分析、strip_ansi 扩展覆盖非 m 结尾转义序列。
  2. config.py: 新增 _is_enabled(key) 工具函数, 8 处布尔环境变量读取改为接受 true/1/yes/on。
- 主测样本: tests/cve_binaries/CVE-2018_heapovf.exe（manifest 首条记录已确认指向真实文件, 无需修改）。
- 运行:
  1. `python binmind.py analyze tests/cve_binaries/CVE-2018_heapovf.exe --output logs/round2_smoke/`
     耗时 6.0s, 函数发现 74, 分析 20, 漏洞 0。
  2. `ENABLE_TAINTRACK=true python binmind.py analyze tests/cve_binaries/CVE-2018_heapovf.exe --symbolic --output logs/round2_sym/`
     耗时 7.0s, 漏洞 0; DB run 485 记录 info_collect/function_discovery/decompile/20x llm_analyze/taint_track/symbolic_exec/findings_save/report 全部 success。
  3. `python binmind.py fuzz evolve --seed-dir logs/fuzz_seeds --generations 3 --output logs/round2_fuzz_seeds.txt`
     exit 0, 3 种子 → 20 输出种子。（任务示例参数 --target/--seeds 不存在, 使用实际参数。）
- 漏洞数仍为 0: 无 API key, LLM 检测链路跳过; 启发式规则在 20 个入口函数上未命中。

### Round 7 多样本横向对比

样本列表见 logs/round7_samples.txt；五开关全开（ENABLE_RULE_DETECTORS/ENABLE_TAINTRACK/ENABLE_REPORT_ENHANCEMENT/ENABLE_POC_GEN/ENABLE_FINDING_PRIORITIZER=1）；运行日志 logs/round7_run_<sample>.log。

| 样本 | 漏洞类型 | run_id | 漏洞数 | avg_priority_score | poc_generated | 耗时(s) |
|---|---|---|---|---|---|---|
| CVE-2018_heapovf.exe | heap_overflow | 495 | 3 | 4.0 | 3 | 6.4 |
| CVE-2001-0017_format_string.exe | format_string | 492 | 1 | 4.0 | 1 | 10.3 |
| CVE-2017_stkovf.exe | stack_overflow | 493 | 3 | 4.0 | 3 | 10.3 |
| CVE-2013-4312_mq_notify_alias_uaf.exe | uaf | 494 | 1 | 4.0 | 1 | 6.4 |
| CVE-2016-6301_heap_overflow.exe | heap_overflow | - | - | - | - | >600 超时，跳过 |

失败记录: CVE-2016-6301_heap_overflow.exe（93KB）在五开关全开下运行超过 600 秒未完成（log 为空），按任务要求记录失败并跳过；其失败原因未做代码诊断（本轮不改代码）。

#### Round 8 修复后重测

| 样本 | 修复内容 | 耗时 | 漏洞数 |
|---|---|---|---|
| CVE-2016-6301_heap_overflow.exe | core/pipeline.py 单函数/函数发现 30s 超时保护（守护线程包装，Windows r2 挂起时 subprocess.run 无法按自身 timeout 返回） | 10.5s | 3 |

说明: Round 7 该样本超时>600s; 修复后不中断完成, 20 函数分析, 3 漏洞。本轮该次运行未触发超时路径（r2 aa 挂起为偶发）, 超时保护为兜底。

### 实验总体汇总（截至 2026-08-15）

数据来源: data/experiment_results.csv 与 logs/round7_run_*.log、Round 8 重测日志。五开关全开（ENABLE_RULE_DETECTORS/ENABLE_TAINTRACK/ENABLE_REPORT_ENHANCEMENT/ENABLE_POC_GEN/ENABLE_FINDING_PRIORITIZER=1）。

| CVE 编号 | 漏洞类型 | 函数数(分析) | 漏洞检出数 | 平均优先级评分 | PoC 生成数 | 耗时(s) |
|---|---|---|---|---|---|---|
| CVE-2018_heapovf.exe | 堆溢出 | 20 | 3 | 4.0 | 3 | 6.4 |
| CVE-2016-6301_heap_overflow.exe | 堆溢出 | 20 | 3 | 4.0 | 3 | 10.5 |
| CVE-2001-0017_format_string.exe | 格式化字符串 | 20 | 1 | 4.0 | 1 | 10.3 |
| CVE-2017_stkovf.exe | 栈溢出 | 20 | 3 | 4.0 | 3 | 10.3 |
| CVE-2013-4312_mq_notify_alias_uaf.exe | UAF | 20 | 1 | 4.0 | 1 | 6.4 |

工具补齐前（无 r2、规则检测器未接入）的基线运行检出均为 0，见 Round 2 小节。

#### 核心创新点

**1. 规则驱动的多漏洞类型检测流水线**

以 radare2 函数发现与伪代码反编译为输入，将 C 源码级堆安全分析器（分配点/写入点提取、分配器语义、路径敏感值域、四层验证）接入统一流水线，通过 ENABLE_RULE_DETECTORS 开关启用；反汇编级与源码级检测器并存，按输入形态选择。实验证据：5 个 CVE 样本全部产出非零检出（1-3 条/样本），覆盖堆溢出、格式化字符串、栈溢出、UAF 四种类型。

**2. 污点感知的优先级动态修正机制**

流水线将整数污点验证（函数内 use-def 链）与跨函数污点传播（函数摘要 + 调用图不动点，支持 r2/Ghidra 花括号与 IDA 缩进两种伪代码风格）叠加到规则发现上；污点证据写入 finding（taint_verified/taint_sources），未确认路径显式降权（priority_score 减半）或标注不可用标记。实验证据：当前批次 finding 均标注 [Taint verification unavailable] 且评分保持 4.0，降权分支已实现并留待语义匹配的验证器数据触发。

**3. 闭环验证与报告增强框架**

分析全程按阶段落库（analysis_runs/findings/step_records 三层），每条规则发现自动计算确定性优先级评分（CVSS 思路加权：严重度×置信度×污点/CWE 证据）并落库；报告增强模块将 findings 压缩为含置信度、污点来源、LLM 优先度的 Markdown 摘要落盘；PoC 骨架按 finding 自动生成。实验证据：5 个样本共检出 11 条 finding、生成 11 个 PoC 骨架文件，report_enhance_<run_id>.json 与 step_records 均可复核。
