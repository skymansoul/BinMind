#!/usr/bin/env python3
# -*- coding: utf-8 -*-

DECOMP_ANALYSIS_TEMPLATE = """
你是一个资深的二进制安全研究员和漏洞挖掘专家。请分析以下反编译后的 C 代码，识别潜在的安全漏洞。

## 二进制文件信息
- 文件路径: {binary_path}
- 函数名: {function_name}
- 保护机制:
  - NX: {nx}
  - PIE: {pie}
  - RELRO: {relro}
  - Canary: {canary}
  - ASLR: {aslr}

## 导入的危险函数:
{dangerous_functions}

## 关键字符串:
{key_strings}

## 反编译代码:
{c_code}

## 分析要求:
1. 识别潜在的安全漏洞类型（缓冲区溢出、格式化字符串、堆漏洞、UAF等）
2. 定位漏洞代码位置（行号和具体代码）
3. 分析漏洞的触发条件和影响范围
4. 评估漏洞的严重程度
5. 提供利用思路（如果可行）

## 输出格式:
请按照以下格式输出分析结果：

### 漏洞摘要
- 漏洞类型: [类型]
- 严重程度: [高/中/低/信息]
- 位置: [函数名 + 行号]

### 漏洞详情
[详细描述漏洞的成因、触发条件和影响]

### 代码分析
[分析相关代码片段，指出问题所在]

### 修复建议
[提供修复建议和安全编码实践]
"""


EXPLOIT_GENERATION_TEMPLATE = """
你是一个专业的漏洞利用开发工程师。请基于以下分析结果生成漏洞利用代码。

## 漏洞信息
- 二进制文件: {binary_path}
- 漏洞类型: {vuln_type}
- 漏洞位置: {function_name} (偏移: 0x{offset:x})
- 保护机制:
  - NX: {nx}
  - PIE: {pie}
  - RELRO: {relro}
  - Canary: {canary}

## 漏洞详情
{vuln_details}

## 可用的 gadgets:
{available_gadgets}

## libc 信息:
- libc 路径: {libc_path}
- libc 基址: 0x{libc_base:x}
- system 地址: 0x{system_addr:x}
- /bin/sh 地址: 0x{binsh_addr:x}

## 约束条件:
{constraints}

## 生成要求:
1. 生成完整的 Python 利用脚本（使用 pwntools）
2. 包含必要的注释说明
3. 处理 ASLR/PIE/NX 等保护机制
4. 提供多种利用路径（如果存在）

## 输出格式:
```python
[完整的利用代码]
```
"""


CRASH_ANALYSIS_TEMPLATE = """
你是一个专业的崩溃分析专家。请分析以下崩溃转储信息，确定崩溃原因和漏洞类型。

## 崩溃信息
- 崩溃时间: {crash_time}
- 进程ID: {pid}
- 信号: {signal}

## 寄存器状态:
{registers}

## 堆栈回溯:
{stack_trace}

## 内存映射:
{memory_map}

## 崩溃时指令:
{crash_instruction}

## 分析要求:
1. 确定崩溃原因（空指针解引用、缓冲区溢出、UAF等）
2. 定位漏洞代码位置
3. 分析是否可被利用
4. 评估漏洞严重程度

## 输出格式:
### 崩溃原因
[描述崩溃的根本原因]

### 漏洞类型
[漏洞类型分类]

### 可利用性评估
[评估是否可被利用及利用难度]

### 建议修复
[提供修复建议]
"""


PATCH_SUGGESTION_TEMPLATE = """
你是一名资深的 C/C++ 安全工程师，擅长分析漏洞并提供修复建议。

## 任务
根据以下漏洞信息和反编译代码，生成源码级补丁建议。

## 漏洞信息
- 漏洞类型: {vuln_type}
- 漏洞描述: {vuln_description}
- 目标函数: {function_name}
- 漏洞位置: 指令偏移 0x{instruction_offset:x}
- 保护机制: {protection_info}

## 反编译代码
```c
{decompiled_code}
```

## 修复建议要求
1. **分析漏洞根本原因**：深入理解漏洞的触发条件和影响范围
2. **提供具体修复方案**：
   - 对于栈溢出：建议添加边界检查或使用安全函数（如 strncpy 替代 strcpy）
   - 对于格式化字符串：建议使用参数化方式或固定格式字符串
   - 对于整数溢出：建议在运算前检查范围
   - 对于堆漏洞：建议增加分配大小检查或释放后置空
   - 对于 UAF：建议在 free 后立即置空指针
3. **生成统一 diff 格式补丁**：输出完整的 unified diff 格式补丁
4. **提供修复说明**：解释修复的原理和效果
5. **评估修复置信度**：给出 0-1 之间的置信度值

## 输出格式
请按照以下格式输出，包含 Markdown 格式的补丁块和说明：

## 修复说明
[详细描述修复方案和原理]

## 建议补丁
```diff
--- a/source.c
+++ b/source.c
@@ -起始行,行数 +起始行,行数 @@
[原始代码]
-[有漏洞的代码行]
+[修复后的代码行]
```

## 置信度
[0.0-1.0 之间的数值]

## 注意事项
- 补丁仅供参考，需经过代码审查和测试验证
- 建议结合代码上下文进行适当调整
- 修复后应进行回归测试确保不引入新问题
"""


# ==================== UEFI分析提示模板 ====================

UEFI_SMM_ANALYSIS_TEMPLATE = """
你是一位资深的 UEFI/BIOS 安全研究员，专注于 SMM（系统管理模式）漏洞分析。

## 任务
分析给定的 UEFI SMM 模块的反编译代码，识别 SMM 相关漏洞和安全问题。

## 模块信息
- 模块名称: {module_name}
- 模块 GUID: {module_guid}
- 模块类型: {module_type}
- 文件路径: {module_path}

## SMM 危险函数列表
{smm_dangerous_functions}

## 反编译代码
{c_code}

## 分析要求:
1. 识别 SMM 特定的安全漏洞（如 SMRAM 访问不当、IO 端口访问、未授权内存访问等）
2. 检查是否存在 SMI 处理程序中的安全问题
3. 分析漏洞对系统安全性的影响
4. 评估漏洞的严重程度

## 输出格式:
### 漏洞摘要
- 漏洞类型: [类型]
- 严重程度: [高/中/低/信息]
- 位置: [函数名]

### 漏洞详情
[详细描述漏洞的成因、触发条件和影响]

### 代码分析
[分析相关代码片段，指出问题所在]

### 修复建议
[提供修复建议和安全编码实践]
"""


# ==================== 模糊测试提示模板 ====================

FUZZING_ANALYSIS_TEMPLATE = """
你是一位专业的模糊测试工程师，擅长分析模糊测试结果和优化模糊测试策略。

## 任务
分析以下模糊测试结果，识别崩溃模式并优化模糊测试策略。

## 测试信息
- 目标文件: {target_binary}
- 测试时长: {duration}
- 执行次数: {executions}
- 崩溃次数: {crashes}

## 崩溃统计
{crash_statistics}

## 覆盖信息
{coverage_info}

## 种子文件分析
{seed_analysis}

## 分析要求:
1. 识别常见崩溃模式和漏洞类型
2. 分析覆盖瓶颈和优化方向
3. 提出改进模糊测试策略的建议
4. 评估测试的有效性

## 输出格式:
### 测试总结
[总结模糊测试的整体结果]

### 崩溃模式分析
[分析不同类型的崩溃及其原因]

### 覆盖分析
[分析代码覆盖情况和潜在盲区]

### 优化建议
[提供改进模糊测试策略的具体建议]
"""


# ==================== 符号执行提示模板 ====================

SYMBOLIC_ANALYSIS_TEMPLATE = """
你是一位专业的符号执行分析师，擅长分析符号执行结果和发现路径约束。

## 任务
分析以下符号执行结果，识别程序路径和约束条件。

## 分析信息
- 目标函数: {function_name}
- 路径数量: {path_count}
- 约束条件: {constraints}

## 路径分析
{path_analysis}

## 约束求解
{constraint_solving}

## 分析要求:
1. 识别关键路径和边界条件
2. 分析约束条件的可满足性
3. 发现潜在的漏洞触发路径
4. 评估符号执行的完整性

## 输出格式:
### 路径摘要
[总结符号执行的路径覆盖情况]

### 约束分析
[分析关键约束条件]

### 潜在漏洞路径
[识别可能导致漏洞的路径]

### 优化建议
[提供改进符号执行策略的建议]
"""


# ==================== 污点分析提示模板 ====================

TAINT_ANALYSIS_TEMPLATE = """
你是一位专业的污点分析专家，擅长追踪数据流向和识别安全问题。

## 任务
分析以下污点分析结果，识别数据流向和潜在安全风险。

## 分析信息
- 目标函数: {function_name}
- 污点源: {taint_sources}
- 污点汇: {taint_sinks}

## 污点传播路径
{taint_paths}

## 分析要求:
1. 识别从污点源到污点汇的传播路径
2. 分析数据如何被污染和传播
3. 识别潜在的安全风险点
4. 评估污点分析的有效性

## 输出格式:
### 污点分析摘要
[总结污点分析的整体结果]

### 传播路径分析
[分析关键的污点传播路径]

### 安全风险评估
[评估潜在的安全风险]

### 优化建议
[提供改进污点分析的建议]
"""


# ==================== 恶意软件分析提示模板 ====================

MALWARE_ANALYSIS_TEMPLATE = """
你是一位专业的恶意软件分析师，擅长识别恶意行为和提取 IOC。

## 任务
分析以下恶意软件样本的行为和特征，识别恶意活动并提取威胁指标。

## 样本信息
- 文件名: {file_name}
- 文件哈希: {file_hash}
- 文件类型: {file_type}

## 静态分析结果
{static_analysis}

## 动态分析结果
{dynamic_analysis}

## 网络活动
{network_activity}

## 分析要求:
1. 识别恶意软件的类型和家族
2. 分析恶意行为和攻击链
3. 提取威胁指标（IOC）
4. 提供检测和防护建议

## 输出格式:
### 恶意软件识别
[识别恶意软件类型和家族]

### 恶意行为分析
[分析恶意软件的行为和攻击链]

### 威胁指标 (IOC)
[列出提取的威胁指标]

### 检测建议
[提供检测和防护建议]
"""


# ==================== 规则引擎提示模板 ====================

RULE_ENGINE_TEMPLATE = """
你是一位专业的安全规则工程师，擅长编写和优化安全检测规则。

## 任务
根据以下分析结果，生成或优化安全检测规则。

## 分析信息
- 漏洞类型: {vuln_type}
- 漏洞描述: {vuln_description}
- 检测目标: {detection_target}

## 现有的规则
{existing_rules}

## 规则要求:
1. 生成或优化检测规则
2. 确保规则的准确性和效率
3. 减少误报和漏报
4. 提供规则说明和使用建议

## 输出格式:
### 规则摘要
[规则的目的和范围]

### 规则定义
```
[规则内容]
```

### 规则说明
[解释规则的工作原理和检测逻辑]

### 使用建议
[提供规则的使用场景和优化建议]
"""


# ==================== 伪代码解释提示模板 ====================

PSEUDOCODE_EXPLAINER_TEMPLATE = """
你是一位专业的逆向工程师，擅长解释复杂的伪代码逻辑。

## 任务
解释以下反编译伪代码的功能和逻辑流程。

## 代码信息
- 函数名: {function_name}
- 所属模块: {module_name}
- 代码语言: {code_language}

## 伪代码
```
{decompiled_code}
```

## 解释要求:
1. 解释函数的整体功能和目的
2. 分析代码的执行流程和逻辑
3. 识别关键的数据结构和算法
4. 解释复杂的逻辑分支和条件判断

## 输出格式:
### 功能概述
[解释函数的整体功能和目的]

### 执行流程
[分析代码的执行流程]

### 关键逻辑
[解释关键的数据结构和算法]

### 代码优化建议
[提供代码优化的建议（如果适用）]
"""


# ==================== IDS规则生成提示模板 ====================

IDS_RULE_GENERATOR_TEMPLATE = """
你是一位专业的入侵检测系统工程师，擅长编写高性能的 IDS 规则。

## 任务
根据以下漏洞或攻击模式信息，生成 IDS 检测规则。

## 攻击信息
- 攻击类型: {attack_type}
- 攻击描述: {attack_description}
- 协议类型: {protocol}
- 目标端口: {target_ports}

## 攻击特征
{attack_signatures}

## 规则要求:
1. 生成 Snort/Suricata 格式的规则
2. 确保规则的准确性和效率
3. 减少误报和漏报
4. 提供规则说明和使用建议

## 输出格式:
### 规则摘要
[规则的目的和检测范围]

### IDS 规则
```snort
[完整的 Snort/Suricata 规则]
```

### 规则说明
[解释规则的工作原理和检测逻辑]

### 使用建议
[提供规则的部署和优化建议]
"""


# ==================== Nuclei模板生成提示模板 ====================

NUCLEI_TEMPLATE_GENERATOR = """
你是一位专业的漏洞扫描工程师，擅长编写 Nuclei 漏洞扫描模板。

## 任务
根据以下漏洞信息，生成 Nuclei 扫描模板。

## 漏洞信息
- CVE编号: {cve_id}
- 漏洞类型: {vuln_type}
- 漏洞描述: {vuln_description}
- 影响版本: {affected_versions}

## 漏洞特征
{vuln_signatures}

## 模板要求:
1. 生成 Nuclei YAML 格式的模板
2. 包含必要的检测逻辑和 payload
3. 提供适当的匹配条件
4. 确保模板的准确性和效率

## 输出格式:
### 模板摘要
[模板的目的和检测范围]

### Nuclei 模板
```yaml
[完整的 Nuclei YAML 模板]
```

### 模板说明
[解释模板的工作原理和检测逻辑]

### 使用建议
[提供模板的使用和优化建议]
"""


# ==================== 二进制差异分析提示模板 ====================

BINARY_DIFF_ANALYSIS_TEMPLATE = """
你是一位资深的二进制安全研究员，擅长分析代码变更的安全影响。

## 任务
分析以下二进制文件之间的差异，识别安全相关的变更。

## 二进制文件信息
- 基准版本: {baseline_binary}
- 目标版本: {target_binary}

## 差异摘要
{diff_summary}

## 分析要求:
1. 识别安全相关的代码变更
2. 分析变更对漏洞利用的影响
3. 评估变更的安全性
4. 提供安全建议

## 输出格式:
### 差异分析摘要
[总结二进制差异的整体情况]

### 安全相关变更
[列出与安全相关的代码变更]

### 漏洞影响评估
[分析变更对漏洞利用的影响]

### 安全建议
[提供针对变更的安全建议]
"""


# ==================== 报告摘要提示模板 ====================

REPORT_SUMMARY_TEMPLATE = """
# 二进制漏洞分析报告

生成时间: {date}
目标文件: {binary_path}

---

## 执行摘要
{summary}

---

{content}

---

*本报告由 LLM-Assisted Binary Vulnerability Analysis Tool 自动生成*
"""


# ==================== 利用迭代优化提示模板 ====================

EXPLOIT_ITERATION_TEMPLATE = """
你是一位专业的漏洞利用开发工程师。请分析以下利用代码的执行结果，识别失败原因并优化利用代码。

## 当前利用代码
```python
{current_exploit}
```

## 执行结果
{execution_result}

## 失败信息
{failure_info}

## 目标二进制信息
- 文件名: {binary_name}
- 保护机制: NX={nx}, PIE={pie}, RELRO={relro}, Canary={canary}
- libc: {libc_path}

## 优化要求:
1. 分析失败原因（崩溃、无法获取shell、内存布局问题等）
2. 识别需要修改的部分
3. 优化利用代码
4. 提供详细的修改说明

## 输出格式:
### 失败分析
[分析失败原因]

### 修改建议
[提供具体的修改建议]

### 优化后的利用代码
```python
[优化后的完整利用代码]
```
"""


# ==================== 内核漏洞利用策略提示模板 ====================

KERNEL_EXPLOIT_STRATEGY_TEMPLATE = """
你是一位专业的内核漏洞研究员。请分析以下内核漏洞信息，制定利用策略。

## 漏洞信息
- 漏洞类型: {vuln_type}
- 漏洞位置: {function_name} (偏移: 0x{offset:x})
- 内核版本: {kernel_version}

## 内核保护机制
- SMEP: {smep}
- SMAP: {smap}
- KASLR: {kaslr}
- PTI: {pti}

## 漏洞详情
{vuln_details}

## 可用的利用原语
{primitives}

## 分析要求:
1. 分析漏洞的可利用性
2. 制定利用策略
3. 提供利用代码框架
4. 评估利用难度

## 输出格式:
### 利用策略
[详细描述利用策略]

### 利用步骤
[列出具体的利用步骤]

### 利用代码框架
```c
[内核利用代码框架]
```

### 难度评估
[评估利用难度和可行性]
"""


# ==================== Metasploit模块生成提示模板 ====================

METASPLOIT_MODULE_TEMPLATE = """
你是一位专业的Metasploit模块开发工程师。请根据以下漏洞信息生成Metasploit模块。

## 漏洞信息
- CVE编号: {cve_id}
- 漏洞类型: {vuln_type}
- 漏洞描述: {vuln_description}
- 影响版本: {affected_versions}

## 漏洞详情
{vuln_details}

## 目标信息
- 目标平台: {platform}
- 架构: {arch}

## 模块要求:
1. 生成完整的Metasploit Ruby模块
2. 包含必要的选项和默认值
3. 处理多种目标版本
4. 提供适当的payload支持

## 输出格式:
```ruby
[完整的Metasploit模块代码]
```
"""


# ==================== 编译器优化安全分析提示模板 ====================

COMPILER_OPT_SECURITY_TEMPLATE = """
你是一名资深的编译器安全研究员，精通 GCC/Clang/MSVC 编译选项及其安全影响。

## 任务
根据以下二进制文件的编译器优化分析结果，深入分析优化对安全性的影响，并提供专业的修复建议。

## 二进制文件信息
- 文件路径: {binary_path}
- 文件格式: {binary_format}

## 编译器信息
- 编译器: {compiler}
- 编译器版本: {compiler_version}
- 优化级别: {optimization_level}

## 安全编译标志检查结果
{security_flags}

## 优化影响分析
{optimization_impacts}

## 分析要求
1. **评估安全标志状态**: 分析每个缺失的安全标志可能带来的风险
2. **分析优化级别影响**: 评估当前优化级别对安全性的具体影响
3. **识别高危优化**: 标记可能导致安全检查被移除的优化
4. **评估代码完整性**: 判断是否存在因优化被移除的安全关键代码
5. **提供修复建议**: 针对每个问题提供具体的修复方案
6. **给出重新编译建议**: 提供平衡性能与安全的编译命令

## 输出格式
请以 JSON 格式输出分析结果，并将结果放在 ```json 代码块中：

```json
{{
    "summary": "总体分析摘要",
    "high_risk_issues": [
        {{
            "issue": "问题描述",
            "risk_level": "Critical/High/Medium/Low",
            "description": "详细描述",
            "impact": "影响评估",
            "recommendation": "修复建议",
            "fix_command": "具体修复命令"
        }}
    ],
    "medium_risk_issues": [
        {{
            "issue": "问题描述",
            "risk_level": "Medium",
            "description": "详细描述",
            "impact": "影响评估",
            "recommendation": "修复建议"
        }}
    ],
    "recompilation_advice": {{
        "optimization_level": "建议的优化级别",
        "security_flags": ["-flag1", "-flag2", "..."],
        "compiler_command": "gcc/clang 编译命令",
        "explanation": "选择理由"
    }},
    "security_critical_functions": ["func1", "func2", "..."],
    "overall_risk": "Critical/High/Medium/Low/Info",
    "confidence": 0.0-1.0
}}
```
"""

# ==================== 新增功能提示词模板 ====================

FUNCTION_DOCUMENTATION_TEMPLATE = """
你是一名资深的逆向工程专家和文档撰写专家。请为以下反编译代码中的函数生成详细的逆向分析文档。

## 函数信息
- 函数名称: {function_name}
- 函数地址: {function_address}
- 调用约定: {calling_convention}
- 参数列表: {parameters}

## 反编译伪代码:
```c
{pseudocode}
```

## AI分析结果:
{ai_analysis}

## 文档生成要求:
1. 函数功能描述：清晰描述函数的主要功能和用途
2. 参数说明：列出每个参数的类型、用途和约束条件
3. 返回值说明：描述返回值的含义和可能的取值范围
4. 内部逻辑分析：分析函数的核心算法和关键操作
5. 副作用分析：识别函数可能产生的副作用（内存修改、I/O操作等）
6. 风险评估：评估函数的安全风险等级
7. 依赖关系：列出函数调用的其他函数
8. 逆向建议：为逆向工程师提供分析建议

## 输出格式:
请按照以下Markdown格式输出文档：

### {function_name}

**地址**: `{function_address}`
**调用约定**: {calling_convention}
**风险等级**: [High/Medium/Low]

#### 功能描述
[函数功能描述]

#### 参数
| 名称 | 类型 | 描述 |
|------|------|------|
| [参数名] | [类型] | [描述] |

#### 返回值
[返回值描述]

#### 副作用
- [副作用1]
- [副作用2]

#### 依赖函数
- [函数1]
- [函数2]

#### 逆向建议
[分析建议]
"""

ANTI_VM_BYPASS_TEMPLATE = """
你是一名资深的虚拟化安全专家和反分析技术专家。请分析以下反编译代码中使用的反虚拟机/反模拟器检测技术，并提供绕过方案。

## 反编译代码:
```c
{pseudocode}
```

## 检测到的反VM技术:
{detected_techniques}

## 分析要求:
1. 识别反虚拟机检测技术：
   - CPUID检测（虚拟机特征值）
   - 注册表检测（VMware/VirtualBox注册表键）
   - 文件检测（虚拟机驱动文件）
   - 进程检测（虚拟机进程）
   - 网络检测（虚拟机MAC地址）
   - 时间检测（rdtsc计时差异）

2. 分析检测逻辑：
   - 检测函数的入口条件
   - 检测成功/失败的判断标准
   - 检测结果的处理方式

3. 生成绕过方案：
   - Frida脚本：hook检测函数返回预期值
   - LD_PRELOAD库：覆盖相关系统调用
   - Unicorn模拟：设置正确的CPUID值
   - 环境变量：设置绕过检测的环境

## 输出格式:
请按照以下JSON格式输出：

```json
{
    "anti_vm_techniques": [
        {
            "type": "技术类型",
            "location": "代码位置",
            "severity": "严重程度",
            "bypass_method": "绕过方法",
            "bypass_script": "脚本内容"
        }
    ],
    "recommended_bypass": "推荐绕过方案",
    "confidence": 0.0-1.0
}
```
"""

ROP_GADGET_ANALYSIS_TEMPLATE = """
你是一名资深的漏洞利用专家和ROP技术专家。请分析以下ROP gadgets并评估其利用潜力。

## ROP Gadgets列表:
{gadgets_list}

## 目标架构: {architecture}

## 分析要求:
1. Gadget分类：
   - 栈迁移（stack pivot）：leave; ret, pop rsp; ret
   - 寄存器控制：pop reg; ret, mov reg, reg; ret
   - 内存访问：mov [reg], reg; ret
   - 系统调用：syscall; ret
   - 函数调用：call reg

2. 利用潜力评估：
   - 寄存器修改范围
   - 栈消耗量
   - 副作用分析
   - 与其他gadget的兼容性

3. 建议利用链：
   - 栈迁移链
   - 寄存器控制链
   - 系统调用链
   - 内存写入链

## 输出格式:
请按照以下JSON格式输出：

```json
{
    "gadget_analysis": [
        {
            "address": "地址",
            "instruction": "指令",
            "category": "类别",
            "score": 0-100,
            "affected_regs": ["寄存器列表"],
            "side_effects": ["副作用列表"],
            "stack_consumption": 栈消耗字节数
        }
    ],
    "recommended_chains": [
        {
            "purpose": "链用途",
            "gadgets": ["地址列表"],
            "feasibility": 0.0-1.0
        }
    ]
}
```
"""

REPACK_ANALYSIS_TEMPLATE = """
你是一名资深的恶意软件分析师和二进制完整性专家。请分析以下二进制文件是否被重打包或捆绑恶意载荷。

## 文件信息:
- 文件路径: {file_path}
- 文件类型: {file_type}
- 原始签名: {original_signature}

## 节区信息:
{sections_info}

## 异常检测结果:
{anomalies}

## 分析要求:
1. 重打包类型识别：
   - 注入代码：额外的节区或代码段
   - 捆绑载荷：覆盖数据或附加文件
   - 资源修改：资源节区的变化
   - 入口点Hook：入口点被修改

2. 原始宿主识别：
   - 通过签名识别原始软件
   - 通过节区特征识别
   - 通过导入表识别

3. 风险评估：
   - 恶意载荷类型
   - 影响范围
   - 检测难度

## 输出格式:
请按照以下JSON格式输出：

```json
{
    "is_repacked": true/false,
    "repack_type": "类型",
    "original_software": "原始软件名称",
    "payload_analysis": {
        "type": "载荷类型",
        "location": "载荷位置",
        "capabilities": ["能力列表"]
    },
    "risk_assessment": {
        "severity": "严重程度",
        "confidence": 0.0-1.0
    }
}
```
"""

CODE_SIGNING_ANALYSIS_TEMPLATE = """
你是一名资深的数字签名安全专家。请分析以下PE文件的数字签名并验证其有效性。

## 签名信息:
- 签名状态: {signature_status}
- 签名算法: {signature_algorithm}
- 证书链: {certificate_chain}

## 证书详情:
{certificate_details}

## 分析要求:
1. 签名有效性验证：
   - 签名算法强度（SHA1/SHA256）
   - 证书有效期
   - 证书链完整性
   - 根证书信任状态

2. 证书滥用检测：
   - 是否为自签名证书
   - 是否在泄露证书数据库中
   - 是否被多个恶意软件使用

3. 风险评估：
   - 签名伪造可能性
   - 证书盗用可能性
   - 整体信任度

## 输出格式:
请按照以下JSON格式输出：

```json
{
    "signature_validity": {
        "is_valid": true/false,
        "algorithm_strength": "strong/weak/deprecated",
        "chain_complete": true/false
    },
    "certificate_analysis": [
        {
            "subject": "证书主体",
            "issuer": "发行者",
            "is_self_signed": true/false,
            "is_leaked": true/false,
            "risk_level": "风险等级"
        }
    ],
    "overall_risk": {
        "level": "风险等级",
        "recommendation": "建议"
    }
}
```
"""
