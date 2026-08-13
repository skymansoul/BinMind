DECOMP_ANALYSIS_TEMPLATE = """
你是一个资深的二进制安全研究员和漏洞挖掘专家。请分析以下反编译后的 C 代码，识别潜在的安全漏洞。

# 二进制文件信息
- 文件路径: {binary_path}
- 函数名: {function_name}
- 保护机制:
  - NX: {nx}
  - PIE: {pie}
  - RELRO: {relro}
  - Canary: {canary}
  - ASLR: {aslr}

# 导入的危险函数:
{dangerous_functions}

# 关键字符串:
{key_strings}

# 反编译代码:
```c
{pseudocode}
```

# 分析要求:
1. 仔细阅读代码，识别可能存在的安全漏洞
2. 关注以下常见漏洞类型:
   - 栈溢出 (Stack Overflow)
   - 格式化字符串漏洞 (Format String)
   - 堆溢出 (Heap Overflow)
   - 使用后释放 (Use-After-Free)
   - 空指针引用 (Null Pointer Dereference)
   - 整数溢出 (Integer Overflow)
   - 条件竞争 (Race Condition)
   - 命令注入 (Command Injection)
3. 对每个发现的漏洞，提供:
   - 漏洞类型
   - 漏洞位置 (行号或代码片段)
   - 触发条件
   - 严重程度 (Critical/High/Medium/Low)
   - 可能的利用方式
4. 如果没有发现明显漏洞，请说明代码的安全特性

请以 JSON 格式输出分析结果，并将结果放在 ```json 代码块中，格式如下:

```json
{{
    "vulnerabilities": [
        {{
            "type": "漏洞类型",
            "location": "漏洞位置",
            "description": "漏洞描述",
            "severity": "严重程度",
            "exploitation": "利用方式说明",
            "code_snippet": "相关代码"
        }}
    ],
    "summary": "总体分析摘要",
    "risk_level": "整体风险等级"
}}
```
"""

CRASH_ANALYSIS_TEMPLATE = """
你是一个资深的二进制安全研究员。请分析以下程序崩溃信息，判断漏洞类型。

# 崩溃信息
# 寄存器状态:
{registers}

# 栈回溯:
{stack_trace}

# 崩溃时的指令:
{fault_instruction}

# 程序输出:
{program_output}

# 保护机制信息:
{protection_info}

# 分析要求:
1. 根据崩溃信息判断漏洞类型
2. 分析漏洞可利用性
3. 估算可能的利用难度
4. 提供验证建议

请以 JSON 格式输出分析结果，并将结果放在 ```json 代码块中:

```json
{{
    "crash_type": "崩溃类型",
    "vulnerability_type": "漏洞类型",
    "analysis": "详细分析",
    "exploitability": "可利用性评估",
    "difficulty": "利用难度 (Easy/Medium/Hard)",
    "recommendations": "验证建议"
}}
```
"""

EXPLOIT_GENERATION_TEMPLATE = """
你是一个资深的二进制漏洞利用专家。请根据以下信息生成 pwntools 利用脚本草案。

# 漏洞信息
- 漏洞类型: {vulnerability_type}
- 漏洞描述: {vulnerability_description}
- 目标文件: {binary_path}

# 保护机制
- NX: {nx}
- PIE: {pie}
- RELRO: {relro}
- Canary: {canary}

# 二进制信息
- 架构: {arch}
- 位数: {bits}
- 基地址 (如果PIE): {base_address}

# 相关函数/符号地址
{symbols}

# 已知 Gadgets
{gadgets}

# 利用思路
{exploitation_approach}

# 要求:
1. 使用 Python 3 和 pwntools 库
2. 包含详细的注释说明
3. 考虑保护机制的绕过策略
4. 代码结构清晰，便于调试和修改
5. 包含失败重试的逻辑框架

请输出完整的 pwntools 利用脚本，并将代码放在 ```python 代码块中:

```python
# 你的利用脚本
```
"""

EXPLOIT_ITERATION_TEMPLATE = """
你是一个资深的二进制漏洞利用专家。之前的利用脚本执行失败，请根据失败信息优化脚本。

# 原始脚本:
```python
{original_script}
```

# 失败信息:
{failure_info}

# 保护机制:
- NX: {nx}
- PIE: {pie}
- RELRO: {relro}
- Canary: {canary}

# 可用信息:
{additional_info}

# 迭代次数: {iteration_count}

# 要求:
1. 分析失败原因
2. 提出改进方案
3. 生成优化后的利用脚本
4. 说明修改点

请以 JSON 格式输出，并将结果放在 ```json 代码块中:

```json
{{
    "failure_analysis": "失败原因分析",
    "improvements": "改进方案",
    "optimized_script": "优化后的完整脚本",
    "changes_made": "具体修改点"
}}
```
"""

REPORT_SUMMARY_TEMPLATE = """
# 二进制漏洞分析报告

# 项目信息
- 分析日期: {date}
- 目标文件: {binary_path}

# 执行摘要
{summary}

---

{content}
"""


KERNEL_VULN_ANALYSIS_TEMPLATE = """
# 内核漏洞分析

对内核模块/驱动进行静态与动态层面的漏洞排查，重点关注以下风险面：

## 数据边界与拷贝
- copy_from_user / copy_to_user 的边界校验是否完备：长度参数来源、用户指针合法性。
- IOCTL 分发路径中命令码与缓冲区大小的对应关系。

## 内存与生命周期
- kmalloc/kzalloc 分配后的初始化与释放配对，是否存在使用后释放。
- 空指针解引用：函数返回值、失败路径与可选参数的判空。

## 并发与状态
- 竞争条件：共享数据的锁粒度、TOCTOU 窗口与中断上下文交互。

## 数值与逻辑
- 整数溢出：长度/索引/计数器运算的溢出与回绕。

## 影响面
- 权限提升：低权限调用路径能否触达高权限操作。
- 信息泄漏：未初始化内存、残留数据与地址泄漏。

## 输出要求
逐项给出：触发条件、可利用性评估、修复建议。仅做防御性分析。
"""

KERNEL_EXPLOIT_STRATEGY_TEMPLATE = """
# 内核利用策略（理论分析）

说明：不生成可执行的利用脚本。以下内容仅用于漏洞机理研究与防御评估，
依据具体内核版本、编译选项与缓解措施（KASLR/SMEP/SMAP/KPTI）展开理论分析。

## 分析框架
1. 漏洞原语归类：越界写/越界读/释放后使用/类型混淆。
2. 目标对象选择：与漏洞同大小的内核对象池。
3. 权限提升路径：cred/文件描述符/全局读写原语。
4. 缓解措施对照：逐一说明绕过或受限的原因。

## 输出要求
只输出理论分析结论与验证思路，不提供任何可执行的利用代码。
"""
