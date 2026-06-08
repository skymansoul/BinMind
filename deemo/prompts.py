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
```c
{pseudocode}
```

## 分析要求:
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

## 崩溃信息
### 寄存器状态:
{registers}

### 栈回溯:
{stack_trace}

### 崩溃时的指令:
{fault_instruction}

### 程序输出:
{program_output}

## 保护机制信息:
{protection_info}

## 分析要求:
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

## 漏洞信息
- 漏洞类型: {vulnerability_type}
- 漏洞描述: {vulnerability_description}
- 目标文件: {binary_path}

## 保护机制
- NX: {nx}
- PIE: {pie}
- RELRO: {relro}
- Canary: {canary}

## 二进制信息
- 架构: {arch}
- 位数: {bits}
- 基地址 (如果PIE): {base_address}

## 相关函数/符号地址
{symbols}

## 已知 Gadgets
{gadgets}

## 利用思路
{exploitation_approach}

## 要求:
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

## 原始脚本:
```python
{original_script}
```

## 失败信息:
{failure_info}

## 保护机制:
- NX: {nx}
- PIE: {pie}
- RELRO: {relro}
- Canary: {canary}

## 可用信息:
{additional_info}

## 迭代次数: {iteration_count}

## 要求:
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

## 项目信息
- 分析日期: {date}
- 目标文件: {binary_path}

## 执行摘要
{summary}

---

{content}
"""

KERNEL_VULN_ANALYSIS_TEMPLATE = """
你是一个资深的内核安全研究员和漏洞挖掘专家。请分析以下内核模块的反编译代码，识别潜在的安全漏洞。

## 内核模块信息
- 模块类型: {module_type}
- 模块名称: {module_name}
- 架构: {arch}
- 位数: {bits}
- 文件路径: {binary_path}

## 内核模块元数据
{module_metadata}

## 发现的内核特有危险函数:
{kernel_dangerous_functions}

## 导出的符号:
{exported_symbols}

## 入口点和处理函数:
{entry_points}

## 关键字符串:
{key_strings}

## 反编译代码:
```c
{pseudocode}
```

## 分析要求:
1. 仔细阅读代码，识别可能存在的内核安全漏洞
2. 重点关注以下内核漏洞类型:
   - 用户态数据验证缺陷 (copy_from_user/copy_to_user 误用)
   - 空指针解引用 (Null Pointer Dereference)
   - 整数溢出 (Integer Overflow)
   - 竞争条件 (Race Condition / TOCTOU)
   - 内核栈溢出 (Kernel Stack Overflow)
   - 堆溢出/Use-After-Free (Slab/Slob/Slub Allocator)
   - 越界访问 (Out-of-Bounds Access)
   - 权限提升漏洞 (Privilege Escalation)
   - 信息泄漏 (Information Disclosure)
   - 资源泄漏 (Resource Leak)
   - 不正确的锁操作 (Locking Issues)
   - 内存映射错误 (MMU/Mapping Issues)
   - IOCTL 命令注入 (IOCTL Handler Vulnerabilities)
   - 设备驱动漏洞 (Driver Vulnerabilities)

3. 对每个发现的漏洞，提供:
   - 漏洞类型
   - 漏洞位置 (函数名/偏移)
   - 触发条件
   - 攻击向量
   - 严重程度 (Critical/High/Medium/Low)
   - 可能的利用方式 (权限提升/拒绝服务/信息泄漏)
   - 影响评估

4. 特别检查:
   - 用户态指针的验证 (access_ok 的正确使用)
   - 用户态传入长度的检查
   - 内核堆内存的安全管理
   - 并发访问的同步保护
   - IOCTL 命令码的范围验证
   - 返回值的错误处理

5. 如果是 Windows 驱动，额外检查:
   - IRP 处理中的内存管理
   - IRP_MJ_DEVICE_CONTROL 处理
   - MmCopyVirtualMemory 的使用
   - ExAllocatePool 相关操作
   - 符号链接创建

请以 JSON 格式输出分析结果，并将结果放在 ```json 代码块中，格式如下:

```json
{{
    "vulnerabilities": [
        {{
            "type": "漏洞类型",
            "location": "漏洞位置",
            "description": "漏洞描述",
            "trigger_condition": "触发条件",
            "attack_vector": "攻击向量",
            "severity": "严重程度",
            "exploitation": "利用方式说明",
            "impact": "影响评估",
            "code_snippet": "相关代码"
        }}
    ],
    "summary": "总体分析摘要",
    "risk_level": "整体风险等级",
    "kernel_specific_notes": "内核特有的安全建议"
}}
```
"""

HEAP_EXPLOIT_STRATEGY_TEMPLATE = """
你是一个资深的堆漏洞利用专家。请根据以下信息生成针对特定分配器的堆漏洞利用步骤。

## 二进制文件信息
- 文件路径: {binary_path}
- 架构: {arch} ({bits}-bit)
- 保护机制:
  - NX: {nx}
  - PIE: {pie}
  - RELRO: {relro}
  - Canary: {canary}

## 分配器信息
- 分配器类型: {allocator_type}
- 检测到的 libc 版本: {libc_version}
- 用户指定的 libc 版本: {user_libc_version}

## 漏洞信息
- 漏洞类型: {vulnerability_type}
- 漏洞描述: {vulnerability_description}
- 漏洞位置: {vulnerability_location}
- 严重程度: {severity}

## glibc 结构偏移（ptmalloc）
```json
{glibc_offsets}
```

## jemalloc 信息（如果适用）
- Size Classes: {jemalloc_size_classes}
- 可用技术: {jemalloc_techniques}

## 分析要求:
1. 根据分配器类型和漏洞类型，选择最适合的利用技术
2. 分析利用难度和需要的信息泄露
3. 提供详细的利用步骤
4. 考虑 libc 版本差异（tcache 引入、hook 移除等）
5. 说明需要手动调整的部分

## 输出要求:
请以 JSON 格式输出分析结果，并将结果放在 ```json 代码块中:

```json
{{
    "allocator": "ptmalloc 或 jemalloc",
    "recommended_technique": "推荐的利用技术名称",
    "technique_description": "技术原理说明",
    "exploitation_steps": [
        "步骤1: ...",
        "步骤2: ..."
    ],
    "information_leak_required": true 或 false,
    "leak_method": "信息泄露方法说明",
    "targets": [
        "__free_hook",
        "__malloc_hook",
        "GOT",
        "IO_FILE"
    ],
    "difficulty": "Easy/Medium/Hard/Expert",
    "version_specific_notes": "版本特定的注意事项",
    "pitfalls": [
        "常见陷阱1",
        "常见陷阱2"
    ],
    "alternative_techniques": [
        "备选技术1",
        "备选技术2"
    ]
}}
```
"""

KERNEL_EXPLOIT_STRATEGY_TEMPLATE = """
你是一个资深的内核漏洞利用专家。请根据以下信息生成内核漏洞利用思路和策略说明。

## 漏洞信息
- 漏洞类型: {vulnerability_type}
- 漏洞描述: {vulnerability_description}
- 目标模块类型: {module_type}
- 目标文件: {binary_path}

## 模块信息
- 架构: {arch}
- 位数: {bits}
- 模块名称: {module_name}

## 漏洞详细信息
{vulnerability_details}

## 内核环境信息
{kernel_env_info}

## 要求:

### 对于 Linux 内核模块 (.ko):
1. 分析漏洞可利用性
2. 提供利用思路（不要生成可执行脚本，仅说明思路）:
   - 权限提升路径（如获取 root 权限）
   - 利用技术（如 ret2usr, SMEP/SMAP 绕过）
   - KASLR 绕过策略
   - SMEP/SMAP 绕过方法
   - KPTI 绕过技术
3. 说明可能的难点和限制
4. 提供缓解措施建议

### 对于 Windows 驱动 (.sys):
1. 分析漏洞可利用性
2. 提供利用思路:
   - 权限提升路径（如 SYSTEM 权限）
   - 利用技术（如任意读写原语）
   - KASLR 绕过策略
   - SMEP/KVA Shadow 绕过
   - 池喷技术
3. 说明可能的难点和限制
4. 提供缓解措施建议

### 重要注意事项:
- 不生成可执行的利用脚本（内核利用高度依赖具体环境）
- 只提供漏洞利用的思路和策略说明
- 明确指出这是理论分析，实际利用需要进一步研究
- 强调内核利用可能导致系统不稳定

请以 JSON 格式输出，并将结果放在 ```json 代码块中:

```json
{{
    "exploitability": "可利用性评估",
    "difficulty": "利用难度 (Easy/Medium/Hard/Extreme)",
    "strategy": {{
        "privilege_escalation_path": "权限提升路径说明",
        "techniques": "利用技术列表",
        "bypass_methods": "保护机制绕过方法",
        "stability_considerations": "稳定性考虑"
    }},
    "challenges": [
        "可能遇到的难点"
    ],
    "mitigations": [
        "缓解措施建议"
    ],
    "disclaimer": "此为理论分析，实际利用需要根据具体环境调整，内核利用可能导致系统崩溃或不稳定"
}}
```
"""
