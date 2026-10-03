# LLM 提示词模板，供兼容引用
from typing import Dict, Optional

# core analysis prompts (在用)

VULN_ANALYSIS_SYSTEM = """You are a binary reverse-engineering expert.
Analyze the provided decompiled C code for security vulnerabilities.
Report buffer overflows, format string bugs, integer overflows,
use-after-free, double-free, race conditions, and logic flaws.
For each vulnerability found, provide:
- type: the vulnerability class
- severity: Critical/High/Medium/Low
- location: function name or address
- description: what makes this exploitable
- cwe: the CWE number if applicable
Output as JSON with a "vulnerabilities" array."""

PATCH_DIFF_ANALYSIS = """
你是一名漏洞研究专家，请分析以下补丁差异，识别被修复的安全漏洞。

原始函数伪代码:
{original_code}

补丁后函数伪代码:
{patched_code}

请分析:
1. 补丁添加了哪些安全检查？
2. 修改了哪些可能导致漏洞的代码逻辑？
3. 推测原始漏洞的类型和触发条件
4. 评估漏洞的严重程度

输出JSON格式:
{{
    "vulnerability_type": "漏洞类型",
    "cwe_id": "CWE编号",
    "severity": "严重程度",
    "description": "漏洞描述",
    "trigger_condition": "触发条件",
    "patch_analysis": {{
        "added_checks": [],
        "modified_logic": [],
        "fixed_behavior": ""
    }}
}}
"""

# cross-architecture exploit transpile (归档)

EXPLOIT_TRANSPILE = """
你是一名漏洞利用开发专家，请将以下源架构的利用代码转换为目标架构。

源架构: {source_arch}
目标架构: {target_arch}
原始利用代码:
{source_exploit}

请提供:
1. 调整后的利用代码（pwntools格式）
2. 寄存器映射说明
3. ROP gadget替换方案
4. Shellcode转换（如需要）
5. 系统调用号调整

注意:
- ARM64使用x0-x7作为参数寄存器，x30作为返回地址
- ARM使用r0-r3作为参数寄存器，lr作为返回地址
- MIPS使用a0-a3作为参数寄存器
- RISC-V使用a0-a7作为参数寄存器，ra作为返回地址
"""

ROP_GADGET_SEARCH = """
请根据以下功能需求，从目标架构的gadget数据库中搜索合适的gadget。

目标架构: {target_arch}
所需功能:
{required_functions}

可用gadget列表:
{available_gadgets}

请推荐每个功能对应的最佳gadget及替代方案。
"""

SHELLCODE_TRANSPILE = """
请将以下源架构的shellcode转换为目标架构的等效shellcode。

源架构: {source_arch}
目标架构: {target_arch}
原始shellcode:
{source_shellcode}

提供目标架构的shellcode（十六进制）和对应汇编代码。
"""

# exploit chain analysis (归档)

EXPLOIT_CHAIN = """
你是一名漏洞利用开发专家，请分析以下漏洞集合，评估它们能否组合成攻击链。

漏洞列表:
{vulnerabilities}

攻击目标: {target}

能力标签说明:
- info_leak:stack/heap/libc - 信息泄露
- arbitrary_write:stack/heap/global - 任意写
- control_pc - 控制程序计数器
- bypass_aslr/dep - 绕过缓解措施
- privilege_escalation - 提权

分析这些漏洞能否按顺序组合形成完整攻击链。
"""


class PromptManager:
    # 命名提示词模板注册表
    _store: Dict[str, str] = {}

    @classmethod
    def register(cls, name: str, template: str):
        cls._store[name] = template

    @classmethod
    def get(cls, name: str) -> Optional[str]:
        return cls._store.get(name)

    @classmethod
    def format(cls, name: str, **kwargs) -> Optional[str]:
        tpl = cls.get(name)
        if tpl is None:
            return None
        try:
            return tpl.format(**kwargs)
        except KeyError:
            return None


# auto-register
for _name, _tpl in [
    ('vuln_analysis', VULN_ANALYSIS_SYSTEM),
    ('patch_diff', PATCH_DIFF_ANALYSIS),
    ('exploit_transpile', EXPLOIT_TRANSPILE),
    ('rop_gadget_search', ROP_GADGET_SEARCH),
    ('shellcode_transpile', SHELLCODE_TRANSPILE),
    ('exploit_chain', EXPLOIT_CHAIN),
]:
    PromptManager.register(_name, _tpl)
