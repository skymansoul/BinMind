# 混淆代码的汇编级模式匹配，反编译器在混淆二进制(UPX/OLLVM等)上失效时的回退。
# 只检测混淆无法隐藏的核心漏洞模式。
import re

# 混淆后常见漏洞模式 (保留核心语义的汇编级特征)
_ASM_VULN_PATTERNS = [
    # UAF: call free; ... mov reg, [freed_ptr] (free后解引用)
    (r'call.*free.*\n.*mov\s+\w+,\s*\[(\w+)\]', 'uaf', 'CWE-416'),
    # 堆溢出: call malloc(N); ... rep movs (memcpy超过N)
    (r'call.*malloc.*\n.*rep\s+movs', 'heap_overflow', 'CWE-787'),
    # 格式串: push fmt_arg; call printf (且fmt_arg非.rodata地址)
    (r'push\s+(?!0x)[er]?\w+\n.*call.*printf', 'format_string', 'CWE-134'),
    # 栈溢出: sub rsp, N; ... call gets/strcpy (危险函数直接写入栈帧)
    (r'sub\s+rsp,\s*(0x[0-9a-f]+).*\n.*call.*(?:gets|strcpy)', 'stack_overflow', 'CWE-120'),
    # Double free: call free; ... call free (同一参数两次free)
    (r'call.*free.*\n.*\n.*call.*free', 'double_free', 'CWE-415'),
]


def detect_from_assembly(asm_lines: list[str]) -> list[dict]:
    """从汇编行检测漏洞模式--用于反编译器在混淆代码上失效时的回退."""
    if not asm_lines:
        return []
    text = '\n'.join(asm_lines)
    findings = []
    for pattern, vuln_type, cwe in _ASM_VULN_PATTERNS:
        for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
            # 估算行号
            line_no = text[:match.start()].count('\n') + 1
            findings.append({
                "rule_id": f"ASM-{vuln_type.upper()}",
                "type": vuln_type,
                "function": "",
                "severity": "Medium",
                "description": f"汇编级模式检测: {vuln_type} @ L{line_no}",
                "cwe": cwe,
                "confidence": 0.45,
                "asm_match": match.group(0)[:80],
                "detection_note": "混淆代码回退模式--置信度较低, 建议人工确认",
            })
    return findings
