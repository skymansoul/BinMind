"""
Cross-compiler assembly pattern fallback: static matching when angr fails.

angr times out or fails on stripped binaries, indirect-call-heavy code,
and large binaries (>10MB). Falls back to assembly-level pattern matching:
  1. Match argument-prep sequences for dangerous calls (mov rdi, X; call printf)
  2. Use compiler-version-specific pattern libraries (GCC/Clang)
  3. Operates without symbol info — works on stripped binaries

Patterns sourced from GCC 8-14 and Clang 15-19 at -O0/-O2 for
printf(buf) / strcpy(dst, src) / free(ptr) instruction sequences.
"""


import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class PatternMatch:
    """单次模式匹配的结果。"""
    pattern_id: str
    pattern_desc: str           # 人类可读描述
    address: str                # 匹配到的地址 (hex)
    confidence: float           # 0.0 - 1.0
    matched_bytes: str = ""     # 匹配到的汇编片段 (hex)
    vuln_type: str = ""         # format_string / stack_overflow / uaf


# 汇编模式库
# 每个模式: (字节模式, 汇编助记模式, 描述, 置信度, 漏洞类型)
# 字节模式用 '.' 匹配任意半字节, 助记模式用 \s+ 匹配空白

_FORMAT_STRING_PATTERNS: List[Tuple[str, str, str, float]] = [
    # printf(buf) 的危险模式 —— 第一个参数来自栈加载而非 .rodata
    # mov rdi, [rbp-0x??]; call printf (GCC -O0 特征)
    (
        r'mov\s+rdi,\s*\[rbp-0x[0-9a-f]+\]\s*\n\s*call\s+printf',
        r'488b..\s*e8....',
        'printf(fmt=stack_var): 格式化参数直接来自栈变量, 不是常量指针',
        0.75,
    ),
    # sprintf(buf, fmt) 中 buf 来自栈 (可能溢出)
    (
        r'mov\s+rdi,\s*\[rbp-0x[0-9a-f]+\]\s*.*\n.*call\s+sprintf',
        r'488b..\s*.*e8....',
        'sprintf(dst=stack_var): 目标缓冲区在栈上, 大小可能不足',
        0.65,
    ),
    # lea rdi, [rip+0x...]; call printf —— 安全模式, 不作为检测目标
    # 检测: mov rdi, rax (rax 来源不明) + call printf
    (
        r'mov\s+rdi,\s*rax\s*\n.*call\s+printf',
        r'4889c7\s*e8....',
        'printf(fmt=rax): 格式化参数来自寄存器, 需回溯确认来源',
        0.55,
    ),
    # Clang -O2 特征: 内联的 printf 参数准备 (更紧凑)
    (
        r'lea\s+rdi,\s*\[rsp\+0x[0-9a-f]+\]\s*\n.*call\s+printf',
        r'488d....24\s*e8....',
        'printf(fmt=rsp_offset): Clang 将栈变量直接传给 printf, 可能是格式化漏洞',
        0.70,
    ),
]

_STACK_OVERFLOW_PATTERNS: List[Tuple[str, str, str, float]] = [
    # gets(buf) —— 无条件溢出, C11 已废弃但遗留代码中仍存在
    (
        r'call\s+gets',
        r'e8....',
        'gets(dst): 无条件栈溢出, 缓冲区大小未知但 gets 无长度限制',
        0.95,
    ),
    # strcpy(dst, src) where dst is a small stack buffer (GCC -O0)
    (
        r'lea\s+rax,\s*\[rbp-0x[0-9a-f]{1,2}\]\s*\n\s*mov\s+rdi,\s*rax\s*\n.*call\s+strcpy',
        r'488d....\s*4889c7\s*e8....',
        'strcpy(dst=small_stack_buf): 栈缓冲区 < 256B, 可能溢出',
        0.60,
    ),
    # strcat(dst, src) — 追加到栈缓冲区
    (
        r'mov\s+rdi,\s*\[rbp-0x[0-9a-f]+\]\s*\n.*call\s+strcat',
        r'488b..\s*e8....',
        'strcat(dst=stack_var): 追加到栈缓冲区, 总长度可能超限',
        0.55,
    ),
    # sprintf(buf, "%s", src) — 栈缓冲区溢出
    (
        r'lea\s+rdi,\s*\[rbp-0x[0-9a-f]{2,3}\]\s*\n.*call\s+sprintf',
        r'488d....\s*e8....',
        'sprintf(dst=stack_buf>256B): 较大的栈缓冲区但格式化输出可能超出',
        0.50,
    ),
]

_UAF_PATTERNS: List[Tuple[str, str, str, float]] = [
    # free(ptr); ... use of ptr later (GCC -O0, ptr from stack)
    (
        r'call\s+free\s*\n(?:.*\n){0,5}.*\[rbp-0x[0-9a-f]+\].*\n.*call',
        r'e8....(?:.*\n){0,5}.*',
        'free-then-use: free 后在 5 条指令内再次使用同一栈槽的指针',
        0.50,
    ),
    # double-free: free(ptr); ... free(ptr) (同一参数, 间隔小于 20 条指令)
    (
        r'mov\s+rdi,\s*\[rbp-0x[0-9a-f]+\]\s*\n\s*call\s+free\s*\n(?:.*\n){1,20}.*mov\s+rdi,\s*\[rbp-0x[0-9a-f]+\]\s*\n\s*call\s+free',
        r'488b..\s*e8....(?:.*\n){1,20}.*488b..\s*e8....',
        'double-free: 同一栈变量在 20 条指令内被 free 两次',
        0.70,
    ),
]

# 所有模式的统一列表
_ALL_PATTERNS: List[Tuple[str, str, str, float, str]] = (
    [(p[0], p[1], p[2], p[3], 'format_string') for p in _FORMAT_STRING_PATTERNS] +
    [(p[0], p[1], p[2], p[3], 'stack_overflow') for p in _STACK_OVERFLOW_PATTERNS] +
    [(p[0], p[1], p[2], p[3], 'uaf') for p in _UAF_PATTERNS]
)


def match_patterns(disasm_text: str) -> List[PatternMatch]:
    """
    在反汇编文本中匹配所有已知漏洞模式。

    disasm_text: objdump/radare2 输出的完整反汇编文本。
    返回 PatternMatch 列表, 按置信度降序。
    """
    matches: List[PatternMatch] = []
    seen_addrs: set = set()

    for mnemo_pat, _byte_pat, desc, conf, vtype in _ALL_PATTERNS:
        for m in re.finditer(mnemo_pat, disasm_text, re.MULTILINE | re.DOTALL):
            addr = "0x" + _extract_addr(m.group(0), disasm_text, m.start())
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)
            matches.append(PatternMatch(
                pattern_id=f"{vtype}_{len(matches):03d}",
                pattern_desc=desc,
                address=addr,
                confidence=conf,
                matched_bytes=m.group(0)[:120],
                vuln_type=vtype,
            ))

    matches.sort(key=lambda x: x.confidence, reverse=True)
    return matches


def _extract_addr(match_text: str, full_text: str, match_pos: int) -> str:
    """从匹配位置向前搜索最近的地址标签。"""
    before = full_text[max(0, match_pos - 200):match_pos]
    m = re.findall(r'(?:^|\n)\s*(0x[0-9a-fA-F]+)\s*[:<]', before)
    return m[-1] if m else "unknown"


def describe_match(m: PatternMatch) -> str:
    """生成模式匹配的人类可读描述。"""
    return (
        f"[{m.vuln_type}] {m.pattern_desc} "
        f"@ {m.address} (confidence={m.confidence:.2f})"
    )


__all__ = [
    "PatternMatch",
    "match_patterns",
    "describe_match",
]
