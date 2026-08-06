"""
Post-free use-site detection via live-variable analysis.

Existing uaf_candidate_scorer only pairs malloc/free and assigns a
probability — it does not know whether the pointer is actually used
after free. This module fills that gap.

  1. Extract free(p) calls and the freed variable p from IR.
  2. Live-variable analysis: in the interval from free to function return,
     does p appear as an operand (load/store/call arg/mov src)?
  3. Use found → confirmed UAF.
  4. p explicitly set to NULL after free (p = NULL) → likely_safe.
  5. Reassignment (p = malloc(...)) after free → not a UAF.

Limitations:
  - Intra-procedural only. free in callee, use in caller → false negative.
  - Depends on decompiler variable name recovery (stripped binaries may fail).
"""

from dataclasses import dataclass, field
import re
from typing import Optional

from core.ir_normalizer import normalize_ir


@dataclass
class FreeSite:
    """一次 free 调用。"""
    pc: int
    freed_var: str           # 被释放的变量名
    freed_expr: str          # free 调用的原始表达式文本
    nulled_after: bool       # free 后是否立即置 NULL


@dataclass
class UseAfterFreeSite:
    """一个确认的 UAF use-site。"""
    free_site: FreeSite
    use_pc: int
    use_line: str             # 使用此指针的 IR 行
    use_type: str             # 'load' | 'store' | 'call_arg' | 'mov_src'
    confidence: float
    description: str


def find_free_calls(ir_lines: list[str]) -> list[FreeSite]:
    """从 IR 中提取 free(p) 调用点。"""
    frees = []
    free_pattern = re.compile(
        r'free\s*\(\s*(\w+)\s*\)',
        re.IGNORECASE,
    )

    for i, line in enumerate(ir_lines):
        m = free_pattern.search(line)
        if not m:
            continue
        freed_var = m.group(1)

        # 检查 free 后是否立即置 NULL (用户代码或 safe_free 宏)
        nulled = False
        for j in range(i + 1, min(len(ir_lines), i + 3)):
            if re.search(rf'{re.escape(freed_var)}\s*=\s*(?:NULL|nullptr|0)\s*;?',
                         ir_lines[j], re.IGNORECASE):
                nulled = True
                break

        frees.append(FreeSite(
            pc=i, freed_var=freed_var,
            freed_expr=m.group(0), nulled_after=nulled,
        ))

    return frees


def detect_use_after_free(
    ir_lines: list[str],
    decompiled_text: str = '',
) -> list[UseAfterFreeSite]:
    """检测 free 后的 actual use。"""
    if not ir_lines and decompiled_text:
        ir_lines = normalize_ir(decompiled_text)

    frees = find_free_calls(ir_lines)
    findings = []

    for free_site in frees:
        if free_site.nulled_after:
            continue

        var = free_site.freed_var
        reassigned = False
        use_after_free_found = False

        for j in range(free_site.pc + 1, len(ir_lines)):
            line = ir_lines[j]

            # Check if the variable was reassigned (legal reuse, not a UAF)
            if not use_after_free_found:
                if re.search(rf'{re.escape(var)}\s*=\s*(?!NULL|nullptr)', line):
                    reassigned = True

            if reassigned:
                break

            # 检查是否使用了已释放的变量
            use_type = _detect_var_use(line, var)
            if use_type:
                use_after_free_found = True
                conf = 0.92 if use_type in ('call_arg', 'store') else 0.75
                findings.append(UseAfterFreeSite(
                    free_site=free_site,
                    use_pc=j,
                    use_line=line.strip()[:80],
                    use_type=use_type,
                    confidence=conf,
                    description=f'{var} freed at line {free_site.pc}, used as {use_type} at line {j}',
                ))
                # Stop after first use; subsequent uses are extensions of the same bug.
                break

    findings.sort(key=lambda f: -f.confidence)
    return findings


def _detect_var_use(line: str, var: str) -> Optional[str]:
    """检测一行 IR 中是否以特定方式使用了变量 var。

    返回 'load' | 'store' | 'call_arg' | 'mov_src' | None。"""
    # Exclude writes to var (var = XXX) — reassignment, not use-after-free.
    if re.match(rf'{re.escape(var)}\s*=', line.strip()):
        return None
    # 排除 var 出现在函数调用名中
    if re.search(rf'(?:call|branch)\s+{re.escape(var)}\s*$', line):
        return None

    # store 到 var 指向的内存
    if re.search(rf'store.*\[.*{re.escape(var)}', line, re.IGNORECASE):
        return 'store'
    # 从 var 指向的内存 load
    if re.search(rf'load.*\[.*{re.escape(var)}', line, re.IGNORECASE):
        return 'load'
    # var 作为函数调用参数
    if re.search(rf'call.*\(.*{re.escape(var)}', line):
        return 'call_arg'
    # var 作为 mov 的源操作数
    if re.search(rf'=\s*.*{re.escape(var)}\b', line):
        return 'mov_src'

    return None
