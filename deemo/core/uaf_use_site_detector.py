"""
free 后 use-site 检测 — 基于活跃变量分析。
uaf_candidate_scorer 只配对 malloc/free 并给出概率, 不判断指针在 free 后是否真的被使用, 本模块补齐该缺口。
流程: 1. 从 IR 提取 free(p) 调用与被释放变量; 2. 活跃变量分析: 在 free 到函数返回的区间内检查 p
是否作为操作数出现 (load/store/call arg/mov src); 3. 出现 → 确认 UAF; 4. free 后置 NULL → 安全;
5. free 后重新赋值 (p = malloc(...)) → 非 UAF。局限: 仅函数内分析 (callee free + caller use 为漏报),
依赖反编译器变量名恢复 (去符号二进制可能失败)。
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

            # 检查变量是否被重新赋值 (合法复用, 非 UAF)
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
                # 首个使用后停止; 后续使用视为同一漏洞的延伸
                break

    findings.sort(key=lambda f: -f.confidence)
    return findings


def _detect_var_use(line: str, var: str) -> Optional[str]:
    """检测一行 IR 中是否以特定方式使用了变量 var。

    返回 'load' | 'store' | 'call_arg' | 'mov_src' | None。"""
    # 排除对 var 的写入 (var = XXX) — 属重新赋值而非 use-after-free
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
