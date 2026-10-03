"""
C源码→伪指令流转换器 — 保留足够结构供Tier 1-3消费.

输出格式: List[Tuple[int, str]]
  (line_no, "mnemonic operand1, operand2, ...")

生成模式:
  · 变量声明+分配: var = malloc(size) → "call malloc, var, size_expr"
  · 常量赋值: var = N → "mov var, const_N"
  · 算术: var = expr op expr → "add var, a, b" / "imul var, a, N"
  · 写入: memcpy(dst, src, N) → "call memcpy, dst, src, N"
  · 条件分支: if (var < N) → "cmp var, N" + "jl label_if"
  · 循环: for(i=0;i<N;i++) → "mov i, const_0" + "cmp i, N" + "jl label_loop"
"""

from __future__ import annotations

import re
from typing import List, Tuple


def c_to_pseudo_insns(c_source: str) -> List[Tuple[int, str]]:
    """将C源码转换为伪指令流, line_no从1开始."""
    insns: List[Tuple[int, str]] = []
    lines = c_source.splitlines()
    pc = 0x1000  # 伪地址基准

    # 第一遍: 收集变量类型信息
    var_types = _collect_var_types(lines)

    for lineno, raw_line in enumerate(lines, start=1):
        s = raw_line.strip()
        if not s or s.startswith('#') or s.startswith('//') or s.startswith('/*'):
            continue
        if s in ('{', '}', 'else'):
            continue

        # 去类型前缀 (保留变量名和操作)
        s = _strip_types(s)

        # 控制流: if(cond)
        if_m = re.match(r'if\s*\((.+)\)\s*$', s)
        if if_m:
            cond = if_m.group(1).strip()
            insns.extend(_emit_condition(pc, lineno, cond))
            pc += 10
            continue

        # 控制流: for(init; cond; incr)
        for_m = re.match(r'for\s*\(([^;]*);([^;]*);([^)]*)\)', s)
        if for_m:
            init_s, cond_s, incr_s = for_m.group(1), for_m.group(2), for_m.group(3)
            insns.extend(_emit_for_loop(pc, lineno, init_s, cond_s, incr_s))
            pc += 20
            continue

        # malloc/calloc/realloc 分配
        alloc_m = re.match(
            r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\((.+)\)', s)
        if alloc_m:
            var, func = alloc_m.group(1), alloc_m.group(2)
            args_raw = alloc_m.group(3).strip()
            if func == 'calloc':
                parts = _split_args(args_raw)
                size_str = f"({parts[0] if parts else '0'})*({parts[1] if len(parts)>1 else '0'})"
            elif func == 'realloc':
                parts = _split_args(args_raw)
                size_str = parts[1] if len(parts) > 1 else parts[0] if parts else '0'
            else:
                size_str = args_raw
            size_norm = _normalize_expr(size_str)
            insns.append((pc, f"call {func}, {var}, {size_norm}"))
            pc += 1
            continue

        # memcpy/memset/memmove/strncpy 写入
        write_m = re.match(
            r'(?:(\w+)\s*=\s*)?(memcpy|memset|memmove|strncpy|strcpy|sprintf)\s*\((.+)\)', s)
        if write_m:
            func = write_m.group(2)
            args_raw = write_m.group(3).strip()
            parts = _split_args(args_raw)
            dst = parts[0] if parts else '?'
            size_str = parts[2] if len(parts) > 2 else (
                parts[1] if len(parts) > 1 and func in ('strcpy', 'sprintf', 'memset') else '?')
            if func == 'memset':
                size_str = parts[2] if len(parts) > 2 else '?'
            elif func == 'strcpy':
                size_str = 'unbounded'
            size_norm = _normalize_expr(size_str)
            insns.append((pc, f"call {func}, {dst}, {size_norm}"))
            pc += 1
            continue

        # 数组写入: var[idx] = value 或 *(var + offset) = value
        arr_m = re.match(r'(\w+)\s*\[([^\]]+)\]\s*=(.+)', s)
        if arr_m:
            var, idx, val = arr_m.group(1), arr_m.group(2).strip(), arr_m.group(3).strip()
            idx_norm = _normalize_expr(idx)
            insns.append((pc, f"store [{var}+{idx_norm}], {_normalize_expr(val)}"))
            pc += 1
            continue

        deref_m = re.match(r'\*\s*\(?\s*(\w+)\s*\+\s*(\d+)\s*\)?\s*=(.+)', s)
        if deref_m:
            var, offset, val = deref_m.group(1), deref_m.group(2), deref_m.group(3).strip()
            insns.append((pc, f"store [{var}+{offset}], {_normalize_expr(val)}"))
            pc += 1
            continue

        # 赋值: var = expr
        assign_m = re.match(r'(\w+)\s*=\s*(.+)', s)
        if assign_m:
            var, rhs = assign_m.group(1), assign_m.group(2).strip().rstrip(';')
            if re.match(r'^\d+$', rhs):
                insns.append((pc, f"mov {var}, const_{rhs}"))
            elif re.match(r'^\w+$', rhs):
                insns.append((pc, f"mov {var}, {rhs}"))
            elif '+' in rhs and '*' not in rhs:
                parts = re.split(r'\s*\+\s*', rhs)
                parts = [p.strip() for p in parts]
                if len(parts) == 2:
                    insns.append((pc, f"add {var}, {parts[0]}, {parts[1]}"))
                else:
                    insns.append((pc, f"lea {var}, [{rhs}]"))
            elif '-' in rhs and '*' not in rhs and not rhs.startswith('-'):
                parts = re.split(r'\s*\-\s*', rhs)
                parts = [p.strip() for p in parts]
                if len(parts) == 2:
                    insns.append((pc, f"sub {var}, {parts[0]}, {parts[1]}"))
                else:
                    insns.append((pc, f"lea {var}, [{rhs}]"))
            elif '*' in rhs:
                # 仿射模式: n*4+8 或 n*sizeof(int)
                insns.append((pc, f"lea {var}, [{rhs}]"))
            else:
                insns.append((pc, f"mov {var}, {_normalize_expr(rhs)}"))
            pc += 1
            continue

        # free(var)
        free_m = re.match(r'free\s*\((\w+)\)', s)
        if free_m:
            insns.append((pc, f"call free, {free_m.group(1)}"))
            pc += 1
            continue

    return insns


def _emit_condition(pc: int, lineno: int, cond: str) -> List[Tuple[int, str]]:
    """将C条件转换为cmp+jcc序列."""
    insns = []
    cond = cond.strip()
    # 匹配 var < N, var <= N, var > N, var >= N, var == N
    for pat, jcc in [
        (r'(\w+)\s*<\s*(\d+|\w+)', 'jl'),
        (r'(\w+)\s*<=\s*(\d+|\w+)', 'jle'),
        (r'(\w+)\s*>\s*(\d+|\w+)', 'jg'),
        (r'(\w+)\s*>=\s*(\d+|\w+)', 'jge'),
        (r'(\w+)\s*==\s*(\d+|\w+)', 'je'),
        (r'(\w+)\s*!=\s*(\d+|\w+)', 'jne'),
    ]:
        m = re.search(pat, cond)
        if m:
            var, val = m.group(1), m.group(2)
            val_str = f"const_{val}" if re.match(r'^\d+$', val) else val
            target = f"if_{lineno}_body"
            insns.append((pc, f"cmp {var}, {val_str}"))
            insns.append((pc + 1, f"{jcc} {target}"))
            return insns
    # 兜底
    insns.append((pc, f"; cond: {cond}"))
    return insns


def _emit_for_loop(pc: int, lineno: int, init_s: str, cond_s: str,
                   incr_s: str) -> List[Tuple[int, str]]:
    """将for循环转换为mov+cmp+jcc序列."""
    insns = []
    init_s = init_s.strip()
    cond_s = cond_s.strip()
    incr_s = incr_s.strip()

    # for(i=0; i<N; i++)
    init_m = re.match(r'(?:int|unsigned|size_t\s+)?(\w+)\s*=\s*(\d+)', init_s)
    if init_m:
        var, val = init_m.group(1), init_m.group(2)
        insns.append((pc, f"mov {var}, const_{val}"))
    else:
        insns.append((pc, f"; init: {init_s}"))

    cond = _emit_condition(pc + 1, lineno, cond_s)
    # 修改jcc目标指向循环体
    for i, (addr, text) in enumerate(cond):
        if any(text.startswith(j) for j in ('jl', 'jle', 'jg', 'jge', 'je', 'jne')):
            parts = text.split()
            cond[i] = (addr, f"{parts[0]} for_{lineno}_body")
    insns.extend(cond)

    incr_m = re.match(r'(\w+)\s*\+\+', incr_s)
    if incr_m:
        insns.append((pc + 2, f"add {incr_m.group(1)}, {incr_m.group(1)}, const_1"))
    return insns


def _normalize_expr(expr: str) -> str:
    """归一化表达式: 去空格, 去cast, 展开sizeof, 统一大小写."""
    s = expr.strip()
    s = re.sub(r'\(\s*\w+\s*\*?\s*\)', '', s)  # 去cast
    s = re.sub(r'sizeof\s*\(\s*\w+\s*\)', '4', s, flags=re.IGNORECASE)
    s = re.sub(r'unsigned\s+', '', s)
    s = re.sub(r'\s+', '', s)
    return s


def _strip_types(s: str) -> str:
    """剥离C类型声明, 保留变量名和操作."""
    # 去cast
    s = re.sub(r'\(\s*(?:char|int|void|size_t|unsigned|float|double|'
               r'uint\d+_t|int\d+_t|long)\s*\**\s*\)', '', s)
    # 去类型前缀 (保留struct名之后的变量声明)
    s = re.sub(r'\b(?:char|int|short|long|void|float|double|size_t|'
               r'ssize_t|unsigned|signed|uint\d+_t|int\d+_t|const|static|'
               r'volatile|extern|register)\s+\**\s*', '', s)
    return s.strip()


def _split_args(s: str) -> List[str]:
    """深度计数分割参数, 处理嵌套括号."""
    args = []
    depth = 0
    current = []
    for ch in s:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current).strip())
    return args


def _collect_var_types(lines: List[str]) -> dict:
    """收集变量类型信息, 用于sizeof推断."""
    var_types = {}
    for line in lines:
        m = re.match(
            r'(?:const\s+)?(?:unsigned\s+)?(char|int|short|long|void|float|double|'
            r'size_t|uint\d+_t|int\d+_t|struct\s+\w+)\s*\*+\s*(\w+)', line)
        if m:
            var_types[m.group(2)] = m.group(1)
    return var_types
