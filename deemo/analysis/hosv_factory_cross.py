"""
工厂分配跨函数写入关联. 将调用点后对目标指针的写入绑定到工厂分配,
执行简单边界判定.

与 hosv_ext_verifier.py 同族: 协调整合器调用本模块完成工厂跨函数
写入的关联与判定.

判定:
  - strcpy/strcat 到 target 且分配大小可解析 → 跨函数溢出 VULN
  - strncpy 长度超过 usable → VULN
  - 工厂 size_expr 经调用点实参替换解析为常量
"""

import re
from typing import List, Tuple

from analysis.heap_overflow_src_patterns import _ptmalloc2_usable


def bind_cross_writes(target: str, factory: str,
                      finfo: Tuple[str, str, str], call_line: int,
                      args: str, lines: List[str], valid: set
                      ) -> List:
    """将调用点后对 target 的写入关联到工厂分配, 执行简单边界判定."""
    from analysis.hosv_ext_verifier import HosvExtOutput
    results = []
    alloc_func, size_expr, alloc_var = finfo
    size_const = try_const_size(size_expr, lines, call_line, args)
    usable = _ptmalloc2_usable(size_const) if size_const > 0 else -1
    for i in range(call_line, len(lines) + 1):
        if valid and i not in valid:
            continue
        text = lines[i - 1].strip()
        # strcpy/memcpy 到 target
        m = re.match(
            r'\b(strcpy|strcat)\s*\(\s*&?'
            + target + r'\s*,\s*([^)]+)\)\s*;', text)
        if m:
            kind = m.group(1)
            if kind == 'strcpy' and usable > 0:
                reason = ("'%s': factory %s() alloc=%s + unbounded %s"
                          " → cross-function overflow risk"
                          % (target, factory, size_expr, kind))
                results.append(HosvExtOutput(
                    verdict="VULN", alloc_line=call_line,
                    write_line=i, var_name=target,
                    alloc_size=size_const, write_size=-1,
                    confidence=0.72, kind="factory_cross",
                    reason=reason))
        if usable <= 0:
            continue
        mc = re.match(r'\bstrncpy\s*\(\s*&?' + target +
                      r'\s*,\s*([^,]+),\s*(\d+)\s*\)\s*;', text)
        if mc and int(mc.group(2)) > usable:
            reason = ("'%s': factory alloc=%dB usable=%d, strncpy %dB"
                      % (target, size_const, usable, int(mc.group(2))))
            results.append(HosvExtOutput(
                verdict="VULN", alloc_line=call_line, write_line=i,
                var_name=target, alloc_size=size_const,
                write_size=int(mc.group(2)),
                overflow_bytes=int(mc.group(2)) - usable,
                confidence=0.70, kind="factory_cross",
                reason=reason))
    return results


def try_const_size(expr: str, lines: List[str],
                   call_line: int, args: str = "") -> int:
    """尝试把工厂 size_expr 解析为常量 (支持 var*sizeof, 数字, 参数替换)."""
    e = expr.strip()
    # 参数替换: make_buf(n) 调用 make_buf(16) → n=16
    if args:
        arg_list = [a.strip() for a in args.split(',') if a.strip()]
        if arg_list:
            # 从工厂签名提取参数名, 按序替换
            sig_re = re.compile(
                r'^[\w\s\*]+?\b(\w[\w]*)\s*\(([^)]*)\)\s*\{')
            for j in range(call_line - 1, -1, -1):
                t = lines[j].strip()
                sm = sig_re.match(t)
                if not sm:
                    continue
                params = [p.strip().split()[-1].rstrip('*').strip()
                          for p in sm.group(2).split(',')
                          if p.strip()]
                if len(params) != len(arg_list):
                    continue
                for p, a in zip(params, arg_list):
                    if p == e:
                        return const_var(a, lines, call_line) \
                            if not re.match(r'^\d+$', a) \
                            else int(a)
                break
    if e.isdigit():
        return int(e)
    m = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', e)
    if m:
        from analysis.hosv_struct_idx import resolve_elem_size
        sz = resolve_elem_size(m.group(2), lines, call_line)
        n = const_var(m.group(1), lines, call_line)
        if n > 0 and sz > 0:
            return n * sz
    m = re.match(r'(\d+)\s*\*\s*(\d+)', e)
    if m:
        return int(m.group(1)) * int(m.group(2))
    return -1


def const_var(name: str, lines: List[str], around_line: int) -> int:
    """解析变量名 → 常量赋值 (仅搜索前文简单赋值)."""
    for j in range(max(0, around_line - 2), -1, -1):
        m = re.search(rf'\b{name}\s*=\s*(\d+)\s*;', lines[j].strip())
        if m:
            return int(m.group(1))
    return -1


__all__ = ['bind_cross_writes', 'try_const_size', 'const_var']
