"""
堆溢出写模式扩展验证器 — 编排各写模式检测模块, 输出兼容 HOSV 的判定.

作为 HeapOverflowSrcVerifier 的补充阶段运行, 只增加写模式覆盖,
不改动原验证器行为.

流程:
  1. 复用原 HOSV 的 find_allocs 提取分配点 (含 size 解析)
  2. 构建 ExtAlloc (别名根 + usable)
  3. 运行各写模式模块:
     - hosv_walk_write:      *p++ 游走写
     - hosv_struct_idx:      b[i].field 结构体数组索引写
     - hosv_unbounded_io:    scanf %s / gets
     - hosv_factory_bind:    工厂函数返回指针 + calloc 回绕
     - hosv_null_terminator: d[l]=0 终止符 off-by-one
  4. 工厂绑定: 将调用点 target 的后续写入关联到工厂分配
  5. 合并 ExtResult → 兼容 (HoResult 形状的轻量对象)

各写模式模块的 UNCERTAIN 结果保留原 HOSV 判定, 不重复报告.
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from analysis.hosv_ext_types import ExtAlloc, ExtResult
from analysis.hosv_walk_write import (
    collect_walk_writes, verify_walk,
)
from analysis.hosv_struct_idx import (
    collect_struct_idx_writes, verify_struct_idx,
)
from analysis.hosv_unbounded_io import (
    collect_unbounded_io, verify_unbounded_io,
)
from analysis.hosv_factory_bind import (
    FactorySummary, build_factory_summaries,
    collect_factory_binds, verify_factory,
)
from analysis.hosv_null_terminator import (
    collect_terminator_writes, verify_terminator,
)
from analysis.heap_overflow_src_phases import find_allocs
from analysis.heap_overflow_src_patterns import (
    _ptmalloc2_usable, _skip_block_comments,
)


@dataclass
class HosvExtOutput:
    """扩展模块输出 — 与 HoResult 形状兼容的轻量结果."""
    verdict: str = "UNCERTAIN"
    alloc_line: int = 0
    write_line: int = 0
    var_name: str = ""
    alloc_size: int = -1
    write_size: int = -1
    overflow_bytes: int = 0
    confidence: float = 0.5
    reason: str = ""
    kind: str = ""
    source: str = "hosv_ext"

    @classmethod
    def from_result(cls, r: ExtResult, source: str) -> "HosvExtOutput":
        return cls(
            verdict=r.verdict, alloc_line=r.alloc_line,
            write_line=r.write_line, var_name=r.var_name,
            alloc_size=r.alloc_size, write_size=r.write_size,
            overflow_bytes=r.overflow_bytes,
            confidence=r.confidence, reason=r.reason,
            kind=r.kind, source=source)


class HosvExtVerifier:
    """写模式扩展验证器 — 覆盖原 HOSV 漏检的写模式."""

    def __init__(self) -> None:
        self._factory = FactorySummary()

    def verify(self, source: str) -> List[HosvExtOutput]:
        """主入口: 对 C 源码运行全部写模式检测模块."""
        raw = source.splitlines()
        valid = {ln for ln, _ in _skip_block_comments(raw)}
        lines = raw

        allocs = find_allocs(lines, valid)

        ext_allocs = [ExtAlloc(
            line=a.line, func=a.func, var=a.var,
            size_expr=a.size_expr, size_const=a.size_const,
            root=a.var,
            usable=_ptmalloc2_usable(a.size_const) if a.size_const > 0 else -1,
        ) for a in allocs]
        alloc_var_set = {a.var for a in allocs}
        alloc_by_var = {a.var: a for a in ext_allocs}

        out: List[HosvExtOutput] = []

        # 模块 4 前置: 工厂摘要独立于 find_allocs — `return calloc(...)`
        # 不产生分配点, 但仍是工厂分配. 先构建摘要供跨函数绑定使用.
        self._factory = build_factory_summaries(lines, valid)

        if not allocs:
            # 无同函数分配点: 工厂模块可能产出 (return-calloc/return-malloc 形态)
            binds = collect_factory_binds(lines, self._factory, valid)
            for (call_line, target, factory, args) in binds:
                finfo = self._factory.get(factory)
                if finfo is None:
                    continue
                alloc_func, size_expr, alloc_var = finfo
                syn_alloc = ExtAlloc(
                    line=call_line, func=alloc_func, var=target,
                    size_expr=size_expr, size_const=-1, root=target,
                    usable=-1)
                r = verify_factory(syn_alloc, call_line, args, lines)
                if r and r.verdict != "UNCERTAIN":
                    out.append(HosvExtOutput.from_result(r, "factory_bind"))
                # 跨函数写入关联同样适用于 return-malloc 工厂
                out.extend(self._bind_cross_writes(
                    target, factory, finfo, call_line, args, lines, valid))
            return self._dedup(out)
        walks = collect_walk_writes(alloc_var_set, lines, valid)
        for w in walks:
            alloc = alloc_by_var.get(w.base)
            r = verify_walk(w, alloc, lines)
            if r and r.verdict != "UNCERTAIN":
                out.append(HosvExtOutput.from_result(r, "walk_write"))

        # 模块 2: 结构体数组索引写
        struct_writes = collect_struct_idx_writes(lines, valid)
        for (line, arr, idx) in struct_writes:
            alloc = alloc_by_var.get(arr)
            if alloc is None:
                continue
            r = verify_struct_idx(alloc, line, idx, lines)
            if r and r.verdict != "UNCERTAIN":
                out.append(HosvExtOutput.from_result(r, "struct_idx"))

        # 模块 3: 无界输入
        io_writes = collect_unbounded_io(lines, valid)
        for (line, target, max_io, kind) in io_writes:
            alloc = alloc_by_var.get(target)
            if alloc is None:
                continue
            r = verify_unbounded_io(alloc, line, max_io, kind)
            if r and r.verdict != "UNCERTAIN":
                out.append(HosvExtOutput.from_result(r, "unbounded_io"))

        # 模块 5: null 终止符 off-by-one
        term_writes = collect_terminator_writes(lines, valid)
        for (line, target, idx_var) in term_writes:
            alloc = alloc_by_var.get(target)
            if alloc is None:
                continue
            r = verify_terminator(alloc, line, idx_var, lines)
            if r and r.verdict != "UNCERTAIN":
                out.append(HosvExtOutput.from_result(r, "null_terminator"))

        # 模块 4: 工厂函数绑定 (摘要已前置构建, 不重复)
        binds = collect_factory_binds(lines, self._factory, valid)
        for (call_line, target, factory, args) in binds:
            finfo = self._factory.get(factory)
            if finfo is None:
                continue
            alloc_func, size_expr, alloc_var = finfo
            # 构造合成分配点用于回绕检查
            syn_alloc = ExtAlloc(
                line=call_line, func=alloc_func, var=target,
                size_expr=size_expr, size_const=-1, root=target,
                usable=-1)
            r = verify_factory(syn_alloc, call_line, args, lines)
            if r and r.verdict != "UNCERTAIN":
                out.append(HosvExtOutput.from_result(r, "factory_bind"))
            # 跨函数写入关联: 调用点之后的 target 写入绑定到工厂分配
            out.extend(self._bind_cross_writes(
                target, factory, finfo, call_line, args, lines, valid))

        return self._dedup(out)

    def _bind_cross_writes(self, target: str, factory: str,
                           finfo: Tuple[str, str, str], call_line: int,
                           args: str, lines: List[str], valid: set
                           ) -> List[HosvExtOutput]:
        """将调用点后对 target 的写入关联到工厂分配, 执行简单边界判定."""
        results = []
        alloc_func, size_expr, alloc_var = finfo
        size_const = self._try_const_size(size_expr, lines, call_line, args)
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

    @staticmethod
    def _try_const_size(expr: str, lines: List[str],
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
                            return _const_var(a, lines, call_line) \
                                if not re.match(r'^\d+$', a) \
                                else int(a)
                    break
        if e.isdigit():
            return int(e)
        m = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', e)
        if m:
            from analysis.hosv_struct_idx import resolve_elem_size
            sz = resolve_elem_size(m.group(2), lines, call_line)
            n = _const_var(m.group(1), lines, call_line)
            if n > 0 and sz > 0:
                return n * sz
        m = re.match(r'(\d+)\s*\*\s*(\d+)', e)
        if m:
            return int(m.group(1)) * int(m.group(2))
        return -1

    @staticmethod
    def _dedup(results: List[HosvExtOutput]) -> List[HosvExtOutput]:
        """去重: 同 (alloc_line, write_line, var) 保留最严重 verdict."""
        sev = {'VULN': 0, 'UNCERTAIN': 1, 'SAFE': 2}
        seen = set()
        out = []
        for r in sorted(results, key=lambda x: (sev.get(x.verdict, 9), -x.confidence)):
            k = (r.alloc_line, r.write_line, r.var_name)
            if k in seen:
                continue
            seen.add(k)
            out.append(r)
        return out


def _const_var(name: str, lines: List[str], around_line: int) -> int:
    """解析变量名 → 常量赋值 (仅搜索前文简单赋值)."""
    for j in range(max(0, around_line - 2), -1, -1):
        import re as _re
        m = _re.search(rf'\b{name}\s*=\s*(\d+)\s*;', lines[j].strip())
        if m:
            return int(m.group(1))
    return -1


__all__ = ['HosvExtVerifier', 'HosvExtOutput']
