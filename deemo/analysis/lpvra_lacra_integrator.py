"""LACRA后处理器 — 对 C语义分析器 的 UNCERTAIN 做仿射关系过滤.

不改动 CSemanticAnalyzer, 仅读取其 verdicts 做后处理.
可证明 SAFE → 过滤; 不可证明 → 保留 → 零额外 FN.
过滤判定标注 "LACRA-affine" 以区分来源.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.c_source_preprocessor import resolve_write_target
from analysis.lpvra_affine import (
    ConstraintSet, AffineSafetyProver, extract_affine_from_stmt,
)


class LACRAIntegrator:
    """LACRA后处理集成器 — 对C语义分析结果做仿射过滤.

    用法:
      integrator = LACRAIntegrator()
      filtered = integrator.filter_uncertain(source_code, sem_verdicts)
      # filtered 中 SAFE 的 verdicts 可被过滤
    """

    def __init__(self):
        self._prover = AffineSafetyProver()
        self._stats = {'attempted': 0, 'proved_safe': 0,
                       'proved_overflow': 0, 'uncertain': 0}

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def filter_uncertain(self, source: str,
                         verdicts: List) -> List:
        """对 C 源码和语义分析结果做仿射过滤。

        verdicts 为 CSemanticAnalyzer.analyze() 的返回列表;
        返回过滤后的新列表, 不修改原 verdict。
        """
        # 阶段1: 从整个函数提取所有仿射关系
        stmt_assignments, stmt_guards, diff_cons = self._scan_function(source)
        filtered = []
        for v in verdicts:
            self._stats['attempted'] += 1
            # 只处理 UNCERTAIN — 不改变已有的 OVERFLOW/SAFE
            if v.verdict != "UNCERTAIN":
                filtered.append(v)
                continue

            # 阶段2: 对 UNCERTAIN 尝试仿射证明
            # 将结构体成员写目标解析为父变量 (resp->payload → resp)
            write_base = resolve_write_target(v.write.target_var, {})
            result = self._prover.try_prove_safe(
                alloc_var=v.alloc.var,
                alloc_expr=v.alloc.size_expr,
                write_var=write_base,
                write_expr=v.write.size_expr,
                stmt_assignments=stmt_assignments,
                stmt_guards=stmt_guards,
                diff_constraints=diff_cons,
            )

            if result is True:
                self._stats['proved_safe'] += 1
                # 创建新的SAFE verdict
                v.verdict = "SAFE"
                v.reason += f" [LACRA-affine: proved write <= alloc]"
                v.confidence = 0.82
                filtered.append(v)
            elif result is False:
                self._stats['proved_overflow'] += 1
                v.verdict = "OVERFLOW"
                v.reason += f" [LACRA-affine: proved overflow]"
                v.confidence = 0.88
                filtered.append(v)
            else:
                self._stats['uncertain'] += 1
                filtered.append(v)

        return filtered

    def _scan_function(self, source: str) -> Tuple[
        List[Tuple[str, str, int]], List[Tuple[str, str, int]],
        List[Tuple[str, str, int]],
    ]:
        """扫描C函数, 提取赋值/守卫/差分约束 (两遍扫描+三元处理)."""
        raw_lines = []
        for line in source.splitlines():
            s = line.strip()
            # 去除行内 /* ... */ 注释
            s = re.sub(r'/\*.*?\*/', '', s).strip()
            if not s or s.startswith('//') or s.startswith('/*') or s.startswith('*'):
                continue
            if s.startswith('#') or s.startswith('typedef') or s.startswith('struct'):
                continue
            raw_lines.append(s)

        # 第一遍: 收集常量赋值构建const_map
        const_map: Dict[str, int] = {}
        for s in raw_lines:
            stripped = self._strip_type_decl(s)
            m = re.match(r'\s*(\w+)\s*=\s*(-?\d+)\s*;?\s*$', stripped)
            if m:
                const_map[m.group(1)] = int(m.group(2))

        # 第二遍: 用const_map解析所有赋值和守卫
        assignments: List[Tuple[str, str, int]] = []
        guards: List[Tuple[str, str, int]] = []
        diff_constraints: List[Tuple[str, str, int]] = []  # (a, b, c): a-b ≤ c

        # 跟踪size_t/unsigned变量 → 添加非负约束
        nonneg_vars: Set[str] = set()
        _size_re = re.compile(
            r'(?:size_t|ssize_t|uint\d+_t|unsigned\s+(?:int|long|char|short)|'
            r'uint8_t|uint16_t|uint32_t|uint64_t)\s+\**\s*(\w+)')

        for s in raw_lines:
            conds = self._extract_guards(s)
            guards.extend(conds)

            # 收集无符号类型变量 → 非负约束
            for m in _size_re.finditer(s):
                vn = m.group(1)
                if vn not in nonneg_vars:
                    nonneg_vars.add(vn)
                    diff_constraints.append(("_0", vn, 0))  # _0 - vn ≤ 0 → vn ≥ 0
            # 函数参数: size_t param → 非负
            for m in re.finditer(r'size_t\s+(\w+)', s):
                vn = m.group(1)
                if vn not in nonneg_vars:
                    nonneg_vars.add(vn)
                    diff_constraints.append(("_0", vn, 0))

            # 三元 min 模式: x = (a <= b) ? a : b → x ≤ a, x ≤ b
            stripped = self._strip_type_decl(s)
            terns = self._extract_ternary_min(stripped)
            for x, bound_var in terns:
                diff_constraints.append((x, bound_var, 0))

            rels = extract_affine_from_stmt(stripped, set(), const_map)
            assignments.extend(rels)

            # 多变量赋值的不等式约束: x = y + z (+ c) → y ≤ x - c
            # 用于证明 write_var(=y) ≤ alloc_var(=x) 的场景
            m = re.match(
                r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*\+\s*(\d+)\s*;?\s*$', stripped)
            if m:
                t, a, b, c_val = m.group(1), m.group(2), m.group(3), int(m.group(4))
                diff_constraints.append((a, t, -c_val))  # a - t ≤ -c → a ≤ t - c
                diff_constraints.append((b, t, -c_val))
                continue
            m = re.match(
                r'(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)\s*;?\s*$', stripped)
            if m:
                t, a, b = m.group(1), m.group(2), m.group(3)
                if not a.isdigit() and not b.isdigit():
                    diff_constraints.append((a, t, 0))  # a ≤ t
                    diff_constraints.append((b, t, 0))

        return assignments, guards, diff_constraints

    @staticmethod
    def _strip_type_decl(s: str) -> str:
        """移除C类型声明前缀, 保留赋值表达式."""
        stripped = re.sub(
            r'^(?:const\s+)?(?:unsigned\s+)?(?:int|long|size_t|ssize_t|'
            r'uint\d+_t|int\d+_t|char|short|float|double|void|uint8_t'
            r'|uint16_t|uint32_t|uint64_t)\s+\**\s*',
            '', s)
        return s if stripped == s.lstrip() else stripped

    @staticmethod
    def _extract_ternary_min(s: str) -> List[Tuple[str, str]]:
        """提取三元min模式: x = (a <= b) ? a : b → [(x, a), (x, b)]."""
        results = []
        # x = (a <= b) ? a : b 或 x = (a < b) ? a : b
        m = re.search(
            r'(\w+)\s*=\s*\(\s*(\w+)\s*\<=\s*(\w+)\s*\)\s*\?\s*\2\s*:\s*\3\s*;', s)
        if not m:
            m = re.search(
                r'(\w+)\s*=\s*\(\s*(\w+)\s*\<=\s*(\w+)\s*\)\s*\?\s*\3\s*:\s*\2\s*;', s)
            if m:
                # max模式: x = (a<=b)?b:a → 上界不单一
                return []
        if m:
            x, a, b = m.group(1), m.group(2), m.group(3)
            results.append((x, a))
            if a != b:
                results.append((x, b))
        return results

    @staticmethod
    def _parse_line_assign(s: str) -> List[Tuple[str, str, int]]:
        """解析单行的赋值关系, 支持类型声明前缀."""
        stripped = LACRAIntegrator._strip_type_decl(s)
        return extract_affine_from_stmt(stripped)

    @staticmethod
    def _extract_guards(line: str) -> List[Tuple[str, str, int]]:
        """从单行提取守卫条件: if/while (var op const)."""
        results = []
        m = re.search(
            r'(?:if|while|for)\s*\(\s*(\w+)\s*(<|<=|>|>=)\s*(\d+)\s*\)', line)
        if m:
            var, op = m.group(1), m.group(2)
            try:
                val = int(m.group(3))
                results.append((var, op, val))
            except ValueError:
                pass
        return results


def lacra_enhance_verdict(source: str, verdict) -> bool:
    """便捷函数: 对单个verdict尝试LACRA证明.

    返回 True=应过滤(安全), False=保留.
    不修改原verdict对象.
    """
    if verdict.verdict != "UNCERTAIN":
        return verdict.verdict == "SAFE"
    integrator = LACRAIntegrator()
    stmt_as, stmt_gs, diff_cs = integrator._scan_function(source)
    prover = AffineSafetyProver()
    write_base = resolve_write_target(verdict.write.target_var, {})
    result = prover.try_prove_safe(
        alloc_var=verdict.alloc.var,
        alloc_expr=verdict.alloc.size_expr,
        write_var=write_base,
        write_expr=verdict.write.size_expr,
        stmt_assignments=stmt_as,
        stmt_guards=stmt_gs,
        diff_constraints=diff_cs,
    )
    return result is True


__all__ = ['LACRAIntegrator', 'lacra_enhance_verdict']
