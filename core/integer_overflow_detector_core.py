# 拆分自 integer_overflow_detector.py — 核心检测器类.
# 独立模块: 检测流程主体, 依赖模式常量与IntOverflowSite数据结构.
import re
from typing import Dict, List, Set, Tuple

from core.integer_overflow_detector_patterns import (
    _ADD_ASSIGN, _ALLOC_FUNC, _CALLOC,
    _extract_balanced_args, _MEM_OPS_FUNC,
    _MUL_ASSIGN, _NARROW_TYPE, _OVERFLOW_GUARD,
    _SHIFT_ASSIGN, _WIDE_TYPE,
)
from core.integer_overflow_detector_types import IntOverflowSite


class IntegerOverflowDetector:
    """整数溢出检测器 — v2: 处理6种IO2BO模式.

    检测流程:
      1. 提取类型信息 (窄类型/宽类型)
      2. 识别所有乘/加赋值, 追踪变量→alloc的数据流
      3. 检查 overflow guard
      4. 综合评估置信度
    """

    def __init__(self):
        self.sites: List[IntOverflowSite] = []

    def detect(self, pseudocode: str) -> List[IntOverflowSite]:
        """对伪代码/IR运行整数溢出检测."""
        self.sites = []
        lines = pseudocode.splitlines()

        # 阶段1: 类型提取
        narrow_vars: Set[str] = set()
        wide_vars: Set[str] = set()
        for line in lines:
            for m in _NARROW_TYPE.finditer(line):
                narrow_vars.add(m.group(1))
            for m in _WIDE_TYPE.finditer(line):
                wide_vars.add(m.group(1))

        # 阶段2: 变量赋值追踪
        # {result_var: (op, left, right, line_no)}
        mul_results: Dict[str, Tuple[str, str, str, int]] = {}
        add_results: Dict[str, Tuple[str, str, str, int]] = {}
        shift_results: Dict[str, Tuple[str, str, int]] = {}
        const_values: Dict[str, int] = {}

        for i, line in enumerate(lines):
            # 乘法赋值
            for m in _MUL_ASSIGN.finditer(line):
                result, left, right = m.group(1), m.group(2), m.group(3)
                mul_results[result] = ('mul', left, right, i)
            # 加法赋值
            for m in _ADD_ASSIGN.finditer(line):
                result, left, right = m.group(1), m.group(2), m.group(3)
                add_results[result] = ('add', left, right, i)
            # 移位赋值: sz = 1 << c 或 sz = n << shift
            for m in _SHIFT_ASSIGN.finditer(line):
                result = m.group(1)
                if m.group(2):  # 1 << var
                    shift_results[result] = ('shift', '1', m.group(2), i)
                elif m.group(3) and m.group(4):  # var << amt
                    shift_results[result] = ('shift', m.group(3), m.group(4), i)
            # 常量赋值
            cm = re.match(r'(\w[\w\d_]*)\s*=\s*(\d+|0x[0-9a-fA-F]+)\s*;?', line.strip())
            if cm:
                try:
                    const_values[cm.group(1)] = int(cm.group(2), 0)
                except ValueError:
                    pass

        # 阶段3: 溢出守卫检测
        guarded_vars: Set[str] = set()
        for line in lines:
            for m in _OVERFLOW_GUARD.finditer(line):
                guarded_vars.add(m.group(1))
            # 简化guard: if (sz < n) → 溢出检测
            gm = re.search(r'if\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)', line)
            if gm:
                guarded_vars.add(gm.group(1))
                guarded_vars.add(gm.group(2))

        # 阶段4: alloc + memory操作分析
        # 使用平衡括号提取 (处理 (unsigned int)var 等嵌套括号)
        for i, line in enumerate(lines):
            # 内存操作: memcpy/memset/... — 检测指针算术溢出 + 截断
            for mm in _MEM_OPS_FUNC.finditer(line):
                mem_args = _extract_balanced_args(line, mm.end() - 1)
                self._analyze_alloc_args(
                    mem_args, i, line, mul_results, add_results, shift_results,
                    narrow_vars, wide_vars, guarded_vars, const_values)
            # calloc模式 (参数简单, 正则足够)
            for cm in _CALLOC.finditer(line):
                n_arg, size_arg = cm.group(1), cm.group(2)
                # calloc(n, m) → 内部 n*m
                self._add_site('calloc', [n_arg, size_arg], '',
                               i, line, narrow_vars, wide_vars, guarded_vars)

            # malloc/realloc/... — 使用平衡括号提取
            for am in _ALLOC_FUNC.finditer(line):
                alloc_args = _extract_balanced_args(line, am.end() - 1)
                # 跳过calloc (已由_CALLOC单独处理, 避免重复)
                func_name = am.group(0).rstrip('(').strip()
                if func_name in ('calloc', 'kcalloc'):
                    continue
                self._analyze_alloc_args(
                    alloc_args, i, line, mul_results, add_results, shift_results,
                    narrow_vars, wide_vars, guarded_vars, const_values)

        return self.sites

    def _analyze_alloc_args(self, args_str: str, line_no: int,
                            line: str,
                            mul_results: dict, add_results: dict,
                            shift_results: dict,
                            narrow_vars: set, wide_vars: set,
                            guarded_vars: set, const_values: dict):
        """分析 alloc 调用参数, 追踪数据流来源."""
        # 去除强制转换: (size_t)expr → expr
        clean = re.sub(r'\(\s*\w+\s*\**\s*\)', '', args_str).strip()

        # 检测截断模式: (unsigned int)long_var → 64位截断为32位
        # 在原始行上匹配, 避免 args_str 因嵌套括号截断而丢失信息
        trunc_m = re.search(
            r'\(\s*(?:unsigned\s+int|uint32_t|u32|int)\s*\)\s*(\w[\w\d_]*)',
            line)
        if trunc_m and trunc_m.group(1) in wide_vars:
            self._add_site('truncation', [trunc_m.group(1)], '',
                           line_no, line, narrow_vars, wide_vars, guarded_vars)

        # 模式1: malloc(n * m) — 直接乘法
        dm = re.search(r'(\w[\w\d_]*)\s*\*\s*(\w[\w\d_]*|sizeof\s*\([^)]+\))', clean)
        if dm:
            self._add_site('direct_mul', [dm.group(1), dm.group(2)], '',
                           line_no, line, narrow_vars, wide_vars, guarded_vars)

        # 模式2: malloc(n + m) — 直接加法
        da = re.search(r'(\w[\w\d_]*)\s*\+\s*(\w[\w\d_]*|\d+)', clean)
        if da:
            self._add_site('direct_add', [da.group(1), da.group(2)], '',
                           line_no, line, narrow_vars, wide_vars, guarded_vars)

        # 模式3: malloc(var) 其中 var = expr1 * expr2 (+ shift)
        var_m = re.match(r'(\w[\w\d_]*)$', clean)
        if var_m:
            var = var_m.group(1)
            if var in mul_results:
                _, left, right, ml = mul_results[var]
                self._add_site('mul_assign', [left, right], var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)
            elif var in add_results:
                _, left, right, al = add_results[var]
                self._add_site('add_assign', [left, right], var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)
            elif var in shift_results:
                _, left, right, sl = shift_results[var]
                self._add_site('shift_assign', [left, right], var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)

        # 模式4: malloc(sz+1) / malloc(sz * 2) — 基于溢出结果的表达式
        expr_m = re.match(r'(\w[\w\d_]*)\s*[\+\*]\s*(\d+)', clean)
        if expr_m:
            base_var = expr_m.group(1)
            if base_var in mul_results:
                _, left, right, _ = mul_results[base_var]
                self._add_site('mul_assign', [left, right], base_var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)
            elif base_var in add_results:
                _, left, right, _ = add_results[base_var]
                self._add_site('add_assign', [left, right], base_var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)
            elif base_var in shift_results:
                _, left, right, _ = shift_results[base_var]
                self._add_site('shift_assign', [left, right], base_var,
                               line_no, line, narrow_vars, wide_vars, guarded_vars)
        # 模式5: 指针算术溢出 — ptr + offset 可能回绕
        ptr_add = re.search(r'(\w[\w\d_]*)\s*\+\s*(\w[\w\d_]*)', clean)
        if ptr_add:
            base = ptr_add.group(1)
            off = ptr_add.group(2)
            if base != off:
                self._add_site('ptr_arith', [base, off], '',
                               line_no, line, narrow_vars, wide_vars, guarded_vars)

    def _add_site(self, pattern: str, operands: list, result_var: str,
                  line_no: int, line: str,
                  narrow_vars: set, wide_vars: set, guarded_vars: set):
        """创建并评估一个溢出候选点."""
        # 检查类型
        narrow = any(op in narrow_vars for op in operands)
        wide = any(op in wide_vars for op in operands)
        has_guard = any(op in guarded_vars for op in operands) or result_var in guarded_vars

        # 置信度计算
        conf = self._compute_confidence(pattern, operands, narrow, wide, has_guard)

        site = IntOverflowSite(
            func_name=f'line_{line_no+1}',
            pattern=pattern,
            operands=list(operands),
            result_var=result_var,
            alloc_line=line_no,
            narrow_type=narrow,
            wide_type=wide,
            has_guard=has_guard,
            confidence=conf,
            line_text=line.strip()[:120],
        )
        self.sites.append(site)

    @staticmethod
    def _compute_confidence(pattern: str, operands: list,
                            narrow: bool, wide: bool,
                            has_guard: bool) -> float:
        """综合评估溢出风险.

        规则:
          - 窄类型(unsigned short)乘法 → 高风险 (0.85)
          - 普通变量乘法 → 中风险 (0.65)
          - calloc(n, m) → 中等风险 (0.60)
          - 移位溢出 → 中高风险 (0.70)
          - 加法溢出 → 中风险 (0.55)
          - 真正宽类型(size_t/uint64_t) → 低风险 (0.25)
          - unsigned int/uint32_t乘法 → 中风险 (0.60, not wide)
          - 有溢出守卫 → 降权 (扣0.15, 保底0.20)
        """
        if pattern in ('mul_assign', 'direct_mul'):
            base = 0.65
        elif pattern == 'calloc':
            base = 0.65  # calloc(n,m)内部乘法, 即使size_t n*m也可能溢出
        elif pattern == 'shift_assign':
            base = 0.70
        elif pattern in ('add_assign', 'direct_add'):
            base = 0.55
        elif pattern == 'ptr_arith':
            base = 0.50  # 指针算术溢出
        elif pattern == 'truncation':
            base = 0.60  # 截断溢出
        else:
            base = 0.50

        # 类型调整
        if narrow:
            base = min(base + 0.20, 0.95)     # 窄类型 → 极易溢出
        if wide:
            # 截断漏洞的核心就是宽类型→窄类型, 不应惩罚宽类型
            if pattern == 'truncation':
                wide_penalty = 0.0
            elif pattern == 'calloc':
                wide_penalty = 0.15  # calloc(n,m)即使size_t也可溢出
            else:
                wide_penalty = 0.30
            base = max(base - wide_penalty, 0.15)

        # 守卫调整 (有守卫降低置信度但不消除)
        if has_guard:
            base = max(base - 0.15, 0.20)

        return round(min(base, 0.95), 2)
