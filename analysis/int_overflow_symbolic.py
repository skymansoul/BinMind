"""
整数溢出符号化范围分析 — 乘积链worklist传播.

理论支撑:
  - Cousot & Cousot: widening/narrowing 保证fixpoint终止
  - Dietz et al.: "Understanding Integer Overflow in C/C++"
  - CWE-190 整数溢出 → CWE-122 堆溢出链

架构 (3层):
  L1 — 符号化乘积提取: regex识别 var = expr * const (兼容现有, 快速)
  L2 — 乘积链图传播 (v2): worklist沿乘积边传播约束 → fixpoint
  L3 — I-GUARD 融合: 符号化阈值 + 值范围传播 + 守卫检测

v2: 新增 ProductChainGraph + WorklistPropagator.
  不再仅用正则提取+简单除法, 而是构建乘积依赖图, worklist传播
  约束直到 fixpoint. 加入 lattice meet/join 操作, 支持非平凡乘积链:
    a = b * 4; c = a + 8; d = c * 2 → 沿图传播到达 malloc 的所有路径.

与现有模块关系:
  - int_overflow_verifier.py: 值范围传播 (ALGORITHMIC) — 广度
  - int_loop_induction.py: 循环归纳变量 (ALGORITHMIC) — 循环感知
  - 本模块: 乘积链worklist传播 (ALGORITHMIC) — 符号化深度
"""


import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.int_overflow_helpers import (
    _SIZEOF_MAP,
    find_overflow_guards,
    infer_var_range,
    assess_overflow,
    is_in_alloc_context,
)

# 平台相关的 SIZE_MAX
_SIZEMAX = {
    'x86': 0xFFFFFFFF,
    'x86_64': 0xFFFFFFFFFFFFFFFF,
    'arm32': 0xFFFFFFFF,
    'aarch64': 0xFFFFFFFFFFFFFFFF,
    'mips32': 0xFFFFFFFF,
    'default': 0xFFFFFFFFFFFFFFFF,
}


@dataclass
class SymbolicProduct:
    """符号化乘法表达式: result = var * constant."""
    result_var: str           # 结果变量名 (如 alloc_size)
    operand_var: str          # 符号变量 (如 count)
    constant: int             # 常量因子 (如 sizeof(int) = 4)
    line_no: int = 0


@dataclass
class OverflowThreshold:
    """溢出阈值分析结果."""
    product: SymbolicProduct
    threshold: int            # SIZE_MAX / constant → 超过此值则溢出
    size_max: int             # 使用的 SIZE_MAX
    var_range_lo: int = 0     # 符号变量的当前下界
    var_range_hi: int = -1    # 符号变量的当前上界 (-1 = 未知)
    is_guarded: bool = False  # 是否有显式溢出守卫
    guard_condition: str = "" # 守卫条件描述
    verdict: str = ""         # SAFE | LIKELY_OVERFLOW | OVERFLOW | UNCERTAIN
    confidence: float = 0.5


class IntOverflowSymbolicAnalyzer:
    """整数溢出符号化分析器.

    与 IntOverflowVerifier 互补:
      - IntOverflowVerifier: 值范围传播 + 守卫检测 + 批量验证 (广度)
      - 本模块: 符号化乘积追踪 + 溢出阈值分析 (深度)
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._size_max = _SIZEMAX.get(platform, _SIZEMAX['default'])

    # 核心分析 ──────────────────────────────────

    def analyze_mul_overflow(
        self, source_code: str, func_name: str = "",
    ) -> List[OverflowThreshold]:
        """分析源码中所有乘法溢出风险.

        识别模式:
          size_t sz = count * sizeof(T);
          buf = malloc(sz);
        """
        results = []
        products = self._extract_symbolic_products(source_code)

        for sp in products:
            threshold = self._compute_threshold(sp)
            guards = find_overflow_guards(source_code, sp.operand_var, threshold)
            var_lo, var_hi = infer_var_range(source_code, sp.operand_var, self._platform)
            verdict, confidence = assess_overflow(
                sp.operand_var, threshold, guards, var_lo, var_hi, source_code)

            results.append(OverflowThreshold(
                product=sp, threshold=threshold, size_max=self._size_max,
                var_range_lo=var_lo, var_range_hi=var_hi,
                is_guarded=len(guards) > 0,
                guard_condition="; ".join(guards) if guards else "",
                verdict=verdict, confidence=confidence,
            ))

        return results

    # 乘法提取 ──────────────────────────────────

    def _extract_symbolic_products(self, source: str) -> List[SymbolicProduct]:
        """提取所有 'var = operand * constant' 形式的乘法表达式.

        特别关注分配上下文中: sz = n * sizeof(T); malloc(sz)
        """
        products = []
        sz_pat = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\*\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)'
            r'|(\w+)\s*=\s*sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)\s*\*\s*(\w+)',
            re.IGNORECASE)

        for i, line in enumerate(source.splitlines()):
            for m in sz_pat.finditer(line):
                if m.group(1):
                    result_var, operand_var = m.group(1), m.group(2)
                    type_name = m.group(3).strip()
                else:
                    result_var, operand_var = m.group(4), m.group(6)
                    type_name = m.group(5).strip()

                elem_size = _SIZEOF_MAP.get(type_name.lower(), 0)
                if elem_size > 0 and operand_var not in ('argc',):
                    products.append(SymbolicProduct(
                        result_var=result_var, operand_var=operand_var,
                        constant=elem_size, line_no=i))

        # var = a * CONST (非sizeof形式)
        const_mul_pat = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)\s*;?$')
        for i, line in enumerate(source.splitlines()):
            for m in const_mul_pat.finditer(line):
                result_var, operand_var = m.group(1), m.group(2)
                const_val = int(m.group(3))
                if is_in_alloc_context(source, result_var, i):
                    products.append(SymbolicProduct(
                        result_var=result_var, operand_var=operand_var,
                        constant=const_val, line_no=i))

        return products

    # 阈值计算 ──────────────────────────────────

    def _compute_threshold(self, sp: SymbolicProduct) -> int:
        """溢出阈值: SIZE_MAX / constant. 超过此值则 product 溢出."""
        if sp.constant == 0:
            return self._size_max
        return self._size_max // sp.constant


# 便捷入口

def analyze_int_overflow_symbolic(
    source_code: str, platform: str = "x86_64",
) -> List[OverflowThreshold]:
    """便捷函数: 符号化整数溢出分析."""
    analyzer = IntOverflowSymbolicAnalyzer(platform)
    return analyzer.analyze_mul_overflow(source_code)


# v2: 乘积链图传播 → 已提取至 analysis.int_product_chain

from analysis.int_product_chain import (  # noqa: F401
    ProductEdge, ProductChainGraph, ProductChainPropagator,
    analyze_product_chain_deep, _collect_path_multipliers,
    combine_with_value_range,
)


__all__ = [
    'SymbolicProduct', 'OverflowThreshold', 'IntOverflowSymbolicAnalyzer',
    'analyze_int_overflow_symbolic', 'combine_with_value_range',
    'ProductEdge', 'ProductChainGraph', 'ProductChainPropagator',
    'analyze_product_chain_deep', '_collect_path_multipliers',
    '_SIZEOF_MAP',
]
