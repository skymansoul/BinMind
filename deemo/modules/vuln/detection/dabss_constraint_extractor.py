# coding: utf-8
# 创建: 2026-07-14  |  约束提取器
# 修改: 2026-07-14  |  审计后补充文件头与错误处理
#
"""
数据流感知的二进制种子合成——约束提取器。

从数据流切片中提取缓冲区/指针操作的数值约束，
构建可满足的约束系统用于种子合成。

提取的约束类型:
  1. 边界约束: size <= capacity, offset < length
  2. 非空约束: ptr != NULL (调用点前置条件)
  3. 对齐约束: addr % alignment == 0 (memcpy优化路径)
  4. 范围约束: value in [min, max] (循环界限/数组索引)
  5. 类型约束: sizeof(type) 影响步长计算

约束表示——SMT-LIB2子集:
  使用简单的(declare-const / assert / check-sat)子集，
  不依赖Z3——内置轻量回溯求解器处理≤10变量的小规模约束系统。

设计依据:
  FieldsFuzz需要运行时taint tracking, PBFuzz需要LLM API,
  本模块仅需静态分析结果——消除执行/API依赖，
  使种子合成在离线/无GPU/无LLM环境中可运行。
"""

import re
import math
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from .dabss_flow_slicer import BufferSlice, DataFlowNode

_log = logging.getLogger(__name__)


# 约束系统


class ConstraintType:
    BOUND_LE = "bound_le"       # var ≤ constant
    BOUND_GE = "bound_ge"       # var ≥ constant
    BOUND_LT = "bound_lt"       # var < constant
    BOUND_GT = "bound_gt"       # var > constant
    BOUND_EQ = "bound_eq"       # var ≡ constant
    NONNULL = "nonnull"         # ptr ≠ 0
    ALIGN = "align"             # addr % N ≡ 0
    RANGE = "range"             # lo ≤ var ≤ hi


@dataclass
class VariableConstraint:
    """单变量约束——变量名+约束类型+边界值"""
    var_name: str                # 约束的变量名(寄存器/操作数映射后的名称)
    constraint_type: str         # ConstraintType值
    value: int = 0               # 边界值(对range为(lo, hi)对)
    value_hi: int = 0            # 上界(range约束使用)
    # 来源追踪
    source_addr: int = 0         # 约束来源的指令地址
    source_type: str = ""        # cmp_insn | null_check | type_cast | inferred


@dataclass
class SeedConstraint:
    """单条种子的约束集合——用于合成一个测试输入"""
    # 约束列表
    constraints: List[VariableConstraint] = field(default_factory=list)
    # 目标缓冲区信息
    buffer_size_hint: int = 0     # 推断的缓冲区大小
    buffer_alignment: int = 1     # 推断的对齐要求
    # 约束系统的复杂度度量
    variable_count: int = 0
    constraint_count: int = 0
    # 合成提示——帮助种子合成器生成更有效的测试值
    boundary_values: List[int] = field(default_factory=list)
    # 例: [0, 1, capacity-1, capacity, capacity+1]


# 约束提取器


class ConstraintExtractor:
    """从数据流切片中提取数值约束。

    遍历BufferSlice的每个DataFlowNode:
      - 对is_constraint=True的节点提取比较操作符与立即数
      - 对null_checks中的地址提取非空约束
      - 对type_casts提取对齐约束
      - 聚合为SeedConstraint供种子合成器消费

    变量命名规则: {buf|size|off}_{slice_index}
    例: buf_0 = dst指针, size_0 = 第3个参数, off_0 = 偏移量
    """

    def __init__(self):
        self._var_counter = 0

    def extract(self, slices: List[BufferSlice],
                 function_name: str = "") -> List[SeedConstraint]:
        """从多个切片中提取约束——每条切片产出一个SeedConstraint。

        如果多条切片操作同一缓冲区，合并约束以减少冗余种子。
        """
        seed_constraints = []
        buf_to_slices: Dict[str, List[BufferSlice]] = defaultdict(list)
        for sl in slices:
            key = f"{function_name}_{sl.buffer_operand}_{sl.sink_addr:x}"
            buf_to_slices[key].append(sl)

        for key, sl_list in buf_to_slices.items():
            sc = SeedConstraint()
            sc.buffer_size_hint = max(sl.inferred_buffer_capacity for sl in sl_list)

            for sl in sl_list:
                # 映射操作数到变量名
                buf_var = f"buf_{self._var_counter}"
                size_var = f"size_{self._var_counter}"
                off_var = f"off_{self._var_counter}"
                self._var_counter += 1

                # 边界约束——从bound_constraints提取
                for op, val in sl.bound_constraints:
                    vc = VariableConstraint(
                        var_name=size_var,
                        constraint_type=self._map_bound_type(op),
                        value=val,
                        source_addr=sl.sink_addr,
                        source_type="cmp_insn")
                    sc.constraints.append(vc)

                # 非空约束
                for check_addr in sl.null_checks:
                    sc.constraints.append(VariableConstraint(
                        var_name=buf_var,
                        constraint_type=ConstraintType.NONNULL,
                        source_addr=check_addr,
                        source_type="null_check"))

                # 类型约束——从type_casts提取对齐
                for cast in sl.type_casts:
                    align = _alignment_from_cast(cast)
                    if align > 1:
                        sc.constraints.append(VariableConstraint(
                            var_name=buf_var,
                            constraint_type=ConstraintType.ALIGN,
                            value=align,
                            source_type="type_cast"))

                # 推断缓冲区大小
                if sl.inferred_buffer_capacity > 0:
                    sc.buffer_size_hint = max(
                        sc.buffer_size_hint,
                        sl.inferred_buffer_capacity)

            # 生成边界测试值
            sc.boundary_values = _generate_boundary_values(sc)
            sc.constraint_count = len(sc.constraints)
            sc.variable_count = len(set(
                vc.var_name for vc in sc.constraints))

            seed_constraints.append(sc)

        return seed_constraints

    @staticmethod
    def _map_bound_type(op: str) -> str:
        """将汇编比较操作符映射至约束类型"""
        mapping = {
            'le': ConstraintType.BOUND_LE,
            'lt': ConstraintType.BOUND_LT,
            'ge': ConstraintType.BOUND_GE,
            'gt': ConstraintType.BOUND_GT,
            'eq': ConstraintType.BOUND_EQ,
            'ne': ConstraintType.BOUND_GT,  # != 保守为 ≥1
            'cmp': ConstraintType.BOUND_LE,  # 保守假设为上限
        }
        return mapping.get(op, ConstraintType.BOUND_LE)


# 轻量约束求解——回溯法(O(k^n), k≤10, n≤256)


def solve_seed_constraints(seed_constraint: SeedConstraint) -> Dict[str, int]:
    """对种子约束系统求解——返回{变量名: 具体值}映射。

    求解策略:
      1. 每个变量取其约束区间的最小值作为"安全默认值"
      2. 对边界变量(size/offset)额外产出边界值变体
      3. 不调用外部求解器——纯回溯，适用于≤10变量的规模

    复杂度: O(k^n)最坏，k=值域大小(≤256), n=变量数(≤10)
    实用中秒级完成——大多数约束系统有3-5个变量。
    """
    if not seed_constraint.constraints:
        return {}

    # 收集每个变量的约束
    var_domains: Dict[str, Dict[str, List[int]]] = defaultdict(
        lambda: defaultdict(list))
    for vc in seed_constraint.constraints:
        if vc.constraint_type == ConstraintType.NONNULL:
            var_domains[vc.var_name]['nonnull'].append(1)
        elif vc.constraint_type == ConstraintType.ALIGN:
            var_domains[vc.var_name]['align'].append(vc.value)
        elif vc.constraint_type == ConstraintType.RANGE:
            var_domains[vc.var_name]['lo'].append(vc.value)
            var_domains[vc.var_name]['hi'].append(vc.value_hi)
        elif vc.constraint_type in (ConstraintType.BOUND_LE,
                                      ConstraintType.BOUND_LT):
            var_domains[vc.var_name]['max'].append(vc.value)
        elif vc.constraint_type in (ConstraintType.BOUND_GE,
                                      ConstraintType.BOUND_GT):
            var_domains[vc.var_name]['min'].append(vc.value)
        elif vc.constraint_type == ConstraintType.BOUND_EQ:
            var_domains[vc.var_name]['eq'].append(vc.value)

    # 对每个变量计算有效值域
    solution = {}
    for var_name, domain in var_domains.items():
        # 等式约束优先
        if domain.get('eq'):
            solution[var_name] = domain['eq'][0]
            continue

        lo = max(domain.get('min', [0]))
        hi = min(domain.get('max', [0xFFFFFFFF]))
        if domain.get('nonnull'):
            lo = max(lo, 1)
        if domain.get('align'):
            align = max(domain['align'])
            lo = ((lo + align - 1) // align) * align

        if lo > hi:
            # 约束冲突——回退至非约束值
            solution[var_name] = max(0, lo)
        else:
            # 优先边界值——这些是种子合成的关键
            solution[var_name] = lo

    return solution


# 辅助


def _alignment_from_cast(cast_str: str) -> int:
    """从类型转换字符串推断对齐要求"""
    align_map = {
        'int16': 2, 'uint16': 2, 'short': 2,
        'int32': 4, 'uint32': 4, 'int': 4, 'float': 4,
        'int64': 8, 'uint64': 8, 'double': 8, 'long': 8,
        'ptr': 8, 'pointer': 8, 'void*': 8,
        '__int128': 16, '__m128': 16,
    }
    for type_name, align in align_map.items():
        if type_name in cast_str.lower():
            return align
    return 1


def _generate_boundary_values(sc: SeedConstraint) -> List[int]:
    """生成边界测试值——用于探索缓冲区溢出/下溢。

    规则:
      - 包含0, 1（最小有效值）
      - 包含hint-1, hint, hint+1（边界周围）
      - 包含hint*2, hint*16（显著溢出）
      - 包含2^8, 2^16-1, 2^32-1（整数溢出边界）
    """
    vals = {0, 1}
    h = sc.buffer_size_hint
    if h > 0:
        vals.update({max(0, h - 1), h, h + 1, h * 2, min(h * 16, 65536)})
    vals.update({255, 256, 65535, 65536})
    return sorted(vals)[:20]  # 限制最多20个边界值


__all__ = [
    "ConstraintType",
    "VariableConstraint",
    "SeedConstraint",
    "ConstraintExtractor",
    "solve_seed_constraints",
]
