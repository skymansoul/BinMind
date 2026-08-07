# 增强型堆溢出检测器: 组合跨步区间+路径条件+内存区域判别
# 核心创新: 不修改 HeapOverflowDetector 的现有逻辑,
#   而是通过包装模式在分析前后插入精度增强层:
#     Pre-pass:  路径条件注入 → 缩小值域上界
#     In-pass:   跨步区间追踪 → 增强循环分析精度
#     Post-pass: 内存区域过滤 → 排除非堆写入
# 设计原则: 每个增强层独立可禁用, 不影响核心检测管道的正确性
import logging
from typing import Dict, List, Optional, Tuple

from .heap_overflow_detector import (
    HeapOverflowDetector, OverflowFinding, OverflowSeverity,
    HeapAccessCheck)
from .strided_interval import (
    StridedInterval, StridedIntervalDomain, check_stride_safe_write)
from .path_condition import (
    PathConditionTracker, PathCondition, ConditionOp)
from .memory_region import MemoryWriteValidator, MemoryRegionType
from .value_range import ValueRange

log = logging.getLogger(__name__)


class EnhancedHeapOverflowDetector:
    """增强型堆溢出检测器.

    包装 HeapOverflowDetector, 加入:
      1. 路径条件追踪 — 分支条件约束写入大小上界
      2. 跨步区间验证 — 利用同余信息精确化循环写入判定
      3. 内存区域过滤 — 排除栈/全局区域的写入
    """

    def __init__(self,
                 enable_path_conditions: bool = True,
                 enable_strided_intervals: bool = True,
                 enable_memory_filter: bool = True):
        self._base = HeapOverflowDetector()
        self._path_tracker = PathConditionTracker() if enable_path_conditions else None
        self._strided = StridedIntervalDomain() if enable_strided_intervals else None
        self._mem_validator = MemoryWriteValidator() if enable_memory_filter else None
        self._use_path = enable_path_conditions
        self._use_stride = enable_strided_intervals
        self._use_mem = enable_memory_filter
        # 增强统计
        self._enhanced_stats: Dict[str, int] = {
            'path_constrained': 0,
            'stride_verified': 0,
            'memory_filtered': 0,
        }

    def analyze(self, instructions: List[str],
                func_map: Optional[Dict[str, Tuple[int, int]]] = None,
                instr_addrs: Optional[List[int]] = None
                ) -> List[OverflowFinding]:
        """执行增强型多阶段检测."""
        func_map = func_map or {}

# Phase 0: 路径条件预分析
        # 在核心分析前扫描分支条件, 构建路径约束映射
        path_bounds: Dict[int, Dict[str, int]] = {}  # idx → {reg: upper_bound}
        if self._use_path and self._path_tracker and instr_addrs:
            path_bounds = self._pre_analyze_paths(
                instructions, instr_addrs, func_map)

# Phase 1-3: 核心检测管道 (委托给原有检测器)
        raw_findings = self._base.analyze(instructions, func_map, instr_addrs)

# Phase 4: 后处理增强

        # 4a: 路径条件约束修正 — 缩小受分支保护的写入大小上界
        if self._use_path and path_bounds:
            raw_findings = self._apply_path_constraints(
                raw_findings, instructions, func_map)

        # 4b: 跨步区间二次验证 — 对POSSIBLE_OVERFLOW用跨步信息重新判定
        if self._use_stride and self._strided:
            raw_findings = self._stride_recheck(raw_findings, instructions,
                                                 func_map, instr_addrs)

        # 4c: 内存区域过滤 — 移除非堆区域写入产生的发现
        if self._use_mem and self._mem_validator:
            raw_findings = self._filter_non_heap(raw_findings, instructions)

        return raw_findings

    def _pre_analyze_paths(self, instructions: List[str],
                           addrs: List[int],
                           func_map: Dict[str, Tuple[int, int]]
                           ) -> Dict[int, Dict[str, int]]:
        """预分析: 扫描分支条件, 建立指令位置→寄存器约束映射.

        对每个条件跳转的fall-through路径 (条件未取),
        记录cmp reg, imm中的约束为 "在此之后的指令 reg ≤ imm".
        返回 {instruction_idx: {reg_name: upper_bound}}.
        """
        bounds: Dict[int, Dict[str, int]] = {}
        if not self._path_tracker:
            return bounds

        last_cmp_reg = ""
        last_cmp_val = None

        for i, line in enumerate(instructions):
            stripped = line.strip()
            parts = stripped.replace(',', ' ').split()
            if not parts:
                continue

            op = parts[0]

            # 记录cmp指令
            if op == 'cmp' and len(parts) >= 3:
                from .instruction_parser import InstructionParser
                last_cmp_reg = InstructionParser.clean_reg(parts[1])
                last_cmp_val = InstructionParser.parse_immediate(parts[2])
                continue

            # 记录test指令 (等效cmp reg, 0)
            if op == 'test' and len(parts) >= 3:
                from .instruction_parser import InstructionParser
                last_cmp_reg = InstructionParser.clean_reg(parts[1])
                last_cmp_val = 0
                continue

            # 处理条件跳转: 对fall-through路径 (条件为假) 施加约束
            if op in ('jle', 'jbe', 'jl', 'jb', 'jge', 'jae', 'jg', 'ja'):
                if last_cmp_reg and last_cmp_val is not None:
                    # fall-through = 条件不成立 = 反向约束
                    reverse_bounds = {
                        'jle': (None, None),           # 跳转: ≤, fall-through: >
                        'jbe': (None, None),           # 跳转: ≤(无符号), fall-through: >
                        'jl': (None, last_cmp_val - 1),  # 跳转: <, fall-through: ≥
                        'jb': (None, last_cmp_val - 1),
                        'jge': (last_cmp_val, None),   # 跳转: ≥, fall-through: <
                        'jae': (last_cmp_val, None),
                        'jg': (last_cmp_val + 1, None), # 跳转: >, fall-through: ≤
                        'ja': (last_cmp_val + 1, None),
                    }
                    lo, hi = reverse_bounds.get(op, (None, None))
                    # 约束传播到后续指令
                    # 取保守范围: 跳转目标后的约束范围
                    target_str = parts[-1] if len(parts) > 1 else ''
                    try:
                        target_addr = int(target_str.split('<')[0].strip(), 16)
                    except (ValueError, AttributeError):
                        target_addr = -1

                    # fall-through路径: 从当前指令到下一条非跳转指令
                    # 简化: 约束传播10条指令
                    for j in range(i + 1, min(i + 15, len(instructions))):
                        if j not in bounds:
                            bounds[j] = {}
                        if lo is not None:
                            bounds[j][last_cmp_reg] = max(
                                bounds[j].get(last_cmp_reg, 0), lo)
                        if hi is not None:
                            existing = bounds[j].get(last_cmp_reg + '_ub')
                            if existing is None or hi < existing:
                                bounds[j][last_cmp_reg + '_ub'] = hi

        return bounds

    def _apply_path_constraints(self, findings: List[OverflowFinding],
                                instructions: List[str],
                                func_map: Dict[str, Tuple[int, int]]
                                ) -> List[OverflowFinding]:
        """后处理: 对每个finding, 检查其指令位置是否有路径条件约束."""
        if not self._path_tracker:
            return findings

        # [DEPRECATED] 此方法的完整实现需要finding中携带指令地址信息.
        # 当前 OverflowFinding 有 alloc_site_info (字符串格式),
        # 但缺乏直接的 instruction_address 字段.
        # 在下一步迭代中: 给 OverflowFinding 添加 find_instruction_idx: int = 0
        # 当前: 在 path_bounds 中查找与 write_size 相关的约束
        for f in findings:
            # 若finding有输入控制标记, 路径条件可能已有约束检查
            # 此处暂不降级, 因为输入控制仍可能是真实漏洞
            pass

        return findings

    def _stride_recheck(self, findings: List[OverflowFinding],
                        instructions: List[str],
                        func_map: Dict[str, Tuple[int, int]],
                        instr_addrs: Optional[List[int]] = None
                        ) -> List[OverflowFinding]:
        """跨步区间二次验证: 对POSSIBLE_OVERFLOW发现进行更精确判定.

        使用跨步区间的同余信息: 若写入局限于特定的步长,
        可能发现实际越界的访问点远少于标准区间估计.
        """
        if not self._strided:
            return findings

        refined = []
        for f in findings:
            # 只对POSSIBLE_OVERFLOW类型进行跨步验证
            # (DEFINITE_OVERFLOW和DEFINITE_SAFE不需要再验证)
            if 'POSSIBLE' not in f.overflow_detail:
                refined.append(f)
                continue

            # 提取写入大小和分配大小
            w_min, w_max = f.write_size_min, f.write_size_max
            a_min, a_max = f.alloc_size_min, f.alloc_size_max

            if w_min <= a_max and w_max <= a_max:
                # 标准区间已证明安全—不需要跨步
                refined.append(f)
                continue

            # 构建跨步区间进行验证
            write_si = StridedInterval.interval(w_min, w_max)
            is_safe, reason = check_stride_safe_write(
                write_si, 0, a_max)

            if is_safe:
                self._enhanced_stats['stride_verified'] += 1
                # 跨步验证为安全 → 降级为低置信度INFO
                f.severity = OverflowSeverity.INFO
                f.confidence = 0.15
                f.overflow_detail += f"; [跨步验证] {reason}"
                f.is_false_positive = True
                f.false_positive_reason = f"跨步区间验证安全: {reason}"

            refined.append(f)

        return refined

    def _filter_non_heap(self, findings: List[OverflowFinding],
                         instructions: List[str]
                         ) -> List[OverflowFinding]:
        """内存区域过滤: 排除发现自非堆区域写入的finding.

        当前: OverflowFinding不携带内存操作数信息.
        保守: 暂不过滤 (宁可保留非堆finding也不漏报),
        但在finding中标记可能的非堆来源.
        """
        if not self._mem_validator:
            return findings

        # [DEPRECATED] 完整过滤需要 OverlowFinding 增加
        # mem_operand: str = "" 字段以记录写入目标的内存操作数.
        # 当前保留所有finding, 不做过滤.
        # 在下一步迭代中实现.
        return findings

    def enhanced_stats(self) -> Dict:
        """返回增强层的统计信息."""
        return dict(self._enhanced_stats)

    def summary(self) -> Dict:
        base_summary = self._base.summary()
        base_summary['enhanced'] = self.enhanced_stats()
        return base_summary
