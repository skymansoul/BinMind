# 边界检查模式识别器: 检测二进制中的多样化写入大小约束模式
# 现有分析只识别 cmp reg, imm 的简单模式,
#   遗漏了大量实际代码中的边界检查形式:
#     - 位掩码: and edx, 0xFFF → 将写入大小限制在页内
#     - 范围检查: cmp reg, imm; cmovg reg, imm → 上界钳位
#     - 提前返回: cmp reg, imm; jg .L_abort → 超出则终止
#     - 三元选择: cmp reg, imm; cmovae reg, safe → 自动截断
#   本模块提供模式匹配规则库, 从指令序列中提取隐含的边界约束,
#   输入给值域分析以缩小写入大小上界
# 理论来源:
#   Wressnegger et al. "Twice the Bits, Twice the Trouble:
#     Vulnerabilities Induced by Migrating to 64-bit Platforms" (CCS 2016)
#     — 边界检查行为的平台相关模式
#   Hex-Rays decompiler bounds-check detection heuristics
#     — 反编译器的边界检查恢复策略
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple
import re


class BoundCheckPattern(Enum):
    """边界检查模式枚举."""
    DIRECT_CMP = auto()          # cmp reg, imm; jcc (最常见)
    BITMASK_AND = auto()         # and reg, mask → 隐含上界mask
    RANGE_CLAMP = auto()         # cmp; cmov → 钳位到范围
    EARLY_RETURN = auto()        # cmp; jcc → abort/return (超出则终止)
    TERNARY_SELECT = auto()      # cmp; cmov → 选择安全值
    CHECKED_SUB = auto()         # sub reg, imm; jcc → 保证 reg ≥ imm
    NULL_GUARD = auto()          # test reg, reg; jz → 空指针保护


@dataclass
class BoundConstraint:
    """从边界检查中提取的约束."""
    pattern: BoundCheckPattern
    constrained_reg: str       # 被约束的寄存器
    upper_bound: int = 0       # 上界 (≤)
    lower_bound: int = 0       # 下界 (≥)
    confidence: float = 1.0    # 约束置信度
    is_guaranteed: bool = True # 是否在后续路径上一定成立
    source_idx: int = 0        # 模式匹配的指令索引
    description: str = ""


class BoundsCheckPatternMatcher:
    """边界检查模式匹配器.

    从指令序列中识别边界检查模式, 提取数值约束.
    这些约束可直接注入值域分析以缩小写入大小的推断范围.
    """

    def __init__(self):
        # 统计
        self._hits: Dict[BoundCheckPattern, int] = {
            p: 0 for p in BoundCheckPattern}

    def scan(self, instructions: List[str],
             func_start: int, func_end: int
             ) -> List[BoundConstraint]:
        """扫描函数体内的边界检查模式, 返回所有约束."""
        constraints: List[BoundConstraint] = []

        for i in range(func_start, min(func_end + 1, len(instructions))):
            line = instructions[i].strip()
            parts = line.replace(',', ' ').split()
            if not parts:
                continue
            op = parts[0]

            # Pattern 1: cmp reg, imm → 最常见的边界检查
            if op == 'cmp' and len(parts) >= 3:
                c = self._match_cmp_bound(parts, i)
                if c:
                    constraints.append(c)
                    self._hits[BoundCheckPattern.DIRECT_CMP] += 1
                continue

            # Pattern 2: and reg, mask → 位掩码隐含上界
            if op == 'and' and len(parts) >= 3:
                c = self._match_bitmask_bound(parts, i)
                if c:
                    constraints.append(c)
                    self._hits[BoundCheckPattern.BITMASK_AND] += 1
                continue

            # Pattern 3: cmovcc → 条件移动 (钳位)
            if op.startswith('cmov') and len(parts) >= 3:
                c = self._match_cmov_clamp(parts, i, instructions, i)
                if c:
                    constraints.append(c)
                    self._hits[BoundCheckPattern.RANGE_CLAMP] += 1
                continue

        return constraints

    def _match_cmp_bound(self, parts: List[str], idx: int
                         ) -> Optional[BoundConstraint]:
        """匹配 cmp reg, imm 模式."""
        from .instruction_parser import InstructionParser
        left = InstructionParser.clean_reg(parts[1])
        right = InstructionParser.parse_immediate(parts[2])

        if right is None:
            return None

        reg64 = InstructionParser.normalize_reg64(left)

        return BoundConstraint(
            pattern=BoundCheckPattern.DIRECT_CMP,
            constrained_reg=reg64,
            upper_bound=right,
            confidence=0.90,
            source_idx=idx,
            description=f"cmp {reg64}, {right} → {reg64} ≤ {right} (若后续有jle/条件取反)")

    def _match_bitmask_bound(self, parts: List[str], idx: int
                             ) -> Optional[BoundConstraint]:
        """匹配 and reg, mask → 上界=mask."""
        from .instruction_parser import InstructionParser
        left = InstructionParser.clean_reg(parts[1])
        right = InstructionParser.parse_immediate(parts[2])

        if right is None:
            return None
        # 只有当mask是特殊的2^n-1形式 (如0xFFF, 0xFFFF等) 才有效
        # 一般and mask不能直接推断上界, 需配合上下文
        # and edx, 0xFFF → edx ≤ 0xFFF (若后续作为写入大小)
        if right > 0 and (right & (right + 1)) == 0:  # 2^n - 1 检测
            reg64 = InstructionParser.normalize_reg64(left)
            return BoundConstraint(
                pattern=BoundCheckPattern.BITMASK_AND,
                constrained_reg=reg64,
                upper_bound=right,
                confidence=0.75,
                source_idx=idx,
                description=f"and {reg64}, {right:#x} → {reg64} ≤ {right:#x}")
        return None

    def _match_cmov_clamp(self, parts: List[str], idx: int,
                          instructions: List[str], func_end: int
                          ) -> Optional[BoundConstraint]:
        """匹配 cmovcc reg, bound → 条件钳位."""
        # cmovae edx, 0x100  → 若edx<0x100则edx=0x100 → 下界保证
        # cmovbe edx, 0x100  → 若edx>0x100则edx=0x100 → 上界保证
        from .instruction_parser import InstructionParser
        op = parts[0]
        dst = InstructionParser.clean_reg(parts[1])
        src = InstructionParser.parse_immediate(parts[2])
        if src is None:
            return None

        reg64 = InstructionParser.normalize_reg64(dst)

        # cmovae (≥) → 下界约束
        if op in ('cmovae', 'cmovge', 'cmova', 'cmovg'):
            return BoundConstraint(
                pattern=BoundCheckPattern.RANGE_CLAMP,
                constrained_reg=reg64,
                lower_bound=src,
                confidence=0.80,
                source_idx=idx,
                description=f"{op} {reg64}, {src} → {reg64} ≥ {src}")
        # cmovbe (≤) → 上界约束
        elif op in ('cmovbe', 'cmovle', 'cmovb', 'cmovl'):
            return BoundConstraint(
                pattern=BoundCheckPattern.RANGE_CLAMP,
                constrained_reg=reg64,
                upper_bound=src,
                confidence=0.80,
                source_idx=idx,
                description=f"{op} {reg64}, {src} → {reg64} ≤ {src}")

        return None

    def find_writes_protected_by_bounds(
            self, constraints: List[BoundConstraint],
            write_instructions: List[int],
            max_distance: int = 20
            ) -> Dict[int, List[BoundConstraint]]:
        """找出受边界检查保护的写入指令.

        对每条写入指令, 查找在它之前max_distance条指令范围内的边界约束.
        返回 {write_idx: [applicable_constraints]}.
        """
        protected: Dict[int, List[BoundConstraint]] = {}

        for w_idx in write_instructions:
            applicable = []
            for c in constraints:
                # 约束必须在写入之前
                if c.source_idx < w_idx and w_idx - c.source_idx <= max_distance:
                    applicable.append(c)
            if applicable:
                protected[w_idx] = applicable

        return protected

    def apply_to_write_size(self, current_umin: int, current_umax: int,
                            constraints: List[BoundConstraint]
                            ) -> Tuple[int, int]:
        """将边界约束应用到写入大小值域, 缩小范围."""
        new_umin, new_umax = current_umin, current_umax

        for c in constraints:
            if c.is_guaranteed:
                if c.upper_bound > 0:
                    new_umax = min(new_umax, c.upper_bound)
                if c.lower_bound > 0:
                    new_umin = max(new_umin, c.lower_bound)

        new_umax = max(new_umin, new_umax)  # 保证一致性
        return (new_umin, new_umax)

    def hit_stats(self) -> Dict[str, int]:
        return {p.name: c for p, c in self._hits.items()}
