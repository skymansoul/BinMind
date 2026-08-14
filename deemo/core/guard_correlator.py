"""
守卫相关性关联 — 将上游 if 守卫匹配到下游堆写入, 用于误报抑制。
对每个堆写入识别其支配守卫及约束区间, 计算守卫强度分数以区分强弱守卫,
按文本支配关系限定作用域, 并关联守卫变量与写入大小变量。
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.forward_interval_prop import Interval

@dataclass
class CorrelatedGuard:
    """已与堆写入关联的守卫。"""
    guard_line: int; write_line: int
    guard_var: str; write_var: str     # 别名时可能不同
    op: str; bound_value: int
    constrains_size: bool              # 守卫限制写入大小(而非仅分配)
    scope_match: bool                  # 守卫作用域包含该写入
    strength: float                    # 0-1, 表示误报过滤的强度
    detail: str = ''

@dataclass
class GuardCorrelationResult:
    """守卫与单个堆写入候选的关联结果。"""
    write_line: int; dst_var: str
    alloc_size: int; write_size_range: Tuple[int, int]
    guards: List[CorrelatedGuard] = field(default_factory=list)
    dominant_guard: Optional[CorrelatedGuard] = None
    safe_confidence: float = 0.0       # 0→可能溢出, 1→可能安全(误报)

# patterns ──────────────────────────────────────────────────────────

_GUARD_IF = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+|0x[0-9a-fA-F]+|\w[\w.]*)\s*\)')

_GUARD_CMP = re.compile(
    r'(?:cmp|if)\s+(\w[\w.]*)\s*(<|<=|>|>=|==|!=)\s*(\d+)')

_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(.+)')

# 堆写入模式
_WRITE_PAT = re.compile(
    r'(memcpy|memmove|strncpy|strcpy|sprintf)\s*\(\s*'
    r'(\w[\w.]*)\s*(?:[+]\s*(\d+|\w[\w.]*))?\s*,\s*[^,]*,\s*([^)]+)\s*\)')

# 变量别名: ptr = buf; q = p; 等
_ALIAS_PAT = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;?')

# engine ────────────────────────────────────────────────────────────

class GuardCorrelator:
    """匹配上游守卫与堆写入, 用于误报过滤。"""

    def __init__(self, max_lookback: int = 50):
        self._lookback = max_lookback

    def extract_guards(self, ir_lines: List[str]) -> List[CorrelatedGuard]:
        """阶段1: 从IR中提取全部守卫点。"""
        raw: List[Tuple[int, str, str, int]] = []
        for i, line in enumerate(ir_lines):
            m = _GUARD_IF.search(line)
            if m:
                try:
                    bound = int(m.group(3), 0)
                    raw.append((i, m.group(1), m.group(2), bound))
                except ValueError:
                    pass  # 符号边界 — 暂不处理
        return []  # correlate() 期间填充

    def correlate(
        self, ir_lines: List[str], write_line: int,
        size_var: str, alloc_var: str, alloc_size: int,
    ) -> GuardCorrelationResult:
        """阶段2-3: 将守卫与具体堆写入关联, 返回关联结果与安全置信度。"""
        wr_size_lo, wr_size_hi = 0, 2**30
        # 尝试从行内解析写入大小
        line = ir_lines[write_line] if write_line < len(ir_lines) else ''
        wm = _WRITE_PAT.search(line)
        if wm:
            size_expr = wm.group(4).strip()
            try:
                wr_size_lo = wr_size_hi = int(size_expr, 0)
            except ValueError:
                pass

        result = GuardCorrelationResult(
            write_line=write_line, dst_var=alloc_var,
            alloc_size=alloc_size, write_size_range=(wr_size_lo, wr_size_hi))

        # 构建别名映射: 变量 → 规范名
        aliases = self._build_alias_map(ir_lines, write_line)

        # 将 size_var 解析为规范名
        canon_size = aliases.get(size_var, size_var)
        canon_alloc = aliases.get(alloc_var, alloc_var)

        # 扫描守卫
        for i in range(max(0, write_line - self._lookback), write_line):
            m = _GUARD_IF.search(ir_lines[i])
            if not m:
                continue
            try:
                bound = int(m.group(3), 0)
            except ValueError:
                continue

            gvar = m.group(1); gop = m.group(2)
            canon_gvar = aliases.get(gvar, gvar)

            # 检查守卫是否约束大小变量或分配变量
            constrains_size = (canon_gvar == canon_size)
            constrains_alloc = (canon_gvar == canon_alloc)
            if not constrains_size and not constrains_alloc:
                continue

            # 检查作用域支配
            scope_ok = self._scope_contains(ir_lines, i, write_line)

            # 强度评分
            strength = self._guard_strength(gop, bound, alloc_size)

            cg = CorrelatedGuard(
                guard_line=i, write_line=write_line,
                guard_var=gvar, write_var=size_var,
                op=gop, bound_value=bound,
                constrains_size=constrains_size,
                scope_match=scope_ok,
                strength=strength,
                detail=f'if({gvar}{gop}{bound}) → write at L{write_line}'
            )
            result.guards.append(cg)

            # 记录最强守卫
            if scope_ok and (result.dominant_guard is None
                             or strength > result.dominant_guard.strength):
                result.dominant_guard = cg

        # 计算安全置信度
        result.safe_confidence = self._compute_safety(result, alloc_size)
        return result

    def _build_alias_map(self, ir: List[str], before: int) -> Dict[str, str]:
        """从窗口内赋值构建 变量→规范名 别名映射。"""
        aliases: Dict[str, str] = {}
        for i in range(max(0, before - 30), before):
            m = _ALIAS_PAT.match(ir[i].strip())
            if m:
                lhs, rhs = m.group(1), m.group(2)
                # 沿已有别名链解析
                canon = aliases.get(rhs, rhs)
                aliases[lhs] = canon
        # 传递闭包(单趟)
        for var in list(aliases.keys()):
            chain = aliases[var]
            while chain in aliases and aliases[chain] != chain:
                chain = aliases[chain]
            aliases[var] = chain
        return aliases

    @staticmethod
    def _scope_contains(ir: List[str], guard: int, target: int) -> bool:
        """检查守卫作用域是否包含目标行, 处理花括号块/单行if/早退模式。"""
        if target <= guard:
            return False
        gline = ir[guard].strip()
        # 无花括号单行if: if (cond) stmt;
        if not gline.endswith('{') and '{' not in ir[guard + 1] if guard + 1 < len(ir) else True:
            # 若下一行为 return/goto/exit, 则继续向下执行
            if guard + 1 < len(ir):
                nxt = ir[guard + 1].strip()
                if re.match(r'^(?:return|goto|exit|break|continue)\b', nxt):
                    # 早退: 下溢路径继承取反后的守卫
                    return target > guard + 1
                else:
                    # 无早退的单行if: 仅下一行受支配
                    return target == guard + 1
            return False
        # 花括号作用域
        d, s = 0, False
        for i in range(guard, min(len(ir), target + 1)):
            if '{' in ir[i]: d += 1; s = True
            if '}' in ir[i]:
                d -= 1
                if d <= 0 and s and i < target:
                    return False
        return s and d > 0

    @staticmethod
    def _guard_strength(op: str, bound: int, alloc: int) -> float:
        """计算守卫强度: 0=弱, 1=强, 用于误报过滤。"""
        # Alloc未知时, 用guard bound做保守估计: 合理上限(~4096)视为有效约束
        effective_alloc = alloc if alloc > 0 else bound if bound <= 4096 else 4096
        if op in ('<', '<='):
            if bound <= effective_alloc:
                return 0.85
            elif bound <= effective_alloc * 2:
                return 0.40
            else:
                return 0.10
        elif op in ('>', '>='):
            # 早退模式: if(var > X) return → 走到底的路径上 var <= X
            if bound <= effective_alloc:
                return 0.80
            elif bound <= effective_alloc * 2:
                return 0.35
            return 0.05
        elif op == '==':
            if bound <= effective_alloc:
                return 0.70
            return 0.20
        return 0.30

    def _compute_safety(
        self, result: GuardCorrelationResult, alloc_size: int,
    ) -> float:
        """由关联守卫计算整体安全置信度。"""
        if not result.guards:
            return 0.0

        # 作用域匹配的支配守卫 → 权重最高
        if result.dominant_guard and result.dominant_guard.scope_match:
            base = result.dominant_guard.strength
        else:
            # 无守卫支配该写入 → 施加作用域惩罚(0.45x), 防止单分支守卫压制其他分支写入
            raw = max((g.strength for g in result.guards), default=0.0)
            base = raw * 0.45

        # 多个独立守卫时加权
        scope_guards = [g for g in result.guards if g.scope_match]
        if len(scope_guards) >= 2:
            base = min(0.95, base + 0.10)

        # 约束大小的守卫强于约束分配的守卫
        if result.dominant_guard and result.dominant_guard.constrains_size:
            base = min(0.95, base + 0.05)

        return base

def correlate_write(
    ir_lines: List[str], write_line: int,
    size_var: str = 'len', alloc_var: str = 'buf', alloc_size: int = 0,
) -> GuardCorrelationResult:
    """便捷接口: 关联单个堆写入的守卫。"""
    gc = GuardCorrelator()
    return gc.correlate(ir_lines, write_line, size_var, alloc_var, alloc_size)

__all__ = ['CorrelatedGuard', 'GuardCorrelationResult',
           'GuardCorrelator', 'correlate_write']
