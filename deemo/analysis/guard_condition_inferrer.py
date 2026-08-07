"""
守卫条件推断器 — 从反编译伪代码中提取 CMP+Jcc 守卫, 推断变量边界。

核心问题:
  现有分析的 FP 很大一部分来自忽略了 "if(idx < 64) buf[idx] = ..." 这样的守卫。
  虽然 buf 是 malloc(64) 返回的, 写入偏移 idx 是变量, 但守卫保证了 idx < 64。

方法 (轻量级, 避免完整 CFG 重建):
  1. 模式匹配: 识别 if(var OP const) / if(const OP var) 模式
  2. 守卫精化: 将守卫条件转换为变量区间约束
  3. 守卫传播: 向前传播守卫约束到同一基本块内的写入操作

与现有模块的关系:
  - 不替代 PathConstraintCollector (它处理更复杂的路径条件)
  - 作为轻量级前置过滤, 用于快速清除明显的 guard-protected 案例
  - 与 allocator_chunk_model 正交: guard 提供变量边界, chunk model 提供容量边界

数学基础:
  - 区间抽象解释: 守卫条件提供变量区间的上/下界
  - 我们不做完整的 widening/narrowing, 只做正向守卫传播 (forward guard propagation)
  - 保守假设: 未识别到守卫 → 变量无界 (unbounded)
"""

import re
from typing import Dict, List, Tuple

from analysis.guard_condition_types import GuardCondition, GuardSet

class GuardConditionInferrer:
    """守卫条件推断器 — 从伪代码提取 if(var OP const) 并推断变量边界。

    支持的模式:
      - if(var < const)        → var ∈ (-∞, const-1]
      - if(var <= const)       → var ∈ (-∞, const]
      - if(var >= const)       → var ∈ [const, +∞)
      - if(var > const)        → var ∈ [const+1, +∞)
      - if(var == const)       → var ∈ [const, const]
      - var = min(a, const)    → var ∈ (-∞, const]
      - var = max(a, const)    → var ∈ [const, +∞)
      - var &= mask            → var ∈ [0, mask] (AND mask 守卫)

    不支持 (故意):
      - if(var1 < var2)        → 关系约束, 需完整约束求解器
      - if(func_call(var))     → 函数返回值, 需过程间分析
    """

    # Pattern for a single comparison anywhere in text
    _CMP_PATTERN = re.compile(
        r'(\w+)\s*(<|<=|>=|>|==|!=)\s*'
        r'(\d+|0x[0-9a-fA-F]+)',
        re.IGNORECASE,
    )
    _CMP_REV_PATTERN = re.compile(
        r'(\d+|0x[0-9a-fA-F]+)\s*(<|<=|>=|>|==|!=)\s*'
        r'(\w+)',
        re.IGNORECASE,
    )
    # min/max 模式: var = min(x, const)
    _MIN_PATTERN = re.compile(
        r'(\w+)\s*=\s*min\s*\(\s*\w+\s*,\s*(\d+)\s*\)', re.IGNORECASE)
    _MAX_PATTERN = re.compile(
        r'(\w+)\s*=\s*max\s*\(\s*\w+\s*,\s*(\d+)\s*\)', re.IGNORECASE)
    # AND mask: var &= 0xFF
    _AND_PATTERN = re.compile(
        r'(\w+)\s*&=\s*(\d+|0x[0-9a-fA-F]+)', re.IGNORECASE)

    def __init__(self):
        self._guards: List[GuardSet] = []

    def extract_guards(self, pseudocode: str) -> List[GuardSet]:
        """从伪代码提取所有守卫条件集。

        两步法:
          1. 找到 if (...) { 的整个条件体
          2. 在条件体内扫描所有 var OP const 模式
        这样能正确处理 if(idx >= 0 && idx < 256) 这种复合条件。
        """
        self._guards = []
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue

            # 处理同一行多个语句的情况: 拆分语句, 查找 if (cond)
            # Ghidra/IDA 反编译输出常见: size_t s = n; if (s < 256) buf[s] = x;
            candidates = [stripped]
            if not (stripped.startswith('if ') or stripped.startswith('if(')):
                # 尝试在分号后拆分, 寻找 if 语句
                parts = stripped.split(';')
                candidates = [p.strip() for p in parts
                             if p.strip().startswith('if ') or p.strip().startswith('if(')]
                if not candidates:
                    continue

            for cand in candidates:
                if not (cand.startswith('if ') or cand.startswith('if(')):
                    continue

                gs = GuardSet(line=i + 1)
                cond_body = self._extract_condition_body(cand)
                if not cond_body:
                    continue

                for m in self._CMP_PATTERN.finditer(cond_body):
                    var, op, const_str = m.group(1), m.group(2), m.group(3)
                    if var in ('if', 'else', 'for', 'while', 'return', 'sizeof',
                               'void', 'int', 'char', 'long', 'short', 'unsigned',
                               'struct', 'union', 'enum', 'static', 'const'):
                        continue
                    gs.conditions.append(GuardCondition(
                        var=var, op=op,
                        constant=int(const_str, 0),
                        line=i + 1,
                    ))

                for m in self._CMP_REV_PATTERN.finditer(cond_body):
                    const_str, op, var = m.group(1), m.group(2), m.group(3)
                    if var in ('if', 'else', 'for', 'while', 'return', 'sizeof',
                               'void', 'int', 'char', 'long', 'short', 'unsigned'):
                        continue
                    rev_op = {'<': '>', '>': '<', '<=': '>=', '>=': '<='}.get(op, op)
                    gs.conditions.append(GuardCondition(
                        var=var, op=rev_op,
                        constant=int(const_str, 0),
                        line=i + 1,
                    ))

                if gs.conditions:
                    self._guards.append(gs)

        return self._guards

    @staticmethod
    def _extract_condition_body(line: str) -> str:
        """从 if 行提取 (...) 内的条件体."""
        start = line.find('(')
        if start == -1:
            return ''
        depth = 0
        for i in range(start, len(line)):
            if line[i] == '(':
                depth += 1
            elif line[i] == ')':
                depth -= 1
                if depth == 0:
                    return line[start + 1:i]
        return ''

    def get_all_bounds(self) -> Dict[str, Tuple[int, int]]:
        """获取所有守卫条件下的全局变量边界 (取最紧约束的交集)。

        用于向前传播: 变量在任何路径上都满足此边界。
        注意: 这是欠近似的 (under-approximate) — 只报告所有守卫都保证的边界。
        """
        if not self._guards:
            return {}

        result: Dict[str, Tuple[int, int]] = {}
        first = True

        for gs in self._guards:
            bounds = gs.get_bounds()
            if first:
                result = dict(bounds)
                first = False
            else:
                for var, (lo, hi) in bounds.items():
                    if var in result:
                        cur_lo, cur_hi = result[var]
                        result[var] = (max(cur_lo, lo), min(cur_hi, hi))
                    else:
                        result[var] = (lo, hi)

        return result

    def dominates_write(
        self,
        guard: GuardSet,
        write_line: int,
        write_var: str,
        alloc_size: int,
    ) -> bool:
        """检查守卫是否支配写入操作, 并保证写入安全。

        简单的后继检查: 守卫行 < 写入行 (在同一个基本块内)。

        Args:
            guard: 守卫条件集
            write_line: 写入操作的行号
            write_var: 写入偏移的变量名
            alloc_size: 分配大小

        Returns:
            True 如果守卫能证明写入在分配范围内
        """
        if guard.line >= write_line:
            return False

        # 合并守卫的变量区间
        bounds = guard.get_bounds()
        if write_var not in bounds:
            return False

        _, hi = bounds[write_var]
        if hi is not None and hi < alloc_size:
            return True
        return False

    def check_safe_with_guard(
        self,
        pseudocode: str,
        alloc_var: str,
        alloc_size: int,
        write_var: str,
        write_line: int,
    ) -> Tuple[bool, str]:
        """检查写入是否被 AND-守卫保护 — 委托给 guard_condition_compound."""
        from analysis.guard_condition_compound import extract_guards_with_logic
        guards_with_logic = extract_guards_with_logic(pseudocode)
        for gs, logic in guards_with_logic:
            if gs.line >= write_line:
                continue
            if logic == 'OR':
                continue
            bounds = gs.get_bounds()
            if write_var in bounds:
                _, hi = bounds[write_var]
                if hi is not None and hi < alloc_size:
                    return (True,
                            f"AND-guard L{gs.line}: "
                            f"{write_var}<={hi}<{alloc_size}")
        return (False, "no dominating AND-guard")

def infer_guard_bounds(pseudocode: str) -> Dict[str, Tuple[int, int]]:
    """便捷函数: 从伪代码推断所有守卫变量边界。"""
    inferrer = GuardConditionInferrer()
    inferrer.extract_guards(pseudocode)
    return inferrer.get_all_bounds()

def check_heap_write_safety(
    pseudocode: str,
    alloc_size: int,
    write_var: str,
    write_line: int,
) -> Tuple[bool, str]:
    """便捷函数: 检查堆写入是否被守卫保护。

    用法:
      pseudocode = open('sample.c').read()
      is_safe, reason = check_heap_write_safety(pseudocode, 64, 'idx', 12)
      if is_safe:
          print(f'SAFE: {reason}')  # "guard at line 11: idx <= 63 < alloc_size 64"
    """
    inferrer = GuardConditionInferrer()
    return inferrer.check_safe_with_guard(
        pseudocode, '_', alloc_size, write_var, write_line,
    )

__all__ = [
    'GuardCondition', 'GuardSet', 'GuardConditionInferrer',
    'infer_guard_bounds', 'check_heap_write_safety',
]
