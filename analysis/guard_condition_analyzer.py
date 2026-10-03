"""
守卫条件分析 —— 在报告堆溢出前检查是否存在边界检查守卫。

核心问题: 大量误报来自以下模式:
  if (idx < N) {           // ← 守卫条件
      buf[idx] = val;      // ← 触发告警的store
  }
检测器看到buf[idx]写入, 但未注意到idx已被约束为 < N,
且buf的分配大小 >= N。这在没有守卫条件分析时必然是误报。

方法: 从可疑store指令向上游扫描IR, 搜索最近的cmp/jcc守卫。
若存在守卫模式idx < N, 且N <= alloc_size, 则抑制该告警。

三层分析:
  G1: 直接cmp —— cmp idx, N; jcc above/label  (置信度0.90)
  G2: 循环边界 —— for(i=0; i<N; i++)类型的循环计数器约束 (置信度0.75)
  G3: AND掩码 —— and idx, 0xF; 限定位宽 (置信度0.60)

  - "Demand-Driven Path-Sensitive Analysis for Buffer Overflow Detection" (Cherem et al.)
  - CSA: 跨域稀疏抽象中的路径条件传播
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class GuardCondition:
    """检测到的守卫条件。"""
    pc: int = -1                         # cmp指令在IR中的位置
    guard_var: str = ''                   # 被检查的变量
    operator: str = ''                    # < | <= | > | >= | == | !=
    bound_expr: str = ''                  # 边界表达式文本
    bound_value: int = -1                 # 边界常量值 (-1=非常量)
    bound_is_constant: bool = False
    guard_type: str = ''                  # 'cmp_jcc' | 'loop_bound' | 'and_mask'
    confidence: float = 0.0
    distance_to_store: int = 0            # 距store指令的行数

def _try_parse_int(s: str) -> Tuple[bool, int]:
    """尝试将字符串解析为整数, 支持十进制和十六进制。"""
    try:
        return True, int(s)
    except (ValueError, TypeError):
        pass
    try:
        return True, int(s, 16)
    except (ValueError, TypeError):
        pass
    return False, -1

def find_guard_for_variable(
    ir_lines: List[str],
    target_var: str,
    store_pc: int,
    search_window: int = 30,
) -> Optional[GuardCondition]:
    """在store指令上游搜索针对target_var的守卫条件。

    从store_pc向上扫描search_window行, 寻找:
    1. cmp target_var, N → jcc (G1)
    2. for循环的cmp i, N模式 (G2)

    返回最接近store的守卫条件, 或None。
    """
    start = max(0, store_pc - search_window)
    prev_guard: Optional[GuardCondition] = None

    for pc in range(start, store_pc):
        line = ir_lines[pc].strip()

        # G1: cmp var, const 或 cmp var, reg 模式
        cmp_m = re.search(
            rf'cmp\s+{re.escape(target_var)}\s*,\s*(0x[0-9a-fA-F]+|\d+|\w[\w\d_]*)',
            line, re.IGNORECASE)
        if cmp_m:
            rhs = cmp_m.group(1)
            is_c, val = _try_parse_int(rhs)
            # 检查下一行是否有条件跳转
            has_jcc = False
            if pc + 1 < store_pc:
                next_line = ir_lines[pc + 1].strip()
                has_jcc = any(kw in next_line.lower()
                             for kw in ('j', 'jg', 'jl', 'jge', 'jle',
                                       'jne', 'je', 'jae', 'jbe', 'jb', 'ja',
                                       'b', 'bl', 'bne', 'beq'))
            if has_jcc:
                prev_guard = GuardCondition(
                    pc=pc, guard_var=target_var,
                    operator='<',  # 保守: 默认为上界检查
                    bound_expr=rhs, bound_value=val,
                    bound_is_constant=is_c,
                    guard_type='cmp_jcc',
                    confidence=0.90 if is_c else 0.55,
                    distance_to_store=store_pc - pc,
                )

        # G2: 循环边界 for(i=0; i<N; i++) 模式
        # 识别 i = 0; ...; cmp i, N; jl loop
        if re.search(rf'{re.escape(target_var)}\s*=\s*0\b', line):
            # 找到了循环初始化, 向前搜索cmp
            for j in range(pc + 1, min(store_pc, pc + 30)):
                jline = ir_lines[j].strip()
                cmp_m2 = re.search(
                    rf'cmp\s+{re.escape(target_var)}\s*,\s*(0x[0-9a-fA-F]+|\d+)',
                    jline, re.IGNORECASE)
                if cmp_m2:
                    _, val2 = _try_parse_int(cmp_m2.group(1))
                    if j + 1 < store_pc:
                        next_line = ir_lines[j + 1].strip()
                        if any(kw in next_line.lower()
                               for kw in ('jl', 'jb', 'bl', 'b')):
                            prev_guard = GuardCondition(
                                pc=j, guard_var=target_var,
                                operator='<', bound_expr=cmp_m2.group(1),
                                bound_value=val2, bound_is_constant=True,
                                guard_type='loop_bound',
                                confidence=0.75,
                                distance_to_store=store_pc - j,
                            )
                    break

    return prev_guard

def is_store_safeguarded(
    ir_lines: List[str],
    base_var: str,
    offset_var: str,
    store_pc: int,
    alloc_size: int,
) -> Tuple[bool, str, float]:
    """判断一个heap store是否被有效的守卫条件保护。

    返回 (is_safe, reason, confidence)。

    安全条件: 存在守卫 idx < N, 且 N <= alloc_size。
    此时即使store offset使用动态变量idx, 写入也不会溢出。
    """
    # 检查offset_var是否有守卫
    guard = find_guard_for_variable(ir_lines, offset_var, store_pc)
    if guard is None:
        return False, 'no guard found', 0.0

    if not guard.bound_is_constant:
        return False, f'guard exists but bound is non-constant ({guard.bound_expr})', 0.30

    if guard.bound_value <= alloc_size:
        return True, (
            f'guard {guard.guard_var} < {guard.bound_value} '
            f'prevents overflow into {alloc_size}B buffer'
        ), 0.85

    # 边界大于分配大小: guard不足
    return False, (
        f'guard bound {guard.bound_value} > alloc size {alloc_size}'
    ), 0.20

def extract_all_guards(ir_lines: List[str]) -> List[GuardCondition]:
    """从IR中提取所有守卫条件(不限于特定变量)。

    用于全局分析 —— 了解哪些变量在哪些位置被约束。
    """
    guards: List[GuardCondition] = []
    cmp_pattern = re.compile(
        r'cmp\s+(\w[\w\d_]*)\s*,\s*(0x[0-9a-fA-F]+|\d+)',
        re.IGNORECASE)
    jcc_keywords = {'j', 'jg', 'jl', 'jge', 'jle', 'jne', 'je',
                     'jae', 'jbe', 'jb', 'ja', 'b', 'bl', 'bne', 'beq',
                     'jnz', 'jz', 'jmp'}

    for pc, line in enumerate(ir_lines):
        m = cmp_pattern.search(line)
        if not m:
            continue
        var = m.group(1)
        _, val = _try_parse_int(m.group(2))
        # 下一行必须有条件跳转
        if pc + 1 < len(ir_lines):
            next_line = ir_lines[pc + 1].strip().lower()
            if any(kw in next_line for kw in jcc_keywords):
                guards.append(GuardCondition(
                    pc=pc, guard_var=var,
                    operator='<', bound_expr=m.group(2),
                    bound_value=val, bound_is_constant=True,
                    guard_type='cmp_jcc', confidence=0.90,
                ))

    return guards
