"""
堆约束传播 — 将分配点的大小约束向前传播到下游内存访问。
通过四条规则解析 heap_alloc_tracker 的 UNCERTAIN 判定:
CP1 常量比较, CP2 变量绑定, CP3 区间推理 (+/- 常量), CP4 用户可控输入。
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ConstraintResult:
    """单个分配-访问对的约束传播结果。"""
    alloc_var: str = ""            # 分配变量名
    alloc_size: int = 0            # 分配大小 (-1=未知)
    access_func: str = ""          # memcpy / strcpy / sprintf
    access_size: int = 0           # 写入大小 (-1=未知)
    access_size_var: str = ""      # 写入大小变量名 (供变量绑定)
    verdict: str = "UNCERTAIN"     # SAFE / UNSAFE / USER_CONTROLLED / UNCERTAIN
    confidence: float = 0.0
    reasoning: str = ""
    rule_applied: str = ""         # CP1_CONSTANT / CP2_VAR_BIND / CP3_INTERVAL / CP4_USER_CTRL


def propagate_constant(alloc_size: int, access_size: int) -> ConstraintResult:
    """CP1: 双方均为编译期常量, 直接比较。"""
    if alloc_size < 0 or access_size < 0:
        return ConstraintResult(alloc_size=alloc_size, access_size=access_size,
                                 verdict='UNCERTAIN', confidence=0.0,
                                 reasoning='incomplete size info')

    if access_size <= alloc_size:
        return ConstraintResult(
            alloc_size=alloc_size, access_size=access_size,
            verdict='SAFE', confidence=0.92,
            reasoning=f'{access_size} <= {alloc_size}: write fits allocation',
            rule_applied='CP1_CONSTANT')
    else:
        return ConstraintResult(
            alloc_size=alloc_size, access_size=access_size,
            verdict='UNSAFE', confidence=0.90,
            reasoning=f'{access_size} > {alloc_size}: heap overflow by {access_size - alloc_size} bytes',
            rule_applied='CP1_CONSTANT')


def propagate_var_bind(alloc_var: str, alloc_size: int,
                        access_size_var: str,
                        decompiled_context: str = ""
                        ) -> ConstraintResult:
    """CP2: 写入大小变量与分配大小同源时判定安全 (buf=malloc(n); memcpy(buf,src,n))。"""
    result = ConstraintResult(
        alloc_var=alloc_var, alloc_size=alloc_size,
        access_size_var=access_size_var)

    if alloc_var == access_size_var:
        result.verdict = 'SAFE'
        result.confidence = 0.85
        result.reasoning = (f'same variable {alloc_var} used for both '
                            f'allocation and write size → safe by construction')
        result.rule_applied = 'CP2_VAR_BIND'
        result.access_size = alloc_size  # 推断写入大小=分配大小
    else:
        result.verdict = 'UNCERTAIN'
        result.confidence = 0.30
        result.reasoning = f'variables differ: alloc={alloc_var}, write_size={access_size_var}'

    return result


def propagate_interval(alloc_size: int, access_size_var: str,
                        decompiled_context: str = ""
                        ) -> ConstraintResult:
    """CP3: 区间推理 — 识别 access_size = alloc_size +/- K 模式 (如 memcpy(buf, src, n-1))。"""
    result = ConstraintResult(
        alloc_size=alloc_size, access_size_var=access_size_var)

    # 查找 alloc_size_var +/- 常量模式 (如 "n - 1", "len + 8")
    m = re.search(r'(\w+)\s*([+-])\s*(\d+)', access_size_var)
    if m:
        base_var = m.group(1)
        op = m.group(2)
        delta = int(m.group(3))
        inferred = alloc_size + delta if op == '+' else alloc_size - delta

        if inferred <= alloc_size:
            result.verdict = 'SAFE'
            result.confidence = 0.78
            result.reasoning = (f'{access_size_var} = {base_var}{op}{delta} '
                                f'=> inferred={inferred} <= alloc={alloc_size}: safe')
            result.rule_applied = 'CP3_INTERVAL'
            result.access_size = inferred
        elif inferred > alloc_size and delta <= 16:
            result.verdict = 'UNSAFE'
            result.confidence = 0.72
            result.reasoning = (f'{access_size_var} = {base_var}{op}{delta} '
                                f'=> inferred={inferred} > alloc={alloc_size}: overflow by {delta}')
            result.rule_applied = 'CP3_INTERVAL'
            result.access_size = inferred
        else:
            result.verdict = 'UNCERTAIN'
    else:
        result.verdict = 'UNCERTAIN'

    return result


def check_user_controlled(access_size_var: str,
                           input_sources: Optional[Set[str]] = None
                           ) -> Optional[ConstraintResult]:
    """CP4: 写入大小来自外部输入 (read/recv/fgets/scanf) 时判定 USER_CONTROLLED。"""
    if input_sources is None:
        input_sources = {'read', 'recv', 'recvfrom', 'fgets', 'scanf',
                         'getline', 'argv', 'argc'}

    for src in input_sources:
        if src in access_size_var.lower():
            return ConstraintResult(
                access_size_var=access_size_var,
                verdict='USER_CONTROLLED', confidence=0.82,
                reasoning=f'write size derived from {src} — attacker-controllable',
                rule_applied='CP4_USER_CTRL')

    return None


def resolve_constraint(alloc_var: str, alloc_size: int,
                        access_func: str, access_size: int,
                        access_size_var: str = "",
                        decompiled_context: str = ""
                        ) -> ConstraintResult:
    """对单个分配-访问对执行完整约束传播 (CP1→CP2→CP3→CP4), 返回最终判定。"""
    # CP1: 常量比较 (精度最高, 先试)
    if alloc_size > 0 and access_size > 0:
        return propagate_constant(alloc_size, access_size)

    # CP2: 变量绑定
    if alloc_var and access_size_var and alloc_var == access_size_var:
        return propagate_var_bind(alloc_var, alloc_size, access_size_var)

    # CP4: 外部输入检测 (优先级高于CP3)
    user_ctrl = check_user_controlled(access_size_var)
    if user_ctrl:
        user_ctrl.alloc_var = alloc_var
        user_ctrl.alloc_size = alloc_size
        user_ctrl.access_func = access_func
        return user_ctrl

    # CP3: 区间推理
    if alloc_size > 0 and access_size_var:
        result = propagate_interval(alloc_size, access_size_var,
                                     decompiled_context)
        result.alloc_var = alloc_var
        result.access_func = access_func
        if result.verdict != 'UNCERTAIN':
            return result

    # 默认: 无法判定
    return ConstraintResult(
        alloc_var=alloc_var, alloc_size=alloc_size,
        access_func=access_func, access_size=access_size,
        verdict='UNCERTAIN', confidence=0.15,
        reasoning='insufficient information for constraint resolution')
