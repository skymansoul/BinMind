"""
C++ 类型混淆利用性评分 — 类层次深度×虚方法数×vtable 可替换性。

问题定义:
  C++ 类型混淆 (CWE-843) 发生在 reinterpret_cast/dynamic_cast 失败
  或 union 误用时。混淆的 blast radius 取决于类层次:
    - 浅层次 (1-2 层) → 虚方法少 → vtable 替换简单
    - 深层次 (>5 层) → 虚方法多 → vtable 注入面大
    - 多重继承 → vtable 布局复杂 → 偏移计算困难
    - 虚继承 → 共享基类只有一个副本 → 混淆影响多个派生类


  CWE-843: Access of Resource Using Incompatible Type ('Type Confusion')
  CVE-2021-30632 (V8): JIT 类型混淆 → 代码执行
  CVE-2023-4069 (V8): 类型混淆 → 任意读写
  现有工具仅提供 CWE 分类与检测.

修改记录:
  2025-04-17 10:44 - 初始版本，类层次×虚方法×继承类型的矩阵模型
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class InheritanceType(Enum):
    SINGLE = "single"            # 单继承
    MULTIPLE = "multiple"        # 多重继承 — vtable 有偏移调整
    VIRTUAL = "virtual"          # 虚继承 — 共享基类 (钻石问题)
    UNKNOWN = "unknown"

class ConfusionKind(Enum):
    UPTR_CAST = "uptr_cast"          # 基类→派生类 (向上转换失败)
    DOWNCAST = "downcast"            # 派生类→基类 (向下转换失败)
    REINTERPRET = "reinterpret"      # reinterpret_cast 误用
    UNION_MISUSE = "union_misuse"    # union 活跃成员误判
    MEMCPY_OBJECT = "memcpy_object"  # 对象级 memcpy (非平凡类型)
    UNKNOWN = "unknown"

@dataclass
class TypeConfusionScore:
    """类型混淆利用性评分。"""
    confusion_kind: ConfusionKind
    inheritance_type: InheritanceType
    hierarchy_depth: int              # 类层次深度
    virtual_method_count: int         # 混淆类中的虚方法数
    vtable_replaceable: bool          # vtable 是否可替换 (攻击者控制)
    exploitability: float             # 0-10
    primitives: List[str] = field(default_factory=list)
    technique: str = ''

def _base_for_kind(kind: ConfusionKind) -> float:
    return {
        ConfusionKind.UPTR_CAST:    7.0,  # 最危险 — 调用错误的虚方法
        ConfusionKind.REINTERPRET:  6.5,
        ConfusionKind.MEMCPY_OBJECT: 5.5,
        ConfusionKind.DOWNCAST:     4.0,  # 信息泄露方向
        ConfusionKind.UNION_MISUSE: 4.5,
        ConfusionKind.UNKNOWN:      3.0,
    }.get(kind, 3.0)

def _hierarchy_amplification(depth: int) -> float:
    """
    类层次深度→利用放大因子。

    深度 1: +0 (简单类型 — 混淆后 vtable 差异小)
    深度 3-5: +2.0 (中等 — 足够大以包含可利用的虚方法差异)
    深度 >10: +1.0 (过于复杂 — 虚方法太多，精确控制困难)
    """
    if depth <= 1:
        return 0.0
    if depth <= 5:
        return (depth - 1) * 0.5   # 线性增长到 +2.0
    if depth <= 10:
        return 2.0 - (depth - 5) * 0.2  # 缓慢下降
    return 1.0  # 极限

def _vtable_penalty(virtual_count: int, replaceable: bool) -> float:
    """
    虚方法数→惩罚/奖励。

    虚方法少 (< 5) 且 vtable 可替换 → +1.5 (精确控制)。
    虚方法多 (> 20) → -1.0 (哪个虚方法被调用的不确定性增大)。
    """
    if replaceable and virtual_count <= 5:
        return 1.5
    if virtual_count > 20:
        return -1.0
    if virtual_count > 10:
        return -0.3
    return 0.0

def _inheritance_complexity(inh_type: InheritanceType) -> float:
    """继承类型→复杂度惩罚。"""
    return {
        InheritanceType.SINGLE: 0.0,
        InheritanceType.MULTIPLE: -1.0,
        InheritanceType.VIRTUAL: -1.5,
        InheritanceType.UNKNOWN: -0.5,
    }.get(inh_type, -0.5)

def score_type_confusion(
    confusion_kind: str = 'uptr_cast',
    inheritance_type: str = 'single',
    hierarchy_depth: int = 2,
    virtual_method_count: int = 5,
    vtable_replaceable: bool = False,
    has_vtable_verification: bool = False,
) -> TypeConfusionScore:
    """
    评估 C++ 类型混淆的利用性。

    vtable_replaceable: 攻击者能否控制 vtable 指针 (例如通过堆溢出覆写)。
    has_vtable_verification: 程序是否有运行时类型检查 (RTTI/dynamic_cast)。
    """
    kind = ConfusionKind(confusion_kind) if confusion_kind in (
        'uptr_cast', 'downcast', 'reinterpret', 'union_misuse',
        'memcpy_object', 'unknown') else ConfusionKind.UNKNOWN

    inh = InheritanceType(inheritance_type) if inheritance_type in (
        'single', 'multiple', 'virtual', 'unknown') else InheritanceType.SINGLE

    base = _base_for_kind(kind)
    amp = _hierarchy_amplification(hierarchy_depth)
    vt = _vtable_penalty(virtual_method_count, vtable_replaceable)
    ic = _inheritance_complexity(inh)

    # RTTI/dynamic_cast 验证惩罚
    rtti_penalty = 3.0 if has_vtable_verification else 0.0

    exploitability = round(max(0.0, min(10.0, base + amp + vt + ic - rtti_penalty)), 1)

    prims = []
    if exploitability >= 6.0 and vtable_replaceable:
        prims.append('vtable_hijack')
    if exploitability >= 4.0:
        prims.append('virtual_call_redirect')
    if kind in (ConfusionKind.UPTR_CAST, ConfusionKind.REINTERPRET) and exploitability >= 5.0:
        prims.append('arbitrary_code_execution')

    if exploitability >= 7.0:
        tech = ('vtable 替换 → 伪造虚方法表 → '
                '虚调用重定向 → 任意代码执行')
    elif exploitability >= 4.0:
        tech = ('虚调用重定向: 利用类型混淆调用不同类的虚方法。'
                '需要堆布局控制 + 信息泄露获取 vtable 地址')
    else:
        tech = ('利用难度高: RTTI/虚继承/深度层次降低了精确控制的可行性。'
                '考虑结合其他原语 (堆溢出+UAF) 提高成功率')

    return TypeConfusionScore(
        confusion_kind=kind,
        inheritance_type=inh,
        hierarchy_depth=hierarchy_depth,
        virtual_method_count=virtual_method_count,
        vtable_replaceable=vtable_replaceable,
        exploitability=exploitability,
        primitives=prims,
        technique=tech,
    )
