# 修改记录:
# 2025-08-06 14:53 - 初始实现：基于寄存器/内存效应重叠的补丁冲突预测

"""补丁冲突预测 — 多补丁并行应用的寄存器/内存效应冲突预检测。

安全维护中常见场景：同一二进制需要同时应用多个补丁。
独立测试每个补丁都通过，但合并后出现三种冲突：
1. 寄存器效应冲突：补丁A保存rbx到栈但补丁B期望rbx不变。
2. 内存布局冲突：补丁A插入NOP padding改变了补丁B的跳转目标偏移。
3. 语义冲突：补丁A添加的边界检查使补丁B的越界路径变为"安全"——但路径逻辑变了。

本模块的静态冲突检测：
- 提取每个补丁的寄存器效应向量（修改/读取/保存的寄存器集）。
- 检测效应冲突：补丁A修改寄存器R，补丁B读取或依赖R的初始值→冲突。
- 检测内存偏移冲突：两补丁修改的字节范围有交叠→冲突。
- 输出冲突矩阵+合并建议（谁先谁后或不可合并）。

- patch_interaction_graph.py：补丁间语义依赖关系图。本模块聚焦低层级效应冲突。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS = 1e-9

class ConflictType(Enum):
    REG_EFFECT = "register_effect"
    MEMORY_OVERLAP = "memory_overlap"
    SEMANTIC = "semantic"
    NONE = "none"

@dataclass
class PatchEffect:
    """一个补丁的低层级效应摘要。"""
    patch_id: str
    # 寄存器效应: reg_name → {READ, WRITE, SAVE, RESTORE, CLOBBER}
    reg_reads: Set[str] = field(default_factory=set)
    reg_writes: Set[str] = field(default_factory=set)
    reg_saves: Set[str] = field(default_factory=set)    # push/保存到栈
    reg_clobbers: Set[str] = field(default_factory=set)  # 破坏原值
    # 内存修改范围
    byte_offsets_modified: Set[Tuple[int, int]] = field(default_factory=set)
    # 语义依赖
    assumes_condition: str = ""     # 补丁假设的前提条件

@dataclass
class ConflictPrediction:
    """一对补丁的冲突预测。"""
    patch_a: str
    patch_b: str
    conflict_type: ConflictType
    severity: float       # [0,1]
    description: str
    suggested_order: str  # "A_first" / "B_first" / "incompatible" / "order_independent"

class PatchConflictPredictor:
    """多补丁并行应用的冲突预测器。"""

    def __init__(self):
        self._patches: Dict[str, PatchEffect] = {}

    def register_patch(self, effect: PatchEffect):
        self._patches[effect.patch_id] = effect

    def predict_conflicts(self) -> List[ConflictPrediction]:
        """预测所有补丁对间的冲突。"""
        _ids = list(self._patches.keys())
        _results: List[ConflictPrediction] = []

        for _i in range(len(_ids)):
            for _j in range(_i + 1, len(_ids)):
                _a = self._patches[_ids[_i]]
                _b = self._patches[_ids[_j]]

                _conflicts = self._analyze_pair(_a, _b)
                _results.extend(_conflicts)

        return sorted(_results, key=lambda c: c.severity, reverse=True)

    def merge_plan(self) -> Dict[str, Any]:
        """生成补丁合并计划——推荐顺序和不可合并标记。"""
        _conflicts = self.predict_conflicts()
        _incompatible: List[Tuple[str, str]] = []
        _order_constraints: List[Tuple[str, str]] = []

        for _c in _conflicts:
            if _c.conflict_type == ConflictType.NONE:
                continue
            if _c.severity > 0.8:
                _incompatible.append((_c.patch_a, _c.patch_b))
            elif _c.suggested_order == "A_first":
                _order_constraints.append((_c.patch_a, _c.patch_b))
            elif _c.suggested_order == "B_first":
                _order_constraints.append((_c.patch_b, _c.patch_a))

        return {
            "incompatible_pairs": _incompatible,
            "order_constraints": _order_constraints,
            "total_conflicts": len(_conflicts),
            "safe_to_merge": len(_incompatible) == 0,
        }

    def _analyze_pair(
        self, a: PatchEffect, b: PatchEffect,
    ) -> List[ConflictPrediction]:
        _results: List[ConflictPrediction] = []

        # R1: 寄存器效应冲突——A修改了B需要读取的
        _reg_conflict = a.reg_writes & b.reg_reads
        if _reg_conflict:
            _results.append(ConflictPrediction(
                patch_a=a.patch_id, patch_b=b.patch_id,
                conflict_type=ConflictType.REG_EFFECT,
                severity=min(1.0, 0.5 + len(_reg_conflict) * 0.15),
                description=f"A writes {_reg_conflict} which B reads",
                suggested_order="B_first",  # B先读→A后写可避免
            ))

        # 反向
        _reg_conflict_rev = b.reg_writes & a.reg_reads
        if _reg_conflict_rev:
            _results.append(ConflictPrediction(
                patch_a=a.patch_id, patch_b=b.patch_id,
                conflict_type=ConflictType.REG_EFFECT,
                severity=min(1.0, 0.5 + len(_reg_conflict_rev) * 0.15),
                description=f"B writes {_reg_conflict_rev} which A reads",
                suggested_order="A_first",
            ))

        # R2: 内存重叠
        _mem_overlap = self._check_memory_overlap(
            a.byte_offsets_modified, b.byte_offsets_modified,
        )
        if _mem_overlap:
            _results.append(ConflictPrediction(
                patch_a=a.patch_id, patch_b=b.patch_id,
                conflict_type=ConflictType.MEMORY_OVERLAP,
                severity=0.9,
                description=f"byte offset overlap: {_mem_overlap}",
                suggested_order="incompatible",
            ))

        # R3: 语义冲突——两补丁的假设互斥
        if a.assumes_condition and b.assumes_condition:
            if self._assumptions_conflict(a.assumes_condition, b.assumes_condition):
                _results.append(ConflictPrediction(
                    patch_a=a.patch_id, patch_b=b.patch_id,
                    conflict_type=ConflictType.SEMANTIC,
                    severity=0.7,
                    description=f"conflicting assumptions: '{a.assumes_condition}' vs '{b.assumes_condition}'",
                    suggested_order="incompatible",
                ))

        return _results

    @staticmethod
    def _check_memory_overlap(
        a_offsets: Set[Tuple[int, int]],
        b_offsets: Set[Tuple[int, int]],
    ) -> List[Tuple[int, int]]:
        """检查两个补丁的字节修改范围是否有交叠。"""
        _overlaps = []
        for _a in a_offsets:
            for _b in b_offsets:
                if _a[0] < _b[1] and _b[0] < _a[1]:
                    _overlaps.append((max(_a[0], _b[0]), min(_a[1], _b[1])))
        return _overlaps[:3]

    @staticmethod
    def _assumptions_conflict(a_assumption: str, b_assumption: str) -> bool:
        """启发式：检测两个假设是否互斥。"""
        _pairs = [
            ("no_canary", "canary_present"),
            ("size_unchecked", "size_bounded"),
            ("user_input", "sanitized"),
        ]
        for _x, _y in _pairs:
            if (_x in a_assumption and _y in b_assumption) or \
               (_y in a_assumption and _x in b_assumption):
                return True
        return False

# 冒烟测试
def _smoke_test():
    _predictor = PatchConflictPredictor()

    _a = PatchEffect(
        "PATCH-A", reg_writes={"rax", "rbx"}, reg_reads=set(),
        reg_saves={"rbx"}, reg_clobbers={"rax"},
        byte_offsets_modified={(0x100, 0x110)},
        assumes_condition="no_canary",
    )
    _b = PatchEffect(
        "PATCH-B", reg_writes={"rcx"}, reg_reads={"rbx"},
        byte_offsets_modified={(0x108, 0x118)},
        assumes_condition="canary_present",
    )

    _predictor.register_patch(_a)
    _predictor.register_patch(_b)
    _conflicts = _predictor.predict_conflicts()

    print(f"[conflict] found {len(_conflicts)} conflicts:")
    for _c in _conflicts:
        print(f"  {_c.patch_a} vs {_c.patch_b}: {_c.conflict_type.value} "
              f"sev={_c.severity:.2f} {_c.description}")

    _plan = _predictor.merge_plan()
    print(f"[conflict] safe_to_merge={_plan['safe_to_merge']}")
    print(f"[conflict] incompatible={_plan['incompatible_pairs']}")

    assert len(_conflicts) >= 3, "should detect reg+memory+semantic conflicts"
    assert not _plan["safe_to_merge"]
    print("[OK] PatchConflictPredictor smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
