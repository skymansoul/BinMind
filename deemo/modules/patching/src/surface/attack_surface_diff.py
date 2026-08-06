# 修改记录:
# 2025-08-07 08:22 - 初始实现：补丁前后攻击面自动对比——新增入口点/数据流变化检测

"""补丁攻击面差分 — 补丁前后二进制的攻击面对比分析。

安全补丁有时会意外扩大攻击面：
- 新增了错误处理路径，其中包含新的输入解析逻辑（新攻击入口）。
- 将内部函数改为导出函数（新可达入口点）。
- 新增的检查函数本身有漏洞（保护者变成受害者）。

本模块从三个维度量化攻击面变化：
D1-新增函数: 比较补丁前后的导出函数表和调用图变化。
D2-输入入口: 检测新增的recv/read/fscanf等外部输入接收点。
D3-权限变化: 检测setuid/capset/mmap(PROT_EXEC)等权限提升操作的新增。
D4-可达性: 新增函数是否可从外部输入路径到达。

输出攻击面增量评分 ΔAS ∈ [-1, 1]：
负值=攻击面缩小（好），正值=攻击面扩大（需审查），0=不变。

参考：
- Manadhata & Wing (2011): 攻击面度量的形式化定义。
- patch_impact_analyzer.py: 补丁对运行时行为的影响。本模块聚焦编译后攻击面。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class FunctionChange:
    """一个函数的变化描述。"""
    func_name: str
    func_address: int
    change_type: str       # ADDED / REMOVED / MODIFIED
    is_exported: bool
    has_input_ops: bool    # 是否有外部输入接收操作
    has_privilege_ops: bool
    reachable_from_input: bool


@dataclass
class AttackSurfaceDiff:
    """补丁前后的攻击面对比。"""
    functions_added: List[FunctionChange]
    functions_removed: List[FunctionChange]
    new_input_entries: List[FunctionChange]
    new_privilege_ops: List[FunctionChange]
    attack_surface_delta: float
    risk_assessment: str


class AttackSurfaceDiffer:
    """补丁攻击面差分分析器。"""

    def __init__(
        self,
        input_apis: Optional[Set[str]] = None,
        privilege_apis: Optional[Set[str]] = None,
    ):
        self.input_apis = input_apis or {
            "recv", "read", "fread", "fscanf", "scanf", "gets",
            "recvfrom", "recvmsg", "MQReceive", "ZwReadFile",
        }
        self.privilege_apis = privilege_apis or {
            "setuid", "setgid", "capset", "mmap", "mprotect",
            "iopl", "ioperm", "sysctl", "system", "execve",
        }

    def diff(
        self,
        pre_functions: List[Dict],
        post_functions: List[Dict],
    ) -> AttackSurfaceDiff:
        """执行攻击面差分分析。"""
        _pre_names = {f["name"]: f for f in pre_functions}
        _post_names = {f["name"]: f for f in post_functions}

        _added: List[FunctionChange] = []
        _removed: List[FunctionChange] = []
        _new_input: List[FunctionChange] = []
        _new_priv: List[FunctionChange] = []

        # 新增函数
        for _name, _func in _post_names.items():
            if _name not in _pre_names:
                _fc = FunctionChange(
                    func_name=_name,
                    func_address=_func.get("address", 0),
                    change_type="ADDED",
                    is_exported=_func.get("is_exported", False),
                    has_input_ops=self._has_input_apis(_func),
                    has_privilege_ops=self._has_privilege_apis(_func),
                    reachable_from_input=self._is_reachable(_func, _post_names),
                )
                _added.append(_fc)
                if _fc.has_input_ops and _fc.reachable_from_input:
                    _new_input.append(_fc)
                if _fc.has_privilege_ops:
                    _new_priv.append(_fc)

        # 删除函数
        for _name, _func in _pre_names.items():
            if _name not in _post_names:
                _removed.append(FunctionChange(
                    func_name=_name,
                    func_address=_func.get("address", 0),
                    change_type="REMOVED",
                    is_exported=_func.get("is_exported", False),
                    has_input_ops=False,
                    has_privilege_ops=False,
                    reachable_from_input=False,
                ))

        # 攻击面增量评分
        _delta = self._compute_delta(_added, _removed, _new_input, _new_priv)

        return AttackSurfaceDiff(
            functions_added=_added,
            functions_removed=_removed,
            new_input_entries=_new_input,
            new_privilege_ops=_new_priv,
            attack_surface_delta=round(_delta, 4),
            risk_assessment=self._risk_assess(_delta, _new_input, _new_priv),
        )

    def _compute_delta(
        self,
        added: List[FunctionChange],
        removed: List[FunctionChange],
        new_input: List[FunctionChange],
        new_priv: List[FunctionChange],
    ) -> float:
        """计算攻击面增量 ΔAS。

        ΔAS = (新增导出函数×0.2 + 新增输入入口×0.5 + 新增权限操作×0.3
               - 删除导出函数×0.2) / max(total_functions, 1)
        """
        _added_score = (
            sum(0.2 for f in added if f.is_exported)
            + len(new_input) * 0.5
            + len(new_priv) * 0.3
        )
        _removed_score = sum(0.2 for f in removed if f.is_exported)
        return min(1.0, max(-1.0, (_added_score - _removed_score) / 10.0))

    @staticmethod
    def _risk_assess(
        delta: float,
        new_input: List,
        new_priv: List,
    ) -> str:
        if delta < -0.1:
            return f"attack surface SHRUNK (Δ={delta:.3f}) — likely safe"
        if delta > 0.2:
            return (f"attack surface EXPANDED (Δ={delta:.3f}) — "
                    f"{len(new_input)} new inputs, {len(new_priv)} new priv ops")
        if new_input or new_priv:
            return "minor attack surface change — review new entries manually"
        return "no significant attack surface change"

    def _has_input_apis(self, func: Dict) -> bool:
        _calls = func.get("callees", [])
        return any(
            any(api in str(c).lower() for api in self.input_apis)
            for c in _calls
        )

    def _has_privilege_apis(self, func: Dict) -> bool:
        _calls = func.get("callees", [])
        return any(
            any(api in str(c).lower() for api in self.privilege_apis)
            for c in _calls
        )

    @staticmethod
    def _is_reachable(func: Dict, all_funcs: Dict) -> bool:
        """简化可达性——检查是否有其他函数调用此函数。"""
        _name = func.get("name", "")
        for _f in all_funcs.values():
            if _name in _f.get("callees", []):
                return True
        return func.get("is_exported", False)


# ---- 冒烟测试 ----
def _smoke_test():
    _differ = AttackSurfaceDiffer()

    _pre = [
        {"name": "parse_request", "address": 0x1000, "is_exported": True,
         "callees": ["recv", "malloc"]},
        {"name": "handle_cmd", "address": 0x2000, "is_exported": False,
         "callees": ["parse_request"]},
    ]
    _post = [
        {"name": "parse_request", "address": 0x1000, "is_exported": True,
         "callees": ["recv", "malloc"]},
        {"name": "handle_cmd", "address": 0x2000, "is_exported": False,
         "callees": ["parse_request"]},
        # 新增导出函数——接收用户输入——潜在攻击面扩大
        {"name": "debug_handler", "address": 0x3000, "is_exported": True,
         "callees": ["recv", "system"], },
        # 新增内部函数——接收输入
        {"name": "new_parser", "address": 0x4000, "is_exported": False,
         "callees": ["fscanf"], },
    ]

    _diff = _differ.diff(_pre, _post)
    print(f"[surface] ΔAS = {_diff.attack_surface_delta:.4f}")
    print(f"[surface] added functions: {len(_diff.functions_added)}")
    print(f"[surface] new input entries: {len(_diff.new_input_entries)}")
    print(f"[surface] new priv ops: {len(_diff.new_privilege_ops)}")
    print(f"[surface] risk: {_diff.risk_assessment}")

    assert _diff.attack_surface_delta > 0, "should detect expanded attack surface"
    assert len(_diff.functions_added) == 2
    print("[OK] AttackSurfaceDiffer smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
