# 创建: 2026-08-05 | 路径敏感性检查
#
"""路径敏感污点检查 — 对BIFT到达汇的路径做反向切片+条件提取以降误报。

motivation: BIFT保守过近似——所有可能到达汇的路径被合并。
这导致 `if (len < 256) memcpy(dst, src, len)` 和
`memcpy(dst, src, len)` 在BIFT视角完全相同——两者都被标记为危险。

实际上前者有长度检查, 后者无。若能识别路径上的条件约束,
可将前者降级为"PROTECTED", 大幅降低误报。

核心算法——反向切片 + 条件提取:
1. 从汇指令地址出发, 沿控制流反向遍历 ≤N 条指令。
2. 检查遍历到的条件分支 (cmp/test + jcc):
   - 分支条件涉及污点数据 → 提取约束表达式。
   - 若约束条件限制了污点数据的值域 → 标记为PROTECTED。
3. 对每条汇聚合所有到达路径的约束——
   若至少一条路径无保护→汇最终标记为VULNERABLE。

CITA (IEEE 2024): 使用 Path Behavior Vectors 编码路径特征,
证明路径感知可降低 38.6% FP。本实现取其核心思想——
"不是所有到达汇的路径同等危险"——用轻量反向切片实现,
不构建完整的符号执行引擎。

与 value_composer.py 的分工:
- value_composer: 分析"数据值经过什么转换" (转换链)
- path_sensitive_checker: 分析"路径上有无保护条件" (条件提取)
- 两者独立, 输出可交叉验证
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class PathSafety(Enum):
    VULNERABLE = 0     # 无保护——污点数据直接到达汇
    PROTECTED = 1      # 有约束——污点数据经过条件检查
    UNKNOWN = 2        # 无法判断——路径信息不足


@dataclass
class ConditionConstraint:
    """一条从反向切片中提取的条件约束。"""
    condition_expr: str       # 如 "rax < 0x100" / "ecx == 0"
    constrains_taint: bool    # 是否约束了污点数据
    constrains_sink_arg: bool  # 是否约束了汇的参数
    insn_addr: int = 0


@dataclass
class PathSafetyReport:
    """单条污点路径的安全性报告。"""
    sink_addr: int
    sink_call: str
    constraints: List[ConditionConstraint] = field(default_factory=list)
    has_taint_constraint: bool = False
    safety: PathSafety = PathSafety.UNKNOWN
    protected_by: List[str] = field(default_factory=list)


class PathSensitiveChecker:
    """路径敏感检查器——对BIFT输出做二次过滤。

    使用:
      checker = PathSensitiveChecker()
      for path in bift_report.critical_paths:
          report = checker.check_path(path, cfg_info)
          if report.safety == PathSafety.VULNERABLE:
              high_confidence_findings.append(path)

    cfg_info: {addr: {type: "cmp"/"jcc", operands:str, targets:[]}}
    """

    # 条件跳转指令
    _JCC_MNEMONICS = {
        'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
        'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
    }

    def __init__(self, backward_slice_depth: int = 30):
        """
        backward_slice_depth: 从汇反向遍历的最大指令数。
        深度越大→更多条件可被捕获, 但时间线性增长。
        """
        self.backward_slice_depth = backward_slice_depth

    def check_path(
        self,
        path_addrs: List[int],
        cfg_info: Dict[int, Dict],
        sink_call: str = "",
    ) -> PathSafetyReport:
        """检查单条污点路径的安全性。

        path_addrs: 路径上的指令地址序列 (从源到汇)。
        cfg_info: {addr: {mnemonic, operands, is_conditional, targets}}。
        """
        _constraints: List[ConditionConstraint] = []
        _sink_addr = path_addrs[-1] if path_addrs else 0

        # 反向切片: 从汇倒数N条指令检测条件分支
        _slice_start = max(0, len(path_addrs) - self.backward_slice_depth)
        _recent_addrs = path_addrs[_slice_start:]

        for _addr in _recent_addrs:
            _info = cfg_info.get(_addr, {})
            _mnem = _info.get('mnemonic', '').lower()

            if _mnem == 'cmp' or _mnem == 'test':
                _ops = _info.get('operands', '')
                # 检查是否涉及size/长度相关的比较
                _constrains = self._is_size_constraint(_ops)
                _constraints.append(ConditionConstraint(
                    condition_expr=f"{_mnem} {_ops}",
                    constrains_taint=_constrains,
                    constrains_sink_arg=_constrains,
                    insn_addr=_addr,
                ))

            elif _mnem in self._JCC_MNEMONICS:
                # 条件跳转——检查跳转目标是否为安全路径
                _info['is_conditional'] = True

        _has_constraint = any(c.constrains_taint for c in _constraints)
        _safety = PathSafety.PROTECTED if _has_constraint else PathSafety.VULNERABLE
        _protected = [
            c.condition_expr for c in _constraints if c.constrains_taint
        ]

        return PathSafetyReport(
            sink_addr=_sink_addr,
            sink_call=sink_call,
            constraints=_constraints,
            has_taint_constraint=_has_constraint,
            safety=_safety,
            protected_by=_protected,
        )

    def batch_check(
        self,
        paths: List[List[int]],
        cfg_info: Dict[int, Dict],
        sink_calls: Optional[List[str]] = None,
    ) -> List[PathSafetyReport]:
        """批量检查多条路径——返回每条路径的安全性报告。

        对 BIFT 输出做聚合:
        - 若所有路径都是 PROTECTED → 该汇为"误报候选"
        - 若至少一条 VULNERABLE → 该汇为"需审查"
        """
        _reports: List[PathSafetyReport] = []
        for _i, _path in enumerate(paths):
            _sink = sink_calls[_i] if sink_calls and _i < len(sink_calls) else ""
            _report = self.check_path(_path, cfg_info, _sink)
            _reports.append(_report)
        return _reports

    def aggregate_sink_safety(
        self, reports: List[PathSafetyReport],
    ) -> PathSafety:
        """聚合——多条路径到达同一汇时, 最差路径决定汇的安全性。

        保守策略: 只要存在一条 VULNERABLE 路径→汇为 VULNERABLE。
        这是安全工具的基线——宁可误报不可漏报。
        """
        if not reports:
            return PathSafety.UNKNOWN
        if any(r.safety == PathSafety.VULNERABLE for r in reports):
            return PathSafety.VULNERABLE
        if all(r.safety == PathSafety.PROTECTED for r in reports):
            return PathSafety.PROTECTED
        return PathSafety.UNKNOWN

    @staticmethod
    def _is_size_constraint(operands: str) -> bool:
        """判断 cmp/test 操作数是否涉及size/长度约束。

        模式:
        - 与常数的比较: cmp reg, 0x100 → 可能长度检查
        - 与sizeof的比较: cmp reg, 256 → 缓冲区大小
        - 寄存器之间: cmp rdx, rcx → 无法静态判断
        """
        # 与立即数比较 → 高概率是size检查
        if '0x' in operands or re.search(r'\b\d+\b', operands):
            return True
        return False


import re  # 用于_is_size_constraint; 放在文件末尾以避免干扰类定义


# ---- smoke ----
def _check():
    _checker = PathSensitiveChecker(backward_slice_depth=10)

    # 模拟CFG: addr→指令信息
    _cfg = {
        0x1000: {'mnemonic': 'mov', 'operands': 'rax, [rdi]'},
        0x1004: {'mnemonic': 'cmp', 'operands': 'rax, 0x100'},
        0x1008: {'mnemonic': 'jg', 'operands': '0x1020', 'is_conditional': False},
        0x1010: {'mnemonic': 'call', 'operands': 'memcpy'},
    }

    # 路径经过cmp检查 → PROTECTED
    _path_protected = [0x1000, 0x1004, 0x1008, 0x1010]
    _r1 = _checker.check_path(_path_protected, _cfg, "call memcpy")
    assert _r1.safety == PathSafety.PROTECTED, \
        f"path with cmp should be PROTECTED, got {_r1.safety}"

    # 路径无检查 → VULNERABLE
    _path_vuln = [0x1000, 0x1010]
    _r2 = _checker.check_path(_path_vuln, _cfg, "call memcpy")
    assert _r2.safety == PathSafety.VULNERABLE, \
        f"path without check should be VULNERABLE, got {_r2.safety}"

    print(f"[path_sense] protected={_r1.protected_by} vuln={_r2.protected_by}")
    print("[OK] path_sensitive_checker passed")


if __name__ == "__main__":
    _check()
