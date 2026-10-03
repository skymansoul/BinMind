"""
抽象解释引擎: 在控制流图上执行 worklist 驱动的区间抽象解释不动点分析,
追踪数值变量与堆对象指针, 以 widening 保证循环收敛, 用于检测反编译伪代码中的堆溢出与 UAF。
"""

import re
from typing import Any, Dict, List, Optional

from core.abstract_state import AbstractState
from core.abstract_transfer import transfer_line
from core.heap_abstract_domain import HeapAbstractDomain, Interval, compute_effective_size
from core.path_constraints import ConstraintExtractor, refine_interval_with_constraints

class AbstractEngine:
    """Worklist 驱动的抽象解释引擎。输入反编译伪代码, 输出每行语句处的 AbstractState, 供溢出查询使用。"""

    MAX_ITERATIONS = 15          # 最多迭代次数
    WIDEN_DELAY = 3              # 第 N 次才触发 widening

    def __init__(self, arch_bits: int = 64):
        self._arch_bits = arch_bits
        self._constraint_extractor = ConstraintExtractor()

    # 公开 API ─────────────────────────────────────────

    def analyze(self, pseudocode: str) -> Dict[int, AbstractState]:
        """对整个函数执行抽象解释, 返回行号→状态的映射。"""
        lines = pseudocode.splitlines()
        n = len(lines)
        if n == 0:
            return {}

        states: Dict[int, AbstractState] = {
            i: AbstractState(reachable=False) for i in range(n)
        }
        init = AbstractState()
        init.heap = HeapAbstractDomain(self._arch_bits)
        states[0] = init

        # worklist 迭代
        worklist: List[int] = [0]
        iteration_count: Dict[int, int] = {}

        while worklist:
            idx = worklist.pop(0)
            if idx >= n:
                continue

            prev_state = states.get(idx)
            if prev_state is None or not prev_state.reachable:
                continue

            iteration_count[idx] = iteration_count.get(idx, 0) + 1
            if iteration_count[idx] > self.MAX_ITERATIONS:
                continue  # 放弃该点

            # 应用当前行的转移函数
            new_state = self._transfer(lines[idx], prev_state.clone(), lines, idx)
            if new_state is None:
                continue

            # 确定后继行
            successors = self._successors(idx, n, lines[idx])
            is_loop_header = idx > 0 and any(s < idx for s in successors)

            for succ in successors:
                if succ >= n:
                    continue
                existing = states.get(succ)
                if existing is None or not existing.reachable:
                    # 首次到达
                    states[succ] = new_state.clone() if succ != idx + 1 else new_state
                    worklist.append(succ)
                else:
                    # 合并
                    use_widen = is_loop_header and iteration_count.get(succ, 0) >= self.WIDEN_DELAY
                    merged = existing.widen(new_state) if use_widen else existing.join(new_state)
                    if self._state_changed(existing, merged):
                        states[succ] = merged
                        worklist.append(succ)

        return states

    def get_overflow_findings(
        self, states: Dict[int, AbstractState],
        pseudocode: str = "",
    ) -> List[Dict[str, Any]]:
        """从分析结果中提取堆溢出告警。"""
        findings: List[Dict[str, Any]] = []
        lines = pseudocode.splitlines() if pseudocode else []

        for line_no, state in sorted(states.items()):
            if not state.reachable:
                continue
            for ptr, obj in state.heap.get_all_objects().items():
                if obj.can_overflow and not obj.is_freed:
                    findings.append({
                        "type": "heap-overflow",
                        "severity": "Critical",
                        "cwe": "CWE-122",
                        "pointer": ptr,
                        "line": line_no,
                        "code": lines[line_no] if line_no < len(lines) else "",
                        "requested_size": obj.requested_size,
                        "effective_size": obj.effective_size,
                        "max_offset": obj.offset_range.high,
                        "confidence": self._confidence(obj),
                        "is_definite": obj.offset_range.is_finite and
                                       obj.offset_range.high is not None and
                                       obj.offset_range.high >= obj.effective_size,
                    })
        return findings

    def get_uaf_findings(
        self, states: Dict[int, AbstractState],
    ) -> List[Dict[str, Any]]:
        """从分析结果中提取 UAF 告警。"""
        findings: List[Dict[str, Any]] = []
        for line_no, state in states.items():
            if not state.reachable:
                continue
            for ptr, obj in state.heap.get_all_objects().items():
                if obj.is_freed and obj.offset_range.high is not None and obj.offset_range.high > 0:
                    findings.append({
                        "type": "use-after-free",
                        "severity": "Critical",
                        "cwe": "CWE-416",
                        "pointer": ptr,
                        "line": line_no,
                        "freed_at": obj.freed_at_line,
                        "confidence": 0.85,
                    })
        return findings

    # 转移函数 (委托给 core.abstract_transfer)

    def _transfer(
        self, line: str, state: AbstractState,
        all_lines: List[str], line_idx: int,
    ) -> Optional[AbstractState]:
        """应用单条语句的转移函数。委托给 abstract_transfer.transfer_line。"""
        return transfer_line(line, state, all_lines, line_idx, self)

    # 辅助 ─────────────────────────────────────────────

    @staticmethod
    def _successors(idx: int, total: int, line: str) -> List[int]:
        """计算控制流后继。简化模型: 顺序执行, return 结束。"""
        stripped = line.strip()
        if stripped.startswith('return') or stripped.startswith('exit'):
            return []
        succ = [idx + 1]
        return [s for s in succ if s < total]

    @staticmethod
    def _state_changed(old: AbstractState, new: AbstractState) -> bool:
        """检查状态是否发生变化。"""
        if old.intervals.keys() != new.intervals.keys():
            return True
        for k in old.intervals:
            o = old.intervals[k]
            n = new.intervals.get(k)
            if n is None:
                return True
            if o.low != n.low or o.high != n.high:
                return True
        return False

    def _eval_size(
        self, expr: str, state: AbstractState,
        all_lines: List[str], line_idx: int,
    ) -> int:
        """估算 size 表达式的值。"""
        expr = expr.strip()
        try:
            return int(expr)
        except ValueError:
            pass
        # 变量查找
        iv = state.intervals.get(expr, Interval(0, None))
        if iv.low is not None and iv.low == iv.high:
            return max(1, iv.low)
        if iv.low is not None:
            return iv.low
        # 使用约束提取器
        constraints = self._constraint_extractor.extract_for_var(
            '\n'.join(all_lines), expr, line_idx,
        )
        lo, hi = refine_interval_with_constraints(expr, None, None, constraints)
        return lo if lo is not None else 0

    def _estimate_write_size(
        self, func: str, args: List[str], state: AbstractState,
    ) -> Optional[int]:
        """估算写入操作的字节数。"""
        if func in ('memcpy', 'memmove', 'memset', 'strncpy', 'snprintf', 'read', 'fread', 'recv'):
            if len(args) >= 3:
                size_arg = args[2].strip()
                try:
                    return int(size_arg)
                except ValueError:
                    iv = state.intervals.get(size_arg, Interval(0, None))
                    return iv.high if iv.high is not None else iv.low
        elif func in ('strcpy', 'sprintf'):
            return None  # 无法静态确定长度
        return None

    @staticmethod
    def _split_args(s: str) -> List[str]:
        """按逗号分割函数参数 (考虑括号嵌套)。"""
        if not s.strip():
            return []
        depth, parts, cur = 0, [], []
        for ch in s:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            if ch == ',' and depth == 0:
                parts.append(''.join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        if cur:
            parts.append(''.join(cur).strip())
        return parts

    @staticmethod
    def _confidence(obj: "HeapObject") -> float:
        """计算置信度。"""
        if obj.offset_range.is_finite and obj.offset_range.high is not None:
            if obj.offset_range.high >= obj.effective_size:
                return 0.90  # 确定溢出
            return 0.15  # 基本安全
        if obj.requested_size <= 0:
            return 0.40  # 大小未知
        return 0.55  # 可能溢出
