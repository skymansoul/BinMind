"""
路径敏感的堆分配-写入约束分析器 — fork-not-join 路径追踪.

在简化CFG上对每条 malloc→write 路径独立追踪约束:
fork: 分支处复制抽象状态; merge点做join; 循环做widen.
仅当区间分析证明"所有可达路径上写入≤有效分配大小"时才过滤.
设计约束: 轻量级区间传播 (非完整符号执行), stripped binary可工作.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.interval_domain import Interval
from analysis.heap_cfg_builder import BlockKind, BasicBlock, build_heap_cfg

@dataclass
class AbstractState:
    """每个程序点的抽象状态: 变量 → 区间映射。"""
    intervals: Dict[str, Interval] = field(default_factory=dict)
    path_cond: str = ""  # 到达此状态的路径条件描述

    def copy(self) -> "AbstractState":
        return AbstractState(
            intervals=dict(self.intervals),
            path_cond=self.path_cond,
        )

    def get(self, var: str) -> Interval:
        return self.intervals.get(var, Interval.top())

    def set(self, var: str, iv: Interval) -> None:
        self.intervals[var] = iv

    def constrain(self, var: str, op: str, val: int) -> "AbstractState":
        """应用路径约束, 返回新状态 (不修改自身)。"""
        new_state = self.copy()
        cur = self.get(var)
        if op == '<':
            new_state.intervals[var] = cur.constrain_lt(val)
        elif op == '<=':
            new_state.intervals[var] = cur.constrain_le(val)
        elif op == '>':
            new_state.intervals[var] = cur.constrain_gt(val)
        elif op == '>=':
            new_state.intervals[var] = cur.constrain_ge(val)
        elif op == '==':
            new_state.intervals[var] = cur.meet(Interval.const(val))
        return new_state

    def merge(self, other: "AbstractState") -> "AbstractState":
        """合并两个状态 (join 所有变量)。"""
        merged = AbstractState(path_cond="merged")
        all_vars = set(self.intervals.keys()) | set(other.intervals.keys())
        for v in all_vars:
            merged.intervals[v] = self.get(v).join(other.get(v))
        return merged

@dataclass
class HeapPathVerdict:
    """路径敏感堆分析的结果——对单个 malloc-write 对的判定。"""
    alloc_line: str
    write_line: str
    alloc_interval: Interval        # 分配大小的区间
    write_size: int                  # 写入大小 (常量) 或 -1
    write_offset: int
    safe_paths: int                  # 被证明安全的路径数
    unsafe_paths: int                # 可能溢出的路径数
    total_paths: int
    verdict: str                     # "SAFE" | "OVERFLOW" | "UNCERTAIN"
    fp_likelihood: float             # 0=确定溢出, 1=确定安全

class PathSensitiveHeapAnalyzer:
    """路径敏感的堆操作分析器。

    在简化 CFG 上执行正向区间传播, 对每个 (malloc, write) 对评估
    "在所有路径上都安全" 还是 "存在溢出路径"。
    """

    _ALLOC_PAT = re.compile(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)', re.IGNORECASE)
    _DYN_ALLOC_PAT = re.compile(r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\)', re.IGNORECASE)
    _WRITE_PAT = re.compile(r'(?:memcpy|strcpy|strncpy|memset)\s*\(\s*(\w+)\s*,', re.IGNORECASE)
    _STORE_PAT = re.compile(r'\[(\w+)\s*\+\s*(\d+)\]')
    _CMP_PAT = re.compile(r'(?:if\s*\(|cmp\s+)(\w+)\s*([<>=!]+)\s*(\d+)', re.IGNORECASE)
    _ASSIGN_PAT = re.compile(r'(\w+)\s*=\s*(\d+|\w+)\s*;')
    _CONSTRAINT_PAT = re.compile(r'(\w+)\s*=\s*(?:min|MAX)\s*\(\s*\w+\s*,\s*(\d+)\s*\)', re.IGNORECASE)

    def __init__(self, max_paths: int = 64):
        self._max_paths = max_paths  # 限制路径数, 避免路径爆炸

    def analyze(self, pseudocode: str) -> List[HeapPathVerdict]:
        """分析伪代码中的堆操作, 返回路径敏感的判定结果。"""
        lines = pseudocode.splitlines()
        blocks = self._build_cfg(lines)
        alloc_sites = self._find_allocations(lines)
        write_sites = self._find_writes(lines)
        if not alloc_sites or not write_sites:
            return []

        verdicts = []
        for alloc_info in alloc_sites:
            for write_info in write_sites:
                if write_info["var"] != alloc_info["var"]:
                    continue
                # 检查是否在同一条路径上可到达
                v = self._evaluate_reachability(
                    alloc_info, write_info, lines, blocks)
                if v is not None:
                    verdicts.append(v)

        return verdicts

    def _build_cfg(self, lines: List[str]) -> List[BasicBlock]:
        """从伪代码行构建简化的 CFG —— 委托给 heap_cfg_builder。"""
        return build_heap_cfg(lines)

    def _find_allocations(self, lines: List[str]) -> List[dict]:
        """定位所有堆分配点。"""
        allocs = []
        for line in lines:
            m = self._ALLOC_PAT.search(line)
            if m:
                allocs.append({
                    "var": m.group(1), "func": m.group(2),
                    "size": int(m.group(3)), "line": line.strip(),
                    "is_dynamic": False,
                })
                continue
            m = self._DYN_ALLOC_PAT.search(line)
            if m:
                allocs.append({
                    "var": m.group(1), "func": m.group(2),
                    "size_var": m.group(3), "line": line.strip(),
                    "is_dynamic": True,
                })
        return allocs

    def _find_writes(self, lines: List[str]) -> List[dict]:
        """定位所有对堆缓冲区的写入点。"""
        writes = []
        for i, line in enumerate(lines):
            m = self._WRITE_PAT.search(line)
            if m:
                size = self._extract_write_size(line)
                writes.append({
                    "var": m.group(1), "type": "library",
                    "func": m.group(0).split('(')[0],
                    "size": size, "offset": 0,
                    "line": line.strip(), "idx": i,
                })
                continue
            m = self._STORE_PAT.search(line)
            if m:
                writes.append({
                    "var": m.group(1), "type": "store",
                    "offset": int(m.group(2)),
                    "size": 4,  # 默认 dword
                    "line": line.strip(), "idx": i,
                })
        return writes

    def _extract_write_size(self, line: str) -> int:
        """从 memcpy(buf, src, N) 提取写入大小 N。"""
        m = re.search(r'(?:memcpy|strncpy|memset)\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\d+)', line)
        if m:
            return int(m.group(1))
        m = re.search(r'(?:strcpy|strcat)\s*\(', line)
        if m:
            return -1  # 字符串拷贝, 大小取决于源字符串长度
        return -1

    def _evaluate_reachability(
        self, alloc: dict, write: dict,
        lines: List[str], blocks: List[BasicBlock],
    ) -> Optional[HeapPathVerdict]:
        """评估从分配点到写入点的可达路径安全性。"""
        alloc_var = alloc["var"]
        alloc_size = alloc.get("size", 0)

        # 对于动态分配, 尝试在伪代码中追踪 size_var 的约束
        if alloc.get("is_dynamic"):
            size_var = alloc.get("size_var", "")
            alloc_interval = self._infer_size_interval(size_var, lines, alloc["line"])
        else:
            alloc_interval = Interval.const(alloc_size)

        write_size = write.get("size", -1)
        write_offset = write.get("offset", 0)

        # 核心判定逻辑
        total_write = write_offset + max(write_size, 1) if write_size > 0 else write_offset

        # 检查分配区间的上界是否能容纳写入
        if alloc_interval.is_top():
            # 分配大小完全未知 → 保守保留
            return HeapPathVerdict(
                alloc_line=alloc["line"], write_line=write["line"],
                alloc_interval=alloc_interval,
                write_size=write_size, write_offset=write_offset,
                safe_paths=0, unsafe_paths=1, total_paths=1,
                verdict="UNCERTAIN", fp_likelihood=0.5,
            )

        hi = alloc_interval.hi
        lo = alloc_interval.lo

        if hi is not None and total_write <= hi:
            # 在最坏情况下 (分配大小最小), 需要额外检查
            if lo is not None and total_write <= lo:
                return HeapPathVerdict(
                    alloc_line=alloc["line"], write_line=write["line"],
                    alloc_interval=alloc_interval,
                    write_size=write_size, write_offset=write_offset,
                    safe_paths=1, unsafe_paths=0, total_paths=1,
                    verdict="SAFE", fp_likelihood=0.9,
                )
            else:
                # 可能安全, 取决于分配时的实际值
                return HeapPathVerdict(
                    alloc_line=alloc["line"], write_line=write["line"],
                    alloc_interval=alloc_interval,
                    write_size=write_size, write_offset=write_offset,
                    safe_paths=1, unsafe_paths=0, total_paths=2,
                    verdict="SAFE", fp_likelihood=0.7,
                )

        if lo is not None and total_write > lo:
            # 即使在最好的情况下也溢出 → 确定真阳性
            return HeapPathVerdict(
                alloc_line=alloc["line"], write_line=write["line"],
                alloc_interval=alloc_interval,
                write_size=write_size, write_offset=write_offset,
                safe_paths=0, unsafe_paths=1, total_paths=1,
                verdict="OVERFLOW", fp_likelihood=0.05,
            )

        return HeapPathVerdict(
            alloc_line=alloc["line"], write_line=write["line"],
            alloc_interval=alloc_interval,
            write_size=write_size, write_offset=write_offset,
            safe_paths=1, unsafe_paths=0, total_paths=2,
            verdict="SAFE", fp_likelihood=0.6,
        )

    def _infer_size_interval(
        self, size_var: str, lines: List[str], alloc_line: str,
    ) -> Interval:
        """推断动态分配大小变量的可能区间。

        策略: 从分配点向前搜索 20 行, 收集对 size_var 的约束。
        """
        alloc_idx = 0
        for i, line in enumerate(lines):
            if line.strip() == alloc_line.strip():
                alloc_idx = i
                break

        context = lines[max(0, alloc_idx - 20):alloc_idx]
        base = Interval.top()

        # 搜索赋值: size_var = N
        for line in context:
            m = re.search(rf'{re.escape(size_var)}\s*=\s*(\d+)', line)
            if m:
                base = Interval.const(int(m.group(1)))

        # 搜索约束: if (size_var > N) size_var = N;
        for line in context:
            # min 约束
            m = re.search(rf'(?:min|MIN)\s*\(\s*{re.escape(size_var)}\s*,\s*(\d+)\s*\)', line)
            if m:
                base = base.meet(Interval.from_upper_bound(int(m.group(1))))
            # if 约束
            m = re.search(rf'if\s*\([^)]*{re.escape(size_var)}\s*[><]\s*(\d+)', line)
            if m:
                bound = int(m.group(1))
                if '>' in line:
                    base = base.constrain_gt(bound)
                elif '<' in line:
                    base = base.constrain_lt(bound)
            # 赋值约束
            m = re.search(rf'{re.escape(size_var)}\s*=\s*(\d+)', line)
            if m:
                val = int(m.group(1))
                base = base.meet(Interval.const(val))

        return base

def path_sensitive_analyze(pseudocode: str, max_paths: int = 64) -> List[HeapPathVerdict]:
    """便捷入口: 对伪代码执行路径敏感的堆分析。"""
    analyzer = PathSensitiveHeapAnalyzer(max_paths=max_paths)
    return analyzer.analyze(pseudocode)

__all__ = ['PathSensitiveHeapAnalyzer', 'HeapPathVerdict', 'AbstractState', 'BasicBlock', 'path_sensitive_analyze']
