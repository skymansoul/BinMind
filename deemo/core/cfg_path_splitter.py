"""
路径敏感 CFG 分裂器: 在分支点复制抽象状态, 合并点保持状态独立, 在写入点逐路径独立评估。
解决前向区间分析在合并点丢失路径特定 guard 约束的误报问题。
判定规则: 全部路径均溢出 → KEEP, 任一路径安全 → SUPPRESS (保守降低误报)。
"""

from __future__ import annotations
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Set, Tuple


# 模式 ──────────────────────────────────────────────────────────────

_GUARD_IF = re.compile(r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==)\s*'
                       r'(\d+|MAX/sizeof)\s*\)\s*(?:return|goto)')
_ALLOC_SITE = re.compile(r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
                         r'(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)')
_WRITE_SITE = re.compile(r'(?:memcpy|memmove|strcpy|strncpy)\s*\(\s*'
                         r'(\w[\w.]*)\s*,')


@dataclass
class PathState:
    """单条 CFG 路径上的抽象状态。"""
    intervals: Dict[str, Tuple[int, int]] = field(default_factory=dict)
    # var → (lo, hi) 区间
    path_guards: List[str] = field(default_factory=list)
    # 路径上遇到的 guard 约束
    is_dead: bool = False  # 路径已不可行


@dataclass
class PathSplitResult:
    """写入点的路径敏感分析结果。"""
    write_line: int; write_var: str = ''
    alloc_size: int = 0; write_size: int = 0
    total_paths: int = 0
    safe_paths: int = 0       # 写入 ≤ 分配的路径数
    overflow_paths: int = 0   # 写入 > 分配的路径数
    dead_paths: int = 0       # 被裁剪的不可行路径数
    verdict: str = 'REVIEW'   # SUPPRESS / KEEP / REVIEW
    confidence: float = 0.50


class CfgPathSplitter:
    """堆写入安全的 BFS 路径敏感 CFG 遍历器。

    在分支点分裂合并路径, 于写入点逐路径独立评估; 任一路径安全则该写入不是确定溢出 → SUPPRESS。
    """

    def __init__(self, max_paths: int = 128, max_depth: int = 100):
        self.max_paths = max_paths
        self.max_depth = max_depth

    def analyze(self, ir_lines: List[str],
                write_line: int) -> PathSplitResult:
        """从入口到 write_line 做 BFS, 在分支处分裂路径。"""
        # 提取写入前的分配信息
        alloc_size = self._find_alloc_size(ir_lines, write_line)
        write_size_est, write_var = self._estimate_write_size(
            ir_lines, write_line)

        result = PathSplitResult(
            write_line=write_line, write_var=write_var,
            alloc_size=alloc_size, write_size=write_size_est)

        # 从第 0 行到 write_line 做 BFS
        queue: List[Tuple[int, PathState]] = [(0, PathState())]
        safe_count = 0; overflow_count = 0; dead_count = 0

        while queue:
            pos, state = queue.pop(0)

            if pos > min(len(ir_lines) - 1, write_line):
                continue
            if state.is_dead:
                dead_count += 1
                continue
            if pos == write_line:
                if self._is_safe(state, alloc_size, write_size_est):
                    safe_count += 1
                else:
                    overflow_count += 1
                continue

            line = ir_lines[pos]

            # 检查 guard: 约束状态
            gm = _GUARD_IF.search(line)
            if gm:
                var, op, val = gm.group(1), gm.group(2), gm.group(3)
                constrained = self._constrain(state, var, op, val)
                if constrained is None:
                    # 路径已不可行
                    state.is_dead = True
                else:
                    state = constrained
                queue.append((pos + 1, state))
                continue

            # 检查分支: 若后续有 guard 则分裂
            next_few = ir_lines[pos:min(len(ir_lines), pos + 3)]
            guarded = any(_GUARD_IF.search(l) for l in next_few)

            if guarded and len(queue) < self.max_paths:
                # 分裂: 真分支 (guard 命中 → return/goto)
                # 分裂: 假分支 (guard 未命中 → 继续)
                true_state = PathState(
                    intervals=dict(state.intervals),
                    path_guards=list(state.path_guards))
                false_state = PathState(
                    intervals=dict(state.intervals),
                    path_guards=list(state.path_guards))
                # 定位 guard 行
                guard_line_idx = None
                for ni, nl in enumerate(next_few):
                    if _GUARD_IF.search(nl):
                        guard_line_idx = pos + ni
                        break
                # 真分支: 跳到 guard 之后
                true_state.path_guards.append(
                    f'guard@{guard_line_idx}')
                queue.append((min(guard_line_idx + 1, write_line + 1)
                              if guard_line_idx else pos + 1, true_state))
                # 假分支: 跳过 guard (未命中)
                queue.append((min(pos + 1, write_line + 1), false_state))
            else:
                queue.append((pos + 1, state))

        result.total_paths = safe_count + overflow_count + dead_count
        result.safe_paths = safe_count
        result.overflow_paths = overflow_count
        result.dead_paths = dead_count

        # 决策: 任一路径安全则 SUPPRESS
        if safe_count > 0 and overflow_count == 0:
            result.verdict = 'SUPPRESS'
            result.confidence = 0.85
        elif safe_count > 0:
            result.verdict = 'REVIEW'
            result.confidence = 0.50
        elif overflow_count > 0:
            result.verdict = 'KEEP'
            result.confidence = 0.80
        else:
            result.verdict = 'REVIEW'
            result.confidence = 0.40

        return result

    # 辅助 ──────────────────────────────────────────────────────

    @staticmethod
    def _find_alloc_size(ir_lines: List[str], write_line: int) -> int:
        """查找 write_line 之前的 malloc(size), 返回大小。"""
        for i in range(write_line - 1, -1, -1):
            m = _ALLOC_SITE.search(ir_lines[i])
            if m:
                try:
                    return int(m.group(2))
                except ValueError:
                    pass
            # 尝试变量分配: buf = malloc(n) → 需解析 n
            alloc_m = re.search(
                r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
                r'malloc\s*\(\s*(\w[\w.]*)\s*\)', ir_lines[i])
            if alloc_m:
                var = alloc_m.group(2)
                # 回溯: var = 数字 赋值
                for j in range(i - 1, -1, -1):
                    const_m = re.search(
                        rf'{re.escape(var)}\s*=\s*(\d+)\s*;', ir_lines[j])
                    if const_m:
                        return int(const_m.group(1))
        return 0

    @staticmethod
    def _estimate_write_size(ir_lines: List[str],
                             write_line: int) -> Tuple[int, str]:
        """从 memcpy/memmove 第三参数估算写入大小。"""
        line = ir_lines[write_line] if write_line < len(ir_lines) else ''
        m = _WRITE_SITE.search(line)
        if not m:
            return 0, ''
        dst = m.group(1)
        # 估算: 查找常量大小参数
        size_m = re.search(r',\s*(\d+)\s*\)', line)
        if size_m:
            return int(size_m.group(1)), dst
        # 变量: 尝试解析
        var_m = re.search(r',\s*(\w[\w.]*)\s*\)', line)
        if var_m:
            vname = var_m.group(1)
            for i in range(write_line - 1, -1, -1):
                cm = re.search(rf'{re.escape(vname)}\s*=\s*(\d+)\s*;',
                               ir_lines[i])
                if cm:
                    return int(cm.group(1)), dst
        return 0, dst

    @staticmethod
    def _constrain(state: PathState, var: str, op: str,
                   val: str) -> Optional[PathState]:
        """对状态施加 guard 约束, 不可行时返回 None。"""
        import copy
        new_state = PathState(
            intervals=dict(state.intervals),
            path_guards=list(state.path_guards))
        new_state.path_guards.append(f'{var}{op}{val}')

        try:
            if val == 'MAX/sizeof':
                ival = 10**10  # 视为无界上界
            else:
                ival = int(val)
        except ValueError:
            return new_state

        if var not in new_state.intervals:
            new_state.intervals[var] = (0, 10**9)
        lo, hi = new_state.intervals[var]

        if op in ('<', '<='):
            new_hi = ival if op == '<' else ival
            if new_hi < lo:
                return None  # 不可行
            new_state.intervals[var] = (lo, new_hi)
        elif op in ('>', '>='):
            new_lo = ival if op == '>' else (ival - 1)
            if new_lo > hi:
                return None  # 不可行
            new_state.intervals[var] = (new_lo, hi)

        return new_state

    @staticmethod
    def _is_safe(state: PathState, alloc_size: int,
                 write_size: int) -> bool:
        """检查该路径的约束是否使写入安全。"""
        if alloc_size <= 0:
            return False  # 分配大小未知, 视为溢出
        # 基本判定: write_size <= alloc_size → 安全
        # 区间约束下: var_hi <= alloc → 安全
        for var, (lo, hi) in state.intervals.items():
            if lo >= 0 and hi <= alloc_size:
                if write_size <= hi:
                    return True
        return write_size <= alloc_size


def check_path_sensitive(ir_lines: List[str],
                         write_line: int,
                         max_paths: int = 128) -> PathSplitResult:
    """便捷入口: 写入点的路径敏感安全检查。"""
    splitter = CfgPathSplitter(max_paths=max_paths)
    return splitter.analyze(ir_lines, write_line)


__all__ = ['PathState', 'PathSplitResult', 'CfgPathSplitter',
           'check_path_sensitive']
