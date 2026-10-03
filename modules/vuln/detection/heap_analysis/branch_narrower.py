# coding: utf-8
#
"""
路径敏感分支窄化 — 对符号约束传播的结果做路径可达性验证。

现有constraint_filter.py的缺陷:
  1. 只收集cmp+jcc约束做区间交集, 不区分taken/not-taken方向
  2. 假设所有约束同时成立 → 过度近似 → 无法裁剪不可达路径
  3. 不处理循环展开产生的矛盾路径

本模块的改进:
  A. 构建CFG基本块边界(简化版: jmp/jcc目标划分)
  B. 从入口到漏洞点的前向路径枚举(限宽DFS, max_path=32)
  C. 每条路径上的约束集合独立求解
  D. 若所有路径不可达 → 该候选可滤除(高置信FP)
  E. 若存在可行路径 → 保留候选

复杂度: O(P * C), P=路径数(≤32), C=路径上约束数

  KLEE(OSDI'08)— 路径级约束求解, 我们用简化版区间法
  Inferbo— interval domain缓冲区推理
  Gasan— 低开销路径敏感, 限宽DFS思路
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict

from modules.vuln.detection.heap_analysis.sym_constraint_engine import (
    SymExpr, ConstraintRecord, _parse_insn, _normalize_reg, _extract_imm)

@dataclass
class BasicBlock:
    """基本块 — 简化CFG节点"""
    start_idx: int
    end_idx: int
    successors: List[int] = field(default_factory=list)
    constraints: List[ConstraintRecord] = field(default_factory=list)

@dataclass
class PathFeasibility:
    """路径可行性分析结果"""
    is_feasible: bool
    path_constraints: List[ConstraintRecord]
    contradiction: str = ""

@dataclass
class BranchNarrowResult:
    """分支窄化结果"""
    total_candidates: int = 0
    proven_unreachable: int = 0
    retained: int = 0
    details: List[dict] = field(default_factory=list)

class BranchNarrower:
    """路径敏感分支窄化器

    对符号约束传播的uncertain候选做二次验证:
    若候选所在的所有CFG路径均不可达 → 标记为可滤除FP
    """

    def __init__(self, max_paths: int = 32, window: int = 200):
        self.max_paths = max_paths
        self.window = window

    def narrow(self, insns_raw: List[str],
               uncertain_indices: List[int],
               alloc_constraints: List[ConstraintRecord],
               base_addr: int = 0x400000) -> BranchNarrowResult:
        """对uncertain候选做路径可行性验证

        参数: insns_raw 指令列表, uncertain_indices 需验证的
        指令索引, alloc_constraints 从入口累积的全局约束;
        返回 BranchNarrowResult。
        """
        result = BranchNarrowResult(total_candidates=len(uncertain_indices))
        if not uncertain_indices or not insns_raw:
            result.retained = len(uncertain_indices)
            return result

        # 构建简化CFG
        blocks = self._build_cfg(insns_raw)

        for idx in uncertain_indices:
            # 从入口到idx的所有路径
            paths = self._enumerate_paths(blocks, 0, idx)
            if not paths:
                # 无路径到达 → 不可达(保守保留)
                result.retained += 1
                result.details.append({
                    'idx': idx, 'verdict': 'retained',
                    'reason': 'no path found — conservative'})
                continue

            # 检查每条路径的约束可行性
            any_feasible = False
            contradictions = []
            for path in paths:
                feedback = self._check_path_feasibility(path, blocks)
                if feedback.is_feasible:
                    any_feasible = True
                    break
                else:
                    contradictions.append(feedback.contradiction)

            if any_feasible:
                result.retained += 1
                result.details.append({
                    'idx': idx, 'verdict': 'retained',
                    'reason': 'at least one feasible path'})
            else:
                result.proven_unreachable += 1
                result.details.append({
                    'idx': idx, 'verdict': 'filtered',
                    'reason': '; '.join(contradictions[:3])})

        return result

    def _build_cfg(self, insns_raw: List[str]) -> List[BasicBlock]:
        """构建简化CFG — 以跳转目标为基本块边界"""
        n = len(insns_raw)
        if n == 0:
            return []

        # 识别跳转目标和跳转指令位置
        jump_targets: Set[int] = {0}
        jump_indices: List[int] = []

        for i, raw in enumerate(insns_raw):
            mnem, ops = _parse_insn(raw)
            if mnem and mnem[0] == 'j' and ops:
                jump_indices.append(i)
                # 解析跳转目标
                try:
                    tgt = int(ops[0], 16)
                    jump_targets.add(i + 1)  # fall-through
                except (ValueError, IndexError):
                    pass
            elif mnem in ('jmp', 'ret') and ops:
                jump_targets.add(i + 1)

        # 构建基本块
        sorted_starts = sorted(jump_targets)
        blocks: List[BasicBlock] = []
        block_start_to_idx: Dict[int, int] = {}

        for bi, start in enumerate(sorted_starts):
            if start >= n:
                continue
            end = sorted_starts[bi + 1] - 1 if bi + 1 < len(sorted_starts) else n - 1
            bb = BasicBlock(start_idx=start, end_idx=end)
            block_start_to_idx[start] = len(blocks)

            # 提取块内约束
            for j in range(start, min(end + 1, n)):
                mnem, ops = _parse_insn(insns_raw[j])
                if mnem == 'cmp' and len(ops) >= 2:
                    reg = _normalize_reg(ops[0])
                    imm = _extract_imm(ops[1])
                    if reg and imm is not None:
                        op = self._find_jcc_op(insns_raw, j)
                        if op:
                            bb.constraints.append(
                                ConstraintRecord(var=reg, op=op, value=imm))
            blocks.append(bb)

        # 建立后继关系
        for bi, bb in enumerate(blocks):
            last_idx = bb.end_idx
            if last_idx < n:
                mnem, ops = _parse_insn(insns_raw[last_idx])
                if mnem and mnem[0] == 'j':
                    # 条件跳转: 两个后继
                    fall_through = last_idx + 1
                    if fall_through < n and fall_through in block_start_to_idx:
                        bb.successors.append(block_start_to_idx[fall_through])
                    if ops:
                        try:
                            tgt = int(ops[0], 16)
                            for bj, other in enumerate(blocks):
                                if other.start_idx == tgt or \
                                   (other.start_idx <= tgt <= other.end_idx):
                                    bb.successors.append(bj)
                                    break
                        except ValueError:
                            pass
                elif mnem == 'jmp' and ops:
                    try:
                        tgt = int(ops[0], 16)
                        for bj, other in enumerate(blocks):
                            if other.start_idx <= tgt <= other.end_idx:
                                bb.successors.append(bj)
                                break
                    except ValueError:
                        pass
                elif mnem == 'ret':
                    pass  # 无后继
                else:
                    # 顺序执行 → 后继是下一块
                    if bi + 1 < len(blocks):
                        bb.successors.append(bi + 1)

        return blocks

    def _enumerate_paths(self, blocks: List[BasicBlock],
                         start_block: int,
                         target_insn_idx: int) -> List[List[int]]:
        """从入口块到包含目标指令的块的路径枚举(限宽DFS)"""
        if not blocks:
            return []

        # 找到目标指令所在的块
        target_block = -1
        for bi, bb in enumerate(blocks):
            if bb.start_idx <= target_insn_idx <= bb.end_idx:
                target_block = bi
                break

        if target_block < 0:
            return []

        # DFS限宽路径枚举
        paths: List[List[int]] = []
        visited: Set[int] = set()

        def _dfs(block_idx: int, path: List[int], depth: int):
            if len(paths) >= self.max_paths or depth > 32:
                return
            if block_idx in path:  # 循环 → 停止
                return
            new_path = path + [block_idx]
            if block_idx == target_block:
                paths.append(new_path)
                return
            block = blocks[block_idx]
            if not block.successors:
                return
            for succ in block.successors:
                _dfs(succ, new_path, depth + 1)

        _dfs(start_block, [], 0)
        return paths

    def _check_path_feasibility(
            self, path: List[int],
            blocks: List[BasicBlock]) -> PathFeasibility:
        """检查单条路径上的约束是否矛盾"""
        all_constraints: List[ConstraintRecord] = []
        for bi in path:
            all_constraints.extend(blocks[bi].constraints)

        if not all_constraints:
            return PathFeasibility(
                is_feasible=True, path_constraints=[])

        # 按变量分组约束, 检查区间交集是否为空
        intervals: Dict[str, List[Tuple[int, int]]] = defaultdict(list)

        for c in all_constraints:
            if c.op in ('le', 'lt'):
                hi = c.value - (1 if c.op == 'lt' else 0)
                intervals[c.var].append((-10**9, hi))
            elif c.op in ('ge', 'gt'):
                lo = c.value + (1 if c.op == 'gt' else 0)
                intervals[c.var].append((lo, 10**9))
            elif c.op == 'eq':
                intervals[c.var].append((c.value, c.value))
            elif c.op == 'ne':
                # 不等约束 — 不影响区间交集
                pass

        for var, bounds in intervals.items():
            if not bounds:
                continue
            lo = max(b[0] for b in bounds)
            hi = min(b[1] for b in bounds)
            if lo > hi:
                return PathFeasibility(
                    is_feasible=False,
                    path_constraints=all_constraints,
                    contradiction=f"{var}: [{lo},{hi}] empty")

        return PathFeasibility(
            is_feasible=True, path_constraints=all_constraints)

    def _find_jcc_op(self, insns: List[str], cmp_idx: int) -> Optional[str]:
        """cmp后查找条件跳转方向"""
        for j in range(cmp_idx + 1, min(cmp_idx + 5, len(insns))):
            mnem, _ = _parse_insn(insns[j])
            op_map = {
                'jle': 'le', 'jbe': 'le', 'jge': 'ge', 'jae': 'ge',
                'jl': 'lt', 'jb': 'lt', 'jg': 'gt', 'ja': 'gt',
                'je': 'eq', 'jne': 'ne'}
            if mnem in op_map:
                return op_map[mnem]
        return None

def narrow_uncertain_findings(
        insns_raw: List[str],
        uncertain_indices: List[int],
        alloc_constraints: List[ConstraintRecord],
        base_addr: int = 0x400000,
        max_paths: int = 32) -> BranchNarrowResult:
    """对uncertain候选做路径可行性验证"""
    narrower = BranchNarrower(max_paths=max_paths)
    return narrower.narrow(insns_raw, uncertain_indices,
                           alloc_constraints, base_addr)

__all__ = [
    "BasicBlock", "PathFeasibility", "BranchNarrowResult",
    "BranchNarrower", "narrow_uncertain_findings",
]
