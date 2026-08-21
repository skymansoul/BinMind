# coding: utf-8
"""
UAF L5-L6 增强管线 — 时序约束窄化 + 统计校准, 对标 heap overflow 深度.
L5: 分支条件感知可达性 — 编码 free→use 路径上的分支条件, 排除不可行路径
L6: CVE 模式校准 — 基于历史 CVE 的贝叶斯后验调整, 函数指针 deref 加权
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter

from .uaf_constraint import UafCandidate, AliasGraph


# L5: 时序约束窄化

@dataclass
class BranchCondition:
    """free→use 路径上的分支条件."""
    addr: int
    condition: str      # e.g. 'ptr==NULL', 'count>0'
    taken: bool          # 沿此路径时条件是否为真


@dataclass
class TemporalPathResult:
    """时序路径分析结果."""
    candidate: Dict
    is_feasible: bool
    must_execute: bool    # True=必经路径, False=条件路径
    branch_count: int     # 从 free 到 use 经过的分支数
    narrowed_confidence: float


class TemporalPathNarrower:
    """L5: 分支条件感知的时序可达性窄化.

    核心方法: 编码 free→use CFG 路径上的分支条件, 排除不可行路径.
    例如: free(p) 之后有 if(p!=NULL) 分支, 若 use(p) 在 p!=NULL 分支内,
    则该分支不可行 (因为 free 后 p 仍为旧值但指向已释放内存).

    与传统路径可达性的区别:
      L3 仅检查 CFG 拓扑可达 (有无路径)
      L5 编码分支条件语义 (该路径在运行时是否可行)
    """

    # 已知的 free() 后置条件: glibc free 不修改指针值 (悬挂指针)
    # 但某些 safe_free 宏会置 ptr=NULL
    _SAFE_FREE_PATTERNS = {'safe_free', 'FREE_AND_NULL', 'g_free', 'SDL_free'}

    def __init__(self):
        self._branches: Dict[int, BranchCondition] = {}

    def add_branch(self, addr: int, condition: str, taken: bool):
        self._branches[addr] = BranchCondition(addr, condition, taken)

    def narrow_temporal_path(
        self, candidate: Dict,
        free_site_callee: str = 'free',
        path_branches: List[Tuple[int, str, bool]] = None,
    ) -> TemporalPathResult:
        """窄化时序路径 — 排除语义上不可行的分支."""
        free_site = candidate['free_site']
        use_site = candidate['use_site']
        confidence = candidate.get('confidence', 0.6)

        if path_branches is None:
            path_branches = []

        # 检查 safe_free 模式: 若 free 后 ptr 被置 NULL
        callee_lower = free_site_callee.lower()
        is_safe_free = any(p.lower() in callee_lower for p in self._SAFE_FREE_PATTERNS)

        if is_safe_free:
            # safe_free → ptr=NULL → use 后必定 crash/NULL-deref
            return TemporalPathResult(
                candidate=candidate, is_feasible=False,
                must_execute=False, branch_count=0,
                narrowed_confidence=0.0)

        # 检查分支条件中是否有 ptr==NULL 检查
        null_guard_found = False
        ptr_name = candidate.get('ptr_name', '')
        feasible_branches = 0
        total_branches = len(path_branches)

        for _, cond, taken in path_branches:
            if ptr_name and ptr_name in cond:
                if 'NULL' in cond or 'null' in cond.lower():
                    # free 后 ptr!=NULL 检查 → 不可行 (ptr 仍为旧值)
                    if '!=' in cond and not taken:
                        # 未走 ptr!=NULL 分支 → 可能是 NULL 路径
                        null_guard_found = True
                        confidence *= 0.60
                    elif '==' in cond and taken:
                        # 走了 ptr==NULL 分支 → ptr 确实为 NULL → use 不可达
                        null_guard_found = True
                        confidence *= 0.30
                    else:
                        feasible_branches += 1
                else:
                    feasible_branches += 1
            else:
                feasible_branches += 1

        # 若所有分支都不可行 → 过滤
        if total_branches > 0 and feasible_branches == 0:
            return TemporalPathResult(
                candidate=candidate, is_feasible=False,
                must_execute=False, branch_count=total_branches,
                narrowed_confidence=0.0)

        # 必经路径 (无分支) → 高置信度
        must_execute = (total_branches == 0)
        if must_execute:
            confidence = min(confidence * 1.15, 0.95)

        return TemporalPathResult(
            candidate=candidate, is_feasible=True,
            must_execute=must_execute, branch_count=total_branches,
            narrowed_confidence=round(confidence, 4))


# L6: CVE 模式统计校准

# UAF CVE 后验特征: 从历史 CVE 中提取的权重重映射
# 来源: CVE-2015-6097, CVE-2016-0189, CVE-2017-0674, CVE-2018-8174 等
_CVE_UAF_PATTERNS = {
    'deref_type': {
        'read':  0.30,   # 读 UAF — 信息泄露, 难以触发 crash
        'write': 0.70,   # 写 UAF — 堆损坏, 更易利用
        'call':  0.95,   # 函数指针调用的 UAF — vtable/IPC 劫持
    },
    'alloc_type': {
        'malloc':  0.60,
        'calloc':  0.50,
        'realloc': 0.75,  # realloc UAF — 更危险 (可能返回新指针)
        'new':     0.70,  # C++ new → vtable 劫持可能
    },
    'free_to_use_gap': {
        # free 和 use 之间的指令数 → 风险因子
        'immediate': 0.95,   # ≤5 指令
        'short':     0.80,   # 6-20 指令
        'medium':    0.55,   # 21-100 指令
        'long':      0.25,   # >100 指令
    },
    'loop_context': {
        # use 是否在循环内 → 多次触发
        'in_loop':     0.85,
        'not_in_loop': 0.55,
    },
    'function_pointer': {
        # use 点是否是函数指针调用
        'yes': 0.95,
        'no':  0.50,
    },
}


class UafStatisticalCalibrator:
    """L6: 基于 CVE 模式的统计校准.

    输入: L0-L5 过滤后的候选
    输出: 校准后的置信度

    方法: 加权评分 — 每个特征维度分配 CVE 衍生的权重,
    最终后验 = 先验置信度 × Π(1 + w_i × (p_i - 0.5))
    其中 p_i 是特征对应的 CVE 模式权重, w_i 是特征重要度.
    """

    def __init__(self):
        self._feature_weights = {
            'deref_type':        0.30,
            'alloc_type':        0.20,
            'free_to_use_gap':   0.25,
            'loop_context':      0.15,
            'function_pointer':  0.35,
        }

    def calibrate(self, candidate: Dict,
                  deref_type: str = 'read',
                  alloc_type: str = 'malloc',
                  free_to_use_instructions: int = 10,
                  in_loop: bool = False,
                  is_function_pointer: bool = False,
                  ) -> Dict:
        """校准单个候选的置信度."""
        prior = candidate.get('confidence', 0.5)
        adjustments = []

        # deref_type 校准
        deref_weight = _CVE_UAF_PATTERNS['deref_type'].get(deref_type, 0.5)
        adj = 1.0 + self._feature_weights['deref_type'] * (deref_weight - 0.5)
        adjustments.append(('deref_type', deref_type, deref_weight, adj))
        prior *= adj

        # alloc_type 校准
        alloc_weight = _CVE_UAF_PATTERNS['alloc_type'].get(alloc_type, 0.5)
        adj = 1.0 + self._feature_weights['alloc_type'] * (alloc_weight - 0.5)
        adjustments.append(('alloc_type', alloc_type, alloc_weight, adj))
        prior *= adj

        # free_to_use_gap 校准
        if free_to_use_instructions <= 5:
            gap_key = 'immediate'
        elif free_to_use_instructions <= 20:
            gap_key = 'short'
        elif free_to_use_instructions <= 100:
            gap_key = 'medium'
        else:
            gap_key = 'long'
        gap_weight = _CVE_UAF_PATTERNS['free_to_use_gap'].get(gap_key, 0.5)
        adj = 1.0 + self._feature_weights['free_to_use_gap'] * (gap_weight - 0.5)
        adjustments.append(('free_to_use_gap', gap_key, gap_weight, adj))
        prior *= adj

        # loop_context 校准
        loop_key = 'in_loop' if in_loop else 'not_in_loop'
        loop_weight = _CVE_UAF_PATTERNS['loop_context'].get(loop_key, 0.5)
        adj = 1.0 + self._feature_weights['loop_context'] * (loop_weight - 0.5)
        adjustments.append(('loop_context', loop_key, loop_weight, adj))
        prior *= adj

        # function_pointer 校准
        fp_key = 'yes' if is_function_pointer else 'no'
        fp_weight = _CVE_UAF_PATTERNS['function_pointer'].get(fp_key, 0.5)
        adj = 1.0 + self._feature_weights['function_pointer'] * (fp_weight - 0.5)
        adjustments.append(('function_pointer', fp_key, fp_weight, adj))
        prior *= adj

        calibrated = min(round(prior, 4), 0.99)

        return {
            **candidate,
            'confidence': calibrated,
            'original_confidence': candidate.get('confidence', 0.5),
            'l6_calibration': {
                'adjustments': adjustments,
                'calibrated_confidence': calibrated,
                'delta': round(calibrated - candidate.get('confidence', 0.5), 4),
            },
        }

    def batch_calibrate(self, candidates: List[Dict],
                        features: Dict[str, Dict] = None,
                        ) -> List[Dict]:
        """批量统计校准."""
        if features is None:
            features = {}
        calibrated = []
        for c in candidates:
            ptr = c.get('ptr_name', '')
            feats = features.get(ptr, {})
            calibrated.append(self.calibrate(
                c,
                deref_type=feats.get('deref_type', 'read'),
                alloc_type=feats.get('alloc_type', 'malloc'),
                free_to_use_instructions=feats.get('gap', 10),
                in_loop=feats.get('in_loop', False),
                is_function_pointer=feats.get('is_function_pointer', False),
            ))
        return calibrated


def simulate_uaf_layers(
    candidates: List[Dict],
    instructions: List[Dict] = None,
    callee_names: Dict[int, str] = None,
) -> Tuple[List[Dict], Dict]:
    """模拟 UAF L5-L6 管线 (用于基准测试)."""
    if instructions is None:
        instructions = []
    if callee_names is None:
        callee_names = {}

    tn = TemporalPathNarrower()
    calibrator = UafStatisticalCalibrator()
    stats = {'L0_input': len(candidates), 'L5_branch_narrowed': 0, 'L6_calibrated': 0}

    # L5: 时序路径窄化
    l5_filtered = []
    for c in candidates:
        free_addr = c.get('free_site', 0)
        callee = callee_names.get(free_addr, 'free')
        result = tn.narrow_temporal_path(c, free_site_callee=callee)
        if result.is_feasible:
            c['confidence'] = result.narrowed_confidence
            c['L5_path'] = {'must_execute': result.must_execute,
                            'branch_count': result.branch_count}
            l5_filtered.append(c)
        else:
            stats['L5_branch_narrowed'] += 1

    # L6: 统计校准
    calibrated = calibrator.batch_calibrate(l5_filtered)
    stats['L6_calibrated'] = len(calibrated)
    stats['final'] = len([c for c in calibrated if c['confidence'] > 0.5])

    return calibrated, stats
