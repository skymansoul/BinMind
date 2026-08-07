"""
补丁语义影响力验证 — CFG 可达性保持分析 + 修复完整性评分。

问题定义:
  二进制补丁发布后需要回答两个问题:
    1. 补丁是否真正消除了漏洞的可利用路径? (修复完整性)
    2. 漏洞是否通过其他执行路径仍然可达? (路径迁移)

  现有二进制差分工具回答"代码哪里变了"，不回答"漏洞是否被修复"。
  本模块基于 GHIDRA/IDA 基本块导出进行轻量级可达性分析。

核心指标:
  BSR (Block Survival Rate): 漏洞块的存活率 [0,1]
  PRI (Path Reachability Index): 存活块中可达入口的比例 [0,1]
  FCS (Fix Completeness Score): 综合评分 0-10

与现有工具的区分:
  - Diaphora: 函数级匹配，无基本块级可达性
  - BinDiff: 图形同构匹配，无攻击面入口感知
  - Binarly US 12,287,885: 跨二进制 ICFG，需完整反汇编

  PatchDiff-AI: 补丁差异驱动根因分析
  BinDiff Manual §4: 基本块匹配算法

修改记录:
  创建 2026-05-07 — 核心评估 (assess_patch, batch_assess, fix_summary)
  2026-07-30 — 辅助函数拆分至 patch_helpers.py
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.output.src.patch_helpers import (
    bb_signature, _estimate_reachable, _entry_candidates, BlockMatch
)

@dataclass
class FixAssessment:
    function_name: str
    total_blocks_old: int
    total_blocks_new: int
    block_survival_rate: float
    path_reachability_index: float
    fix_completeness_score: float
    matched_blocks: List[BlockMatch] = field(default_factory=list)
    new_blocks_added: int = 0
    severity_change: str = 'unchanged'

    def is_fixed(self) -> bool:
        return self.fix_completeness_score >= 7.0

    def risk_verdict(self) -> str:
        if self.fix_completeness_score >= 8.5:
            return 'confirmed_fixed'
        if self.fix_completeness_score >= 5.0:
            return 'partially_fixed'
        if self.fix_completeness_score >= 3.0:
            return 'likely_unfixed'
        return 'vulnerability_migrated'

def assess_patch(
    function_name: str,
    old_blocks: List[List[str]],
    new_blocks: List[List[str]],
    old_adjacency: Optional[Dict[int, List[int]]] = None,
    new_adjacency: Optional[Dict[int, List[int]]] = None,
    import_calls_old: Optional[Dict[str, List[int]]] = None,
    import_calls_new: Optional[Dict[str, List[int]]] = None,
    vuln_block_indices: Optional[Set[int]] = None,
) -> FixAssessment:
    """评估补丁对单个函数的修复完整性。返回 FixAssessment。"""
    n_old, n_new = len(old_blocks), len(new_blocks)
    import_calls_old = import_calls_old or {}
    import_calls_new = import_calls_new or {}

    old_sigs: Dict[int, str] = {}
    new_sig_to_idx: Dict[str, List[int]] = defaultdict(list)
    for i, insns in enumerate(old_blocks):
        old_sigs[i] = bb_signature(insns)
    for j, insns in enumerate(new_blocks):
        new_sig_to_idx[bb_signature(insns)].append(j)

    entry_indices = _entry_candidates(function_name, import_calls_new)

    if vuln_block_indices is None:
        vuln_block_indices = set()
        for i, insns in enumerate(old_blocks):
            joined = ' '.join(insns).lower()
            if any(kw in joined for kw in ('call','jmp','ret','memcpy','strcpy')):
                if i > max(n_old * 0.7, 1):
                    vuln_block_indices.add(i)
        if not vuln_block_indices:
            vuln_block_indices = set(range(max(0, n_old - 3), n_old))

    block_matches: List[BlockMatch] = []
    surviving_matched, surviving_reachable = 0, 0

    for old_idx in range(n_old):
        sig = old_sigs[old_idx]
        new_indices = new_sig_to_idx.get(sig, [])
        if new_indices:
            new_idx = new_indices[0]
            is_vuln = old_idx in vuln_block_indices
            reachable = None
            if is_vuln:
                surviving_matched += 1
                reachable = _estimate_reachable(
                    new_idx, n_new, entry_indices, new_adjacency or {})
                if reachable:
                    surviving_reachable += 1
            block_matches.append(BlockMatch(
                old_index=old_idx, new_index=new_idx, signature=sig,
                matched=True, reachability_preserved=reachable))
        else:
            is_vuln = old_idx in vuln_block_indices
            block_matches.append(BlockMatch(
                old_index=old_idx, new_index=-1, signature=sig,
                matched=False,
                reachability_preserved=False if is_vuln else None))

    vuln_count = len(vuln_block_indices)
    bsr = surviving_matched / vuln_count if vuln_count > 0 else 0.0
    pri = surviving_reachable / surviving_matched if surviving_matched > 0 else 0.0

    old_sig_set = set(old_sigs.values())
    new_sig_set = {bb_signature(insns) for insns in new_blocks}
    new_blocks_added = len(new_sig_set - old_sig_set)

    raw_fcs = 10.0 - 10.0 * bsr * pri
    if new_blocks_added >= 3:
        change_bonus = min(new_blocks_added / max(n_old, 1), 1.0) * 2.0
        raw_fcs += change_bonus
    if n_old > 0 and n_new < n_old * 0.7:
        raw_fcs += 1.0
    fcs = max(0.0, min(10.0, raw_fcs))

    sev_change = 'reduced' if fcs >= 7.0 else ('worsened' if fcs <= 3.0 else 'unchanged')

    return FixAssessment(
        function_name=function_name, total_blocks_old=n_old,
        total_blocks_new=n_new,
        block_survival_rate=round(bsr, 4),
        path_reachability_index=round(pri, 4),
        fix_completeness_score=round(fcs, 1),
        matched_blocks=block_matches, new_blocks_added=new_blocks_added,
        severity_change=sev_change)

def batch_assess(
    vuln_functions: List[Dict[str, Any]],
    old_binary_blocks: Dict[str, List[List[str]]],
    new_binary_blocks: Dict[str, List[List[str]]],
) -> Dict[str, FixAssessment]:
    results: Dict[str, FixAssessment] = {}
    for vf in vuln_functions:
        fname = vf['function_name']
        old_bb = old_binary_blocks.get(fname, [])
        new_bb = new_binary_blocks.get(fname, [])
        if not old_bb:
            results[fname] = FixAssessment(
                function_name=fname, total_blocks_old=0,
                total_blocks_new=len(new_bb), block_survival_rate=0.0,
                path_reachability_index=0.0, fix_completeness_score=10.0,
                severity_change='reduced')
            continue
        results[fname] = assess_patch(
            function_name=fname, old_blocks=old_bb, new_blocks=new_bb,
            vuln_block_indices=vf.get('vuln_block_indices'))
    return results

def fix_summary(assessments: Dict[str, FixAssessment]) -> Dict[str, Any]:
    if not assessments:
        return {'total': 0, 'confirmed_fixed': 0, 'partially_fixed': 0,
                'likely_unfixed': 0, 'vulnerability_migrated': 0, 'mean_fcs': 0.0}
    verdicts = defaultdict(int)
    scores = []
    for a in assessments.values():
        verdicts[a.risk_verdict()] += 1
        scores.append(a.fix_completeness_score)
    return {
        'total': len(assessments),
        'confirmed_fixed': verdicts.get('confirmed_fixed', 0),
        'partially_fixed': verdicts.get('partially_fixed', 0),
        'likely_unfixed': verdicts.get('likely_unfixed', 0),
        'vulnerability_migrated': verdicts.get('vulnerability_migrated', 0),
        'mean_fcs': round(sum(scores) / len(scores), 1),
        'worst_function': min(assessments.items(),
                              key=lambda x: x[1].fix_completeness_score)[0],
    }
