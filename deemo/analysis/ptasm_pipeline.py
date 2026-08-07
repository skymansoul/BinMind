"""
PTASM 管线集成层 — 将 PTASM 引擎接入 UAF 检测管线.

本模块是 PTASM 与现有 TARPS 五阶段管线的桥接:
  - ptasm_analyze: 便捷分析入口
  - ptasm_verify_candidates: 批量形式化验证 (作为 TARPS Stage 3.5)
  - ptasm_detect_uaf: 独立检测模式
  - ptasm_pipeline_detect: 完整单次分析管线

保守性保证 (功能只增不减):
  - PTASM 仅 FILTER 可证明安全的候选项
  - PTASM 仅 CONFIRM 形式化确认的UAF
  - 不确定候选项 → UNCERTAIN, fall through 到 TARPS 继续处理
"""


from typing import Dict, List, Tuple

from analysis.ptasm_engine import PTASMEngine, PTASMStats, PTASMResult
from analysis.ptasm_types import PtrState

# 兼容常量 (对接 uaf_verifier.py 判定语义)

PTASM_PROTECTED = "PROTECTED"       # 可证明安全 → FP, 应由管线过滤
PTASM_CONFIRMED = "CONFIRMED"       # 形式化确认 UAF → 置信度提升
PTASM_UNCERTAIN = "UNCERTAIN"       # 无法判定 → fall through


def ptasm_analyze(source: str) -> Tuple[List[PTASMResult], PTASMStats]:
    """便捷入口: 对源码执行 PTASM 分析 (单次调用)."""
    engine = PTASMEngine()
    return engine.analyze(source)


def _extract_candidate_ptr(candidate: dict) -> str:
    """从候选字典提取指针变量名, 兼容多种命名约定.

    支持的键名: freed_variable / ptr_var / pointer_name / alloc_var / variable
    """
    return (candidate.get('freed_variable')
            or candidate.get('ptr_var')
            or candidate.get('pointer_name')
            or candidate.get('alloc_var')
            or candidate.get('variable', ''))


def ptasm_verify_candidates(
    candidates: List[dict],
    source: str = '',
    min_confidence: float = 0.0,
) -> Tuple[List[dict], List[dict]]:
    """PTASM 形式化验证 UAF 候选列表.

    作为 UAF 管线中的形式化验证层 (Stage 3.5):
      - PTASM 确认 UAF → 保留 (CONFIRMED, +0.20 置信度)
      - PTASM 证明安全 → 过滤 (PROTECTED, 不加入 filtered)
      - PTASM 无法判定 → 保留 (UNCERTAIN, fall through)

    Args:
        candidates: UAF 检测器输出的候选列表 (dict 形式)
        source: C 源码文本
        min_confidence: 最低置信度阈值, 低于此值的候选跳过验证

    Returns:
        (filtered_candidates, verification_results)
        与 uaf_verifier.verify_uaf_candidates 格式兼容
    """
    if not candidates or not source:
        return list(candidates), []

    engine = PTASMEngine()
    ptasm_results, stats = engine.analyze(source)

    # 判决索引: ptr_name → PTASMResult (含别名)
    ptasm_index: Dict[str, PTASMResult] = {}
    for r in ptasm_results:
        ptasm_index[r.ptr_name] = r
        for alias in r.aliases_involved:
            if alias not in ptasm_index:
                ptasm_index[alias] = r

    verification_results = []
    filtered = []

    for idx, c in enumerate(candidates):
        ptr_name = _extract_candidate_ptr(c)
        confidence = c.get('confidence', 0.5)

        if confidence < min_confidence:
            filtered.append(c)
            verification_results.append({
                'candidate_index': idx,
                'verdict': PTASM_UNCERTAIN,
                'stage': 'PTASM (skipped)',
                'reason': f'confidence {confidence:.2f} below threshold {min_confidence}',
                'confidence_delta': 0.0,
                'pointer_name': ptr_name,
            })
            continue

        ptr_result = ptasm_index.get(ptr_name)

        if ptr_result is None:
            filtered.append(c)
            verification_results.append({
                'candidate_index': idx,
                'verdict': PTASM_UNCERTAIN,
                'stage': 'PTASM (untracked)',
                'reason': f'pointer {ptr_name} not tracked by PTASM',
                'confidence_delta': 0.0,
                'pointer_name': ptr_name,
            })
        elif ptr_result.uaf_detected:
            c['confidence'] = min(0.98, confidence + 0.20)
            c['ptasm_verified'] = True
            c['ptasm_reason'] = ptr_result.reason
            filtered.append(c)
            verification_results.append({
                'candidate_index': idx,
                'verdict': PTASM_CONFIRMED,
                'stage': 'PTASM (confirmed)',
                'reason': ptr_result.reason,
                'confidence_delta': +0.20,
                'pointer_name': ptr_name,
            })
        elif ptr_result.safe:
            verification_results.append({
                'candidate_index': idx,
                'verdict': PTASM_PROTECTED,
                'stage': 'PTASM (safe)',
                'reason': ptr_result.reason,
                'confidence_delta': -0.50,
                'pointer_name': ptr_name,
            })
        else:
            filtered.append(c)
            verification_results.append({
                'candidate_index': idx,
                'verdict': PTASM_UNCERTAIN,
                'stage': 'PTASM (uncertain)',
                'reason': ptr_result.reason,
                'confidence_delta': 0.0,
                'pointer_name': ptr_name,
            })

    return filtered, verification_results


def ptasm_detect_uaf(source: str) -> Dict:
    """PTASM 独立检测模式 — 从源码检测 UAF.

    检测能力 (功能只增不减):
      - 直接 free→use: free(p) → *p / p->field / p[idx]
      - 别名传播: q=p, free(p) → use(q) UAF
      - 双 free: free(p); free(p) → double-free UAF
      - 回调参数: func(data) 中 data 作为指针使用
      - 结构体字段: free(p) → p->field
      - Free-wrapper: free_request(r) 等价于 free(r)
      - 条件路径: if(cond) free(p); else use(p) → 各路径独立分析

    Returns:
        {detected, findings, count, free_count, stats}
        格式兼容 uaf_detector 返回
    """
    engine = PTASMEngine()
    ptasm_results, stats = engine.analyze(source)

    findings = []
    for r in ptasm_results:
        if r.uaf_detected:
            findings.append({
                'ptr_var': r.ptr_name,
                'free_line': r.free_line,
                'use_line': r.use_line,
                'use_line_text': '',
                'used_var': r.ptr_name,
                'type': 'use-after-free',
                'verdict': 'PTASM_CONFIRMED',
                'guarded': r.guarded,
                'aliases': r.aliases_involved,
                'reason': r.reason,
                'confidence': 0.90,
            })
        elif r.safe:
            findings.append({
                'ptr_var': r.ptr_name,
                'free_line': r.free_line,
                'use_line': r.use_line,
                'type': 'safe',
                'verdict': 'PTASM_SAFE',
                'reason': r.reason,
                'confidence': 0.05,
            })

    return {
        'detected': any(f['type'] == 'use-after-free' for f in findings),
        'findings': findings,
        'count': len([f for f in findings if f['type'] == 'use-after-free']),
        'free_count': stats.frees_found,
        'stats': {
            'allocs_found': stats.allocs_found,
            'frees_found': stats.frees_found,
            'aliases_tracked': stats.aliases_tracked,
            'uaf_confirmed': stats.uaf_confirmed,
            'safe_filtered': stats.safe_filtered,
            'uncertain': stats.uncertain,
        },
    }


def ptasm_pipeline_detect(source: str) -> Dict:
    """完整 PTASM 管线: 主检测 + 形式化验证 (单次分析).

    PTASM 推荐入口 — 同时充当检测器和验证器:
      1. PTASM 主检测 → UAF candidates
      2. 同一分析结果: CONFIRMED / SAFE / UNCERTAIN

    管线架构:
      Source → [PTASM Engine] → confirmed UAFs  (confidence ≥ 0.90)
                               → safe pointers (filtered, 零新增漏报)
                               → uncertain     (fall through → TARPS)

    Returns:
        {detected, findings, confirmed, filtered, uncertain, stats}
    """
    result = ptasm_detect_uaf(source)
    uaf_list = [f for f in result['findings'] if f['type'] == 'use-after-free']
    safe_list = [f for f in result['findings'] if f['type'] == 'safe']

    return {
        'detected': result['detected'],
        'findings': result['findings'],
        'confirmed': len(uaf_list),
        'filtered': len(safe_list),
        'uncertain': result['stats'].get('uncertain', 0),
        'stats': result['stats'],
        'uaf_details': uaf_list,
        'safe_details': safe_list,
    }


__all__ = [
    'PTASM_PROTECTED', 'PTASM_CONFIRMED', 'PTASM_UNCERTAIN',
    'ptasm_analyze', 'ptasm_verify_candidates',
    'ptasm_detect_uaf', 'ptasm_pipeline_detect',
]
