"""

包含:
  - extract_alloc_write_pairs(): Stage 1 IR→alloc sites 提取
  - apply_interproc_summaries(): Stage 2 跨函数摘要应用
  - compute_final_verdict(): Stage 8 综合判定

设计决策: 提取为纯函数 + PipelineFinding dataclass,
  消除对 UnifiedHeapPipeline 实例的依赖, 便于单独测试。
"""

from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

from analysis.strided_interval import StridedInterval


# Stage 1: 从单函数代码中提取 alloc+write pairs

_ALLOC_RE = re.compile(
    r'(?:(\w+)\s*=\s*)?(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
    re.IGNORECASE,
)
_WRITE_RE = re.compile(
    r'(?:memcpy|memmove|strcpy|strncpy|sprintf)\s*\(([^)]+)\)',
    re.IGNORECASE,
)


def extract_alloc_write_pairs(
    func_name: str, code: str,
) -> List[Dict[str, Any]]:
    """从单个函数的伪代码中提取所有 alloc+write pair。

    realloc 追踪: 当 realloc(var, new_size) 出现且已有同一 var 的
    alloc site 时, 更新该 site 的 alloc_size, 避免旧 size 误判溢出。
    返回 dict 列表, 键: func_name/line/alloc_func/alloc_size/write_size/size_var。
    """
    results = []
    lines = code.splitlines()
    var_to_idx: Dict[str, int] = {}

    for i, line in enumerate(lines):
        alloc_m = _ALLOC_RE.search(line)
        if not alloc_m:
            continue

        size_var = alloc_m.group(1) or ""
        alloc_func = alloc_m.group(2).lower()
        raw_args = alloc_m.group(3).strip()

        if alloc_func == "realloc":
            parts = [p.strip() for p in raw_args.split(",")]
            realloc_var = parts[0] if parts else ""
            new_size = 0
            if len(parts) >= 2:
                try:
                    new_size = int(parts[1], 0)
                except (ValueError, TypeError):
                    pass
            if realloc_var in var_to_idx:
                idx = var_to_idx[realloc_var]
                if new_size > 0:
                    results[idx]['alloc_size'] = new_size
                results[idx]['alloc_func'] = 'realloc'
                continue
            size_var = realloc_var
            alloc_size = new_size
        else:
            alloc_size = 0
            size_expr = raw_args.split(",")[0].strip()
            try:
                alloc_size = int(size_expr, 0)
            except (ValueError, TypeError):
                pass

        # 找此 alloc 之后最近的写入
        write_size = 0
        for j in range(i + 1, min(i + 30, len(lines))):
            wm = _WRITE_RE.search(lines[j])
            if wm:
                args = wm.group(1).split(",")
                if len(args) >= 3:
                    try:
                        write_size = int(args[2].strip(), 0)
                    except (ValueError, TypeError):
                        write_size = int(alloc_size * 1.5) if alloc_size else 64
                elif len(args) >= 2:
                    write_size = alloc_size
                break

        if size_var:
            var_to_idx[size_var] = len(results)
        results.append({
            'func_name': func_name, 'line': i,
            'alloc_func': alloc_func, 'alloc_size': alloc_size,
            'write_size': write_size, 'size_var': size_var,
        })

    return results


# Stage 2: 跨函数摘要应用

def apply_interproc_summaries(
    findings: List[Any],
    summaries: Dict,
) -> None:
    """将跨函数 size constraint 摘要应用到 findings 列表。

    就地修改 findings (按需更新 alloc_size)。
    """
    for pf in findings:
        summary = summaries.get(pf.func_name)
        if summary is None:
            continue
        for site in summary.alloc_sites:
            if site.line == pf.line:
                if (not site.interval.is_unbounded()
                        and pf.alloc_size <= 0):
                    pf.alloc_size = site.interval.hi


# Stage 8: 综合判定

def compute_final_verdict(pf: Any) -> Tuple[float, float, bool, str]:
    """综合所有阶段计算最终判定。

    返回 (fp_likelihood, confidence, is_true_positive, reasoning)。
    """
    fp_score = 0.0

    if pf.allocator_verdict == "FILTER":
        fp_score += 0.40
    elif pf.allocator_verdict == "KEEP":
        fp_score -= 0.20

    if pf.is_guarded:
        fp_score += 0.25

    fp_score += pf.path_safe_ratio * 0.20

    if pf.exploitability < 0.25:
        fp_score += 0.15

    fp_likelihood = min(1.0, max(0.0, fp_score))
    is_tp = fp_likelihood < 0.40
    confidence = 1.0 - fp_likelihood

    # 构建推理描述
    parts = []
    if getattr(pf, 'allocator_verdict', '') == "FILTER":
        eff = getattr(pf, 'alloc_effective', '?')
        parts.append(f"allocator: write({pf.write_size})≤effective({eff})")
    if getattr(pf, 'is_guarded', False):
        guard = getattr(pf, 'guard_desc', '')[:60]
        parts.append(f"guarded: {guard}")
    if getattr(pf, 'path_safe_ratio', 0.0) > 0.5:
        parts.append(f"path_safe={pf.path_safe_ratio:.1%}")
    parts.append(f"exploit={getattr(pf, 'exploitability', 0.0):.2f}")
    reasoning = "; ".join(parts) if parts else "insufficient data"

    return fp_likelihood, confidence, is_tp, reasoning


__all__ = [
    'extract_alloc_write_pairs', 'apply_interproc_summaries',
    'compute_final_verdict',
]
