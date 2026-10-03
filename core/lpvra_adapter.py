"""LPVRA适配器 - 将LPVRA抽象解释引擎接入unified_heap_pipeline的finding格式。
桥接LPVRA的HeapVerdict为管线可消费的finding dict，支持三方对比。
LPVRA采用前向区间传播+join+widening（适合循环/复杂CFG），与
path_sensitive_vrf（DFS+仿射区间，适合线性代码）互补。"""


import re
from typing import Any, Dict, List, Tuple


def lpvra_analyze(code: str, func_name: str = "") -> Tuple[List[dict], Dict[str, Any]]:
    """LPVRA 桥接入口: 对伪代码执行抽象解释, 输出 unified 格式。

    返回 (findings, stats), findings 为 dict 列表, stats 含各阶段统计。
    """
    stats = {
        "function": func_name,
        "allocator": "glibc-ptmalloc2",
        "alloc_sites": 0,
        "write_sites": 0,
        "confirmed": 0,
        "filtered": 0,
        "possible": 0,
        "lpvra_paths_explored": 0,
        "lpvra_paths_filtered": 0,
        "errors": [],
    }

    findings: List[dict] = []

    try:
        from analysis.lpvra_engine import LPVRAEngine
        from analysis.lpvra_types import Verdict

        engine = LPVRAEngine(max_paths=128, widening_threshold=1 << 20)
        result = engine.analyze(code)

        stats["alloc_sites"] = len(result.allocs)
        stats["write_sites"] = len(result.writes)
        stats["lpvra_paths_explored"] = result.total_paths_explored
        stats["lpvra_paths_filtered"] = result.paths_filtered

        for v in result.verdicts:
            alloc_size_val = (v.alloc_size_iv.const_val()
                              if v.alloc_size_iv.is_const() else -1)
            finding = {
                "type": "heap-overflow",
                "function": func_name,
                "alloc_var": v.alloc_var,
                "alloc_size": (alloc_size_val
                               if alloc_size_val > 0
                               else str(v.alloc_size_iv)),
                "write_var": v.write_var,
                "write_size": v.write_size,
                "write_offset": v.write_offset,
                "effective_boundary": v.effective_boundary,
                "cwe": "CWE-122",
                "lpvra_reason": v.reason,
                "safe_paths": v.safe_paths,
                "total_paths": v.total_paths,
            }

            if v.verdict == Verdict.SAFE:
                finding["verdict"] = "SAFE"
                finding["severity"] = "Info"
                finding["confidence"] = 0.05
                finding["tier"] = "lpvra_safe"
                finding["description"] = (
                    f"LPVRA SAFE: {v.alloc_var} (size={v.alloc_size_iv}) "
                    f"write at {v.write_var}[+{v.write_offset}] x {v.write_size}B "
                    f"effective_boundary={v.effective_boundary} [{v.reason}]")
                stats["filtered"] += 1
            elif v.verdict == Verdict.OVERFLOW:
                finding["verdict"] = "DEFINITE"
                finding["severity"] = "Critical"
                finding["confidence"] = 0.95
                finding["tier"] = "lpvra_overflow"
                finding["description"] = (
                    f"LPVRA OVERFLOW: {v.alloc_var} (size={v.alloc_size_iv}) "
                    f"write at {v.write_var}[+{v.write_offset}] x {v.write_size}B "
                    f"effective_boundary={v.effective_boundary} [{v.reason}]")
                stats["confirmed"] += 1
            else:
                finding["verdict"] = "POSSIBLE"
                finding["severity"] = "Medium"
                finding["confidence"] = 0.50
                finding["tier"] = "lpvra_uncertain"
                finding["description"] = (
                    f"LPVRA UNCERTAIN: {v.alloc_var} (size={v.alloc_size_iv}) "
                    f"write at {v.write_var}[+{v.write_offset}] x {v.write_size}B "
                    f"effective_boundary={v.effective_boundary} [{v.reason}]")
                stats["possible"] += 1

            findings.append(finding)

    except ImportError as e:
        stats["errors"].append(f"LPVRA import: {e}")
    except Exception as e:
        stats["errors"].append(f"LPVRA error: {e}")

    return findings, stats


def lpvra_detect(code: str) -> Dict[str, Any]:
    """便捷入口: 返回 {detected, tier, confidence, reason}.
    与 gapsbv_benchmark.run_enhanced_detect 接口兼容.
    """
    result = {'detected': False, 'tier': 'none', 'stats': {},
              'confidence': 0.0, 'reason': ''}

    try:
        findings, stats = lpvra_analyze(code)
        result['stats'] = stats

        actionable = [f for f in findings
                      if f.get('verdict', '') in ('POSSIBLE', 'DEFINITE')
                      and f.get('severity', '') in ('Critical', 'High', 'Medium')]

        if actionable:
            result['detected'] = True
            result['tier'] = actionable[0].get('tier', 'lpvra_uncertain')
            result['confidence'] = max(f.get('confidence', 0) for f in actionable)
            result['reason'] = actionable[0].get('description', '')
        else:
            result['detected'] = False
            result['tier'] = findings[0].get('tier', 'none') if findings else 'none'
            result['reason'] = (findings[0].get('lpvra_reason', '')
                                if findings else 'no findings')

    except ImportError as e:
        result['reason'] = f'LPVRA unavailable: {e}'
    except Exception as e:
        result['reason'] = f'LPVRA error: {e}'

    return result
