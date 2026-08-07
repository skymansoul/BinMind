"""DFC-PV Pipeline — 提供简洁的 double-free 检测入口.

DFC-PV (Double-free Causal-chain Pattern Verifier) 整合:
  AOI 分配对象身份追踪 + 多跳别名解析 + 路径敏感安全性证明 + 跨函数包装链解析
"""

from typing import List, Dict, Any
from analysis.dfc_pv_verifier import DfcPvVerifier
from analysis.dfc_pv_types import DfcVerdict, DfcResult


def detect_double_free_dfc(source: str) -> List[Dict[str, Any]]:
    """DFC-PV 检测入口, 返回结构化结果列表."""
    verifier = DfcPvVerifier()
    results = verifier.verify(source)
    return [_result_to_dict(r) for r in results]


def _result_to_dict(r: DfcResult) -> Dict[str, Any]:
    return {
        'type': 'double-free',
        'verdict': r.verdict.value,
        'first_free_line': r.first_free_line,
        'second_free_line': r.second_free_line,
        'variable': r.var_name,
        'alias_chain': r.alias_chain,
        'confidence': r.confidence,
        'pattern': r.pattern,
        'reason': r.reason,
        'cwe': 'CWE-415',
        'severity': 'Critical' if r.verdict == DfcVerdict.VULN else 'Info',
    }


__all__ = ['detect_double_free_dfc', 'DfcPvVerifier']
