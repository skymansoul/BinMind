"""fmtov — 格式源验证 (FSV) 格式化字符串检测包。

复用 heapov 的 C 解析器; 轻量污点传播 + 字面量来源证明,
与 CACBV/LCV 同构(证明式安全过滤 + 污点确认报告)。
"""

from fmtov.detector import analyze_source
from fmtov.baseline_detector import analyze_baseline
from fmtov import verdict as V

__all__ = ['analyze_source', 'analyze_baseline', 'V']
