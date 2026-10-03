"""uafov — 生命周期耦合验证 (LCV) UAF 检测包。

复用 heapov 的 C 解析器; 对象流 + 分支互斥 + double-free 判定,
与 容量感知耦合边界验证 同构(证明式安全过滤 + 未证否即报告)。
"""

from .detector import analyze_source
from .baseline_detector import analyze_baseline
from . import verdict as V

__all__ = ['analyze_source', 'analyze_baseline', 'V']
