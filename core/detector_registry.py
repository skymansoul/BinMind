# 检测器注册表 — 集中管理所有漏洞分析器的注册/发现/调用
#
# 解决每次加新分析器都要改 vuln_analyzer.py 的问题。
# 新分析器在此注册后, vuln_analyzer.analyze_all() 自动发现。

from typing import Any, Callable, Dict, List, Optional

_AnalyzerFn = Callable[..., List[Dict[str, Any]]]
_registry: Dict[str, _AnalyzerFn] = {}


def register(vuln_type: str):
    """装饰器: 将函数注册为指定漏洞类型的分析器"""
    def decorator(fn: _AnalyzerFn) -> _AnalyzerFn:
        _registry[vuln_type] = fn
        return fn
    return decorator


def get_all() -> Dict[str, _AnalyzerFn]:
    return dict(_registry)


def get(vuln_type: str) -> Optional[_AnalyzerFn]:
    return _registry.get(vuln_type)


def registered_types() -> List[str]:
    return list(_registry.keys())
