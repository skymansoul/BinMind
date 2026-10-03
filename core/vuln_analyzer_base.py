"""
vuln_analyzer 基础设施：分析器注册表、装饰器、共享辅助函数。

保留原注册机制以对外兼容；_VULN_ANALYZERS 仍由入口文件
在 import 阶段触发各 analyzer 模块的副作用填充，故此处仅提供容器与装饰器。
"""


import logging
from typing import Any, Dict, List

_log = logging.getLogger(__name__)

# 分析器注册表：vuln_type -> analyzer 函数。保留为模块级单例，
# 供 analyze_all 和测试断言引用同一份状态
_VULN_ANALYZERS: Dict[str, Any] = {}


def _register(vuln_type: str):
	"""装饰器：将函数注册为指定漏洞类型的分析器，并原样返回函数。"""
	def decorator(fn):
		_VULN_ANALYZERS[vuln_type] = fn
		return fn
	return decorator


def _normalize_if_compact(code: str) -> str:
	"""紧致单行 C 源码按语句拆行；判定依据是分号数远超换行数。

	失败静默回退原始文本，避免正常化缺失阻断下游检测。
	"""
	if code and ';' in code and code.count('\n') < code.count(';'):
		try:
			from core.source_normalizer import normalize_c_source
			return '\n'.join(normalize_c_source(code))
		except ImportError:
			pass
	return code


def _apply_rules_for_categories(
	code: str,
	func_name: str,
	categories: List[str],
) -> List[Dict[str, Any]]:
	"""按类别关键词过滤规则集后执行规则引擎。

	category 匹配基于规则 _source_file 子串，保持与原实现对齐；
	无命中规则时直接返回空列表，避免空集合触发误报。
	"""
	from core.rule_engine import load_rules, apply_rules

	all_rules = load_rules()
	filtered = [
		r for r in all_rules
		if any(cat in r.get('_source_file', '') for cat in categories)
	]
	if not filtered:
		return []
	return apply_rules(code, func_name, filtered)
