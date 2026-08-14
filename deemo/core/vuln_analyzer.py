"""
统一漏洞分析器入口 — 按漏洞类型分发到专用模块并聚合结果。
模块拆分: vuln_analyzer_base 注册表/装饰器; vuln_analyzer_heuristics 堆启发式;
vuln_analyzer_analyzers 8 个 @_register 分析器; vuln_analyzer_layers 值流分析+误报过滤;
本文件为对外 API 入口, 保持 analyze_all 等符号不变。
"""


import logging
from typing import Any, Dict, List, Optional

# 顺序敏感：先 import base 提供注册表容器，再 import analyzers 触发 @register
# 副作用填充 _VULN_ANALYZERS；layers 仅提供函数无需副作用
from core.vuln_analyzer_base import (
	_VULN_ANALYZERS,
	_register,
	_normalize_if_compact,
	_apply_rules_for_categories,
)
from core.vuln_analyzer_heuristics import (
	_check_uaf_heuristic,
	_check_double_free,
	_check_uaf_args,
)
from core.vuln_analyzer_analyzers import (  # noqa: F401  import 即注册副作用
	analyze_stack_overflow_vulns,
	analyze_format_string_vulns,
	analyze_heap_corruption_vulns,
	analyze_integer_overflow_vulns,
	analyze_heap_lifecycle_vulns,
	analyze_format_string_indirect_vulns,
	analyze_obfuscated_fallback_vulns,
	analyze_command_injection_vulns,
)
from core.vuln_analyzer_layers import (
	_run_value_flow_analysis,
	_apply_false_positive_filter,
)

_log = logging.getLogger(__name__)


def analyze_all(
	binary_path: str = '/dev/null',
	decompiled: Optional[Dict[str, str]] = None,
	vuln_types: Optional[List[str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	"""运行所有已注册分析器并聚合发现。"""
	all_findings = []
	target_types = vuln_types or list(_VULN_ANALYZERS.keys())

	for vtype in target_types:
		if vtype in _VULN_ANALYZERS:
			try:
				findings = _VULN_ANALYZERS[vtype](
					binary_path, decompiled=decompiled, **kwargs,
				)
				all_findings.extend(findings)
			except Exception as e:
				_log.debug('analyzer %s failed: %s', vtype, e)
	# 叠加值流分析增强层
	if decompiled:
		_run_value_flow_analysis(decompiled, all_findings)
		_apply_false_positive_filter(all_findings, decompiled)

	# 符号执行可达性过滤
	if binary_path and all_findings:
		try:
			from core.lightweight_sym_verify import filter_by_reachability
			before = len(all_findings)
			all_findings = filter_by_reachability(all_findings, binary_path)
			_log.debug('sym_verify: %d→%d findings', before, len(all_findings))
		except ImportError:
			pass

	# 去重：按 rule_id + function + 描述前缀
	seen = set()
	unique = []
	for f in all_findings:
		key = (f.get('rule_id', ''), f.get('function', ''),
			f.get('description', '')[:60])
		if key not in seen:
			seen.add(key)
			unique.append(f)

	return unique
