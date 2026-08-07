"""
vuln_analyzer 分析器集合：按漏洞类型分发的 8 个注册分析器。

拆分自 vuln_analyzer.py。每个分析器经 @_register 注册到 _VULN_ANALYZERS，
入口文件 import 本模块即触发副作用完成注册。为兼容测试，函数名与签名保持不变。
"""


from typing import Any, Dict, List, Optional

from core.vuln_analyzer_base import (
	_register,
	_apply_rules_for_categories,
	_normalize_if_compact,
)
from core.vuln_analyzer_heuristics import (
	_check_uaf_heuristic,
	_check_double_free,
	_check_uaf_args,
)


@_register('stack-overflow')
def analyze_stack_overflow_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	findings = []
	for func_name, code in (decompiled or {}).items():
		try:
			findings.extend(
				_apply_rules_for_categories(code, func_name, ['stack_overflow']))
		except Exception:
			pass
		# 叠加符号执行栈溢出判定
		try:
			from core.stack_overflow_analyzer import analyze_stack_overflow
			result = analyze_stack_overflow(binary_path, func_name)
			if result.get('overflowable'):
				findings.append({
					'rule_id': 'SO-AUTO',
					'type': 'stack-overflow',
					'function': func_name,
					'severity': 'Critical',
					'description': (
						f'stack overflow detected: padding={result.get("padding")}'
						f', canary={result.get("has_canary")}'
					),
					'cwe': 'CWE-120',
				})
		except Exception:
			pass
	return findings


@_register('format-string')
def analyze_format_string_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	findings = []
	for func_name, code in (decompiled or {}).items():
		fmt_findings = []
		try:
			fmt_findings = _apply_rules_for_categories(
				code, func_name, ['format_string'])
		except Exception:
			pass
		findings.extend(fmt_findings)

		# 叠加 format_string_detector 独立分析
		try:
			from core.format_string_detector import detect_format_string_vulns
			fmt_results = detect_format_string_vulns(binary_path)
			for f in fmt_results:
				findings.append({
					'rule_id': 'FS-AUTO',
					'type': 'format-string',
					'function': f.get('function', func_name),
					'severity': 'High',
					'description': (
						f'format string: {f.get("format_func", "?")}'
						f' offset={f.get("offset", "?")}'
					),
					'cwe': 'CWE-134',
				})
		except Exception:
			pass
	return findings


@_register('heap-corruption')
def analyze_heap_corruption_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	findings = []
	for func_name, code in (decompiled or {}).items():
		code = _normalize_if_compact(code)
		_check_uaf_heuristic(func_name, code, findings, binary_path)
		_check_double_free(func_name, code, findings)
		_check_uaf_args(func_name, code, findings)
		try:
			findings.extend(
				_apply_rules_for_categories(code, func_name, ['heap_corruption']))
		except Exception:
			pass
	return findings


@_register('integer-overflow')
def analyze_integer_overflow_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	findings = []
	for func_name, code in (decompiled or {}).items():
		findings.extend(
			_apply_rules_for_categories(code, func_name, ['integer_overflow']))
	return findings


@_register('heap-lifecycle')
def analyze_heap_lifecycle_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	"""FSM 形态的堆生命周期静态 UAF 检测。"""
	findings = []
	try:
		from core.heap_lifecycle_fsm import detect_uaf_static
		for func_name, code in (decompiled or {}).items():
			uaf_findings = detect_uaf_static(code, func_name)
			findings.extend(uaf_findings)
	except ImportError:
		pass
	return findings


@_register('format-string-indirect')
def analyze_format_string_indirect_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	"""def-use 回溯式间接格式串检测。"""
	findings = []
	try:
		from core.format_string_indirect import detect_indirect_fmt
		for func_name, code in (decompiled or {}).items():
			indirect = detect_indirect_fmt(code, func_name)
			for f in indirect:
				findings.append({
					'rule_id': 'FS-INDIRECT',
					'type': 'format-string',
					'function': f.get('function', func_name),
					'severity': 'Medium',
					'description': f.get('description', ''),
					'cwe': 'CWE-134',
					'confidence': f.get('confidence', 0.55),
				})
	except ImportError:
		pass
	return findings


@_register('obfuscated-fallback')
def analyze_obfuscated_fallback_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	"""混淆代码兜底：汇编级模式检测。"""
	findings = []
	try:
		from core.obfuscated_code_heuristic import detect_from_assembly
		asm_lines = kwargs.get('asm_lines', [])
		if asm_lines:
			findings = detect_from_assembly(asm_lines)
	except ImportError:
		pass
	return findings


@_register('command-injection')
def analyze_command_injection_vulns(
	binary_path: str,
	decompiled: Optional[Dict[str, str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	findings = []
	for func_name, code in (decompiled or {}).items():
		findings.extend(
			_apply_rules_for_categories(code, func_name, ['command_injection']))
	return findings
