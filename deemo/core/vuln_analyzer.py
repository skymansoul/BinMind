"""
Unified vulnerability analyzer: dispatches by vulnerability type to specialized modules.

Integrates rule_engine, stack_overflow_analyzer, format_string_detector, and
heap_corruption rules behind a single entry point with a consistent API.

Each vulnerability-type method returns standardized finding entries usable
directly in the pipeline for save_finding and report generation.

References:
  - "The Art of Software Security Assessment" (Dowd et al., 2006)
  - CWE Top 25 Most Dangerous Software Weaknesses (2024)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

_VULN_ANALYZERS: Dict[str, Any] = {}


def _register(vuln_type: str):
	def decorator(fn):
		_VULN_ANALYZERS[vuln_type] = fn
		return fn
	return decorator


def _normalize_if_compact(code: str) -> str:
	"""Normalize compact single-line C source into one-statement-per-line format."""
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
	"""Run rules against a function code filtered by category keywords.

	
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
		# Try symbolic execution analysis
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

		# Supplement with format_string_detector analysis
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
	"""Heap lifecycle FSM static UAF detection."""
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
	"""Indirect format string detection via def-use back-tracing."""
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
	"""Obfuscated code fallback via assembly-level pattern detection."""
	findings = []
	try:
		from core.obfuscated_code_heuristic import detect_from_assembly
		# Get assembly lines from kwargs (if provided by caller)
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


def _run_value_flow_analysis(decompiled, findings):
	"""Run value flow + heap analysis as additional detection layer.
	Appends new UAF/double_free/heap_overflow findings without modifying existing ones.
	"""
	try:
		from core.value_flow import ValueFlowAnalyzer
		from core.heap_analyzer import HeapAnalyzer
		from core.ir_normalizer import normalize_ir
		vfa = ValueFlowAnalyzer(); ha = HeapAnalyzer()
		for func_name, code in (decompiled or {}).items():
			ir = normalize_ir(code, source='auto')
			if len(ir) < 3:
				continue
			vfa.analyze(ir, func_name)
			heap_findings = ha.analyze_all(vfa, ir, func_name)
			for hf in heap_findings:
				findings.append({
					'rule_id': f'VF-{hf.vuln_type.upper()}',
					'type': hf.vuln_type,
					'function': func_name,
					'severity': 'High' if hf.confidence > 0.7 else 'Medium',
					'description': hf.description,
					'cwe': hf.cwe,
					'confidence': hf.confidence,
					'line_alloc': hf.alloc_line,
					'line_free': hf.free_line,
					'line_use': hf.use_line,
				})
	except ImportError:
		pass  # Silent fallback when value flow analysis module is unavailable


def _apply_false_positive_filter(findings, decompiled):
	"""Apply false positive reduction filters to detection results."""
	try:
		from core.false_positive_filter import FalsePositiveFilter
		from core.const_propagation import SparseConstantPropagation
		from core.taint_filter import TaintFilter
		from core.interval_analysis import IntervalAnalyzer
		from core.ir_normalizer import normalize_ir
		fpf = FalsePositiveFilter()
		for func_name, code in (decompiled or {}).items():
			ir = normalize_ir(code, source='auto')
			if len(ir) < 3:
				continue
			scp = SparseConstantPropagation().analyze(ir, func_name)
			tf = TaintFilter().analyze(ir)
			ia = IntervalAnalyzer().analyze(ir, func_name)
			fpf.setup(ir, scp, tf, ia)
			# Only filter findings related to this function
			func_findings = [f for f in findings
						if f.get('function') == func_name]
			if not func_findings:
				continue
			filtered = fpf.filter_findings(func_findings)
			for fr in filtered:
				if fr.filtered_out:
					fr.finding['filtered'] = True
					fr.finding['filter_reason'] = fr.filter_reason
					fr.finding['filter_layer'] = fr.filter_layer
	except ImportError:
		pass


def analyze_all(
	binary_path: str = '/dev/null',
	decompiled: Optional[Dict[str, str]] = None,
	vuln_types: Optional[List[str]] = None,
	**kwargs,
) -> List[Dict[str, Any]]:
	"""Run all registered vulnerability analyzers, return aggregated findings list."""
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
	# Append value flow analysis layer
	if decompiled:
		_run_value_flow_analysis(decompiled, all_findings)
		_apply_false_positive_filter(all_findings, decompiled)

	# Symbolic execution reachability filter
	if binary_path and all_findings:
		try:
			from core.lightweight_sym_verify import filter_by_reachability
			before = len(all_findings)
			all_findings = filter_by_reachability(all_findings, binary_path)
			_log.debug('sym_verify: %d→%d findings', before, len(all_findings))
		except ImportError:
			pass

	# Deduplicate
	seen = set()
	unique = []
	for f in all_findings:
		key = (f.get('rule_id', ''), f.get('function', ''),
			f.get('description', '')[:60])
		if key not in seen:
			seen.add(key)
			unique.append(f)

	return unique


def _check_uaf_heuristic(func_name: str, code: str,
						findings: List[Dict[str, Any]],
						binary_path: str = '') -> None:
	"""UAF heuristic detection with CFG reachable path filtering.

	Checks reachability from free to deref via basic block analysis when angr is available.
	Falls back to regex when CFG is unavailable (prefer false positives over false negatives).
	"""
	freed = set(re.findall(r'free\s*\(\s*(?:&)?(\w+)\s*\)', code))
	for var in freed:
		if not re.search(rf'free\s*\(\s*(?:&)?{var}\s*\).*?{var}\s*->',
						code, re.DOTALL):
			continue

		cfg_verified = False
		if binary_path and os.path.isfile(binary_path):
			try:
				from core.cfg_path_filter import verify_uaf_path
				is_tp, reason = verify_uaf_path(
					binary_path, func_name, var, var,
				)
				cfg_verified = is_tp
				if not is_tp:
					_log.info("UAF CFG filter: %s", reason)
					continue  # CFG confirmed as false positive -> skip
			except Exception:
				pass

		findings.append({
			'rule_id': 'HC-HEUR-UAF',
			'type': 'heap-corruption',
			'function': func_name,
			'severity': 'Critical',
			'description': f'use-after-free: {var} dereferenced after free()',
			'cwe': 'CWE-416',
			'cfg_verified': cfg_verified,
		})


def _check_double_free(func_name: str, code: str,
					findings: List[Dict[str, Any]]) -> None:
	free_calls = re.findall(r'free\s*\(\s*(?:&)?(\w+)\s*\)', code)
	seen = set()
	for var in free_calls:
		if var in seen:
			findings.append({
				'rule_id': 'HC-HEUR-DF',
				'type': 'heap-corruption',
				'function': func_name,
				'severity': 'Critical',
				'description': f'double-free: {var} freed more than once',
				'cwe': 'CWE-415',
			})
		seen.add(var)


def _check_uaf_args(func_name: str, code: str,
					findings: List[Dict[str, Any]]) -> None:
	"""UAF argument matching - supplements heap_lifecycle_fsm detection blind spots..

	Detects patterns where p appears in function call args/return value/array index after free(p).
	These patterns are missed by FSM assignment RHS detection - supplement here.
	"""
	try:
		from core.uaf_argument_matcher import detect_uaf_args
		extra = detect_uaf_args(code, func_name)
		for f in extra:
			findings.append({
				'rule_id': f.get('rule_id', 'UAF-ARG'),
				'type': 'heap-corruption',
				'function': func_name,
				'severity': 'Critical',
				'description': f.get('description', ''),
				'cwe': 'CWE-416',
				'confidence': f.get('confidence', 0.72),
			})
	except ImportError:
		pass
