"""
漏洞分析器辅助函数 — heap-corruption启发式检测 + 值流分析 + 误报过滤.

"""


import logging
import os
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)


def _check_uaf_heuristic(func_name: str, code: str,
						findings: List[Dict[str, Any]],
						binary_path: str = '') -> None:
	"""UAF 启发式检测 — 带 CFG 可达路径过滤。

	angr 可用时经基本块分析检查 free 到解引用的可达性; CFG 不可用时回退正则匹配
	(宁可误报也不漏报)。
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
					continue
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
	"""UAF 参数匹配 — 补充 heap_lifecycle_fsm 的检测盲区。

	检测 free(p) 后 p 出现在函数调用参数/返回值/数组下标中的模式。
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


def _run_value_flow_analysis(decompiled, findings):
	"""运行值流+堆分析作为附加检测层。
	追加新的 UAF/double_free/heap_overflow 发现, 不修改既有发现。
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
		pass


def _apply_false_positive_filter(findings, decompiled):
	"""对检测结果应用误报削减过滤。"""
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
