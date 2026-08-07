"""
vuln_analyzer 检测增强层：值流分析 + 误报过滤。

拆分自 vuln_analyzer.py。两层均延后 import 对应模块，故仅在调用时依赖；
任一依赖缺失静默跳过，保持核心检测管线可用。
"""


from typing import Any, Dict, List


def _run_value_flow_analysis(decompiled, findings):
	"""值流 + 堆分析叠加层：追加 UAF/double_free/heap_overflow 而不改动既有结果。"""
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
		pass  # 值流模块缺失时静默降级


def _apply_false_positive_filter(findings, decompiled):
	"""误报削减层：常量传播/taint/区间/FP 过滤叠加标注 filtered 标记。

	仅对 finding function 与当前函数一致者过滤，避免跨函数误标。
	"""
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
