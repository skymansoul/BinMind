"""
vuln_analyzer 堆损坏启发式检测：UAF 启发式、double-free、UAF 参数匹配。

三者均为基于正则 + 可选 CFG/外部模块的文本级检测
保留在独立模块以便 heap-corruption analyzer 复用而不污染注册表逻辑。
"""


import logging
import os
import re
from typing import Any, Dict, List

_log = logging.getLogger(__name__)


def _check_uaf_heuristic(func_name: str, code: str,
						findings: List[Dict[str, Any]],
						binary_path: str = '') -> None:
	"""UAF 启发式：free 后 -> 解引用模式匹配，叠加 CFG 可达性过滤。

	angr 可用时以 CFG 判定 free→deref 可达性，不可达则按假阳跳过；
	CFG 不可用时退回正则，优先召回而非精度。
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
					continue  # CFG 确认为误报 → 跳过
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
	"""同一变量多次 free 即判 double-free；顺序敏感，仅首次后再次出现才记录。"""
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
	"""UAF 参数匹配：补 FSM 的 RHS 赋值盲区。

	标 free(p) 后 p 出现在函数调用实参/返回值/数组下标的模式；
	FSM 赋值右侧检测无法覆盖，此处补齐。
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
