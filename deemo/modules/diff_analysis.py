# 二进制差异分析 - 对比两个版本的函数特征，识别新增/删除/修改函数
# 及漏洞回归（新增危险调用等）。

import os
import re
from typing import Dict, List, Set, Any, Optional


class FunctionFeatures:
    """单个函数的特征集合 - 用于跨版本相似度比较。"""

    DANGEROUS_CALLS = {
        'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf',
        'memcpy', 'strncpy', 'strncat', 'snprintf', 'system', 'popen',
        'malloc', 'free', 'realloc', 'calloc', 'strlen', 'memset',
    }

    def __init__(self, name: str, address: int = 0):
        self.name = name
        self.address = address
        self.pseudocode = ""
        self.basic_block_count = 0
        self.instruction_count = 0
        self.calls: List[str] = []
        self.dangerous_calls: Set[str] = set()
        self.cfg_hash = ""

    def _count_basic_blocks(self, pseudocode: str) -> int:
        """统计伪代码中的基本块数 - 以条件/循环/返回语句为分割点。"""
        if not pseudocode:
            return 0
        count = 0
        for line in pseudocode.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            if re.match(r'^\s*(if|while|for|do|switch|case|return|else)\b', stripped):
                count += 1
            elif re.match(r'^\s*[};]\s*$', stripped):
                count += 1
        return max(count, 1)

    def _extract_function_calls(self, pseudocode: str) -> List[str]:
        """提取伪代码中的函数调用名。"""
        if not pseudocode:
            return []
        calls = []
        for m in re.finditer(r'\b(\w+)\s*\(', pseudocode):
            name = m.group(1)
            if name not in ('if', 'while', 'for', 'return', 'switch', 'do'):
                calls.append(name)
        return calls

    def _identify_dangerous_calls(self, calls: List[str]) -> Set[str]:
        """筛选危险函数调用。"""
        return {c for c in calls if c in self.DANGEROUS_CALLS}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': self.address,
            'basic_block_count': self.basic_block_count,
            'instruction_count': self.instruction_count,
            'calls': self.calls,
            'dangerous_calls': sorted(self.dangerous_calls),
            'cfg_hash': self.cfg_hash,
            'has_pseudocode': bool(self.pseudocode),
        }


class BinaryDiffAnalyzer:
    """两个二进制版本的函数级差异分析器。"""

    def __init__(self, baseline_path: str, target_path: str):
        self.baseline_path = baseline_path
        self.target_path = target_path
        if not os.path.exists(baseline_path):
            raise FileNotFoundError(f"baseline binary not found: {baseline_path}")
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"target binary not found: {target_path}")
        self.baseline_functions: Dict[str, FunctionFeatures] = {}
        self.target_functions: Dict[str, FunctionFeatures] = {}
        self.added_functions: List[str] = []
        self.removed_functions: List[str] = []
        self.modified_functions: List[Dict[str, Any]] = []
        self.vuln_db: Any = None

    def _calculate_cosine_similarity(self, vec1: List[float],
                                     vec2: List[float]) -> float:
        """余弦相似度 - 维度对齐的浮点向量。"""
        if not vec1 or not vec2 or len(vec1) != len(vec2):
            return 0.0
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)

    def _calculate_jaccard_similarity(self, set1: Set, set2: Set) -> float:
        """Jaccard 相似度 - 集合交集/并集。"""
        if not set1 and not set2:
            return 1.0
        inter = set1 & set2
        union = set1 | set2
        if not union:
            return 0.0
        return len(inter) / len(union)

    def _compare_pseudocode(self, pseudo1: str, pseudo2: str) -> float:
        """伪代码相似度 - 基于危险调用集合的 Jaccard。"""
        calls1 = set(re.findall(r'\b(\w+)\s*\(', pseudo1 or ''))
        calls2 = set(re.findall(r'\b(\w+)\s*\(', pseudo2 or ''))
        return self._calculate_jaccard_similarity(calls1, calls2)

    def _feature_to_dict(self, ff: FunctionFeatures) -> Dict[str, Any]:
        """将函数特征序列化为可比较字典。"""
        return {
            'name': ff.name,
            'basic_block_count': ff.basic_block_count,
            'instruction_count': ff.instruction_count,
            'call_count': len(ff.calls),
            'dangerous_calls': sorted(ff.dangerous_calls),
            'cfg_hash': ff.cfg_hash,
            'has_pseudocode': bool(ff.pseudocode),
        }

    def _generate_diff_summary(self) -> str:
        """生成差异摘要文本。"""
        lines = [
            f"差异分析: {os.path.basename(self.baseline_path)} → "
            f"{os.path.basename(self.target_path)}",
            f"新增函数: {len(self.added_functions)}",
            f"删除函数: {len(self.removed_functions)}",
            f"修改函数: {len(self.modified_functions)}",
        ]
        if self.added_functions:
            lines.append("  新增: " + ", ".join(self.added_functions))
        if self.removed_functions:
            lines.append("  删除: " + ", ".join(self.removed_functions))
        if self.modified_functions:
            lines.append("  修改: " + ", ".join(
                m.get('function_name', '') for m in self.modified_functions))
        return "\n".join(lines)

    def check_vulnerability_regression(self) -> List[Dict[str, Any]]:
        """检测漏洞回归 - 修改函数中新增的危险调用。"""
        regressions = []
        for mod in self.modified_functions:
            name = mod.get('function_name', '')
            base_func = self.baseline_functions.get(name)
            target_func = self.target_functions.get(name)
            if base_func is None or target_func is None:
                continue
            added_calls = target_func.dangerous_calls - base_func.dangerous_calls
            if added_calls:
                regressions.append({
                    'type': 'new_dangerous_call',
                    'function': name,
                    'added_calls': sorted(added_calls),
                })
        return regressions
