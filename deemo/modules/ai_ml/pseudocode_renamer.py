"""
Pseudocode Renamer - Semantic variable and function renaming for decompiled code.

Infers meaningful names from usage patterns and context to replace
compiler-generated names (sub_XXXX, v1, v2, etc.) in decompiled pseudocode.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class RenameOperation:
    """A single rename operation."""
    original: str
    new_name: str
    reason: str
    type: str = "variable"  # variable, function, parameter
    confidence: float = 1.0


class VariableRoleInferer:
    """Infers variable roles and semantic meanings from usage patterns."""

    # Common API patterns that reveal variable purpose
    # 每个 API 映射到 (角色名, 简短别名), 高置信度匹配
    API_PATTERNS: Dict[str, Tuple[str, str]] = {
        'malloc': ('allocated_size', 'buffer'),
        'calloc': ('allocated_count', 'buffer'),
        'realloc': ('resized_buffer', 'buffer'),
        'free': ('freed', 'pointer'),
        'strlen': ('string_length', 'length'),
        'strcpy': ('destination_buffer', 'dest'),
        'strncpy': ('destination_buffer', 'dest'),
        'strcat': ('destination_buffer', 'dest'),
        'memcpy': ('destination_buffer', 'dest'),
        'memmove': ('destination_buffer', 'dest'),
        'memset': ('target_buffer', 'buffer'),
        'memcmp': ('comparison_result', 'result'),
        'fopen': ('file_handle', 'handle'),
        'fclose': ('file_handle', 'handle'),
        'fread': ('bytes_read', 'count'),
        'fwrite': ('bytes_written', 'count'),
        'fprintf': ('bytes_written', 'count'),
        'sprintf': ('bytes_written', 'count'),
        'snprintf': ('bytes_written', 'count'),
        'sscanf': ('items_parsed', 'count'),
        'send': ('bytes_sent', 'count'),
        'recv': ('bytes_received', 'count'),
        'socket': ('socket_fd', 'fd'),
        'bind': ('bind_result', 'result'),
        'listen': ('listen_result', 'result'),
        'accept': ('client_fd', 'fd'),
        'connect': ('connect_result', 'result'),
        'CreateFile': ('file_handle', 'handle'),
        'ReadFile': ('bytes_read', 'count'),
        'WriteFile': ('bytes_written', 'count'),
        'CloseHandle': ('closed_handle', 'handle'),
        'VirtualAlloc': ('allocated_memory', 'buffer'),
        'VirtualFree': ('freed_memory', 'pointer'),
        'LoadLibrary': ('library_handle', 'handle'),
        'GetProcAddress': ('function_ptr', 'ptr'),
        'CreateThread': ('thread_handle', 'handle'),
        'RegOpenKey': ('registry_key', 'key'),
        'RegQueryValue': ('query_result', 'result'),
    }

    # Type-based naming hints
    TYPE_HINTS: Dict[str, str] = {
        'size_t': 'size',
        'ssize_t': 'size',
        'off_t': 'offset',
        'pid_t': 'pid',
        'uid_t': 'uid',
        'gid_t': 'gid',
        'time_t': 'time_val',
        'bool': 'flag',
        'HANDLE': 'handle',
        'HWND': 'window',
        'SOCKET': 'sock',
        'FILE': 'file_ptr',
        'DIR': 'dir_ptr',
    }

    # 置信度阈值: mode -> (min_confidence, description)
    CONFIDENCE_THRESHOLDS: Dict[str, float] = {
        'strict': 0.8,
        'balanced': 0.5,
        'aggressive': 0.2,
    }

    # 基于模式推理的置信度评分
    PATTERN_CONFIDENCE: Dict[str, float] = {
        'api_return': 0.95,        # var = KnownAPI(...) — 几乎可以确定用途
        'type_hint': 0.85,         # 类型信息提供了强信号
        'comparison_limit': 0.70,  # var < size / len — 可能是边界检查
        'increment': 0.65,         # var++ — 大概率是计数器
        'zero_init': 0.40,         # var = 0 — 弱信号, 可能是多种用途
        'conditional_guard': 0.55, # if (var) — 状态/哨兵变量
        'loop_var': 0.60,          # while (var) — 迭代变量
    }

    def __init__(self) -> None:
        self._name_counter: Dict[str, int] = {}
        self.last_inference_confidence: float = 0.0
        # 记录每次推理的详情，供调试用
        self._inference_trail: List[Dict[str, str]] = []

    def reset(self) -> None:
        """重置内部计数器，避免跨批次分析的计数值膨胀。"""
        self._name_counter.clear()
        self.last_inference_confidence = 0.0
        self._inference_trail.clear()

    def infer_name(
        self,
        var_name: str,
        context: str,
        api_calls: Optional[Dict[str, int]] = None,
        min_confidence: float = 0.0,
    ) -> Optional[Tuple[str, float]]:
        """Infer a meaningful name for a variable based on usage context."""
        # Check immediate surrounding lines for clues
        surrounding = self._get_relevant_lines(context, var_name)

        # Look for API patterns — 最高置信度路径
        for api, (role_name, _) in self.API_PATTERNS.items():
            if api in context and var_name in context:
                # Check if var is used as result of this API
                if re.search(rf'{re.escape(var_name)}\s*=\s*{re.escape(api)}\s*\(', context):
                    confidence = self.PATTERN_CONFIDENCE['api_return']
                    if confidence >= min_confidence:
                        self.last_inference_confidence = confidence
                        self._inference_trail.append({
                            'var': var_name, 'method': 'api_return',
                            'api': api, 'confidence': str(confidence),
                        })
                        return (self._unique_name(role_name), confidence)

        # 同时利用 api_calls 统计做辅助判断
        if api_calls:
            dominant_api = max(api_calls, key=api_calls.get) if api_calls else None
            if dominant_api and dominant_api in self.API_PATTERNS:
                role_name, _ = self.API_PATTERNS[dominant_api]
                # 只在使用频率极高时采用此路径
                if api_calls[dominant_api] >= 3:
                    confidence = 0.72
                    if confidence >= min_confidence:
                        self.last_inference_confidence = confidence
                        return (self._unique_name(role_name), confidence)

        # Check for common patterns
        return self._infer_from_patterns(var_name, surrounding, min_confidence)

    def _get_relevant_lines(self, context: str, var_name: str) -> List[str]:
        """Get lines that reference the variable."""
        lines = context.split('\n')
        relevant: List[str] = []
        for i, line in enumerate(lines):
            if var_name in line:
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                relevant.extend(lines[start:end])
                break
        return relevant

    def _infer_from_patterns(
        self, var_name: str, surrounding: List[str], min_confidence: float = 0.0,
    ) -> Optional[Tuple[str, float]]:
        """Infer variable purpose from usage patterns.

        返回值: (建议名称, 置信度) 或 None。置信度低于 min_confidence 时拒绝推荐。
        """
        combined = '\n'.join(surrounding)
        confidence = 0.0
        suggestion: Optional[str] = None

        # 模式1: 与常量比较 — 边界检查 / 索引
        if re.search(rf'{re.escape(var_name)}\s*[<>]=?\s*\d+', combined):
            if 'size' in combined.lower() or 'len' in combined.lower():
                suggestion = self._unique_name('max_size')
                confidence = self.PATTERN_CONFIDENCE['comparison_limit']
            else:
                suggestion = self._unique_name('index')
                confidence = self.PATTERN_CONFIDENCE['comparison_limit']

        # 模式2: 自增 — 计数器
        elif re.search(rf'{re.escape(var_name)}\s*\+\+', combined):
            suggestion = self._unique_name('counter')
            confidence = self.PATTERN_CONFIDENCE['increment']

        # 模式3: 零初始化 — 弱信号
        elif re.search(rf'{re.escape(var_name)}\s*=', combined):
            if re.search(rf'{re.escape(var_name)}\s*=\s*0', combined):
                suggestion = self._unique_name('result')
                confidence = self.PATTERN_CONFIDENCE['zero_init']

        # 模式4: if 条件中出现 — 状态/哨兵
        elif re.search(rf'if.*{re.escape(var_name)}', combined):
            suggestion = self._unique_name('status')
            confidence = self.PATTERN_CONFIDENCE['conditional_guard']

        # 模式5: while 循环条件 — 迭代器
        elif re.search(rf'while.*{re.escape(var_name)}', combined):
            suggestion = self._unique_name('iterator')
            confidence = self.PATTERN_CONFIDENCE['loop_var']

        if suggestion is None:
            return None

        if confidence < min_confidence:
            return None

        self.last_inference_confidence = confidence
        self._inference_trail.append({
            'var': var_name, 'method': 'pattern_match',
            'suggestion': suggestion, 'confidence': str(confidence),
        })
        return (suggestion, confidence)

    def _unique_name(self, base: str) -> str:
        """Generate a unique name from a base suggestion."""
        if base not in self._name_counter:
            self._name_counter[base] = 1
            return base
        self._name_counter[base] += 1
        return f"{base}_{self._name_counter[base]}"

    def infer_function_name(
        self,
        func_name: str,
        pseudocode: str,
    ) -> Optional[str]:
        """Infer a meaningful function name from its behavior."""
        code_lower = pseudocode.lower()

        if re.search(r'\b(memcpy|memmove|memset|strcpy|strncpy|strcat|sprintf|snprintf)\s*\(', code_lower):
            if re.search(r'\b(memcpy|memmove|strcpy|strncpy|strcat)\s*\(', code_lower):
                return "copy_data"

        if re.search(r'\b(malloc|calloc|realloc|new\b|VirtualAlloc)\s*\(', code_lower):
            return "allocate_memory"

        if re.search(r'\b(free|delete\b|VirtualFree)\s*\(', code_lower):
            return "free_memory"

        if re.search(r'\b(strcmp|strncmp|memcmp|wcscmp)\s*\(', code_lower):
            return "compare_strings"

        if re.search(r'\b(strlen|wcslen)\s*\(', code_lower):
            return "get_string_length"

        if re.search(r'\b(fopen|fread|fwrite|fclose|CreateFile|ReadFile|WriteFile|CloseHandle)\s*\(', code_lower):
            return "file_operation"

        if re.search(r'\b(socket|bind|listen|accept|connect|send|recv)\s*\(', code_lower):
            return "network_operation"

        if re.search(r'\b(Crypt|Encrypt|Decrypt|Hash|AES|RSA|SHA|MD5)\s*\(', code_lower):
            return "crypto_operation"

        if re.search(r'\b(base64|encode|decode|compress|decompress)\s*\(', code_lower):
            return "data_transform"

        if re.search(r'\b(system|popen|exec|CreateProcess|WinExec|ShellExecute)\s*\(', code_lower):
            return "execute_command"

        if re.search(r'\b(RegOpenKey|RegQueryValue|RegSetValue|RegCloseKey)\s*\(', code_lower):
            return "registry_operation"

        return None


class PseudocodeRenamer:
    """Renames decompiled pseudocode identifiers with semantic names."""

    GENERATED_NAME_PATTERNS = [
        re.compile(r'^sub_[0-9A-Fa-f]+$'),
        re.compile(r'^v\d+$'),
        re.compile(r'^a\d+$'),
        re.compile(r'^var_\d+$'),
        re.compile(r'^loc_[0-9A-Fa-f]+$'),
        re.compile(r'^arg_\d+$'),
        re.compile(r'^unk_[0-9A-Fa-f]+$'),
    ]

    # 调用点模式: func_name(...) -- 用于在改名后同步替换调用处
    _CALL_PATTERN = re.compile(
        r'(?<!\w)(sub_[0-9A-Fa-f]+)\s*\(',
    )

    # 默认使用的推理模式
    _DEFAULT_MODE = 'balanced'

    def __init__(self, mode: str = 'balanced') -> None:
        self.inferer = VariableRoleInferer()
        self._rename_log: List[RenameOperation] = []
        self._func_rename_map: Dict[str, str] = {}
        self.mode = mode

    @property
    def min_confidence(self) -> float:
        """当前模式对应的最低置信度阈值。"""
        return self.inferer.CONFIDENCE_THRESHOLDS.get(
            self.mode,
            self.inferer.CONFIDENCE_THRESHOLDS['balanced'],
        )

    def rename(
        self,
        pseudocode: str,
        function_map: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, List[RenameOperation]]:
        """Rename generated identifiers in pseudocode with meaningful names."""
        self._rename_log = []
        self._func_rename_map = {}
        # 每次 rename 前重置推断器计数器，避免跨轮次累积
        self.inferer.reset()
        result = pseudocode

        # First pass: rename functions
        result = self._rename_functions(result, function_map)

        # 1.5 pass: rename function call sites -- 确保调用点也替换为新名
        result = self._rename_function_callsites(result)

        # Second pass: rename variables
        result = self._rename_variables(result)

        return result, self._rename_log

    def _is_generated_name(self, name: str) -> bool:
        """Check if a name appears to be compiler-generated."""
        for pattern in self.GENERATED_NAME_PATTERNS:
            if pattern.match(name):
                return True
        return False

    def _rename_functions(
        self,
        code: str,
        function_map: Optional[Dict[str, str]],
    ) -> str:
        """Rename compiler-generated function names.

        同时建立 _func_rename_map, 供后续调用点替换使用。
        """
        result = code

        # Find function definitions
        func_pattern = re.compile(
            r'(\w[\w\s*]*?)\s+(sub_[0-9A-Fa-f]+)\s*\(([^)]*)\)',
        )

        for match in func_pattern.finditer(code):
            ret_type, func_name, params = match.groups()
            suggestion = self.inferer.infer_function_name(func_name, code)
            if suggestion:
                # 若建议名已存在冲突，追加下划线编号
                unique_suggestion = self._deduplicate_func_name(suggestion)
                result = result.replace(func_name, unique_suggestion)
                self._func_rename_map[func_name] = unique_suggestion
                self._rename_log.append(RenameOperation(
                    original=func_name,
                    new_name=unique_suggestion,
                    reason="Inferred from function behavior",
                    type="function",
                    confidence=0.90,
                ))

        return result

    def _deduplicate_func_name(self, base: str) -> str:
        """确保函数名不与已有映射冲突。"""
        existing = set(self._func_rename_map.values())
        if base not in existing:
            return base
        idx = 2
        while f"{base}_{idx}" in existing:
            idx += 1
        return f"{base}_{idx}"

    def _rename_function_callsites(self, code: str) -> str:
        """根据 _func_rename_map 替换所有函数调用点。

        这是新增的关键步骤: 之前只重命名了函数定义,
        却没有同步修改 call site, 导致反编译输出中产生未定义引用。
        """
        if not self._func_rename_map:
            return code

        result = code
        for original, new_name in self._func_rename_map.items():
            # 使用 word boundary 确保精确替换
            result = re.sub(
                rf'(?<!\w){re.escape(original)}(?!\w)',
                new_name,
                result,
            )

        return result

    def _rename_variables(self, code: str) -> str:
        """Rename generated variable names."""
        result = code

        # Find local variable declarations and uses
        var_pattern = re.compile(r'\b(v\d+|a\d+|var_\d+|loc_[0-9A-Fa-f]+|arg_\d+)\b')
        found_vars: Set[str] = set(var_pattern.findall(code))

        # 按出现次数降序排列，频繁使用的变量优先获得好名字
        var_freq: Dict[str, int] = {}
        for m in var_pattern.finditer(code):
            v = m.group(0)
            var_freq[v] = var_freq.get(v, 0) + 1
        sorted_vars = sorted(found_vars, key=lambda v: var_freq.get(v, 0), reverse=True)

        for var_name in sorted_vars:
            suggestion_result = self.inferer.infer_name(
                var_name, code, min_confidence=self.min_confidence,
            )
            if suggestion_result is not None:
                suggestion, confidence = suggestion_result
                # Use word boundary replacement to avoid partial matches
                result = re.sub(
                    rf'\b{re.escape(var_name)}\b',
                    suggestion,
                    result,
                )
                self._rename_log.append(RenameOperation(
                    original=var_name,
                    new_name=suggestion,
                    reason="Inferred from variable usage pattern",
                    type="variable",
                    confidence=confidence,
                ))

        return result

    def suggest_name(
        self,
        identifier: str,
        context: str,
    ) -> Optional[str]:
        """Suggest a better name without modifying code."""
        if self._is_generated_name(identifier):
            result = self.inferer.infer_name(identifier, context)
            if result is not None:
                return result[0]
        return None

    def batch_rename(
        self,
        function_dict: Dict[str, str],
    ) -> Dict[str, Tuple[str, List[RenameOperation]]]:
        """Rename multiple functions at once."""
        results: Dict[str, Tuple[str, List[RenameOperation]]] = {}
        # 批量分析时重置一次，全局计数器统一管理
        self.inferer.reset()
        for name, code in function_dict.items():
            results[name] = self.rename(code, function_dict)
        return results

    @property
    def rename_history(self) -> List[RenameOperation]:
        """Return the rename operations from the last rename() call."""
        return self._rename_log

    def get_stats(self) -> Dict[str, int]:
        """返回最近一次 rename() 的统计摘要。"""
        total = len(self._rename_log)
        by_type: Dict[str, int] = {}
        high_conf = 0
        for op in self._rename_log:
            by_type[op.type] = by_type.get(op.type, 0) + 1
            if op.confidence >= 0.8:
                high_conf += 1
        return {
            'total': total,
            'functions': by_type.get('function', 0),
            'variables': by_type.get('variable', 0),
            'high_confidence': high_conf,
        }


def rename_pseudocode(
    pseudocode: str,
    mode: str = 'balanced',
) -> Tuple[str, List[RenameOperation]]:
    """Convenience function for one-shot pseudocode renaming."""
    renamer = PseudocodeRenamer(mode=mode)
    return renamer.rename(pseudocode)
