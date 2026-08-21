# 符号恢复 — 从脱壳二进制中恢复变量名、函数签名和数据结构
# 基于: ReSym [Zotero: "Harnessing LLMs to Recover Variable and Data Structure Symbols from Stripped Binaries"]
# HyRES [Zotero: "Recovering Data Structures in Binaries via Semantic Enhanced Hybrid Reasoning"]
# 核心: 结合静态分析约束和启发式推断, 为脱壳函数重建有意义的符号名

from __future__ import annotations
import re
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class RecoveredSymbol:
    original_name: str       # sub_401000
    recovered_name: str      # validate_input_buffer
    symbol_type: str         # function / variable / struct_field / parameter
    confidence: float
    evidence: List[str] = field(default_factory=list)
    data_type_hint: str = ""


@dataclass
class StructLayout:
    name: str
    fields: List[Tuple[int, str, str]]  # (offset, field_name, type_hint)
    total_size: int
    confidence: float


class SymbolRecoveryEngine:
    """符号恢复引擎 — ReSym风格的多证据融合推理

    从三个维度恢复符号:
      1. API上下文: 函数调用的API暗示功能意图
      2. 数据访问模式: 内存访问模式暗示数据结构
      3. 控制流特征: 循环/分支结构暗示算法类型
    """

    # API → 功能意图映射
    API_INTENT_MAP = {
        'recv': ('network_receive', 0.90), 'send': ('network_send', 0.90),
        'socket': ('network_init', 0.85), 'connect': ('network_connect', 0.85),
        'bind': ('network_bind', 0.80), 'listen': ('network_listen', 0.80),
        'accept': ('network_accept', 0.85),
        'fopen': ('file_open', 0.85), 'fread': ('file_read', 0.85),
        'fwrite': ('file_write', 0.85), 'fclose': ('file_close', 0.80),
        'fseek': ('file_seek', 0.75),
        'malloc': ('memory_allocate', 0.80), 'free': ('memory_free', 0.80),
        'realloc': ('memory_realloc', 0.75), 'calloc': ('memory_allocate_zero', 0.80),
        'memcpy': ('memory_copy', 0.85), 'memset': ('memory_set', 0.80),
        'memcmp': ('memory_compare', 0.75), 'memmove': ('memory_move', 0.80),
        'strcpy': ('string_copy', 0.85), 'strncpy': ('string_copy_n', 0.85),
        'strlen': ('string_length', 0.80), 'strcmp': ('string_compare', 0.80),
        'strcat': ('string_concat', 0.80), 'strstr': ('string_search', 0.75),
        'sprintf': ('string_format', 0.80), 'snprintf': ('string_format_n', 0.80),
        'atoi': ('string_to_int', 0.75), 'atol': ('string_to_long', 0.75),
        'crypto': ('crypto_operation', 0.90), 'decrypt': ('decrypt_data', 0.90),
        'encrypt': ('encrypt_data', 0.90), 'hash': ('hash_compute', 0.85),
        'CreateFile': ('file_create', 0.85), 'ReadFile': ('file_read', 0.85),
        'WriteFile': ('file_write', 0.85), 'CloseHandle': ('handle_close', 0.75),
        'CreateProcess': ('process_create', 0.90), 'CreateThread': ('thread_create', 0.85),
        'VirtualAlloc': ('memory_virtual_alloc', 0.85), 'VirtualProtect': ('memory_protect', 0.85),
        'RegOpenKey': ('registry_open', 0.80), 'RegQueryValue': ('registry_query', 0.80),
        'LoadLibrary': ('library_load', 0.80), 'GetProcAddress': ('function_resolve', 0.85),
    }

    def __init__(self, min_confidence: float = 0.4):
        self.min_conf = min_confidence

    def recover_function_name(self, func_addr: str, pseudo_code: str,
                              imports: List[str], strings: List[str]) -> RecoveredSymbol:
        """恢复函数名"""
        evidence_scores: Dict[str, Tuple[str, float, List[str]]] = {}

        # 1. API意图推断
        api_intents = defaultdict(list)
        for imp in imports:
            for api_key, (intent, conf) in self.API_INTENT_MAP.items():
                if api_key.lower() in imp.lower():
                    api_intents[intent].append((imp, conf))

        for intent, matches in api_intents.items():
            max_conf = max(c[1] for c in matches)
            evidence_scores[intent] = (intent, max_conf,
                                       [f"API: {m[0]}" for m in matches])

        # 2. 字符串提示
        for s in strings[:10]:
            s_clean = s.strip().lower()
            if any(kw in s_clean for kw in ['error', 'fail', 'success', 'warn',
                                              'alloc', 'init', 'parse', 'config']):
                for kw in ['error', 'fail', 'success', 'warn', 'alloc', 'init',
                           'parse', 'config']:
                    if kw in s_clean:
                        name = f"{kw}_handler" if kw in ('error','fail','success','warn') else f"{kw}_data"
                        if name not in evidence_scores:
                            evidence_scores[name] = (name, 0.55, [f"string: {s_clean[:40]}"])

        # 3. 控制流特征命名
        loops = len(re.findall(r'\b(?:for|while|do)\s*\(', pseudo_code))
        branches = len(re.findall(r'\bif\s*\(', pseudo_code))
        calls = len(re.findall(r'\b\w+\s*\(', pseudo_code))

        if loops >= 3:
            evidence_scores['process_loop'] = ('process_loop', 0.45,
                [f'控制流: {loops}个循环, {branches}个分支'])
        if branches >= 8:
            evidence_scores['dispatch_handler'] = ('dispatch_handler', 0.50,
                [f'控制流: 大型switch/dispatch 模式'])

        # 选择最佳名称
        if not evidence_scores:
            return RecoveredSymbol(
                original_name=func_addr,
                recovered_name=func_addr,
                symbol_type='function',
                confidence=0.0,
            )

        best = max(evidence_scores.values(), key=lambda x: x[1])
        return RecoveredSymbol(
            original_name=func_addr,
            recovered_name=best[0],
            symbol_type='function',
            confidence=best[1],
            evidence=best[2],
        )

    def infer_variable_types(self, pseudo_code: str) -> Dict[str, str]:
        """从伪代码推断变量类型"""
        var_types = {}

        # 从赋值和API调用模式推断
        patterns = [
            (r'(\w+)\s*=\s*malloc\s*\(', 'pointer'),
            (r'(\w+)\s*=\s*strlen\s*\(', 'size_t'),
            (r'(\w+)\s*=\s*atoi\s*\(', 'int'),
            (r'(\w+)\s*=\s*fopen\s*\(', 'FILE*'),
            (r'(\w+)\s*=\s*socket\s*\(', 'SOCKET'),
            (r'(\w+)\s*=\s*CreateFile\s*\(', 'HANDLE'),
            (r'\b(DWORD|int|char|void|size_t|uint\w*_t)\s+(\w+)', None),
            (r'(\w+)\[\d+\]', 'array'),
        ]

        for pattern, type_hint in patterns:
            if type_hint:
                for match in re.finditer(pattern, pseudo_code):
                    var_name = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    if var_name not in var_types:
                        var_types[var_name] = type_hint
            else:
                for match in re.finditer(pattern, pseudo_code):
                    if match.lastindex and match.lastindex >= 2:
                        type_name, var_name = match.group(1), match.group(2)
                        var_types[var_name] = type_name

        return var_types

    def recover_struct_layout(self, pseudo_code: str,
                              var_types: Dict[str, str]) -> Optional[StructLayout]:
        """从内存访问模式推断结构体布局"""
        # 检测结构体访问: var->field 或 var.field
        struct_access = re.findall(r'(\w+)\s*(?:->|\.)\s*(\w+)', pseudo_code)

        if len(struct_access) < 2:
            return None

        # 按基变量分组
        groups: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for base, field in struct_access:
            offset_match = re.search(r'\+0x([0-9a-fA-F]+)', field)
            off = int(offset_match.group(1), 16) if offset_match else 0
            groups[base].append((field, off))

        # 推断布局
        layouts = []
        for base, fields in groups.items():
            if len(fields) >= 2:
                sorted_fields = sorted(fields, key=lambda x: x[1])
                layout_fields = []
                for field_name, offset in sorted_fields:
                    type_hint = var_types.get(field_name, 'unknown')
                    layout_fields.append((offset, field_name, type_hint))
                layouts.append(StructLayout(
                    name=f"inferred_struct_{base}",
                    fields=layout_fields,
                    total_size=max(f[0] for f in layout_fields) + 8 if layout_fields else 0,
                    confidence=min(0.9, len(fields) * 0.15),
                ))

        return layouts[0] if layouts else None


def create_symbol_recovery_engine(min_confidence: float = 0.4) -> SymbolRecoveryEngine:
    return SymbolRecoveryEngine(min_confidence=min_confidence)
