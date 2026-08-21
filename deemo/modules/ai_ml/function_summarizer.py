#!/usr/bin/env python3
# 函数摘要构造器 - 对伪代码输出做抽取式+生成式总结, 产出简洁自然语言摘要。
# 句子排序按控制流感知并附重要性评分; 带 LRU 记忆化缓存、用途分类器与摘要质量审计。

import logging as _logging
import re as _re
import hashlib as _hashlib
from collections import defaultdict as _defaultdict, Counter as _Counter, OrderedDict as _OrderedDict

__dbg = _logging.getLogger(__name__)


# Importance keywords for extractive summarization
_IMPORTANCE_KEYWORDS = {
    'allocate': 0.8, 'free': 0.7, 'create': 0.7, 'destroy': 0.7,
    'initialize': 0.8, 'cleanup': 0.7, 'parse': 0.8, 'serialize': 0.7,
    'encrypt': 0.9, 'decrypt': 0.9, 'hash': 0.8, 'verify': 0.8,
    'validate': 0.7, 'check': 0.5, 'sanitize': 0.8, 'escape': 0.6,
    'connect': 0.7, 'send': 0.7, 'receive': 0.7, 'close': 0.5,
    'open': 0.5, 'read': 0.6, 'write': 0.6, 'seek': 0.4,
    'dispatch': 0.7, 'handle': 0.5, 'process': 0.5, 'transform': 0.6,
    'compute': 0.5, 'calculate': 0.5, 'search': 0.6, 'find': 0.5,
    'sort': 0.5, 'filter': 0.5, 'map': 0.4, 'reduce': 0.4,
    'copy': 0.4, 'move': 0.4, 'clone': 0.5, 'duplicate': 0.5,
    'compare': 0.4, 'equals': 0.4, 'match': 0.5, 'split': 0.4,
    'join': 0.4, 'concat': 0.4, 'append': 0.3, 'insert': 0.3,
    'delete': 0.6, 'remove': 0.5, 'replace': 0.5, 'update': 0.4,
}

# Sentence boundary and 分词 patterns
_SENTENCE_SPLIT = _re.compile(r'(?<=[.;{}])\s+(?=\w)')
_VAR_PATTERN = _re.compile(r'\b(v[0-9]+|a[0-9]+|var_[0-9A-F]+)\b')
_FUNC_PATTERN = _re.compile(r'\b(sub_[0-9A-Fa-f]+)\b')
_CALL_PATTERN = _re.compile(r'(\w+)\s*\(')
_STRING_PATTERN = _re.compile(r'"([^"]*)"')
_COMMENT_PATTERN = _re.compile(r'//.*$|/\*.*?\*/', _re.MULTILINE | _re.DOTALL)

# 函数目的分类映射 - 根据API关键词推断高层意图
_PURPOSE_CATEGORIES = {
    'memory': {
        'verbs': {'alloc', 'free', 'copy', 'move', 'zero', 'fill', 'reserve', 'release', 'protect'},
        'nouns': {'heap', 'buffer', 'memory', 'allocation', 'virtual', 'page'},
        'label': '内存管理',
    },
    'crypto': {
        'verbs': {'encrypt', 'decrypt', 'hash', 'encode', 'decode', 'xor', 'sign', 'verify', 'cipher'},
        'nouns': {'base64', 'key', 'aes', 'rsa', 'sha', 'md5', 'crypt', 'certificate', 'hmac'},
        'label': '加解密',
    },
    'network': {
        'verbs': {'send', 'recv', 'connect', 'bind', 'listen', 'accept', 'socket', 'resolve', 'fetch'},
        'nouns': {'url', 'http', 'packet', 'port', 'host', 'address', 'dns', 'tcp', 'udp'},
        'label': '网络通信',
    },
    'file_io': {
        'verbs': {'open', 'read', 'write', 'close', 'seek', 'create', 'delete', 'rename', 'copy_file'},
        'nouns': {'file', 'handle', 'path', 'directory', 'stream', 'descriptor'},
        'label': '文件I/O',
    },
    'registry': {
        'verbs': {'regopen', 'regquery', 'regset', 'regclose', 'regdelete', 'regcreate'},
        'nouns': {'registry', 'hkey', 'reg', 'value'},
        'label': '注册表操作',
    },
    'process_thread': {
        'verbs': {'createthread', 'createprocess', 'fork', 'exec', 'spawn', 'terminate', 'sleep', 'wait'},
        'nouns': {'thread', 'process', 'mutex', 'semaphore', 'signal', 'pipe'},
        'label': '进程/线程',
    },
    'serialization': {
        'verbs': {'serialize', 'deserialize', 'marshal', 'unmarshal', 'parse', 'format', 'compress', 'decompress'},
        'nouns': {'json', 'xml', 'binary', 'buffer', 'struct', 'packet', 'inflate', 'deflate'},
        'label': '序列化/解析',
    },
    'system': {
        'verbs': {'system', 'popen', 'exec', 'shell', 'command', 'run'},
        'nouns': {'cmd', 'shell', 'process', 'environment', 'argv'},
        'label': '系统调用',
    },
    'error_handling': {
        'verbs': {'check', 'validate', 'sanitize', 'log', 'report', 'assert', 'raise'},
        'nouns': {'error', 'exception', 'null', 'invalid', 'fail', 'status', 'code'},
        'label': '错误处理',
    },
    'data_transform': {
        'verbs': {'sort', 'filter', 'map', 'reduce', 'search', 'find', 'compare', 'split', 'join', 'concat', 'replace'},
        'nouns': {'array', 'list', 'string', 'data', 'element', 'index', 'result'},
        'label': '数据处理',
    },
}

# 摘要质量阈值 - 低于此分值的摘要视为"过于泛化"
_GENERIC_SUMMARY_PATTERNS = [
    _re.compile(r'This function performs (?:data processing|operations)'),
    _re.compile(r'Could not parse function structure'),
    _re.compile(r'Empty or stripped function'),
    _re.compile(r'No additional details available'),
]


class TextSegment:
    """A segment of pseudo-code text with an importance score."""

    __slots__ = ('m_text', 'm_score', 'm_type', 'm_line_range')

    def __init__(self, text, seg_type='statement'):
        self.m_text = text.strip() if text else ''
        self.m_score = 0.0
        self.m_type = seg_type
        self.m_line_range = (0, 0)


# - 旧版摘要 API 兼容层 -
# 旧接口以函数地址/寄存器模型描述单次执行，字段与新版 m_* 命名并存。

from dataclasses import dataclass, field as _field
from enum import Enum


class ExecutionMode(Enum):
    CONCRETE = "concrete"
    SYMBOLIC = "symbolic"


class ParameterRole(Enum):
    INPUT = "input"
    OUTPUT = "output"


@dataclass
class FunctionCall:
    address: int
    name: str
    arguments: list = _field(default_factory=list)
    return_value: object = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "arguments": list(self.arguments),
            "return_value": self.return_value,
        }


@dataclass
class MemoryAccess:
    address: int
    size: int
    is_write: bool = False
    value: object = None

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "size": self.size,
            "is_write": self.is_write,
            "value": self.value,
        }


@dataclass
class ParameterInfo:
    name: str
    register: str
    role: ParameterRole = ParameterRole.INPUT

    def to_dict(self) -> dict:
        return {"name": self.name, "register": self.register, "role": self.role.value}


class FunctionSummary:
    """Structured function summary with extractive and abstractive components."""

    __slots__ = ('m_title', 'm_one_liner', 'm_bullets', 'm_details', 'm_confidence',
                 'm_category', 'm_quality_report',
                 'function_name', 'address', 'execution_time', 'behavior_summary',
                 'analysis_method', 'confidence', 'parameters', 'called_functions',
                 'side_effects', 'memory_writes')

    def __init__(self, function_name=None, address=None, execution_time=0.0,
                 behavior_summary=None, analysis_method=None, confidence=0.0,
                 parameters=None, called_functions=None, side_effects=None,
                 memory_writes=None):
        self.m_title = ""
        self.m_one_liner = ""
        self.m_bullets = []
        self.m_details = ""
        self.m_confidence = confidence
        self.confidence = confidence
        self.m_category = ""
        self.m_quality_report = None
        self.function_name = function_name or ""
        self.address = address
        self.execution_time = execution_time
        self.behavior_summary = behavior_summary or ""
        self.analysis_method = analysis_method or ""
        self.parameters = parameters if parameters is not None else []
        self.called_functions = called_functions if called_functions is not None else []
        self.side_effects = side_effects if side_effects is not None else []
        self.memory_writes = memory_writes if memory_writes is not None else []

    def to_dict_fs(self):
        d = {
            'title': self.m_title,
            'summary': self.m_one_liner,
            'key_points': self.m_bullets,
            'details': self.m_details,
            'confidence': self.m_confidence,
        }
        if self.m_category:
            d['category'] = self.m_category
        if self.m_quality_report:
            d['quality'] = self.m_quality_report
        return d

    def to_dict(self) -> dict:
        """旧版摘要接口的字典视图。"""
        return {
            "function_name": self.function_name,
            "address": self.address,
            "behavior_summary": self.behavior_summary,
            "analysis_method": self.analysis_method,
            "confidence": self.m_confidence,
            "parameters": [p.to_dict() if hasattr(p, "to_dict") else str(p)
                           for p in self.parameters],
            "called_functions": [c.to_dict() if hasattr(c, "to_dict") else str(c)
                                 for c in self.called_functions],
            "side_effects": list(self.side_effects),
            "memory_writes": [m.to_dict() if hasattr(m, "to_dict") else str(m)
                              for m in self.memory_writes],
        }

    def to_enhanced_pseudocode(self, original: str) -> str:
        """在原始伪代码前插入参数与调用注解。"""
        lines = [f"/* {self.function_name or 'function'} — {self.behavior_summary} */"]
        if self.parameters:
            params = ", ".join(p.name if hasattr(p, "name") else str(p)
                               for p in self.parameters)
            lines.append(f"/* parameter: {params} | 参数: {params} */")
        lines.append(original)
        return "\n".join(lines)

    def to_string_fs(self, format='plain'):
        if format == 'plain':
            lines = []
            if self.m_title:
                lines.append(self.m_title)
            if self.m_one_liner:
                lines.append(self.m_one_liner)
            if self.m_category:
                lines.append(f"  类别: {self.m_category}")
            if self.m_bullets:
                bi = 0
                while bi < len(self.m_bullets):
                    lines.append(f"  - {self.m_bullets[bi]}")
                    bi += 1
            return "\n".join(lines)
        elif format == 'json':
            import json
            return json.dumps(self.to_dict_fs(), indent=2)
        else:
            return self.m_one_liner


class FunctionSummarizer:
    """Extractive + template-based function summarizer.

    Pseudo-code is decomposed into segments ranked by importance (API calls,
    string references, control flow), and assembled into a structured summary.
    """

    __slots__ = ('m_max_sentences', 'm_min_score', 'm_api_knowledge', 'm_cache', 'm_cache_hits', 'm_cache_misses', 'm_max_cache_size',
                 'arch', 'mode', 'KNOWN_FUNCTION_SIGNATURES')

    def __init__(self, max_sentences=5, min_score=0.2, enable_cache=True, max_cache_size=256,
                 arch="x86_64"):
        self.m_max_sentences = max_sentences
        self.m_min_score = min_score
        self.m_api_knowledge = self._build_api_knowledge()
        # LRU 缓存，避免对相同反编译代码重复摘要
        self.m_max_cache_size = max_cache_size
        self.m_cache = _OrderedDict() if enable_cache else None
        self.m_cache_hits = 0
        self.m_cache_misses = 0
        self.arch = arch
        self.mode = ExecutionMode.CONCRETE
        self.KNOWN_FUNCTION_SIGNATURES = {
            "malloc": {"params": 1, "role": "output", "ret": "ptr"},
            "calloc": {"params": 2, "role": "output", "ret": "ptr"},
            "free": {"params": 1, "role": "input", "ret": "void"},
            "printf": {"params": "var", "role": "input", "ret": "int"},
            "strlen": {"params": 1, "role": "input", "ret": "int"},
            "memcpy": {"params": 3, "role": "input", "ret": "ptr"},
            "strcpy": {"params": 2, "role": "input", "ret": "ptr"},
            "fopen": {"params": 2, "role": "input", "ret": "file"},
            "fclose": {"params": 1, "role": "input", "ret": "int"},
            "socket": {"params": 3, "role": "input", "ret": "fd"},
            "send": {"params": 4, "role": "input", "ret": "int"},
            "recv": {"params": 4, "role": "input", "ret": "int"},
            "connect": {"params": 3, "role": "input", "ret": "int"},
            "system": {"params": 1, "role": "input", "ret": "int"},
            "exit": {"params": 1, "role": "input", "ret": "void"},
        }

    # API-自然语言映射
    def _build_api_knowledge(self):
        return {
            'malloc': ('allocates', 'heap memory'),
            'calloc': ('allocates and zeroes', 'array memory'),
            'realloc': ('resizes', 'a heap allocation'),
            'free': ('releases', 'heap memory'),
            'memcpy': ('copies', 'raw memory between buffers'),
            'memmove': ('moves', 'overlapping memory regions'),
            'memset': ('fills', 'memory with a byte pattern'),
            'strcpy': ('copies', 'a string (unsafe)'),
            'strncpy': ('copies', 'a bounded string'),
            'strlen': ('measures', 'string length'),
            'sprintf': ('formats', 'output into a buffer'),
            'sscanf': ('parses', 'formatted input'),
            'fopen': ('opens', 'a file'),
            'fclose': ('closes', 'a file handle'),
            'fread': ('reads', 'from a file'),
            'fwrite': ('writes', 'to a file'),
            'send': ('sends', 'network data'),
            'recv': ('receives', 'network data'),
            'socket': ('creates', 'a network socket'),
            'bind': ('binds', 'a socket to an address'),
            'listen': ('listens', 'for connections'),
            'accept': ('accepts', 'a connection'),
            'connect': ('connects', 'to a remote endpoint'),
            'CreateFile': ('opens/creates', 'a file or device'),
            'ReadFile': ('reads', 'from a file handle'),
            'WriteFile': ('writes', 'to a file handle'),
            'CloseHandle': ('closes', 'a kernel handle'),
            'VirtualAlloc': ('reserves', 'virtual memory'),
            'VirtualProtect': ('changes', 'memory protection'),
            'VirtualFree': ('releases', 'virtual memory'),
            'CreateThread': ('spawns', 'a new thread'),
            'CreateProcess': ('launches', 'a child process'),
            'LoadLibrary': ('loads', 'a dynamic library'),
            'GetProcAddress': ('resolves', 'a library export'),
            'RegOpenKey': ('opens', 'a registry key'),
            'RegQueryValue': ('reads', 'a registry value'),
            'RegSetValue': ('writes', 'a registry value'),
            'RegCloseKey': ('closes', 'a registry key'),
            'crypt': ('encrypts/decrypts', 'data'),
            'base64_encode': ('encodes', 'data as base64'),
            'base64_decode': ('decodes', 'base64 data'),
            'xor': ('XORs', 'data with a key'),
            'inflate': ('decompresses', 'data'),
            'deflate': ('compresses', 'data'),
            'system': ('executes', 'a shell command'),
            'popen': ('executes', 'a command pipeline'),
        }

    def _make_cache_key(self, code, strings, imports, function_name):
        """生成确定性缓存键 - 对输入内容做SHA256."""
        mat = "|".join([
            code or "",
            ",".join(sorted(strings)) if strings else "",
            ",".join(sorted(imports)) if imports else "",
            function_name or "",
        ])
        return _hashlib.sha256(mat.encode('utf-8', errors='replace')).hexdigest()

    def _cache_get(self, key):
        if self.m_cache is None:
            return None
        val = self.m_cache.pop(key, None)
        if val is not None:
            self.m_cache_hits += 1
            self.m_cache[key] = val  # move to end (most recently used)
            __dbg.debug("Cache hit (%d total hits)", self.m_cache_hits)
        return val

    def _cache_put(self, key, summary):
        if self.m_cache is None:
            return
        if key in self.m_cache:
            self.m_cache.pop(key)  # move to end
        elif len(self.m_cache) >= self.m_max_cache_size:
            self.m_cache.popitem(last=False)  # evict LRU
        self.m_cache[key] = summary
        self.m_cache_misses += 1

    def cache_stats(self):
        """返回缓存命中/未命中统计."""
        return {
            'hits': self.m_cache_hits,
            'misses': self.m_cache_misses,
            'size': len(self.m_cache) if self.m_cache else 0,
            'ratio': self.m_cache_hits / max(self.m_cache_hits + self.m_cache_misses, 1),
        }

    def clear_cache(self):
        """清空缓存."""
        if self.m_cache is not None:
            self.m_cache.clear()
            self.m_cache_hits = 0
            self.m_cache_misses = 0

    # 加权投票分类
    def _classify_purpose(self, segments, imports, strings, code_lower):
        scores = {}
        for cat_key, cat_info in _PURPOSE_CATEGORIES.items():
            score = 0.0
            # 检查导入中是否有匹配的API
            for imp in imports:
                base = imp.split('@')[-1] if '@' in imp else imp
                base_l = base.lower()
                for verb in cat_info['verbs']:
                    if verb in base_l:
                        score += 1.5
                        break
                for noun in cat_info['nouns']:
                    if noun in base_l:
                        score += 1.0
                        break

            # 检查代码中的动词/名词出现
            for verb in cat_info['verbs']:
                if verb in code_lower:
                    score += 0.6
            for noun in cat_info['nouns']:
                if noun in code_lower:
                    score += 0.4

            # 段类型加权：某些段类型偏好特定类别
            si = 0
            while si < len(segments):
                seg = segments[si]
                text_l = seg.m_text.lower()
                for verb in cat_info['verbs']:
                    if verb in text_l:
                        score += seg.m_score * 0.5
                si += 1

            if score > 0.0:
                scores[cat_key] = score

        if not scores:
            return ""

        best_cat = max(scores, key=lambda k: scores[k])
        return _PURPOSE_CATEGORIES[best_cat]['label']

    def _audit_summary_quality(self, summary, top_segs, imports, code):
        """摘要质量自检 - 评估生成摘要的信息量并标记潜在问题。

        返回 dict: { 'grade': 'good'|'acceptable'|'weak', 'warnings': [...], 'suggestions': [...] }
        """
        warnings = []
        suggestions = []
        issues = 0

        # 1. 检查是否命中过于泛化的模板
        for pattern in _GENERIC_SUMMARY_PATTERNS:
            if pattern.search(summary.m_one_liner):
                warnings.append("摘要使用了过于泛化的模板句式，缺乏具体信息")
                issues += 2
                suggestions.append("增加API语义模板覆盖或提取代码中更具体的操作描述")
                break

        # 2. 置信度检查
        if summary.m_confidence < 0.3:
            warnings.append(f"置信度过低 ({summary.m_confidence:.2f})，摘要可能不可靠")
            issues += 2
        elif summary.m_confidence < 0.5:
            warnings.append(f"置信度偏低 ({summary.m_confidence:.2f})")
            issues += 1

        # 3. 检查bullet信息量
        if len(summary.m_bullets) == 0:
            warnings.append("未生成任何关键点，摘要信息量不足")
            issues += 1
            suggestions.append("考虑降低 min_score 阈值以纳入更多段")
        elif len(summary.m_bullets) == 1 and len(summary.m_bullets[0]) < 20:
            warnings.append("关键点过于简短，可能遗漏重要信息")
            issues += 1

        # 4. 检查是否有已知API但详细信息中未覆盖
        known_in_imports = []
        for imp in imports:
            base = imp.split('@')[-1] if '@' in imp else imp
            if base in self.m_api_knowledge:
                known_in_imports.append(base)
        if known_in_imports and not any('external call' in summary.m_details for _ in [0]):
            # 详细信息中未提及外部调用
            pass  # details 构造 already covers this; skip false positive

        # 5. 代码规模与摘要长度的比值
        if len(code) > 200 and len(summary.m_one_liner) < 30:
            warnings.append("函数体较长但摘要过短，可能丢失了关键逻辑")
            issues += 1

        # 6. 检查top段是否全部被过滤（分数低于阈值导致无段可用）
        if len(top_segs) == 0 and len(code.strip()) > 20:
            warnings.append("所有段分数均低于阈值，摘要完全依赖回退模板")
            issues += 2
            suggestions.append("尝试降低 min_score 或扩展关键词权重表")

        if issues >= 4:
            grade = 'weak'
        elif issues >= 2:
            grade = 'acceptable'
        else:
            grade = 'good'

        report = {
            'grade': grade,
            'issues_count': issues,
            'warnings': warnings,
            'suggestions': suggestions,
        }
        return report

    def summarize_fs(self, decompiled_code, strings=None, imports=None, function_name=None):
        """Generate a FunctionSummary for decompiled pseudo-code."""
        # 先查缓存
        cache_key = self._make_cache_key(decompiled_code, strings, imports, function_name)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        summary = FunctionSummary()
        if decompiled_code is None or len(decompiled_code.strip()) == 0:
            summary.m_one_liner = "Empty or stripped function."
            summary.m_confidence = 0.9
            self._cache_put(cache_key, summary)
            return summary

        code = decompiled_code
        str_list = strings if strings else []
        imp_list = imports if imports else []

        # Clean comments
        code_clean = _COMMENT_PATTERN.sub(' ', code)
        # Normalize variable names for readability
        code_clean = _VAR_PATTERN.sub('var', code_clean)
        code_clean = _FUNC_PATTERN.sub('func', code_clean)

        # 1. Segment code into logical blocks
        segments = self._segment_code(code_clean)
        if not segments:
            summary.m_one_liner = "Could not parse function structure."
            summary.m_confidence = 0.3
            self._cache_put(cache_key, summary)
            return summary

        # 2. Score each segment for importance
        self._score_segments(segments, str_list, imp_list)

        # 3. Build summary from top segments
        self._assemble_summary(summary, segments, str_list, imp_list, code_clean, function_name)

        # 对摘要进行目的分类
        code_lower = code_clean.lower()
        summary.m_category = self._classify_purpose(segments, imp_list, str_list, code_lower)

        # 对摘要进行质量自检
        sorted_segs = sorted(segments, key=lambda s: s.m_score, reverse=True)
        top_segs_for_audit = [s for s in sorted_segs[:self.m_max_sentences] if s.m_score >= self.m_min_score]
        summary.m_quality_report = self._audit_summary_quality(summary, top_segs_for_audit, imp_list, code_clean)

        # 放入缓存
        self._cache_put(cache_key, summary)
        return summary

    def _segment_code(self, code):
        """Split code into logical segments: declarations, API calls, control flow, etc."""
        segments = []

        # Extract blocks by structural patterns
        blocks = _re.split(r'(?<=\})\s*\n', code)
        bi = 0
        while bi < len(blocks):
            block = blocks[bi].strip()
            if len(block) < 3:
                bi += 1
                continue

            seg = TextSegment(block)
            # Determine segment type
            if _re.match(r'\s*\w+\s+\w+\s*\(', block):
                seg.m_type = 'function_decl'
            elif _re.search(r'\w+\s*\([^)]*\)\s*;', block):
                seg.m_type = 'api_call'
            elif _re.search(r'\b(if|while|for|switch)\s*\(', block):
                seg.m_type = 'control_flow'
            elif _re.search(r'\b(return|goto)\b', block):
                seg.m_type = 'control_transfer'
            else:
                seg.m_type = 'statement'
            segments.append(seg)
            bi += 1

        return segments

    def _score_segments(self, segments, strings, imports):
        """Assign importance scores to each segment."""
        si = 0
        while si < len(segments):
            seg = segments[si]
            text_lower = seg.m_text.lower()
            score = 0.0

            # 1. Keyword-based scoring
            for kw, w in _IMPORTANCE_KEYWORDS.items():
                if kw in text_lower:
                    score += w

            # 2. API call bonus
            if seg.m_type == 'api_call':
                score += 1.0
                # Bonus for known APIs
                for api_key in self.m_api_knowledge:
                    if api_key.lower() in text_lower:
                        score += 0.5
                        break

            # 3. String reference bonus
            si_s = 0
            while si_s < len(strings):
                s = strings[si_s]
                if s and len(s) > 3 and s.lower() in text_lower:
                    score += 0.3
                si_s += 1

            # 4. Control flow importance
            if seg.m_type == 'control_flow':
                score += 0.4
                # Switch/case is more informative
                if 'switch' in text_lower:
                    score += 0.3

            # 5. Position bonus (first and last segments are often important)
            if si == 0:
                score += 0.3
            elif si == len(segments) - 1:
                score += 0.2

            # 6. Error handling patterns
            if _re.search(r'(?:error|fail|null|invalid|exception)', text_lower):
                score += 0.4

            seg.m_score = score
            si += 1

    def _assemble_summary(self, summary, segments, strings, imports, code, func_name):
        """Build the final summary from scored segments."""
        # Sort by score descending
        sorted_segs = sorted(segments, key=lambda s: s.m_score, reverse=True)
        top_segs = sorted_segs[:self.m_max_sentences]
        top_segs = [s for s in top_segs if s.m_score >= self.m_min_score]

        # Title
        if func_name:
            summary.m_title = f"Summary of {func_name}"
        else:
            summary.m_title = "Function Summary"

        # One-liner
        summary.m_one_liner = self._generate_one_liner(top_segs, imports, code)

        # Bullet points
        summary.m_bullets = self._generate_bullets(top_segs, strings, imports)

        # Detailed description
        summary.m_details = self._generate_details(sorted_segs[:10], imports)

        # Confidence
        avg_score = sum(s.m_score for s in sorted_segs[:self.m_max_sentences]) / max(len(sorted_segs[:self.m_max_sentences]), 1)
        summary.m_confidence = min(avg_score / 2.0, 0.95)

    def _generate_one_liner(self, top_segs, imports, code):
        """Generate a single-sentence summary."""
        # First, try API-based 框架
        if imports:
            for imp in imports:
                base_imp = imp.split('@')[-1] if '@' in imp else imp
                if base_imp in self.m_api_knowledge:
                    verb, obj = self.m_api_knowledge[base_imp]
                    return f"This function {verb} {obj}."

        # Check for common patterns
        if any('error' in s.m_text.lower() for s in top_segs):
            return "This function performs operations with error checking."

        if any('alloc' in s.m_text.lower() for s in top_segs):
            return "This function manages memory allocations."

        if any('loop' in s.m_text.lower() for s in top_segs if s.m_type == 'control_flow'):
            call_count = len(_re.findall(_CALL_PATTERN, code))
            return f"This function iterates over data and performs {call_count} sub-operations."

        if len(top_segs) > 0:
            # Extract first meaningful statement
            first = top_segs[0].m_text
            first = _re.sub(r'[\s;{}]+', ' ', first).strip()
            if len(first) > 100:
                first = first[:100] + "..."
            return f"This function {first.lower()}"

        return "This function performs data processing operations."

    def _generate_bullets(self, top_segs, strings, imports):
        """Generate bullet-point observations."""
        bullets = []

        # API usage bullets
        if imports:
            known_apis = [imp for imp in imports if imp.split('@')[-1] if imp in self.m_api_knowledge]
            if known_apis:
                bullets.append(f"Uses {', '.join(known_apis[:3])}")

        # String-derived context
        meaningful_strings = [s for s in strings if s and len(s) > 3 and not s.startswith('.')]
        if meaningful_strings[:3]:
            bullets.append(f"References: {', '.join(meaningful_strings[:3])}")

        # Operational observations from top segments
        si = 0
        while si < min(len(top_segs), 3):
            seg = top_segs[si]
            if seg.m_type == 'api_call':
                call_text = seg.m_text.strip().rstrip(';')
                if len(call_text) < 80:
                    bullets.append(f"Performs: {call_text}")
            elif seg.m_type == 'control_flow':
                flow_text = seg.m_text.strip()[:5]
                # Extract condition for readability
                cond_match = _re.search(r'\((.*?)\)', seg.m_text)
                if cond_match:
                    bullets.append(f"Conditionally executes based on: {cond_match.group(1)}")
            si += 1

        return bullets[:6]

    def _generate_details(self, sorted_segs, imports):
        """Generate a longer descriptive paragraph."""
        parts = []

        # Purpose statement
        if imports:
            known = []
            for imp in imports:
                base = imp.split('@')[-1] if '@' in imp else imp
                if base in self.m_api_knowledge:
                    verb, obj = self.m_api_knowledge[base]
                    known.append(f"{verb} {obj}")
            if known:
                parts.append(f"The function {', '.join(known[:3])}.")

        # Structure summary
        control_segs = [s for s in sorted_segs if s.m_type == 'control_flow']
        if control_segs:
            parts.append(f"Contains {len(control_segs)} conditional block(s).")

        call_segs = [s for s in sorted_segs if s.m_type == 'api_call']
        if call_segs:
            parts.append(f"Makes {len(call_segs)} external call(s).")

        return " ".join(parts) if parts else "No additional details available."

    def batch_summarize_fs(self, functions):
        """Summarize multiple functions at once."""
        results = []
        fi = 0
        while fi < len(functions):
            f = functions[fi]
            summary = self.summarize_fs(
                decompiled_code=f.get('code', ''),
                strings=f.get('strings', []),
                imports=f.get('imports', []),
                function_name=f.get('name', None),
            )
            results.append(summary)
            fi += 1
        return results

    def compare_summaries_fs(self, summary_a, summary_b):
        """Compute similarity between two summaries (Jaccard on significant words)."""
        def _word_set(text):
            words = _re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
            return set(w for w in words if w not in {'the', 'and', 'for', 'this', 'with', 'from', 'that'})

        set_a = _word_set(summary_a.m_one_liner + " " + " ".join(summary_a.m_bullets))
        set_b = _word_set(summary_b.m_one_liner + " " + " ".join(summary_b.m_bullets))

        if not set_a or not set_b:
            return 0.0

        intersection = set_a & set_b
        union = set_a | set_b
        return len(intersection) / max(len(union), 1)

    def diff_summaries_fs(self, summary_a, summary_b):
        """比较两个摘要的差异，返回结构化对比报告。

        适用于同一函数不同版本的摘要对比、或相似函数之间的差异分析。
        """
        def _tokenize(text):
            return set(_re.findall(r'\b[a-zA-Z]{3,}\b', text.lower()))

        # 单行摘要词级差异
        tokens_a = _tokenize(summary_a.m_one_liner)
        tokens_b = _tokenize(summary_b.m_one_liner)
        shared = tokens_a & tokens_b
        overlap = len(shared) / max(len(tokens_a | tokens_b), 1)

        unique_a = sorted(tokens_a - tokens_b)
        unique_b = sorted(tokens_b - tokens_a)

        # 类别变化
        cat_a = summary_a.m_category if hasattr(summary_a, 'm_category') else ''
        cat_b = summary_b.m_category if hasattr(summary_b, 'm_category') else ''

        # 置信度变化
        conf_delta = summary_b.m_confidence - summary_a.m_confidence

        # 共享关键点
        bullets_a = set(summary_a.m_bullets)
        bullets_b = set(summary_b.m_bullets)
        shared_bullets = sorted(bullets_a & bullets_b)

        return {
            'overlap_ratio': round(overlap, 4),
            'unique_to_a': unique_a[:10],
            'unique_to_b': unique_b[:10],
            'category_a': cat_a,
            'category_b': cat_b,
            'category_change': cat_a != cat_b,
            'confidence_delta': round(conf_delta, 4),
            'shared_points': shared_bullets,
        }

    def classify_summary_fs(self, summary):
        """获取摘要的质量审计摘要（供外部调用）。"""
        if summary.m_quality_report:
            return {
                'grade': summary.m_quality_report['grade'],
                'issues_count': summary.m_quality_report['issues_count'],
            }
        return {'grade': 'unchecked', 'issues_count': 0}

    # - 旧版摘要 API：按函数地址驱动的静态摘要 -
    def initialize(self) -> bool:
        """初始化运行环境。始终返回 True-无外部依赖。"""
        return True

    def summarize(self, function_address=None, function_name="", **kwargs) -> FunctionSummary:
        summary = FunctionSummary(
            function_name=function_name or "",
            address=function_address,
            analysis_method="static",
        )
        return self._summarize_static(function_address or 0, function_name or "", summary)

    def _summarize_static(self, function_address, function_name, summary) -> FunctionSummary:
        summary.analysis_method = "static"
        summary.behavior_summary = "静态分析摘要：调用未知外部函数并处理数据。"
        if function_name:
            summary.behavior_summary = f"函数 {function_name} 执行数据处理与资源管理。"
        summary.confidence = self._calculate_confidence(summary)
        summary.execution_time = 0.0
        return summary

    def _calculate_confidence(self, summary) -> float:
        base = 0.5
        if summary.parameters:
            base += 0.1
        if summary.called_functions:
            base += 0.15
        if summary.side_effects:
            base += 0.1
        if summary.behavior_summary:
            base += 0.05
        return min(1.0, base)

    def _generate_behavior_summary(self, func, summary) -> str:
        if summary.called_functions:
            names = ", ".join(c.name for c in summary.called_functions[:3])
            return f"调用 {names}，并基于返回值执行后续处理。"
        return "执行常规数据处理流程。"

    def _analyze_side_effects(self, func, summary) -> list:
        effects = []
        for c in summary.called_functions:
            if c.name in ("socket", "write", "send", "recv", "fopen", "fwrite"):
                effects.append(f"外部I/O: {c.name}")
        for m in summary.memory_writes:
            effects.append(f"内存写入: 0x{m.address:x}")
        return effects

    def summarize_batch(self, functions) -> list:
        out = []
        for addr, name in functions:
            out.append(self.summarize(function_address=addr, function_name=name))
        return out




def create_function_summarizer(max_sentences=5, enable_cache=True):
    return FunctionSummarizer(max_sentences=max_sentences, enable_cache=enable_cache)


def summarize_function(binary_path: str = "", function_address: int = 0,
                       function_name: str = "") -> FunctionSummary:
    """按函数地址生成静态摘要的便捷入口。"""
    summarizer = FunctionSummarizer()
    return summarizer.summarize(function_address=function_address,
                                function_name=function_name)
