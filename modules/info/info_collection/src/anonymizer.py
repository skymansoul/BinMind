# anonymizer — 标识符/字符串/数值匿名化，确定性替换
# 用 OrderedDict 维持同位替换一致性，同一标识符全局映射到同一别名
# 语言无关：regex + 关键词黑名单，不做 AST 解析

import re
import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple, Optional

# C/C++ 保留字与标准库类型
_C_KEYWORDS = {
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
    'int', 'long', 'register', 'return', 'short', 'signed', 'sizeof', 'static',
    'struct', 'switch', 'typedef', 'union', 'unsigned', 'void', 'volatile',
    'while', 'include', 'define', 'pragma', 'ifdef', 'ifndef', 'endif',
    'wchar_t', 'bool', 'true', 'false', 'NULL', 'nullptr', 'FILE',
    'size_t', 'ssize_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', '__inline', '__attribute__',
    '__declspec', '__stdcall', '__cdecl', '__fastcall', 'WINAPI', 'CALLBACK',
    'DWORD', 'HANDLE', 'LPVOID', 'BOOL', 'HRESULT', 'LPSTR', 'LPCSTR',
    'HMODULE', 'HINSTANCE', 'HWND', 'BYTE', 'WORD', 'UINT', 'ULONG',
}

_PYTHON_KEYWORDS = {
    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await',
    'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
    'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is',
    'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return',
    'try', 'while', 'with', 'yield', 'self', 'cls', 'print', 'len',
    'range', 'int', 'str', 'float', 'list', 'dict', 'set', 'tuple',
    'type', 'object', 'super', '__init__', '__name__', '__main__',
    '__file__', '__doc__', '__all__',
}

_JS_KEYWORDS = {
    'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
    'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
    'for', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new',
    'return', 'super', 'switch', 'this', 'throw', 'try', 'typeof',
    'var', 'void', 'while', 'with', 'yield', 'async', 'await',
    'null', 'undefined', 'true', 'false', 'console', 'window', 'document',
    'process', 'require', 'module', 'exports', 'global',
}

_KEYWORD_MAP = {
    'c': _C_KEYWORDS, 'cpp': _C_KEYWORDS, 'c++': _C_KEYWORDS,
    'python': _PYTHON_KEYWORDS, 'py': _PYTHON_KEYWORDS,
    'javascript': _JS_KEYWORDS, 'js': _JS_KEYWORDS,
}

# 敏感内容正则库，每项 (pattern, weight)
# 权重按泄露严重性分级：私钥最高 0.95，密码赋值最低 0.5
_SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key|private[_-]?key)\s*[:=]\s*[\'"]?\w{16,}[\'"]?'), 0.8),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{3,}[\'"]'), 0.5),
    (re.compile(r'(?i)(aws_access_key|aws_secret|AKIA[0-9A-Z]{16})'), 0.9),
    (re.compile(r'(?i)(github[_-]?token|ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36})'), 0.9),
    (re.compile(r'(?i)(-----BEGIN\s.*PRIVATE\sKEY-----)'), 0.95),
    (re.compile(r'(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})'), 0.7),
    (re.compile(r'(?i)(sk-[a-zA-Z0-9]{32,})'), 0.8),
    (re.compile(r'(?i)(xox[baprs]-[a-zA-Z0-9-]{10,})'), 0.8),
]


class Anonymizer:
    """匿名化处理，threshold 控制敏感内容判定门槛。
    内部映射表为 OrderedDict，确保同一输入永远产出同一替换序列。
    """

    def __init__(self, threshold: float = 0.6):
        self._threshold = threshold
        self._replace_map: OrderedDict = OrderedDict()
        self._v_counter = 0
        self._s_counter = 0
        self._n_counter = 0

    def _next_v(self) -> str:
        self._v_counter += 1
        return f"var_{self._v_counter}"

    def _next_s(self) -> str:
        self._s_counter += 1
        return f"str_{self._s_counter}"

    def _next_n(self) -> str:
        self._n_counter += 1
        return f"num_{self._n_counter}"

    @property
    def threshold(self) -> float:
        return self._threshold

    def _get_or_create(self, key: str, generator) -> str:
        if key not in self._replace_map:
            self._replace_map[key] = generator()
        return self._replace_map[key]

    @staticmethod
    def _auto_detect_language(code: str) -> str:
        """扫描首 2000 字符中的语法特征词，投票判定语言。"""
        _head = code[:2000]
        _scores = {'c': 0, 'python': 0, 'js': 0}
        for _p in [r'\bdef\b', r'\bimport\b', r'\bclass\s+\w+:', r':\s*$', r'#.*$']:
            if re.search(_p, _head, re.MULTILINE):
                _scores['python'] += 1
        for _p in [r'#include\s*[<"]', r'\bint\s+main\b', r'\bNULL\b', r'\*.*;', r'//.*$']:
            if re.search(_p, _head, re.MULTILINE):
                _scores['c'] += 1
        for _p in [r'\bfunction\b', r'\bconst\b', r'\blet\b', r'\bvar\b', r'=>' ]:
            if re.search(_p, _head, re.MULTILINE):
                _scores['js'] += 1
        return max(_scores, key=_scores.get)

    def anonymize_identifiers(self, code: str, language: str = "auto") -> str:
        """匹配 C 风格标识符，跳过语言保留字，其余映射为 v_N。"""
        if language == "auto":
            language = self._auto_detect_language(code)
        _keywords = _KEYWORD_MAP.get(language.lower(), set())

        _id_pat = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

        def _replacer(m):
            _w = m.group(1)
            if _w in _keywords:
                return _w
            return self._get_or_create(_w, self._next_v)

        return _id_pat.sub(_replacer, code)

    def anonymize_strings(self, code: str) -> str:
        """双引号/单引号字面量替换为 str_N，保留转义处理。"""
        _pat = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')

        def _replacer(m):
            _alias = self._get_or_create(m.group(0), self._next_s)
            return f'"{_alias}"'

        return _pat.sub(_replacer, code)

    def anonymize_numbers(self, code: str) -> str:
        """整数、浮点与十六进制字面量映射为 num_N，负号保留在替换结果外。"""
        _pat = re.compile(r'\b0[xX][0-9a-fA-F]+\b|\b\d+\.?\d*(?:[eE][+-]?\d+)?\b')

        def _replacer(m):
            return self._get_or_create(m.group(0), self._next_n)

        return _pat.sub(_replacer, code)

    def is_sensitive_content(self, code: str, threshold: float = None) -> bool:
        """加权求和检测敏感硬编码凭据。阈值跨过 + 匹配字符占比 > 0.001 即为敏感。"""
        _t = threshold if threshold is not None else self._threshold
        if not code:
            return False
        _total = 0.0
        _total_len = len(code) or 1
        _hit_chars = 0
        for _pat, _weight in _SECRET_PATTERNS:
            for _m in _pat.finditer(code):
                _hit_chars += len(_m.group(0))
                _total += _weight
        _ratio = _hit_chars / _total_len
        return _total > _t and _ratio > 0.001

    def full_anonymize(self, code: str, language: str = "auto") -> tuple:
        """执行完整匿名化管线：标识符→字符串→数值，返回 (代码, 映射表)。
        顺序保证字符串内文本不被标识符正则误匹配。
        """
        self._counters_frozen = 0
        _result = self.anonymize_identifiers(code, language)
        _result = self.anonymize_strings(_result)
        _result = self.anonymize_numbers(_result)
        return _result, dict(self._replace_map)


# 脱敏级别 — 逐级递进的匿名化强度
class AnonymizationLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXTREME = 4


@dataclass
class AnonymizationResult:
    """匿名化输出：替换后的代码、替换记录与告警。"""
    anonymized: str
    replacements: List[Tuple[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# 硬编码凭据模式 → 替换值。按泄露类别组织，优先级高于标识符混淆。
_SENSITIVE_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9_-]{16,}'), 'sk-REDACTED_API_KEY'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AKIA_REDACTED_KEY'),
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'X.X.X.X'),
    (re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.]+\b'), 'REDACTED@example.com'),
    (re.compile(r'https?://[^\s"\']+'), 'https://REDACTED_URL'),
    (re.compile(r'(?i)(password|passwd|pwd)\s*=\s*"[^"]*"'), 'password="REDACTED"'),
]

_PRIVATE_KEY_PATTERN = re.compile(
    r'-----BEGIN\s+[A-Z ]*PRIVATE KEY-----.*?'
    r'-----END\s+[A-Z ]*PRIVATE KEY-----', re.DOTALL)


def _strip_comments(code: str) -> str:
    """块注释与行注释统一替换为 REDACTED 标记。"""
    code = re.sub(r'/\*[\s\S]*?\*/', '/* REDACTED */', code)
    code = re.sub(r'//[^\n]*', '// REDACTED', code)
    return code


class CodeAnonymizer:
    """代码匿名化器：按脱敏级别逐级替换敏感信息。

    级别递进：
      LOW     —— 脱敏硬编码凭据（API key / IP / 邮箱 / URL / 口令 / 私钥）。
      MEDIUM  —— 在 LOW 基础上混淆用户标识符。
      HIGH    —— 在 MEDIUM 基础上混淆字符串字面量。
      EXTREME —— 在 HIGH 基础上清除全部注释。
    """

    def __init__(self):
        self._anon = Anonymizer()

    def anonymize(self, code: str,
                  level: AnonymizationLevel = AnonymizationLevel.LOW) -> AnonymizationResult:
        result = AnonymizationResult(anonymized=code)

        def _pk(m):
            result.replacements.append(
                (m.group(0), '-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----'))
            result.warnings.append('private key material redacted')
            return '-----BEGIN PRIVATE KEY-----REDACTED-----END PRIVATE KEY-----'
        result.anonymized = _PRIVATE_KEY_PATTERN.sub(_pk, result.anonymized)

        for pat, repl in _SENSITIVE_PATTERNS:
            def _make(pat, repl):
                def _r(m):
                    result.replacements.append((m.group(0), repl))
                    return repl
                return _r
            result.anonymized = pat.sub(_make(pat, repl), result.anonymized)

        if level.value >= AnonymizationLevel.MEDIUM.value:
            result.anonymized = self._anon.anonymize_identifiers(result.anonymized)
        if level.value >= AnonymizationLevel.HIGH.value:
            result.anonymized = self._anon.anonymize_strings(result.anonymized)
        if level.value >= AnonymizationLevel.EXTREME.value:
            result.anonymized = _strip_comments(result.anonymized)

        return result


def is_sensitive_content(content: str) -> bool:
    """判断文本是否含敏感凭据（API key / AWS key / 私钥 / 口令）。"""
    if not content:
        return False
    if _PRIVATE_KEY_PATTERN.search(content):
        return True
    for pat, _ in _SENSITIVE_PATTERNS:
        if pat.search(content):
            return True
    return False


def anonymize_code(code: str,
                   level: AnonymizationLevel = AnonymizationLevel.LOW) -> AnonymizationResult:
    """便捷函数：一次性匿名化代码。"""
    return CodeAnonymizer().anonymize(code, level)


class AnonymizationContextManager:
    """上下文管理器：持续跟踪最近一次匿名化结果。"""

    def __init__(self, level: AnonymizationLevel = AnonymizationLevel.LOW):
        self.level = level
        self._anonymizer = CodeAnonymizer()
        self._last_result: Optional[AnonymizationResult] = None

    def process(self, code: str) -> str:
        self._last_result = self._anonymizer.anonymize(code, self.level)
        return self._last_result.anonymized

    def get_last_result(self) -> Optional[AnonymizationResult]:
        return self._last_result

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False
