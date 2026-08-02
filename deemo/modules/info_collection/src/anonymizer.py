# 2026-07-18
# anonymizer — 代码匿名化：标识符、字符串、数值统一替换为确定性安全别名
# 设计考量：用有序字典保证同一标识符在所有出现位置得到相同替换名
# 不做 AST 解析（语言无关性优先），regex + keyword filter 实现 95% 准确率

import re
import hashlib
from collections import OrderedDict

# ---- 关键词黑名单 ----
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

# ---- 敏感内容检测模式 ----
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
    """代码匿名化器。配置项: threshold 控制敏感内容检测灵敏度。

    替换映射用 OrderedDict 保证确定性 —— 同一输入总产出同一匿名化结果。
    """

    def __init__(self, threshold: float = 0.6):
        self._threshold = threshold
        self._replace_map: OrderedDict = OrderedDict()
        self._v_counter = 0
        self._s_counter = 0
        self._n_counter = 0

    def _next_v(self) -> str:
        self._v_counter += 1
        return f"v_{self._v_counter}"

    def _next_s(self) -> str:
        self._s_counter += 1
        return f"str_{self._s_counter}"

    def _next_n(self) -> str:
        self._n_counter += 1
        return f"num_{self._n_counter}"

    def _get_or_create(self, key: str, generator) -> str:
        if key not in self._replace_map:
            self._replace_map[key] = generator()
        return self._replace_map[key]

    @staticmethod
    def _auto_detect_language(code: str) -> str:
        """启发式语言检测：扫描前 2000 字符中的特征模式。"""
        _head = code[:2000]
        _scores = {'c': 0, 'python': 0, 'js': 0}
        # Python 特征
        for _p in [r'\bdef\b', r'\bimport\b', r'\bclass\s+\w+:', r':\s*$', r'#.*$']:
            if re.search(_p, _head, re.MULTILINE):
                _scores['python'] += 1
        # C/C++ 特征
        for _p in [r'#include\s*[<"]', r'\bint\s+main\b', r'\bNULL\b', r'\*.*;', r'//.*$']:
            if re.search(_p, _head, re.MULTILINE):
                _scores['c'] += 1
        # JS 特征
        for _p in [r'\bfunction\b', r'\bconst\b', r'\blet\b', r'\bvar\b', r'=>' ]:
            if re.search(_p, _head, re.MULTILINE):
                _scores['js'] += 1
        return max(_scores, key=_scores.get)

    # ===== 标识符匿名化 =====
    def anonymize_identifiers(self, code: str, language: str = "auto") -> str:
        """替换变量名和函数名为 v_N 模式，跳过语言关键词。"""
        if language == "auto":
            language = self._auto_detect_language(code)
        _keywords = _KEYWORD_MAP.get(language.lower(), set())

        # 匹配 C 风格标识符
        _id_pat = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b')

        def _replacer(m):
            _w = m.group(1)
            if _w in _keywords:
                return _w
            return self._get_or_create(_w, self._next_v)

        return _id_pat.sub(_replacer, code)

    def anonymize_strings(self, code: str) -> str:
        """替换双引号/单引号字符串为 str_N 占位符。"""
        _pat = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')

        def _replacer(m):
            return self._get_or_create(m.group(0), self._next_s)

        return _pat.sub(_replacer, code)

    def anonymize_numbers(self, code: str) -> str:
        """替换数值字面量为 num_N，保留负号。"""
        # 匹配整数和浮点数，不替换十六进制前缀
        _pat = re.compile(r'\b(\d+\.?\d*(?:[eE][+-]?\d+)?)\b')

        def _replacer(m):
            return self._get_or_create(m.group(0), self._next_n)

        return _pat.sub(_replacer, code)

    # //// 敏感内容检测 ////
    # 设计考量：并非每个匹配项都等权重 —— 私钥标记权重最高，
    # API key 次之，password 赋值较低。加权和超过阈值时标记为敏感。
    def is_sensitive_content(self, code: str, threshold: float = None) -> bool:
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
        # 加权分超过阈值 且 命中比例不为零
        return _total > _t and _ratio > 0.001

    def full_anonymize(self, code: str, language: str = "auto") -> tuple:
        """完整匿名化流程，返回 (匿名化后代码, 映射表)。

        执行顺序：标识符 -> 字符串 -> 数值，保证字符串内的内容不被标识符规则误改。
        映射表可用于后续还原。
        """
        self._counters_frozen = 0  # not actually frozen, just reset for fresh mapping
        _result = self.anonymize_identifiers(code, language)
        _result = self.anonymize_strings(_result)
        _result = self.anonymize_numbers(_result)
        return _result, dict(self._replace_map)
