"""代码匿名化 — 将标识符与字面量替换为确定性安全别名以供外部分享。"""

import re
import ast
import hashlib as _hl
import random as _r
import string as _s

name = "CodeAnonymizer"
module = "anonymizerBinmind"

# ── 匿名化深度等级 ───────────────────────────────────────────────────────

class AnonymizationLevel:
    NONE = "none"
    PARTIAL = "partial"       # 仅函数与变量
    FULL = "full"             # 标识符、字符串、数值字面量


_LEVEL_HIERARCHY = {AnonymizationLevel.NONE: 0,
                    AnonymizationLevel.PARTIAL: 1,
                    AnonymizationLevel.FULL: 2}


def _indistinguishable_char(char):
    """以原始字符为种子，生成同类替换字符。"""
    r = _r.Random(ord(char) + 0xCAFE)
    if char.isupper():
        return r.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    if char.islower():
        return r.choice('abcdefghijklmnopqrstuvwxyz')
    if char.isdigit():
        return r.choice('0123456789')
    return char


def _anonymize_string(orig: str) -> str:
    """为字符串字面量生成保长的非确定性别名。"""
    length = len(orig)
    sb = [_indistinguishable_char(c) if _r.getrandbits(1) else c for c in orig]
    seed_char = _indistinguishable_char(orig[0]) if orig else 's'
    return f'str_{seed_char}_{length}'


def _anonymize_number(val_str: str):
    """通过可逆 XOR 掩码混淆数值字面量。"""
    try:
        v = int(val_str, 0)
        return str(v ^ 0xDEADBEEF & 0x7FFFFFFF)
    except ValueError:
        return '0xCAFE'


# ── 编译后的词法单元匹配模式 ─────────────────────────────────────────────

_FUNCTION_RE = re.compile(
    r'\b(?:[a-zA-Z_]\w*)\s*(?=\()'          # 函数调用点
)
_VARIABLE_RE = re.compile(
    r'\b([a-zA-Z_]\w*)\b'
)
_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'                    # 双引号字符串
    r"|'(?:[^'\\]|\\.)*'"                   # 单引号字符串
)
_NUMBER_RE = re.compile(
    r'\b(?:0x[0-9a-fA-F]+|\d+)\b'
)
_PREPROC_RE = re.compile(
    r'^\s*#\s*(?:include|define|ifdef|ifndef|endif|pragma|error|warning).*$',
    re.MULTILINE
)

# 语言关键字集合 — 不可被匿名化替换
_RESERVED = frozenset({
    # C/C++ 关键字
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
    'break', 'continue', 'return', 'goto', 'typedef', 'struct', 'union',
    'enum', 'sizeof', 'volatile', 'const', 'static', 'extern', 'register',
    'auto', 'void', 'char', 'short', 'int', 'long', 'float', 'double',
    'signed', 'unsigned', 'inline', '__inline', '__attribute__',
    '__declspec', '__asm', '__cdecl', '__stdcall', '__fastcall',
    'class', 'public', 'private', 'protected', 'virtual', 'template',
    'typename', 'namespace', 'using', 'new', 'delete', 'this',
    'try', 'catch', 'throw', 'noexcept', 'nullptr', 'true', 'false',
    # Python 关键字
    'def', 'class', 'import', 'from', 'as', 'with', 'yield', 'lambda',
    'None', 'True', 'False', 'and', 'or', 'not', 'in', 'is',
    'print', 'range', 'len', 'type', 'isinstance', 'hasattr', 'getattr',
    'setattr', 'super', 'self', 'cls',
    # 常见 C 类型别名
    'bool', 'size_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t', 'DWORD', 'HANDLE',
    'HMODULE', 'LPVOID', 'LPCSTR', 'LPCTSTR', 'BOOL',
})


def _resolve_prefix(sample, registered):
    """选择不与已注册标识符冲突的前缀字符串。"""
    prefixes = [sample]
    while any(sample in r for r in registered):
        sample = sample + _r.choice(_s.ascii_lowercase)
    return sample


class CodeAnonymizer:
    """将标识符、字符串及数值字面量替换为非确定性别名。"""

    def __init__(self):
        self._mapping = {}           # 原始标识 → 匿名化标识 查找表
        self._level = AnonymizationLevel.FULL
        self._func_cnt = 0
        self._var_cnt = 0
        self._preserved_lines = {}   # 行号 → 原始文本（预处理器行）

    def anonymize(self, code, level=AnonymizationLevel.FULL):
        """将源码或汇编代码转换为可安全分享的表示形式。"""
        if not code:
            return code
        if _LEVEL_HIERARCHY.get(level, 2) <= _LEVEL_HIERARCHY[AnonymizationLevel.NONE]:
            return code

        self._level = level
        self._mapping.clear()

        lines = code.split('\n')
        preprocessor_indices = set()

        # 固定预处理器指令 — 不可被匿名化
        for i, line in enumerate(lines):
            if _PREPROC_RE.match(line):
                preprocessor_indices.add(i)

        result_lines = []
        for i, line in enumerate(lines):
            if i in preprocessor_indices:
                result_lines.append(line)
                continue
            result_lines.append(self._process_line(line))

        return '\n'.join(result_lines)

    def _process_line(self, line):
        if self._level == AnonymizationLevel.PARTIAL:
            line = self._replace_identifiers(line)
        elif self._level == AnonymizationLevel.FULL:
            line = self._replace_strings(line)
            line = self._replace_numbers(line)
            line = self._replace_identifiers(line)
        return line

    def _replace_identifiers(self, line):
        """将函数名与变量名替换为基于计数器的别名。"""
        def replacer(m):
            word = m.group(1)
            if not word:
                return m.group(0)
            if word.lower() in _RESERVED:
                return m.group(0)
            if word in self._mapping:
                return self._mapping[word]

            if word[0].isupper():
                # 首字母大写 → 可能为类型或类名
                prefix = word[0]
                alias = f'{prefix}{self._func_cnt:04d}'
                self._func_cnt += 1
            else:
                alias = f'var_{self._var_cnt:04d}'
                self._var_cnt += 1

            self._mapping[word] = alias
            return alias

        return _VARIABLE_RE.sub(replacer, line)

    def _replace_strings(self, line):
        def replacer(m):
            orig = m.group(0)
            safe = _anonymize_string(orig[1:-1])
            return f'"{safe}"' if orig.startswith('"') else f"'{safe}'"
        return _STRING_RE.sub(replacer, line)

    def _replace_numbers(self, line):
        return _NUMBER_RE.sub(
            lambda m: _anonymize_number(m.group(0)), line
        )


# ── 旧版便捷别名（保留以维持向后兼容）──────────────────────────────────

AnonymizationContextManager = type('AnonymizationContextManager', (), {
    '__init__': lambda self: None,
    '__enter__': lambda self: CodeAnonymizer(),
    '__exit__': lambda *_: None,
})

anonymize_code = CodeAnonymizer().anonymize


def is_sensitive_content(text, threshold=0.3):
    """启发式分类：估算文本包含敏感代码信息的概率。

    对四个信号维度进行加权：URL、文件路径、十六进制常量、邮箱地址。
    """
    if not text:
        return False
    total_chars = len(text.replace(' ', '').replace('\n', '').replace('\t', ''))
    if total_chars == 0:
        return False
    # 信号一：URL 模式
    url_like = len(re.findall(r'https?://|ftp://|@\w+\.\w+', text))
    # 信号二：文件系统路径
    path_like = len(re.findall(r'[A-Z]:\\|/home/|/var/|/etc/', text))
    # 信号三：十六进制常量
    hex_like = len(re.findall(r'0x[0-9a-fA-F]{8,}', text))
    # 信号四：邮箱地址
    email_like = len(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text))

    score = (url_like * 0.1 + path_like * 0.15 + hex_like * 0.05 + email_like * 0.2)
    return score >= threshold
