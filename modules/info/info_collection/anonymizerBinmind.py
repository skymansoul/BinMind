"""代码脱敏：将标识符与字面量替换为确定性安全别名，用于外部分享审计。"""

import re
import ast
import hashlib as _hl
import random as _r
import string as _s

name = "CodeAnonymizer"
module = "anonymizerBinmind"

# 脱敏深度等级：NONE / PARTIAL（仅标识符）/ FULL（含字符串与数值）


class AnonymizationLevel:
    NONE = "none"
    PARTIAL = "partial"       # 仅函数与变量名
    FULL = "full"             # 标识符 + 字符串 + 数值字面量


_LEVEL_HIERARCHY = {AnonymizationLevel.NONE: 0,
                    AnonymizationLevel.PARTIAL: 1,
                    AnonymizationLevel.FULL: 2}


def _indistinguishable_char(char):
    """以原字符为种子生成同类替换字符，保持大小写/数字类别不变。"""
    r = _r.Random(ord(char) + 0xCAFE)
    if char.isupper():
        return r.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    if char.islower():
        return r.choice('abcdefghijklmnopqrstuvwxyz')
    if char.isdigit():
        return r.choice('0123456789')
    return char


def _anonymize_string(orig: str) -> str:
    """字符串字面量 → 保长非确定性别名，首字符作为类型种子。"""
    length = len(orig)
    sb = [_indistinguishable_char(c) if _r.getrandbits(1) else c for c in orig]
    seed_char = _indistinguishable_char(orig[0]) if orig else 's'
    return f'str_{seed_char}_{length}'


def _anonymize_number(val_str: str):
    """数值字面量 → XOR 掩码混淆（0xDEADBEEF 取低31位）。"""
    try:
        v = int(val_str, 0)
        return str(v ^ 0xDEADBEEF & 0x7FFFFFFF)
    except ValueError:
        return '0xCAFE'


# 编译后的词法单元匹配模式

_FUNCTION_RE = re.compile(
    r'\b(?:[a-zA-Z_]\w*)\s*(?=\()'
)
_VARIABLE_RE = re.compile(
    r'\b([a-zA-Z_]\w*)\b'
)
_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
)
_NUMBER_RE = re.compile(
    r'\b(?:0x[0-9a-fA-F]+|\d+)\b'
)
_PREPROC_RE = re.compile(
    r'^\s*#\s*(?:include|define|ifdef|ifndef|endif|pragma|error|warning).*$',
    re.MULTILINE
)

# 不可匿名化的保留字集合 — C/C++/Python 关键字及常见类型别名
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
    """前缀冲突消解：追加随机小写字母直到与已注册别名无冲突。"""
    prefixes = [sample]
    while any(sample in r for r in registered):
        sample = sample + _r.choice(_s.ascii_lowercase)
    return sample


# 信息密度辅助函数：区分 API key / token / base64 与自然语言文本


def _compute_info_density(text: str) -> float:
    """高信息密度字符占比。十六进制数字、特殊符号、大写字母的覆盖比例。

    自然语言文本通常 < 0.35，API key / token / base64 显著偏高。
    替代纯模式计数，降低误报率。
    """
    if not text:
        return 0.0
    n = len(text)
    high_info = sum(1 for c in text if c.isdigit() or c in ':/\\@._-+=' or c.isupper())
    return high_info / n


class CodeAnonymizer:
    """源码脱敏器：标识符、字符串、数值字面量 → 确定性安全别名。"""

    def __init__(self):
        self._mapping = {}           # 原始标识 → 匿名化标识 查找表
        self._level = AnonymizationLevel.FULL
        self._func_cnt = 0
        self._var_cnt = 0
        self._preserved_lines = {}   # 行号 → 原始文本（预处理器行不脱敏）

    def anonymize(self, code, level=AnonymizationLevel.FULL):
        """入口：源码 → 安全可分享的脱敏表示。"""
        if not code:
            return code
        if _LEVEL_HIERARCHY.get(level, 2) <= _LEVEL_HIERARCHY[AnonymizationLevel.NONE]:
            return code

        self._level = level
        self._mapping.clear()

        lines = code.split('\n')
        preprocessor_indices = set()

        # 锁定预处理器指令行：不做任何替换
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
        """函数名/变量名 → var_NNNN 或 首字母+序号。保留字不处理。"""
        def replacer(m):
            word = m.group(1)
            if not word:
                return m.group(0)
            if word.lower() in _RESERVED:
                return m.group(0)
            if word in self._mapping:
                return self._mapping[word]

            if word[0].isupper():
                # 首字母大写 → 可能为类型/类名
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


# 旧版兼容别名（向后兼容）
AnonymizationContextManager = type('AnonymizationContextManager', (), {
    '__init__': lambda self: None,
    '__enter__': lambda self: CodeAnonymizer(),
    '__exit__': lambda *_: None,
})

anonymize_code = CodeAnonymizer().anonymize


def auto_select_level(code: str) -> str:
    """内容感知等级选择：按敏感模式密度自动判定 FULL / PARTIAL / NONE。

    检测信号：十六进制常量密度、API key 模式、硬编码 URL。
    任一信号超阈值 → FULL，中密度 → PARTIAL，低密度 → NONE。
    """
    if not code:
        return AnonymizationLevel.NONE
    lines = code.split('\n')
    total_lines = max(1, len(lines))
    hex_cnt = len(re.findall(r'0x[0-9a-fA-F]{6,}', code))
    url_cnt = len(re.findall(r'https?://|ftp://', code))
    key_cnt = len(re.findall(r'(?i)(api[_-]?key|secret|token|password)\s*[:=]', code))
    density = (hex_cnt + url_cnt * 3 + key_cnt * 5) / total_lines
    if density > 0.3:
        return AnonymizationLevel.FULL
    if density > 0.08:
        return AnonymizationLevel.PARTIAL
    return AnonymizationLevel.NONE


def is_sensitive_content(text, threshold=0.3):
    """敏感内容启发式分类：加权四维信号 + 信息密度补偿因子。

    信号：URL、文件路径、十六进制常量、邮箱。
    信息密度 > 0.5 时额外 +0.15，捕获 base64 token / 证书指纹等非标准格式。
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
    # 信号四：邮箱
    email_like = len(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text))

    # 信号五：信息密度补偿
    density = _compute_info_density(text)
    density_bonus = 0.15 if density > 0.5 else 0.0

    score = (url_like * 0.1 + path_like * 0.15 + hex_like * 0.05 +
             email_like * 0.2 + density_bonus)
    return score >= threshold
