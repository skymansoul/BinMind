"""轻量 C 词法器 — 只服务本分析器的 C 子集。

跳过注释与空白; 识别 id/num/str/char/punct; 多字符运算符
两字符优先于单字符匹配，避免 <= 被拆成 < 与 =。
"""


from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Token:
    kind: str        # id num str char punct
    value: str
    pos: int         # 源码偏移, 用于报告定位

    def is_kw(self, kw: str) -> bool:
        return self.kind == 'id' and self.value == kw


_TWO_PUNCT = [
    '<<=', '>>=', '...', '->', '++', '--', '<<', '>>', '<=', '>=',
    '==', '!=', '&&', '||', '+=', '-=', '*=', '/=', '%=', '&=',
    '|=', '^=',
]
_ONE_PUNCT = set('+-*/%<>=!&|^~()[]{};,?:.')


class LexError(Exception):
    pass


def tokenize(src: str) -> List[Token]:
    toks: List[Token] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        # 预处理指令行 (#include 等): 整体跳过
        if c == '#':
            j = src.find('\n', i)
            i = n if j < 0 else j + 1
            continue
        # 行注释
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            i = n if j < 0 else j + 1
            continue
        # 块注释
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            continue
        # 标识符/关键字
        if c.isalpha() or c == '_':
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] == '_'):
                j += 1
            toks.append(Token('id', src[i:j], i))
            i = j
            continue
        # 数字
        if c.isdigit() or (c == '.' and i + 1 < n and src[i + 1].isdigit()):
            j = i
            if src[j:j + 2].lower() == '0x':
                j += 2
                while j < n and (src[j] in '0123456789abcdefABCDEF'):
                    j += 1
            else:
                while j < n and (src[j].isdigit() or src[j] == '.'):
                    j += 1
            while j < n and src[j] in 'uUlLfF':
                j += 1
            toks.append(Token('num', src[i:j], i))
            i = j
            continue
        # 字符串字面量
        if c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                if src[j] == '\\':
                    j += 1
                j += 1
            j = min(j + 1, n)
            toks.append(Token('str', src[i:j], i))
            i = j
            continue
        # 字符字面量
        if c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                if src[j] == '\\':
                    j += 1
                j += 1
            j = min(j + 1, n)
            toks.append(Token('char', src[i:j], i))
            i = j
            continue
        # 多字符运算符
        two = src[i:i + 3]
        if two in _TWO_PUNCT:
            toks.append(Token('punct', two, i))
            i += 3
            continue
        two = src[i:i + 2]
        if two in _TWO_PUNCT:
            toks.append(Token('punct', two, i))
            i += 2
            continue
        if c in _ONE_PUNCT:
            toks.append(Token('punct', c, i))
            i += 1
            continue
        # 未知字符: 跳过, 不中断分析
        i += 1
    return toks


def strip_suffixes(num: str) -> str:
    """去掉数字后缀并转为整数(0x/八进制/十进制)。"""
    s = num
    while s and s[-1] in 'uUlLfF':
        s = s[:-1]
    try:
        if s.lower().startswith('0x'):
            return str(int(s, 16))
        return str(int(s, 0))
    except ValueError:
        return '0'
