"""表达式解析 — 优先级爬升 + 一元/后缀/主表达式, 供语句解析器混入。"""

from __future__ import annotations

from typing import List

from heapov.clexer import Token
from heapov.expr_ast import (
    Expr, Const, Var, Neg, Binary, Call, Index, Field, Deref, Addr,
    Sizeof,
)

_BINOPS = {
    '||': 1, '&&': 2, '|': 3, '^': 4, '&': 5,
    '==': 6, '!=': 6, '<': 7, '<=': 7, '>': 7, '>=': 7,
    '<<': 8, '>>': 8, '+': 9, '-': 9,
    '*': 10, '/': 10, '%': 10,
}
_ASSIGN_OPS = {'=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='}

_TYPE_WORDS = frozenset([
    'void', 'char', 'short', 'int', 'long', 'float', 'double',
    'unsigned', 'signed', 'const', 'static', 'register', 'volatile',
    'extern', 'size_t', 'ssize_t', 'int8_t', 'int16_t', 'int32_t',
    'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'bool',
    'BOOL', 'DWORD', 'WORD', 'BYTE', 'HANDLE', 'FILE', 'va_list',
])
_STRUCT_KEYWORDS = frozenset(['struct', 'union', 'enum'])
_TYPE_SIZES = {
    'char': 1, 'signed': 4, 'unsigned': 4, 'short': 2, 'int': 4,
    'long': 8, 'float': 4, 'double': 8, 'void': 1, 'size_t': 8,
    'ssize_t': 8, 'bool': 1,
}


class ParseError(Exception):
    pass


class ExprParserMixin:
    """表达式子解析器。需宿主提供 _peek/_next/_eat/_at/_expect/_parse_type。"""

    def _parse_expr(self) -> Expr:
        e = self._parse_binary(1)
        if self._at('?'):
            self._next()
            a = self._parse_expr()
            self._expect(':')
            b = self._parse_expr()
            e = Call('__ternary__', [e, a, b])
        t = self._peek()
        if t is not None and t.value in _ASSIGN_OPS:
            op = self._next().value
            rhs = self._parse_expr()
            e = Binary(op, e, rhs)
        return e

    def _parse_binary(self, min_prec: int) -> Expr:
        left = self._parse_unary()
        while True:
            t = self._peek()
            if t is None or t.kind != 'punct':
                break
            prec = _BINOPS.get(t.value)
            if prec is None or prec < min_prec:
                break
            self._next()
            right = self._parse_binary(prec + 1)
            left = Binary(t.value, left, right)
        return left

    def _parse_unary(self) -> Expr:
        t = self._peek()
        if t is None:
            raise ParseError('unexpected EOF in expression')
        if t.value == '-':
            self._next()
            return Neg(self._parse_unary())
        if t.value == '+':
            self._next()
            return self._parse_unary()
        if t.value == '!':
            self._next()
            return Binary('==', self._parse_unary(), Const(0))
        if t.value == '~':
            self._next()
            return Binary('^', self._parse_unary(), Const(-1))
        if t.value == '*':
            self._next()
            return Deref(self._parse_unary())
        if t.value == '&':
            self._next()
            return Addr(self._parse_unary())
        if t.value == '++':
            self._next()
            return Binary('+', self._parse_unary(), Const(1))
        if t.value == '--':
            self._next()
            return Binary('-', self._parse_unary(), Const(1))
        return self._parse_postfix()

    def _parse_postfix(self) -> Expr:
        e = self._parse_primary()
        while True:
            if self._at('('):
                self._next()
                args: List[Expr] = []
                if not self._at(')'):
                    while True:
                        args.append(self._parse_expr())
                        if not self._eat(','):
                            break
                self._expect(')')
                if isinstance(e, Var):
                    e = Call(e.name, args)
                else:
                    e = Call('__indirect__', [e] + args)
                continue
            if self._at('['):
                self._next()
                idx = self._parse_expr()
                self._expect(']')
                e = Index(e, idx)
                continue
            if self._at('.'):
                self._next()
                f = self._expect_id()
                e = Field(e, f.value)
                continue
            if self._at('->'):
                self._next()
                f = self._expect_id()
                e = Field(e, f.value)
                continue
            if self._at('++'):
                self._next()
                e = Binary('+', e, Const(1))
                continue
            if self._at('--'):
                self._next()
                e = Binary('-', e, Const(1))
                continue
            break
        return e

    def _expect_id(self) -> Token:
        t = self._next()
        if t is None or t.kind != 'id':
            raise ParseError(f'expect identifier, got {t.value if t else None}')
        return t

    def _parse_primary(self) -> Expr:
        t = self._peek()
        if t is None:
            raise ParseError('unexpected EOF')
        if t.kind == 'num':
            self._next()
            from heapov.clexer import strip_suffixes
            return Const(int(strip_suffixes(t.value)))
        if t.kind == 'str':
            self._next()
            self._str_seq += 1
            name = f'__str__{self._str_seq}'
            self._str_lits[name] = _decode_str(t.value)
            return Var(name)
        if t.kind == 'char':
            self._next()
            return Const(1)
        if t.value == '(':
            # 类型转换 (char*)p / (unsigned)n
            save = self._i
            self._next()
            cast_type = self._parse_type()
            if cast_type:
                while self._eat('*'):
                    pass
                if self._eat(')'):
                    return self._parse_unary()
            self._i = save
            self._next()
            e = self._parse_expr()
            self._expect(')')
            return e
        if t.kind == 'id':
            if t.value == 'sizeof':
                return self._parse_sizeof()
            self._next()
            return Var(t.value)
        raise ParseError(f'unexpected token {t.value!r}')

    def _parse_sizeof(self) -> Expr:
        self._next()  # sizeof
        self._expect('(')
        if self._peek() is not None and self._peek().kind == 'id':
            if self._peek().value in _TYPE_WORDS | _STRUCT_KEYWORDS:
                base = self._parse_type()
                self._expect(')')
                size = _TYPE_SIZES.get(base.strip().split(' ')[-1], 0)
                return Sizeof(base.strip(), size)
        e = self._parse_expr()
        self._expect(')')
        if isinstance(e, Var):
            # sizeof(数组变量): 尺寸由声明处的初始化推导
            return Sizeof(e.name, 0)
        return Sizeof('expr', 0)


def _decode_str(raw: str) -> str:
    """解码 C 字符串字面量(含引号), 返回实际内容。"""
    body = raw[1:-1]
    out = []
    i = 0
    while i < len(body):
        c = body[i]
        if c == '\\' and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == 'n':
                out.append('\n'); i += 2; continue
            if nxt == 't':
                out.append('\t'); i += 2; continue
            if nxt == 'r':
                out.append('\r'); i += 2; continue
            if nxt == '\\':
                out.append('\\'); i += 2; continue
            if nxt == '"':
                out.append('"'); i += 2; continue
            if nxt == '0':
                out.append('\0'); i += 2; continue
            if nxt == 'x' and i + 3 < len(body):
                try:
                    out.append(chr(int(body[i + 2:i + 4], 16)))
                    i += 4; continue
                except ValueError:
                    pass
            out.append(nxt); i += 2; continue
        out.append(c)
        i += 1
    return ''.join(out)
