"""C 解析器 — 词法/表达式/语句级解析与语句模型。

声明中的初始化提升为赋值语句, 使数据流统一处理 buf = malloc(n)。
表达式解析由 exprparse 提供; 语句模型由 stmts 提供。
"""

# TODO: 补充 do-while 与 for-init 三目表达式, 覆盖更广的控制流


from typing import List, Optional

from heapov.clexer import Token, tokenize, strip_suffixes
from heapov.expr_ast import Expr, Binary, Call
from heapov.exprparse import (
    ExprParserMixin, ParseError,
    _TYPE_WORDS, _STRUCT_KEYWORDS, _ASSIGN_OPS,
)
from heapov.stmts import (
    Assign, CallStmt, ExprStmt, If, For, While, Return, Block, Decl, Func,
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
    'BOOL', 'DWORD', 'WORD', 'BYTE', 'HANDLE',
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


class CParser(ExprParserMixin):
    def __init__(self, src: str):
        self._toks = tokenize(src)
        self._i = 0
        self._str_seq = 0
        self._str_lits: dict = {}
    def _peek(self) -> Optional[Token]:
        return self._toks[self._i] if self._i < len(self._toks) else None
    def _next(self) -> Optional[Token]:
        t = self._peek()
        if t is not None:
            self._i += 1
        return t
    def _at(self, v: str) -> bool:
        t = self._peek()
        return t is not None and t.value == v
    def _eat(self, v: str) -> bool:
        if self._at(v):
            self._i += 1
            return True
        return False
    def _expect(self, v: str) -> Token:
        t = self._next()
        if t is None or t.value != v:
            raise ParseError(f'expect {v!r} at pos {t.pos if t else -1}')
        return t

    def parse(self) -> List[Func]:
        funcs: List[Func] = []
        while self._peek() is not None:
            start = self._i
            f = self._parse_function()
            if f is not None:
                funcs.append(f)
            elif self._i == start:
                # 未消费任何 token: 强制前进, 避免死循环
                self._i += 1
        return funcs

    def _parse_function(self) -> Optional[Func]:
        """解析 TYPE name(params) {body}; 无函数体或 typedef 时跳过。"""
        start = self._i
        base_type = self._parse_type()
        if not base_type:
            self._i = start
            return None
        while self._eat('*'):
            pass  # 函数返回指针: TYPE * name(...)
        if self._peek() is None or self._peek().kind != 'id':
            self._i = start
            return None
        name_tok = self._next()
        if self._at(';'):
            self._next()  # 原型声明
            return None
        if not self._eat('('):
            self._skip_decl_tail()  # 全局变量声明
            return None
        params = self._parse_params()
        self._expect(')')
        if self._at(';'):
            self._next()
            return None
        if not self._at('{'):
            raise ParseError(f'expected body for {name_tok.value}')
        body = self._parse_block()
        return Func(name_tok.value, params, body, name_tok.pos)

    def _skip_decl_tail(self) -> None:
        depth = 0
        while self._peek() is not None:
            v = self._peek().value
            if v == ';' and depth == 0:
                self._next()
                return
            if v in '({[':
                depth += 1
            elif v in ')}]':
                depth -= 1
            self._next()

    def _parse_params(self) -> List[str]:
        names: List[str] = []
        if self._at(')'):
            return names
        while True:
            self._parse_type()
            while self._eat('*'):
                pass
            if self._at('...'):
                self._next()  # 变参: 终止参数列表
                break
            if self._peek() is not None and self._peek().kind == 'id':
                names.append(self._next().value)
            while self._at('['):
                self._next()
                if self._peek() is not None and self._peek().kind == 'num':
                    self._next()
                self._eat(']')
            if not self._eat(','):
                break
        return names

    def _parse_type(self) -> str:
        """消费类型前缀, 返回 base 类型名(可能为空)。"""
        words: List[str] = []
        while True:
            t = self._peek()
            if t is None:
                break
            if t.is_kw('struct') or t.is_kw('union') or t.is_kw('enum'):
                self._next()
                words.append(t.value)
                if self._peek() is not None and self._peek().kind == 'id':
                    self._next()  # struct tag
                if self._at('{'):
                    self._skip_braced()
                continue
            if t.kind == 'id' and t.value in _TYPE_WORDS:
                self._next()
                words.append(t.value)
                continue
            break
        return ' '.join(words)

    def _skip_braced(self) -> None:
        self._expect('{')
        depth = 1
        while depth > 0:
            t = self._next()
            if t is None:
                break
            if t.value == '{':
                depth += 1
            elif t.value == '}':
                depth -= 1

    def _looks_like_type_start(self) -> bool:
        t = self._peek()
        if t is None:
            return False
        if t.kind == 'id' and t.value in _TYPE_WORDS | _STRUCT_KEYWORDS:
            return True
        if t.kind == 'id':
            nxt = self._toks[self._i + 1] if self._i + 1 < len(self._toks) else None
            return nxt is not None and (nxt.kind == 'id' or nxt.value == '*')
        return False

    def _parse_block(self) -> Block:
        self._expect('{')
        blk = Block(pos=self._toks[self._i - 1].pos)
        while self._peek() is not None and not self._at('}'):
            stmt = self._parse_statement()
            if stmt is not None:
                blk.stmts.append(stmt)
        self._expect('}')
        return blk

    def _parse_statement(self):
        t = self._peek()
        if t is None:
            return None
        if t.value == '{':
            return self._parse_block()
        if t.value == ';':
            self._next()
            return None
        if t.is_kw('if'):
            return self._parse_if()
        if t.is_kw('for'):
            return self._parse_for()
        if t.is_kw('while'):
            self._next()
            self._expect('(')
            cond = self._parse_expr()
            self._expect(')')
            body = self._parse_statement()
            return While(cond, body, t.pos)
        if t.is_kw('return'):
            self._next()
            if not self._at(';'):
                val = self._parse_expr()
            else:
                val = None
            self._expect(';')
            return Return(val, t.pos)
        if t.is_kw('break') or t.is_kw('continue') or t.is_kw('goto'):
            while self._peek() is not None and not self._at(';'):
                self._next()
            self._eat(';')
            return None
        if self._looks_like_type_start():
            return self._parse_declaration()
        return self._parse_expr_statement()

    def _parse_if(self) -> If:
        pos = self._next().pos
        self._expect('(')
        cond = self._parse_expr()
        self._expect(')')
        then_b = self._parse_statement()
        else_b = None
        if self._peek() is not None and self._peek().is_kw('else'):
            self._next()
            else_b = self._parse_statement()
        return If(cond, then_b, else_b, pos)

    def _parse_for(self) -> For:
        pos = self._next().pos
        self._expect('(')
        init = None
        if not self._at(';'):
            if self._looks_like_type_start():
                ds = self._parse_declaration(require_semi=False)
                init = ds[0] if ds else None
            else:
                init = self._parse_expr()
        self._expect(';')
        cond = None
        if not self._at(';'):
            cond = self._parse_expr()
        self._expect(';')
        incr = None
        if not self._at(')'):
            incr = self._parse_expr()
        self._expect(')')
        body = self._parse_statement()
        return For(init, cond, incr, body, pos)

    def _parse_declaration(self, require_semi: bool = True) -> List[Decl]:
        base_type = self._parse_type()
        decls: List[Decl] = []
        while True:
            is_ptr = False
            while self._eat('*'):
                is_ptr = True
            name_tok = self._next()
            array_size = None
            if self._at('['):
                self._next()
                if self._peek() is not None and self._peek().kind == 'num':
                    array_size = int(strip_suffixes(self._next().value))
                self._eat(']')
            init = None
            if self._peek() is not None and self._peek().value in _ASSIGN_OPS:
                self._next()
                if self._at('{'):
                    self._skip_braced()
                else:
                    init = self._parse_expr()
            decls.append(Decl(name_tok.value, base_type, is_ptr,
                              array_size, init, name_tok.pos))
            if not self._eat(','):
                break
        if require_semi:
            self._expect(';')
        return decls

    def _parse_expr_statement(self):
        e = self._parse_expr()
        self._expect(';')
        if isinstance(e, Call):
            return CallStmt(e, 0)
        if isinstance(e, Binary) and e.op in _ASSIGN_OPS:
            return Assign(e.left, e.op, e.right, 0)
        return ExprStmt(e, 0)

def parse_source(src: str) -> List[Func]:
    """解析 C 源码, 返回函数列表。解析失败返回空列表(不中断)。"""
    try:
        return CParser(src).parse()
    except ParseError:
        return []

def parse_source_full(src: str):
    """解析 C 源码, 返回 (funcs, 字符串字面量表)。"""
    try:
        p = CParser(src)
        funcs = p.parse()
        return funcs, dict(p._str_lits)
    except ParseError:
        return [], {}
