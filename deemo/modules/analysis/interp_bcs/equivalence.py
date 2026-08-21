# equivalence.py：神经反编译等价校验（Fine-Grained Equivalence Checking）
#
# 对应论文:
# Fast, Fine-Grained Equivalence Checking for Neural 反编译引擎s -
# [待验证]
#
# 设计意图:
#   反编译产物是对真实语义的近似，不能凭文本相似断言等价。本模块对
#   反编译结果与参考实现做细粒度等价性检查，输出三类结论:
# EQUIVALENT - 符号执行证明全部可达路径输出一致
#     NOT_EQUIVALENT - 采样对拍或符号反例发现可观察差异
# UNKNOWN - 求解器不可用 / 路径爆炸截断 / 解析失败
#   证据链由两部分叠加:
#     (1) 输入采样对拍: 在参数取值范围上随机采样，具体执行两段代码比较输出
#     (2) 符号路径枚举: 将受限 C 子集翻译为 z3 约束，逐路径比较输出表达式
# 可选接入现有 symbolic/symexec_优化器.SymExec优化器.optimize_solve
# 作为路径可行性求解后端，体现与既有符号执行子模块的衔接
#
# 边界条件:
# 解析器仅支持受限 C 子集（整型算术、位运算、比较、//for、
#   声明、赋值、return）。库函数副作用不可模拟-符号执行中把同一
# (被调函数, 实参) 映射为同一符号变量，采样中把调用视为返回 0
# 循环做有界展开，路径数有上限，超出即判 UNKNOWN

import hashlib
import logging
import random
import re
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_MAX_DEFAULT_SAMPLES = 24
_MAX_DEFAULT_PATHS = 12
_MAX_DEFAULT_LOOP_ITERS = 3


class EquivVerdict(Enum):
    EQUIVALENT = 'equivalent'
    NOT_EQUIVALENT = 'not_equivalent'
    UNKNOWN = 'unknown'


@dataclass
class EquivResult:
    """一次等价性检查的完整输出"""
    verdict: EquivVerdict
    evidence: List[str] = field(default_factory=list)
    counterexample: Optional[Dict[str, Any]] = None
    method_used: str = ''            # 'sampling' | 'symbolic' | 'hybrid'
    paths_a: int = 0                 # 函数 A 的符号路径数
    paths_b: int = 0
    samples_run: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'verdict': self.verdict.value,
            'evidence': self.evidence,
            'counterexample': self.counterexample,
            'method_used': self.method_used,
            'paths_a': self.paths_a,
            'paths_b': self.paths_b,
            'samples_run': self.samples_run,
        }


# 词法分析：把受限 C 子集切成 token 流

_TOKEN_PAT = re.compile(r'''
    (?P<WS>\s+)
  | (?P<COMMENT>//[^\n]*|/\*.*?\*/)
  | (?P<STRING>"(?:[^"\\]|\\.)*")
  | (?P<NUM>0[xX][0-9a-fA-F]+|\d+)
  | (?P<ID>[A-Za-z_]\w*)
  | (?P<OP><<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\|=|\^=|\+\+|--|[+\-*/%<>&|^~!?:=;(){},])
''', re.VERBOSE)


def _tokenize(code: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    while pos < len(code):
        m = _TOKEN_PAT.match(code, pos)
        if not m:
            pos += 1
            continue
        kind = m.lastgroup
        val = m.group()
        if kind not in ('WS', 'COMMENT'):
            tokens.append((kind, val))
        pos = m.end()
    return tokens


# 表达式 AST 与递归下降解析器
# AST 形式:
#   ('num', int) | ('id', name) | ('call', name, [args])
#   ('unop', op, operand) | ('binop', op, l, r) | ('tern', c, t, f)
#   ('cast', ctype, operand)
# 优先级自低到高:?: || && | ^ & ==!= < <= > >= << >> + - * / % 一元


class _ExprParser:
    def __init__(self, tokens: List[Tuple[str, str]], pos: int = 0):
        self.tokens = tokens
        self.pos = pos

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> Optional[Tuple[str, str]]:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def expect_op(self, *ops: str) -> Optional[str]:
        tok = self.peek()
        if tok and tok[0] == 'OP' and tok[1] in ops:
            self.pos += 1
            return tok[1]
        return None

    def parse(self) -> Any:
        return self.parse_ternary()

    def parse_ternary(self) -> Any:
        cond = self.parse_or()
        if self.expect_op('?'):
            t = self.parse()
            self.expect_op(':')
            f = self.parse()
            return ('tern', cond, t, f)
        return cond

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.expect_op('||'):
            left = ('binop', '||', left, self.parse_and())
        return left

    def parse_and(self) -> Any:
        left = self.parse_bitor()
        while self.expect_op('&&'):
            left = ('binop', '&&', left, self.parse_bitor())
        return left

    def parse_bitor(self) -> Any:
        left = self.parse_bitxor()
        while self.expect_op('|'):
            left = ('binop', '|', left, self.parse_bitxor())
        return left

    def parse_bitxor(self) -> Any:
        left = self.parse_bitand()
        while self.expect_op('^'):
            left = ('binop', '^', left, self.parse_bitand())
        return left

    def parse_bitand(self) -> Any:
        left = self.parse_equality()
        while self.expect_op('&'):
            left = ('binop', '&', left, self.parse_equality())
        return left

    def parse_equality(self) -> Any:
        left = self.parse_rel()
        while True:
            op = self.expect_op('==', '!=')
            if op is None:
                break
            left = ('binop', op, left, self.parse_rel())
        return left

    def parse_rel(self) -> Any:
        left = self.parse_shift()
        while True:
            op = self.expect_op('<', '<=', '>', '>=')
            if op is None:
                break
            left = ('binop', op, left, self.parse_shift())
        return left

    def parse_shift(self) -> Any:
        left = self.parse_add()
        while True:
            op = self.expect_op('<<', '>>')
            if op is None:
                break
            left = ('binop', op, left, self.parse_add())
        return left

    def parse_add(self) -> Any:
        left = self.parse_mul()
        while True:
            op = self.expect_op('+', '-')
            if op is None:
                break
            left = ('binop', op, left, self.parse_mul())
        return left

    def parse_mul(self) -> Any:
        left = self.parse_unary()
        while True:
            op = self.expect_op('*', '/', '%')
            if op is None:
                break
            left = ('binop', op, left, self.parse_unary())
        return left

    def parse_unary(self) -> Any:
        tok = self.peek()
        if tok and tok[0] == 'OP' and tok[1] in ('-', '!', '~'):
            self.next()
            return ('unop', tok[1], self.parse_unary())
        if tok and tok[0] == 'OP' and tok[1] in ('++', '--'):
            # 前缀自增/自减
            self.next()
            name_tok = self.next()
            name = name_tok[1] if name_tok else '_'
            return ('preinc' if tok[1] == '++' else 'predec', name)
        return self.parse_postfix()

    def parse_postfix(self) -> Any:
        atom = self.parse_atom()
        tok = self.peek()
        if tok and tok[0] == 'OP' and tok[1] == '(':
            # 函数调用
            self.next()
            args: List[Any] = []
            if not (self.peek() and self.peek()[0] == 'OP' and self.peek()[1] == ')'):
                args.append(self.parse())
                while self.expect_op(','):
                    args.append(self.parse())
            self.expect_op(')')
            return ('call', atom[1] if atom[0] == 'id' else '?', args)
        if tok and tok[0] == 'OP' and tok[1] in ('++', '--'):
            # 后缀自增/自减：返回旧值，副作用由执行器应用
            self.next()
            if atom[0] == 'id':
                return ('postinc' if tok[1] == '++' else 'postdec', atom[1])
            return atom
        return atom

    def parse_atom(self) -> Any:
        tok = self.next()
        if tok is None:
            return ('num', 0)
        if tok[0] == 'NUM':
            if tok[1].lower().startswith('0x'):
                return ('num', int(tok[1], 16))
            return ('num', int(tok[1], 10))
        if tok[0] == 'ID':
            nxt = self.peek()
            if nxt and nxt[0] == 'OP' and nxt[1] == '(':
                # 类型转换风格: (unsigned) expr 已由 unary 处理，这里处理 name(.)
                self.next()
                args: List[Any] = []
                if not (self.peek() and self.peek()[0] == 'OP' and self.peek()[1] == ')'):
                    args.append(self.parse())
                    while self.expect_op(','):
                        args.append(self.parse())
                self.expect_op(')')
                return ('call', tok[1], args)
            return ('id', tok[1])
        if tok[0] == 'OP' and tok[1] == '(':
            e = self.parse()
            self.expect_op(')')
            return e
        # 未知 token 按 0 处理，保持解析健壮
        return ('num', 0)


# 语句解析：把函数体解析为语句树
# 语句形式:
# block / (cond,, else) / / for / 返回 / decl / assign /
#   expr / break / continue


class _StmtParser:
    def __init__(self, code: str):
        self.tokens = _tokenize(code)
        self.pos = 0

    def peek(self, offset: int = 0) -> Optional[Tuple[str, str]]:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def next(self) -> Optional[Tuple[str, str]]:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def expect(self, kind: str, val: Optional[str] = None) -> bool:
        tok = self.peek()
        if tok and tok[0] == kind and (val is None or tok[1] == val):
            self.pos += 1
            return True
        return False

    def parse_function_body(self) -> List[Dict[str, Any]]:
        """定位第一个 '{' 并解析其块体；失败返回空列表"""
        while self.peek() and not (self.peek()[0] == 'OP' and self.peek()[1] == '{'):
            self.next()
        if not self.expect('OP', '{'):
            return []
        return self.parse_block_body()

    def parse_block_body(self) -> List[Dict[str, Any]]:
        stmts: List[Dict[str, Any]] = []
        while self.peek():
            if self.expect('OP', '}'):
                break
            stmt = self.parse_stmt()
            if stmt is not None:
                stmts.append(stmt)
        return stmts

    def parse_stmt(self) -> Optional[Dict[str, Any]]:
        tok = self.peek()
        if tok is None:
            return None
        if tok[0] == 'OP' and tok[1] == '{':
            self.next()
            body = self.parse_block_body()
            return {'kind': 'block', 'body': body}
        if tok[0] == 'ID' and tok[1] == 'if':
            return self.parse_if()
        if tok[0] == 'ID' and tok[1] in ('while', 'for'):
            return self.parse_loop(tok[1])
        if tok[0] == 'ID' and tok[1] == 'return':
            self.next()
            value = None
            if not self.expect('OP', ';'):
                expr_parser = _ExprParser(self.tokens, self.pos)
                value = expr_parser.parse()
                self.pos = expr_parser.pos
                self.expect('OP', ';')
            return {'kind': 'return', 'value': value}
        if tok[0] == 'ID' and tok[1] == 'break':
            self.next()
            self.expect('OP', ';')
            return {'kind': 'break'}
        if tok[0] == 'ID' and tok[1] == 'continue':
            self.next()
            self.expect('OP', ';')
            return {'kind': 'continue'}
        return self.parse_decl_or_expr()

    def parse_if(self) -> Dict[str, Any]:
        self.next()  # if
        self.expect('OP', '(')
        cond_parser = _ExprParser(self.tokens, self.pos)
        cond = cond_parser.parse()
        self.pos = cond_parser.pos
        self.expect('OP', ')')
        then_branch = self.parse_branch_body()
        else_branch = None
        if self.peek() and self.peek()[0] == 'ID' and self.peek()[1] == 'else':
            self.next()
            nxt = self.peek()
            if nxt and nxt[0] == 'ID' and nxt[1] == 'if':
                # else if 链：递归解析为嵌套 if
                else_branch = [self.parse_if()]
            else:
                else_branch = self.parse_branch_body()
        return {'kind': 'if', 'cond': cond, 'then': then_branch, 'else': else_branch}

    def parse_loop(self, kind: str) -> Dict[str, Any]:
        self.next()  # while/for
        self.expect('OP', '(')
        init = None
        cond = None
        update = None
        if kind == 'for':
            # for (init; cond; update)
            init = self.parse_simple_semicolon_stmt()
            cond_parser = _ExprParser(self.tokens, self.pos)
            cond = cond_parser.parse()
            self.pos = cond_parser.pos
            self.expect('OP', ';')
            update = self.parse_loop_update()
            self.expect('OP', ')')
        else:
            cond_parser = _ExprParser(self.tokens, self.pos)
            cond = cond_parser.parse()
            self.pos = cond_parser.pos
            self.expect('OP', ')')
        body = self.parse_branch_body()
        return {'kind': kind, 'init': init, 'cond': cond,
                'update': update, 'body': body}

    def parse_loop_update(self) -> Optional[Any]:
        """解析 for 更新子句：`++` / `--` / ` = + 1` / ` += 1`

        更新子句不是普通表达式-可能含赋值/复合赋值，需在此处特殊处理
        """
        tok = self.peek()
        if tok is None or (tok[0] == 'OP' and tok[1] == ')'):
            return None
        if tok[0] == 'ID' and self.peek(1) and self.peek(1)[0] == 'OP' \
                and self.peek(1)[1] in _ASSIGN_OPS:
            name = self.next()[1]
            op = self.next()[1]
            expr_parser = _ExprParser(self.tokens, self.pos)
            value = expr_parser.parse()
            self.pos = expr_parser.pos
            return ('assignop', name, op, value)
        expr_parser = _ExprParser(self.tokens, self.pos)
        expr = expr_parser.parse()
        self.pos = expr_parser.pos
        return expr

    def parse_simple_semicolon_stmt(self) -> Optional[Dict[str, Any]]:
        """解析 for 初始化语句：声明或赋值，直到 ';'"""
        tok = self.peek()
        if tok is None:
            return None
        if tok[0] == 'OP' and tok[1] == ';':
            self.next()
            return None
        if tok[0] == 'ID' and tok[1] in _TYPE_KEYWORDS:
            return self.parse_decl(allow_semicolon=True)
        return self._parse_assign_or_expr(consume_semicolon=True)

    def parse_branch_body(self) -> List[Dict[str, Any]]:
        if self.expect('OP', '{'):
            return self.parse_block_body()
        stmt = self.parse_stmt()
        return [stmt] if stmt is not None else []

    def parse_decl_or_expr(self) -> Dict[str, Any]:
        tok = self.peek()
        if tok and tok[0] == 'ID' and tok[1] in _TYPE_KEYWORDS:
            return self.parse_decl(allow_semicolon=True)
        return self._parse_assign_or_expr(consume_semicolon=True)

    def _parse_assign_or_expr(self, consume_semicolon: bool) -> Dict[str, Any]:
        """统一解析赋值/复合赋值/自增自减/普通表达式语句"""
        tok = self.peek()
        if tok and tok[0] == 'ID' and self.peek(1) and self.peek(1)[0] == 'OP' \
                and self.peek(1)[1] in _ASSIGN_OPS:
            name = self.next()[1]
            op = self.next()[1]
            expr_parser = _ExprParser(self.tokens, self.pos)
            value = expr_parser.parse()
            self.pos = expr_parser.pos
            if consume_semicolon:
                self.expect('OP', ';')
            if op == '=':
                return {'kind': 'assign', 'target': name, 'value': value}
            return {'kind': 'assignop', 'target': name, 'op': op, 'value': value}
        expr_parser = _ExprParser(self.tokens, self.pos)
        expr = expr_parser.parse()
        self.pos = expr_parser.pos
        if consume_semicolon:
            self.expect('OP', ';')
        if expr[0] == 'binop' and expr[1] == '=' and expr[2][0] == 'id':
            return {'kind': 'assign', 'target': expr[2][1], 'value': expr[3]}
        return {'kind': 'expr', 'value': expr}

    def parse_decl(self, allow_semicolon: bool = True) -> Dict[str, Any]:
        """解析 `int x;` / `int x = expr;` / `char *p =.;` 形式的声明"""
        ctype = self.next()[1]
        # 跳过指针星号
        while self.expect('OP', '*'):
            pass
        name_tok = self.next()
        name = name_tok[1] if name_tok else 'v'
        value = None
        if self.expect('OP', '='):
            expr_parser = _ExprParser(self.tokens, self.pos)
            value = expr_parser.parse()
            self.pos = expr_parser.pos
        if allow_semicolon:
            self.expect('OP', ';')
        return {'kind': 'decl', 'target': name, 'value': value, 'ctype': ctype}


_TYPE_KEYWORDS = frozenset({
    'int', 'char', 'void', 'long', 'short', 'unsigned', 'signed',
    'float', 'double', 'size_t', 'bool',
})

# 赋值运算符集合（含复合赋值），在语句级识别 `ID op= expr`
_ASSIGN_OPS = frozenset({
    '=', '+=', '-=', '*=', '/=', '%=', '<<=', '>>=', '&=', '|=', '^=',
})


def _extract_param_names(code: str) -> List[str]:
    """从函数头提取形参名。`void f(int a, char *buf)` -> ['a', 'buf']"""
    match = re.search(r'\(([^)]*)\)\s*\{', code, re.DOTALL)
    if not match:
        return []
    inner = match.group(1)
    if inner.strip() == 'void':
        return []
    names: List[str] = []
    for part in inner.split(','):
        ids = re.findall(r'[A-Za-z_]\w*', part.strip())
        if len(ids) >= 2:
            names.append(ids[-1])
    return names


# 受限 C 解释器：具体求值（采样对拍用）


class _MiniCInterp:
    """具体求值器：在给定参数输入下执行函数体，返回返回值或 None"""

    def __init__(self, max_loop_iters: int = _MAX_DEFAULT_LOOP_ITERS):
        self.max_loop_iters = max_loop_iters

    def run(self, stmts: List[Dict[str, Any]], params: List[str],
            inputs: List[int]) -> Optional[int]:
        env: Dict[str, int] = {}
        for name, val in zip(params, inputs):
            env[name] = val
        out: Dict[str, Any] = {'value': None}
        self._exec_stmts(stmts, env, out)
        return out['value']

    def _eval(self, ast: Any, env: Dict[str, int]) -> int:
        tag = ast[0]
        if tag == 'num':
            return ast[1]
        if tag == 'id':
            return env.get(ast[1], 0)
        if tag in ('postinc', 'preinc'):
            new_val = env.get(ast[1], 0) + 1
            env[ast[1]] = new_val
            return env.get(ast[1], 0) - 1 if tag == 'postinc' else new_val
        if tag in ('postdec', 'predec'):
            new_val = env.get(ast[1], 0) - 1
            env[ast[1]] = new_val
            return env.get(ast[1], 0) + 1 if tag == 'postdec' else new_val
        if tag == 'unop':
            v = self._eval(ast[2], env)
            if ast[1] == '-':
                return -v
            if ast[1] == '!':
                return 0 if v else 1
            if ast[1] == '~':
                return ~v
            return v
        if tag == 'binop':
            op = ast[1]
            l = self._eval(ast[2], env)
            r = self._eval(ast[3], env)
            return self._apply_binop(op, l, r)
        if tag == 'tern':
            c = self._eval(ast[1], env)
            return self._eval(ast[2], env) if c else self._eval(ast[3], env)
        if tag == 'cast':
            return self._eval(ast[2], env)
        if tag == 'call':
            # 库调用副作用不可模拟；具体求值统一返回 0
            for arg in ast[2]:
                self._eval(arg, env)
            return 0
        return 0

    def _apply_binop(self, op: str, l: int, r: int) -> int:
        if op == '+':
            return l + r
        if op == '-':
            return l - r
        if op == '*':
            return l * r
        if op == '/':
            return int(l / r) if r != 0 else 0
        if op == '%':
            return l % r if r != 0 else 0
        if op == '&':
            return l & r
        if op == '|':
            return l | r
        if op == '^':
            return l ^ r
        if op == '<<':
            return l << r if 0 <= r < 64 else 0
        if op == '>>':
            return l >> r if 0 <= r < 64 else 0
        if op == '==':
            return 1 if l == r else 0
        if op == '!=':
            return 1 if l != r else 0
        if op == '<':
            return 1 if l < r else 0
        if op == '<=':
            return 1 if l <= r else 0
        if op == '>':
            return 1 if l > r else 0
        if op == '>=':
            return 1 if l >= r else 0
        if op == '&&':
            return 1 if l and r else 0
        if op == '||':
            return 1 if l or r else 0
        return 0

    def _exec_stmts(self, stmts: List[Dict[str, Any]], env: Dict[str, int],
                    out: Dict[str, Any]) -> Optional[str]:
        """执行语句列表，返回信号: None(贯穿) / '返回' / 'break' / 'continue'"""
        for stmt in stmts:
            sig = self._exec_stmt(stmt, env, out)
            if sig is not None:
                return sig
        return None

    def _exec_stmt(self, stmt: Dict[str, Any], env: Dict[str, int],
                   out: Dict[str, Any]) -> Optional[str]:
        k = stmt['kind']
        if k == 'block':
            return self._exec_stmts(stmt['body'], env, out)
        if k == 'decl':
            val = self._eval(stmt['value'], env) if stmt.get('value') is not None else 0
            env[stmt['target']] = val
            return None
        if k == 'assign':
            env[stmt['target']] = self._eval(stmt['value'], env)
            return None
        if k == 'assignop':
            op = stmt['op'][:-1]
            cur = env.get(stmt['target'], 0)
            val = self._eval(stmt['value'], env)
            env[stmt['target']] = self._apply_binop(op, cur, val)
            return None
        if k == 'expr':
            self._eval(stmt['value'], env)
            return None
        if k == 'return':
            out['value'] = (self._eval(stmt['value'], env)
                            if stmt.get('value') is not None else None)
            return 'return'
        if k == 'if':
            cond = self._eval(stmt['cond'], env)
            branch = stmt['then'] if cond else stmt.get('else')
            if branch:
                return self._exec_stmts(branch, env, out)
            return None
        if k == 'while':
            iters = 0
            while self._eval(stmt['cond'], env) and iters < self.max_loop_iters:
                iters += 1
                sig = self._exec_stmts(stmt['body'], env, out)
                if sig == 'return':
                    return sig
                if sig == 'break':
                    break
            return None
        if k == 'for':
            if stmt.get('init') is not None:
                self._exec_stmt(stmt['init'], env, out)
            iters = 0
            cond = stmt['cond']
            while (cond is None or self._eval(cond, env)) and iters < self.max_loop_iters:
                iters += 1
                sig = self._exec_stmts(stmt['body'], env, out)
                if sig == 'return':
                    return sig
                if sig == 'break':
                    break
                if stmt.get('update') is not None:
                    self._apply_update(stmt['update'], env)
            return None
        if k == 'break':
            return 'break'
        if k == 'continue':
            return 'continue'
        return None

    def _apply_update(self, update: Any, env: Dict[str, int]) -> None:
        """具体求值 for 更新子句并写入环境"""
        if update[0] in ('postinc', 'preinc'):
            env[update[1]] = env.get(update[1], 0) + 1
        elif update[0] in ('postdec', 'predec'):
            env[update[1]] = env.get(update[1], 0) - 1
        elif update[0] == 'assignop':
            name, op = update[1], update[2]
            cur = env.get(name, 0)
            val = self._eval(update[3], env)
            if op == '=':
                env[name] = val
            else:
                env[name] = self._apply_binop(op[:-1], cur, val)
        else:
            # 普通表达式更新：具体求值以触发潜在副作用
            self._eval(update, env)


# 符号执行：把函数体翻译为 (guard, out) 路径集合


class _SymbolicPathBuilder:
    """在 z3 上枚举受限 C 子集的可达返回路径

    库调用映射为按 (被调函数, 实参规范化串) 键控的独立符号变量
    使两段代码中对同一库函数的相同调用共享同一符号值
    """

    def __init__(self, params: List[str], shared_params: List[Any],
                 max_paths: int, max_loop_iters: int,
                 call_env: Dict[Tuple[str, str], Any]):
        # shared_params: 两个函数共享的"按位置"参数符号变量
        # 形参名不同(变量重命名)时，两函数的输出表达式仍以同一组
        # 符号变量 p0/p1/. 表示，从而可做逐路径对拍
        self.params = params
        self.shared = shared_params
        self.max_paths = max_paths
        self.max_loop_iters = max_loop_iters
        self.call_env = call_env
        self.param_vars: Dict[str, Any] = {}
        for i, p in enumerate(params):
            self.param_vars[p] = shared_params[i] if i < len(shared_params) else 0

# 符号表达式翻译
    def _sym_expr(self, ast: Any, env: Dict[str, Any]) -> Any:
        import z3
        tag = ast[0]
        if tag == 'num':
            return ast[1]
        if tag == 'id':
            return env.get(ast[1], self.param_vars.get(ast[1], 0))
        if tag in ('postinc', 'postdec', 'preinc', 'predec'):
            # 符号求值近似：返回当前值，副作用由语句层应用
            return env.get(ast[1], 0)
        if tag == 'unop':
            v = self._sym_expr(ast[2], env)
            if ast[1] == '!':
                return z3.Not(self._as_bool(v))
            if ast[1] == '~':
                return ~v
            if ast[1] == '-':
                return -v
            return v
        if tag == 'binop':
            op = ast[1]
            l = self._sym_expr(ast[2], env)
            r = self._sym_expr(ast[3], env)
            return self._binop(op, l, r)
        if tag == 'tern':
            import z3
            c = self._as_bool(self._sym_expr(ast[1], env))
            t = self._sym_expr(ast[2], env)
            f = self._sym_expr(ast[3], env)
            return z3.If(c, t, f)
        if tag == 'cast':
            return self._sym_expr(ast[2], env)
        if tag == 'call':
            return self._call_var(ast[1], ast[2], env)
        return 0

    def _as_bool(self, e: Any) -> Any:
        import z3
        if isinstance(e, z3.BoolRef):
            return e
        return e != 0

    def _binop(self, op: str, l: Any, r: Any) -> Any:
        import z3
        if op == '+':
            return l + r
        if op == '-':
            return l - r
        if op == '*':
            return l * r
        if op == '/':
            return z3.If(r != 0, l / r, 0)
        if op == '%':
            return z3.If(r != 0, l % r, 0)
        if op == '&':
            return l & r
        if op == '|':
            return l | r
        if op == '^':
            return l ^ r
        if op == '<<':
            return l << r
        if op == '>>':
            return l >> r
        if op == '==':
            return l == r
        if op == '!=':
            return l != r
        if op == '<':
            return l < r
        if op == '<=':
            return l <= r
        if op == '>':
            return l > r
        if op == '>=':
            return l >= r
        if op == '&&':
            return z3.And(self._as_bool(l), self._as_bool(r))
        if op == '||':
            return z3.Or(self._as_bool(l), self._as_bool(r))
        return 0

    def _call_var(self, name: str, args: List[Any], env: Dict[str, Any]) -> Any:
        import z3
        key = (name, self._canon(args, env))
        if key not in self.call_env:
            self.call_env[key] = z3.Int(f'call_{name}_{len(self.call_env)}')
        return self.call_env[key]

    def _canon(self, args: List[Any], env: Dict[str, Any]) -> str:
        parts: List[str] = []
        for a in args:
            tag = a[0]
            if tag == 'id':
                sym = env.get(a[1], self.param_vars.get(a[1]))
                parts.append(a[1] if sym is None else str(sym))
            else:
                parts.append(repr(a))
        return ','.join(parts)

# 语句执行：返回继续状态 (env, guard) 列表
    def build(self, stmts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        import z3
        state = {'count': 0}
        out_paths: List[Dict[str, Any]] = []
        env = dict(self.param_vars)
        guard = True
        self._sym_stmts(stmts, env, guard, out_paths, state)
        return out_paths

    def _sym_stmts(self, stmts: List[Dict[str, Any]], env: Dict[str, Any],
                   guard: Any, out_paths: List[Dict[str, Any]],
                   state: Dict[str, int]) -> List[Tuple[Dict[str, Any], Any]]:
        conts: List[Tuple[Dict[str, Any], Any]] = [(env, guard)]
        for stmt in stmts:
            if state['count'] >= self.max_paths:
                break
            new_conts: List[Tuple[Dict[str, Any], Any]] = []
            for env_i, g_i in conts:
                new_conts.extend(self._sym_stmt(stmt, env_i, g_i, out_paths, state))
            conts = new_conts
        return conts

    def _sym_stmt(self, stmt: Dict[str, Any], env: Dict[str, Any], guard: Any,
                  out_paths: List[Dict[str, Any]], state: Dict[str, int],
                  ) -> List[Tuple[Dict[str, Any], Any]]:
        import z3
        k = stmt['kind']
        if k == 'block':
            return self._sym_stmts(stmt['body'], env, guard, out_paths, state)
        if k == 'decl':
            val = self._sym_expr(stmt['value'], env) if stmt.get('value') is not None else 0
            return [(dict(env, **{stmt['target']: val}), guard)]
        if k == 'assign':
            return [(dict(env, **{stmt['target']: self._sym_expr(stmt['value'], env)}),
                     guard)]
        if k == 'assignop':
            op = stmt['op'][:-1]
            cur = env.get(stmt['target'], 0)
            val = self._sym_expr(stmt['value'], env)
            return [(dict(env, **{stmt['target']: self._binop(op, cur, val)}),
                     guard)]
        if k == 'expr':
            v = stmt['value']
            if v[0] in ('postinc', 'preinc'):
                return [(dict(env, **{v[1]: env.get(v[1], 0) + 1}), guard)]
            if v[0] in ('postdec', 'predec'):
                return [(dict(env, **{v[1]: env.get(v[1], 0) - 1}), guard)]
            self._sym_expr(v, env)
            return [(env, guard)]
        if k == 'return':
            val = (self._sym_expr(stmt['value'], env)
                   if stmt.get('value') is not None else None)
            out_paths.append({'guard': guard, 'value': val})
            state['count'] += 1
            return []
        if k == 'if':
            c = self._as_bool(self._sym_expr(stmt['cond'], env))
            conts: List[Tuple[Dict[str, Any], Any]] = []
            conts.extend(self._sym_stmts(stmt['then'], env, z3.And(guard, c),
                                         out_paths, state))
            if stmt.get('else'):
                conts.extend(self._sym_stmts(stmt['else'], env,
                                             z3.And(guard, z3.Not(c)),
                                             out_paths, state))
            else:
                conts.append((env, z3.And(guard, z3.Not(c))))
            return conts
        if k in ('while', 'for'):
            return self._sym_loop(stmt, env, guard, out_paths, state)
        if k == 'break':
            return []
        if k == 'continue':
            return []
        return [(env, guard)]

    def _sym_loop(self, stmt: Dict[str, Any], env: Dict[str, Any], guard: Any,
                  out_paths: List[Dict[str, Any]], state: Dict[str, int],
                  ) -> List[Tuple[Dict[str, Any], Any]]:
        import z3
        cond = stmt.get('cond')
        body = stmt.get('body', [])
        update = stmt.get('update')
        init = stmt.get('init')
        conts: List[Tuple[Dict[str, Any], Any]] = [(env, guard)]
        if init is not None:
            conts = self._sym_stmt(init, env, guard, out_paths, state)
        for _ in range(self.max_loop_iters):
            new_conts: List[Tuple[Dict[str, Any], Any]] = []
            for env_i, g_i in conts:
                c = self._as_bool(self._sym_expr(cond, env_i)) if cond is not None else True
                body_conts = self._sym_stmts(body, env_i, z3.And(g_i, c),
                                             out_paths, state)
                if update is not None:
                    body_conts = [(self._apply_update(update, env_u), g_u)
                                  for env_u, g_u in body_conts]
                new_conts.extend(body_conts)
                # 退出循环路径
                new_conts.append((env_i, z3.And(g_i, z3.Not(c))))
            conts = new_conts
            if state['count'] >= self.max_paths:
                break
        return conts

    def _apply_update(self, update: Any, env: Dict[str, Any]) -> Dict[str, Any]:
        """应用 for 更新子句到符号环境，返回新环境

        支持 ++ / -- / = expr / += expr 等形式；
        无法识别的更新表达式保持环境不变（保守）
        """
        if update[0] in ('postinc', 'preinc'):
            return dict(env, **{update[1]: env.get(update[1], 0) + 1})
        if update[0] in ('postdec', 'predec'):
            return dict(env, **{update[1]: env.get(update[1], 0) - 1})
        if update[0] == 'assignop':
            name, op = update[1], update[2]
            val = self._sym_expr(update[3], env)
            cur = env.get(name, 0)
            if op == '=':
                return dict(env, **{name: val})
            return dict(env, **{name: self._binop(op[:-1], cur, val)})
        return dict(env)


# 求解后端：优先接入 SymExec优化器.optimize_solve，失败回退裸 z3

_optimizer_lock = threading.Lock()
_optimizer_instance = None
_optimizer_failed = False


def _get_shared_optimizer():
    """惰性创建 SymExecOptimizer 单例（线程安全）

    仅当 symbolic.symexec_optimizer 可导入时启用；否则置失败标记
    后续直接走裸 z3，避免反复尝试导入的开销
    """
    global _optimizer_instance, _optimizer_failed
    with _optimizer_lock:
        if _optimizer_instance is not None:
            return _optimizer_instance
        if _optimizer_failed:
            return None
        try:
            from modules.analysis.symbolic.symexec_optimizer import create_optimizer
            _optimizer_instance = create_optimizer({
                'parallel_solvers': 1,
                'enable_complexity_estimator': False,
                'simplify_constraints': True,
                'incremental_solving': False,
            })
            logger.info("[EquivCheck] SymExecOptimizer 接入成功")
            return _optimizer_instance
        except Exception as e:  # noqa: BLE001
            logger.debug("[EquivCheck] SymExecOptimizer 不可用，回退裸 z3: %s", e)
            _optimizer_failed = True
            return None


def _model_satisfies(constraints: List[Any], solution: Dict[str, Any]) -> bool:
    """校验优化器返回的候选模型是否真正满足全部约束

    设计依据: SymExecOptimizer 的简化器存在丢弃平凡假约束的缺陷
    (会把 [False] 简化为空集从而误报 sat)，故不可直接采信其
    satisfiable 字段；本函数把候选模型代回每条约束逐一化简
    全部为真才返回 True
    """
    import z3
    try:
        consts: Dict[str, Any] = {}
        for c in constraints:
            for sub in z3.get_vars(c):
                consts[str(sub)] = sub
        subs: List[Tuple[Any, Any]] = []
        for name, val_str in solution.items():
            if name not in consts:
                continue
            val_str = str(val_str)
            if val_str == 'True':
                val = z3.BoolVal(True)
            elif val_str == 'False':
                val = z3.BoolVal(False)
            elif val_str.startswith('#x'):
                val = z3.BitVecVal(int(val_str[2:], 16), 64)
            elif '/' in val_str:
                num, _, den = val_str.partition('/')
                val = z3.RatVal(int(num), int(den))
            else:
                try:
                    val = z3.IntVal(int(val_str))
                except ValueError:
                    continue
            subs.append((consts[name], val))
        if not subs:
            return False
        for c in constraints:
            if not z3.is_true(z3.simplify(z3.substitute(c, subs))):
                return False
        return True
    except Exception as e:  # noqa: BLE001
        logger.debug("[EquivCheck] 候选模型复核失败: %s", e)
        return False


_optimizer_runtime_failed = False


def _check_feasible(constraints: List[Any]) -> Optional[bool]:
    """判断约束合取是否可满足；None 表示求解器不可用/出错

    判定策略:
    SymExecOptimizer 作为加速首查-其求解缓存可降低重复路径对拍的
    开销；但上游存在误报 sat 与复杂度预估器 NameError 等缺陷，故仅当
    其返回 satisfiable=True 且附带完整候选模型、且该模型经
    _model_satisfies 逐条复核通过时才采信。其余情况一律回退裸 z3
    权威判定，保证等价校验的结论不依赖可疑的上游结果
    """
    global _optimizer_runtime_failed
    if not constraints:
        return True
    if not _optimizer_runtime_failed:
        optimizer = _get_shared_optimizer()
        if optimizer is not None:
            try:
                result = optimizer.optimize_solve(constraints) or {}
                if result.get('satisfiable') is True:
                    solution = result.get('solution') or {}
                    if solution and _model_satisfies(constraints, solution):
                        return True
            except Exception as e:  # noqa: BLE001
                # 上游求解器反复抛错：永久降级为裸 z3，避免热路径反复抛异常
                logger.debug("[EquivCheck] 优化器求解失败，降级裸 z3: %s", e)
                _optimizer_runtime_failed = True
    try:
        import z3
        solver = z3.Solver()
        solver.set
        solver.add(z3.And(*constraints))
        r = solver.check()
        return r == z3.sat
    except Exception as e:  # noqa: BLE001
        logger.debug("[EquivCheck] z3 求解失败: %s", e)
        return None


def _z3_available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except ImportError:
        return False


# 顶层等价性检查器


class EquivalenceChecker:
    """对反编译结果与参考实现做细粒度等价性校验

    调用方式:
    checker = EquivalenceChecker()
    result = checker.检查(decompiled_text, 引用_text)
    """

    def __init__(self, samples: int = _MAX_DEFAULT_SAMPLES,
                 max_paths: int = _MAX_DEFAULT_PATHS,
                 max_loop_iters: int = _MAX_DEFAULT_LOOP_ITERS):
        self.samples = samples
        self.max_paths = max_paths
        self.max_loop_iters = max_loop_iters
        self._call_env: Dict[Tuple[str, str], Any] = {}

    # 主入口
    def check(self, decompiled: str, reference: str,
              param_names: Optional[List[str]] = None,
              input_ranges: Optional[List[Tuple[int, int]]] = None,
              use_symbolic: bool = True) -> EquivResult:
        evidence: List[str] = []

        if not decompiled or not reference:
            return EquivResult(EquivVerdict.UNKNOWN,
                               evidence=['空输入'], method_used='none')

        # 分别提取两函数的形参名；变量重命名(等价变换)下按位置对齐
        params_a = list(param_names or _extract_param_names(decompiled) or [])
        params_b = list(param_names or _extract_param_names(reference) or [])
        if params_a and params_b and len(params_a) != len(params_b):
            return EquivResult(
                EquivVerdict.NOT_EQUIVALENT,
                evidence=[f'声明参数个数不同: {len(params_a)} vs {len(params_b)}'],
                method_used='none')
        params = params_a or params_b
        if not params:
            params = ['a', 'b', 'c', 'd', 'e', 'f'][:1]

        try:
            stmts_a = _StmtParser(decompiled).parse_function_body()
            stmts_b = _StmtParser(reference).parse_function_body()
        except Exception as e:  # noqa: BLE001
            return EquivResult(EquivVerdict.UNKNOWN,
                               evidence=[f'解析失败: {e}'], method_used='none')
        if not stmts_a or not stmts_b:
            return EquivResult(EquivVerdict.UNKNOWN,
                               evidence=['函数体为空或无法解析'],
                               method_used='none')

        ranges = input_ranges or [(0, 15)] * len(params)

# 阶段 1: 输入采样对拍
        sampling_verdict = self._sampling_check(
            stmts_a, stmts_b, params_a or params, params_b or params,
            ranges, evidence)
        if sampling_verdict is EquivVerdict.NOT_EQUIVALENT:
            return EquivResult(EquivVerdict.NOT_EQUIVALENT, evidence,
                               self._last_counterexample, 'sampling',
                               samples_run=self.samples)

# 阶段 2: 符号路径比较
        if use_symbolic and _z3_available():
            sym_verdict = self._symbolic_check(stmts_a, stmts_b,
                                               params_a or params,
                                               params_b or params, evidence)
            if sym_verdict is EquivVerdict.EQUIVALENT:
                return EquivResult(EquivVerdict.EQUIVALENT, evidence,
                                   method_used='hybrid',
                                   samples_run=self.samples,
                                   paths_a=self._paths_a,
                                   paths_b=self._paths_b)
            if sym_verdict is EquivVerdict.NOT_EQUIVALENT:
                return EquivResult(EquivVerdict.NOT_EQUIVALENT, evidence,
                                   self._last_counterexample, 'hybrid',
                                   samples_run=self.samples,
                                   paths_a=self._paths_a,
                                   paths_b=self._paths_b)

        # 采样未发现差异 + 符号未能证明 → UNKNOWN
        evidence.append('采样一致但符号证明未收敛')
        return EquivResult(EquivVerdict.UNKNOWN, evidence, method_used='hybrid',
                           samples_run=self.samples,
                           paths_a=self._paths_a, paths_b=self._paths_b)

    # 采样对拍
    def _sampling_check(self, stmts_a: List[Dict[str, Any]],
                        stmts_b: List[Dict[str, Any]],
                        params_a: List[str], params_b: List[str],
                        ranges: List[Tuple[int, int]],
                        evidence: List[str]) -> EquivVerdict:
        interp = _MiniCInterp(max_loop_iters=self.max_loop_iters)
        rng = random.Random(0xC0FFEE)
        # 输入向量按位置生成，分别绑定到两函数各自的形参名
        # 从而容忍等价变换中的变量重命名
        for _ in range(self.samples):
            inputs = [rng.randint(lo, hi) for lo, hi in ranges]
            va = interp.run(stmts_a, params_a, inputs)
            vb = interp.run(stmts_b, params_b, inputs)
            if va != vb:
                self._last_counterexample = {
                    'inputs': dict(zip(params_a or params_b, inputs)),
                    'decompiled_output': va,
                    'reference_output': vb,
                }
                evidence.append(
                    f'采样反例: 输入 {dict(zip(params_a or params_b, inputs))} 下 '
                    f'反编译输出={va}，参考输出={vb}')
                return EquivVerdict.NOT_EQUIVALENT
        evidence.append(f'{self.samples} 组采样输出一致')
        return EquivVerdict.UNKNOWN

    # 符号路径比较
    _paths_a = 0
    _paths_b = 0
    _last_counterexample: Optional[Dict[str, Any]] = None

    def _symbolic_check(self, stmts_a: List[Dict[str, Any]],
                        stmts_b: List[Dict[str, Any]],
                        params_a: List[str], params_b: List[str],
                        evidence: List[str]) -> EquivVerdict:
        import z3
        # 共享按位置参数符号变量: 两函数输出表达式均以 p0/p1/. 表示
        # 重命名不影响等价比较
        n_params = max(len(params_a), len(params_b), 1)
        shared_params = [z3.Int(f'p{i}') for i in range(n_params)]
        self._call_env = {}
        builder_a = _SymbolicPathBuilder(params_a or params_b, shared_params,
                                         self.max_paths, self.max_loop_iters,
                                         self._call_env)
        paths_a = builder_a.build(stmts_a)
        self._paths_a = len(paths_a)

        builder_b = _SymbolicPathBuilder(params_b or params_a, shared_params,
                                         self.max_paths, self.max_loop_iters,
                                         self._call_env)
        paths_b = builder_b.build(stmts_b)
        self._paths_b = len(paths_b)

        if not paths_a or not paths_b:
            evidence.append(f'符号路径为空 (A={len(paths_a)}, B={len(paths_b)})')
            return EquivVerdict.UNKNOWN

        evidence.append(f'符号路径 A={len(paths_a)}，B={len(paths_b)}')

        # 逐路径对比较：对所有可同时满足的 (pa, pb)，输出必须一致
        for pa in paths_a:
            for pb in paths_b:
                feasible = _check_feasible([pa['guard'], pb['guard']])
                if feasible is False:
                    continue
                if feasible is None:
                    evidence.append('路径可行性求解不可用')
                    return EquivVerdict.UNKNOWN

                va, vb = pa['value'], pb['value']
                if va is None or vb is None:
                    if va != vb:
                        self._record_sym_counterexample(
                            builder_a, builder_b, [pa['guard'], pb['guard']])
                        evidence.append('返回类型不一致(一方 void)')
                        return EquivVerdict.NOT_EQUIVALENT
                    continue

                differ = _check_feasible([pa['guard'], pb['guard'], va != vb])
                if differ is True:
                    self._record_sym_counterexample(
                        builder_a, builder_b, [pa['guard'], pb['guard'], va != vb])
                    evidence.append('符号反例：存在输入使两函数输出不同')
                    return EquivVerdict.NOT_EQUIVALENT
                if differ is None:
                    evidence.append('输出差异求解不可用')
                    return EquivVerdict.UNKNOWN

        evidence.append('全部可达路径对输出一致（符号证明）')
        return EquivVerdict.EQUIVALENT

    def _record_sym_counterexample(self, builder_a: Any, builder_b: Any,
                                   constraints: List[Any]) -> None:
        try:
            import z3
            solver = z3.Solver()
            solver.add(z3.And(*constraints))
            if solver.check() == z3.sat:
                model = solver.model()
                inputs = {}
                for name, var in builder_a.param_vars.items():
                    if isinstance(var, z3.ArithRef) and var in model:
                        try:
                            inputs[name] = model.eval(var).as_long()
                        except Exception:  # noqa: BLE001
                            inputs[name] = '?'
                self._last_counterexample = {'inputs': inputs,
                                             'decompiled_output': '?',
                                             'reference_output': '?'}
        except Exception:  # noqa: BLE001
            self._last_counterexample = None


__all__ = [
    'EquivVerdict',
    'EquivResult',
    'EquivalenceChecker',
    '_extract_param_names',
]
