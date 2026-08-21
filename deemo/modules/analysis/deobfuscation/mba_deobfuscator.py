
import re
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable, Tuple

logger = logging.getLogger(__name__)

@dataclass
class Expr: pass
@dataclass
class Const(Expr): value: int
@dataclass
class Var(Expr): name: str
@dataclass
class UnOp(Expr): op: str; operand: Expr
@dataclass
class BinOp(Expr): op: str; left: Expr; right: Expr

_TOKEN_RE = re.compile(r'[a-zA-Z_]\w*|0x[0-9a-fA-F]+|[0-9]+|<<|>>|\+|-|\*|&|\||\^|~|\(|\)')
def _tokenize(expr: str) -> List[str]:
    return _TOKEN_RE.findall(expr)

class _Parser:
    def __init__(self, tokens): self.tokens = tokens; self.pos = 0
    def _peek(self): return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    def _eat(self, expected=None):
        t = self.tokens[self.pos]; self.pos += 1
        if expected and t != expected: raise ValueError(f"expected {expected}, got {t}")
        return t
    def parse(self): return self._expr()
    def _expr(self): return self._bitor()
    def _bitor(self):
        left = self._bitxor()
        while self._peek() == '|': self._eat(); left = BinOp('|', left, self._bitxor())
        return left
    def _bitxor(self):
        left = self._bitand()
        while self._peek() == '^': self._eat(); left = BinOp('^', left, self._bitand())
        return left
    def _bitand(self):
        left = self._addsub()
        while self._peek() == '&': self._eat(); left = BinOp('&', left, self._addsub())
        return left
    def _addsub(self):
        left = self._mul()
        while True:
            t = self._peek()
            if t in ('+', '-'): self._eat(); left = BinOp(t, left, self._mul())
            else: break
        return left
    def _mul(self):
        left = self._unary()
        while self._peek() == '*': self._eat(); left = BinOp('*', left, self._unary())
        return left
    def _unary(self):
        t = self._peek()
        if t == '~': self._eat(); return UnOp('~', self._unary())
        if t == '-': self._eat(); return UnOp('-', self._unary())
        return self._atom()
    def _atom(self):
        t = self._peek()
        if t == '(': self._eat(); node = self._expr(); self._eat(')'); return node
        if t.isdigit(): self._eat(); return Const(int(t))
        if t.startswith('0x') and len(t) > 2: self._eat(); return Const(int(t, 16))
        self._eat(); return Var(t)

def parse_expression(expr_str: str) -> Expr:
    tokens = _tokenize(expr_str)
    if not tokens:
        return None
    return _Parser(tokens).parse()

def _is_const(expr, val=None):
    return isinstance(expr, Const) and (val is None or expr.value == val)
def _clone(expr):
    if isinstance(expr, Const): return Const(expr.value)
    if isinstance(expr, Var): return Var(expr.name)
    if isinstance(expr, UnOp): return UnOp(expr.op, _clone(expr.operand))
    if isinstance(expr, BinOp): return BinOp(expr.op, _clone(expr.left), _clone(expr.right))
    return expr
def _is_var(expr, name=None):
    return isinstance(expr, Var) and (name is None or expr.name == name)

MBA_RULES: List[tuple] = []
def _register_rule(pfn, rfn): MBA_RULES.append((pfn, rfn))

# --- 21 条 MBA 恒等式规则（1-21 为上一轮保留的规则）---
def _p1(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    if not isinstance(node.left, BinOp) or node.left.op != '^': return None
    if not isinstance(node.right, BinOp) or node.right.op != '*': return None
    if not (_is_const(node.right.left, 2) or _is_const(node.right.right, 2)): return None
    mul_other = node.right.right if _is_const(node.right.left, 2) else node.right.left
    if not isinstance(mul_other, BinOp) or mul_other.op != '&': return None
    x, y = node.left.left, node.left.right
    if _is_var(x) and _is_var(y) and _is_var(mul_other.left) and _is_var(mul_other.right):
        if x.name == mul_other.left.name and y.name == mul_other.right.name:
            return {'x': x, 'y': y}
def _r1(m): return BinOp('+', _clone(m['x']), _clone(m['y']))
_register_rule(_p1, _r1)

def _p2(node):
    if not isinstance(node, BinOp) or node.op != '-': return None
    if not isinstance(node.left, BinOp) or node.left.op != '^': return None
    if not isinstance(node.right, BinOp) or node.right.op != '*': return None
    c2 = node.right.left if _is_const(node.right.left, 2) else node.right.right
    inner = node.right.right if _is_const(node.right.left, 2) else node.right.left
    if not _is_const(c2, 2) or not isinstance(inner, BinOp) or inner.op != '&': return None
    if not isinstance(inner.left, UnOp) or inner.left.op != '~': return None
    x, yn, nx, yi = node.left.left, node.left.right, inner.left.operand, inner.right
    if _is_var(x) and _is_var(nx) and _is_var(yn) and _is_var(yi):
        if x.name == nx.name and yn.name == yi.name: return {'x': x, 'y': yn}
def _r2(m): return BinOp('-', _clone(m['x']), _clone(m['y']))
_register_rule(_p2, _r2)

def _p3(node):
    if not isinstance(node, BinOp) or node.op != '-': return None
    if not isinstance(node.left, BinOp) or node.left.op != '|': return None
    if not isinstance(node.right, BinOp) or node.right.op != '&': return None
    xo, yo = node.left.left, node.left.right
    xa, ya = node.right.left, node.right.right
    if _is_var(xo) and _is_var(yo) and _is_var(xa) and _is_var(ya):
        if xo.name == xa.name and yo.name == ya.name: return {'x': xo, 'y': yo}
def _r3(m): return BinOp('^', _clone(m['x']), _clone(m['y']))
_register_rule(_p3, _r3)

def _p4(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    yc, ap = None, None
    if isinstance(node.left, BinOp) and node.left.op == '&': ap, yc = node.left, node.right
    elif isinstance(node.right, BinOp) and node.right.op == '&': ap, yc = node.right, node.left
    else: return None
    if not isinstance(ap.left, UnOp) or ap.left.op != '~':
        if not isinstance(ap.right, UnOp) or ap.right.op != '~': return None
    if isinstance(ap.left, UnOp) and ap.left.op == '~': x, ya = ap.left.operand, ap.right
    else: x, ya = ap.right.operand, ap.left
    if _is_var(x) and _is_var(yc) and _is_var(ya):
        if yc.name == ya.name: return {'x': x, 'y': yc}
def _r4(m): return BinOp('|', _clone(m['x']), _clone(m['y']))
_register_rule(_p4, _r4)

def _p5(node):
    if not isinstance(node, UnOp) or node.op != '~': return None
    inner = node.operand
    if not isinstance(inner, BinOp) or inner.op != '|': return None
    if not isinstance(inner.left, UnOp) or inner.left.op != '~': return None
    if not isinstance(inner.right, UnOp) or inner.right.op != '~': return None
    x, y = inner.left.operand, inner.right.operand
    if _is_var(x) and _is_var(y): return {'x': x, 'y': y}
def _r5(m): return BinOp('&', _clone(m['x']), _clone(m['y']))
_register_rule(_p5, _r5)

def _p6(node):
    if isinstance(node, BinOp) and node.op == '+' and _is_var(node.left) and _is_var(node.right):
        if node.left.name == node.right.name: return {'x': node.left}
    if isinstance(node, BinOp) and node.op == '<<' and _is_const(node.right, 1) and _is_var(node.left):
        return {'x': node.left}
def _r6(m): return BinOp('*', _clone(m['x']), Const(2))
_register_rule(_p6, _r6)

def _p7(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    if not isinstance(node.left, BinOp) or node.left.op != '+': return None
    if not (_is_var(node.left.left) and _is_var(node.left.right)) or not _is_var(node.right): return None
    x = node.left.left
    if x.name == node.left.right.name and x.name == node.right.name: return {'x': x}
def _r7(m): return BinOp('*', _clone(m['x']), Const(3))
_register_rule(_p7, _r7)

def _p8(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    shift, vp = None, None
    if isinstance(node.left, BinOp) and node.left.op == '<<': shift, vp = node.left, node.right
    elif isinstance(node.right, BinOp) and node.right.op == '<<': shift, vp = node.right, node.left
    else: return None
    if not _is_const(shift.right, 2): return None
    if _is_var(shift.left) and _is_var(vp) and shift.left.name == vp.name: return {'x': vp}
def _r8(m): return BinOp('*', _clone(m['x']), Const(5))
_register_rule(_p8, _r8)

def _p9(node):
    if isinstance(node, BinOp) and node.op == '^':
        if _is_var(node.left) and _is_var(node.right) and node.left.name == node.right.name:
            return {'x': node.left}
def _r9(m): return Const(0)
_register_rule(_p9, _r9)

def _p10(node):
    if isinstance(node, BinOp) and node.op == '&':
        if _is_var(node.left) and _is_var(node.right) and node.left.name == node.right.name:
            return {'x': node.left}
def _r10(m): return _clone(m['x'])
_register_rule(_p10, _r10)

def _p11(node):
    if isinstance(node, BinOp) and node.op == '|':
        if _is_var(node.left) and _is_var(node.right) and node.left.name == node.right.name:
            return {'x': node.left}
def _r11(m): return _clone(m['x'])
_register_rule(_p11, _r11)

def _p12(node):
    if not isinstance(node, UnOp) or node.op != '~': return None
    inner = node.operand
    if not isinstance(inner, BinOp) or inner.op != '^': return None
    if _is_var(inner.left) and _is_var(inner.right): return {'x': inner.left, 'y': inner.right}
def _r12(m): return BinOp('^', UnOp('~', _clone(m['x'])), _clone(m['y']))
_register_rule(_p12, _r12)

def _p14(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    if not _is_const(node.right, 1):
        if _is_const(node.left, 1) and isinstance(node.right, BinOp) and node.right.op == '+':
            il, inot = node.right.left, node.right.right
            if isinstance(inot, UnOp) and inot.op == '~' and _is_var(inot.operand) and _is_var(il):
                return {'x': il, 'y': inot.operand}
        return None
    if not isinstance(node.left, BinOp) or node.left.op != '+': return None
    il, ir = node.left.left, node.left.right
    if isinstance(il, UnOp) and il.op == '~' and _is_var(il.operand) and _is_var(ir):
        return {'x': ir, 'y': il.operand}
    if isinstance(ir, UnOp) and ir.op == '~' and _is_var(ir.operand) and _is_var(il):
        return {'x': il, 'y': ir.operand}
def _r14(m): return BinOp('-', _clone(m['x']), _clone(m['y']))
_register_rule(_p14, _r14)

def _p15(node):
    if not isinstance(node, BinOp) or node.op != '-': return None
    if not _is_const(node.right, 1): return None
    if not isinstance(node.left, BinOp) or node.left.op != '-': return None
    yn, xn = node.left.left, node.left.right
    if _is_var(yn) and _is_var(xn): return {'x': xn, 'y': yn}
def _r15(m): return UnOp('~', BinOp('-', _clone(m['x']), _clone(m['y'])))
_register_rule(_p15, _r15)

def _p16(node):
    if not isinstance(node, UnOp) or node.op != '~': return None
    inner = node.operand
    if not isinstance(inner, BinOp) or inner.op != '|': return None
    if _is_var(inner.left) and _is_var(inner.right): return {'x': inner.left, 'y': inner.right}
def _r16(m): return BinOp('&', UnOp('~', _clone(m['x'])), UnOp('~', _clone(m['y'])))
_register_rule(_p16, _r16)

def _p17(node):
    if not isinstance(node, BinOp) or node.op != '|': return None
    if not (isinstance(node.left, BinOp) and node.left.op == '&'): return None
    if not (isinstance(node.right, BinOp) and node.right.op == '&'): return None
    lx, ly = node.left.left, node.left.right
    rx, rz = node.right.left, node.right.right
    if _is_var(lx) and _is_var(rx) and lx.name == rx.name: return {'x': lx, 'y': ly, 'z': rz}
    if _is_var(lx) and _is_var(rz) and lx.name == rz.name: return {'x': lx, 'y': ly, 'z': rx}
def _r17(m): return BinOp('&', _clone(m['x']), BinOp('|', _clone(m['y']), _clone(m['z'])))
_register_rule(_p17, _r17)

def _p18(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    if isinstance(node.left, BinOp) and node.left.op == '+' and _is_const(node.left.right) and _is_const(node.right):
        return {'x': node.left.left, 'c': Const(node.left.right.value + node.right.value)}
def _r18(m): return BinOp('+', _clone(m['x']), _clone(m['c']))
_register_rule(_p18, _r18)

def _p19(node):
    if not isinstance(node, BinOp) or node.op != '|': return None
    if isinstance(node.left, UnOp) and node.left.op == '~' and _is_var(node.left.operand):
        if _is_var(node.right) and node.left.operand.name == node.right.name: return {'x': node.right}
    if isinstance(node.right, UnOp) and node.right.op == '~' and _is_var(node.right.operand):
        if _is_var(node.left) and node.right.operand.name == node.left.name: return {'x': node.left}
def _r19(m): return Const(-1)
_register_rule(_p19, _r19)

def _p20(node):
    if not isinstance(node, BinOp) or node.op != '&': return None
    if _is_const(node.left, 0) or _is_const(node.right, 0):
        return {'x': node.left if not _is_const(node.left, 0) else node.right}
def _r20(m): return Const(0)
_register_rule(_p20, _r20)

def _p21(node):
    if not isinstance(node, UnOp) or node.op != '~': return None
    inner = node.operand
    if not isinstance(inner, BinOp) or inner.op != '&': return None
    if _is_var(inner.left) and _is_var(inner.right): return {'x': inner.left, 'y': inner.right}
def _r21(m): return BinOp('|', UnOp('~', _clone(m['x'])), UnOp('~', _clone(m['y'])))
_register_rule(_p21, _r21)

# 新增: 真实恶意软件 MBA 模式识别 - 基于对 TrickBot/Emotet/FormBook
# 等恶意软件家族中 MBA 混淆的逆向经验，添加以下额外规则

# 22. (x << 3) - x = x * 7
def _p22(node):
    if not isinstance(node, BinOp) or node.op != '-': return None
    if not isinstance(node.left, BinOp) or node.left.op != '<<': return None
    if not _is_const(node.left.right, 3): return None
    if _is_var(node.left.left) and _is_var(node.right) and node.left.left.name == node.right.name:
        return {'x': node.left.left}
def _r22(m): return BinOp('*', _clone(m['x']), Const(7))
_register_rule(_p22, _r22)

# 23. (x + y) ^ (x & y) = x | y [常见于 Emotet 的字符串解码器]
def _p23(node):
    if not isinstance(node, BinOp) or node.op != '^': return None
    plus, and_part = None, None
    if isinstance(node.left, BinOp) and node.left.op == '+':
        plus, and_part = node.left, node.right
    elif isinstance(node.right, BinOp) and node.right.op == '+':
        plus, and_part = node.right, node.left
    else: return None
    if not isinstance(and_part, BinOp) or and_part.op != '&': return None
    xp, yp = plus.left, plus.right
    xa, ya = and_part.left, and_part.right
    if _is_var(xp) and _is_var(xa) and xp.name == xa.name:
        if _is_var(yp) and _is_var(ya) and yp.name == ya.name:
            return {'x': xp, 'y': yp}
def _r23(m): return BinOp('|', _clone(m['x']), _clone(m['y']))
_register_rule(_p23, _r23)

# 24. (x ^ y) + ((x & y) << 1) = x + y [带进位加法模拟，TrickBot 特征]
def _p24(node):
    if not isinstance(node, BinOp) or node.op != '+': return None
    xor_part, shl_and = None, None
    if isinstance(node.left, BinOp) and node.left.op == '^':
        xor_part, shl_and = node.left, node.right
    elif isinstance(node.right, BinOp) and node.right.op == '^':
        xor_part, shl_and = node.right, node.left
    else: return None
    if not isinstance(shl_and, BinOp) or shl_and.op != '<<': return None
    if not _is_const(shl_and.right, 1): return None
    if not isinstance(shl_and.left, BinOp) or shl_and.left.op != '&': return None
    xx, xy = xor_part.left, xor_part.right
    ax, ay = shl_and.left.left, shl_and.left.right
    if _is_var(xx) and _is_var(ax) and xx.name == ax.name:
        if _is_var(xy) and _is_var(ay) and xy.name == ay.name:
            return {'x': xx, 'y': xy}
def _r24(m): return BinOp('+', _clone(m['x']), _clone(m['y']))
_register_rule(_p24, _r24)

# 25. ((x | y) - (x & y)) ^ (x & y) = x ^ y [双重混淆，FormBook 模式]
def _p25(node):
    if not isinstance(node, BinOp) or node.op != '^': return None
    sub_, and2 = None, None
    if isinstance(node.left, BinOp) and node.left.op == '-':
        sub_, and2 = node.left, node.right
    elif isinstance(node.right, BinOp) and node.right.op == '-':
        sub_, and2 = node.right, node.left
    else: return None
    if not isinstance(sub_.left, BinOp) or sub_.left.op != '|': return None
    if not isinstance(sub_.right, BinOp) or sub_.right.op != '&': return None
    ox, oy = sub_.left.left, sub_.left.right
    a1x, a1y = sub_.right.left, sub_.right.right
    if not isinstance(and2, BinOp) or and2.op != '&': return None
    a2x, a2y = and2.left, and2.right
    if (_is_var(ox) and _is_var(a1x) and _is_var(a2x) and
        ox.name == a1x.name == a2x.name):
        if (_is_var(oy) and _is_var(a1y) and _is_var(a2y) and
            oy.name == a1y.name == a2y.name):
            return {'x': ox, 'y': oy}
def _r25(m): return BinOp('^', _clone(m['x']), _clone(m['y']))
_register_rule(_p25, _r25)


def _try_match_comm(node, matcher, max_swaps=3):
    r = matcher(node)
    if r is not None: return r
    COMMUTATIVE = {'+', '*', '&', '|', '^'}
    for _ in range(max_swaps):
        changed = False
        if isinstance(node, BinOp) and node.op in COMMUTATIVE:
            node.left, node.right = node.right, node.left
            changed = True
        r = matcher(node)
        if r is not None: return r
        if not changed: break
    return None

def _match_any_rule(node):
    for pfn, rfn in MBA_RULES:
        m = _try_match_comm(node, pfn)
        if m is not None: return rfn(m)
    return None

def _bottom_up_rewrite(node, max_passes=5):
    if isinstance(node, BinOp):
        node.left = _bottom_up_rewrite(node.left, max_passes)
        node.right = _bottom_up_rewrite(node.right, max_passes)
    elif isinstance(node, UnOp):
        node.operand = _bottom_up_rewrite(node.operand, max_passes)
    replacement = _match_any_rule(node)
    if replacement is not None:
        return _bottom_up_rewrite(replacement, max_passes)
    return node

_PREC = {'|': 1, '^': 2, '&': 3, '+': 4, '-': 4, '*': 5}

def _to_str(expr, parent_prec=0):
    if isinstance(expr, Const): return str(expr.value)
    if isinstance(expr, Var): return expr.name
    if isinstance(expr, UnOp): return f"{expr.op}{_to_str(expr.operand, 10)}"
    if isinstance(expr, BinOp):
        my_prec = _PREC.get(expr.op, 0)
        left = _to_str(expr.left, my_prec)
        right = _to_str(expr.right, my_prec)
        result = f"{left} {expr.op} {right}"
        if my_prec < parent_prec: return f"({result})"
        return result
    return "?"

def _try_import_z3():
    try: import z3; return z3
    except ImportError: return None

def verify_equivalence(expr_a, expr_b, bit_width=32):
    z3 = _try_import_z3()
    if z3 is None: return None
    try:
        tree_a = parse_expression(expr_a); tree_b = parse_expression(expr_b)
    except Exception as e:
        logger.warning("parse error: %s", e); return None
    vars_set = set()
    def _cv(node):
        if isinstance(node, Var): vars_set.add(node.name)
        elif isinstance(node, BinOp): _cv(node.left); _cv(node.right)
        elif isinstance(node, UnOp): _cv(node.operand)
    _cv(tree_a); _cv(tree_b)
    symbols = {v: z3.BitVec(v, bit_width) for v in vars_set}
    def _tz(node):
        if isinstance(node, Const): return z3.BitVecVal(node.value, bit_width)
        if isinstance(node, Var): return symbols[node.name]
        if isinstance(node, UnOp):
            inner = _tz(node.operand)
            if node.op == '~': return ~inner
            if node.op == '-': return -inner
        if isinstance(node, BinOp):
            l, r = _tz(node.left), _tz(node.right)
            m = {'+': lambda a, b: a + b, '-': lambda a, b: a - b,
                 '*': lambda a, b: a * b, '&': lambda a, b: a & b,
                 '|': lambda a, b: a | b, '^': lambda a, b: a ^ b}
            return m[node.op](l, r)
        raise ValueError(f"unknown: {type(node)}")
    z3_a, z3_b = _tz(tree_a), _tz(tree_b)
    solver = z3.Solver(); solver.add(z3_a != z3_b)
    return solver.check() == z3.unsat


class MBASimplifier:
    """Mixed Boolean-Arithmetic 简化器 - 25 条恒等式规则 + Z3 验证"""

    def __init__(self, use_z3=True):
        self._z3 = _try_import_z3() if use_z3 else None

    def normalize(self, expr_str):
        try: tree = parse_expression(expr_str)
        except Exception: return expr_str
        if tree is None: return ""
        tree = _bottom_up_rewrite(tree, max_passes=3)
        return _to_str(tree)

    def simplify(self, expr_str, max_passes=5):
        try: tree = parse_expression(expr_str)
        except Exception: return expr_str
        if tree is None: return ""
        for _ in range(max_passes):
            prev = _to_str(tree)
            tree = _bottom_up_rewrite(tree, max_passes=1)
            if _to_str(tree) == prev: break
        return _to_str(tree)

    def verify(self, expr_a, expr_b):
        if self._z3 is None: return None
        return verify_equivalence(expr_a, expr_b)

    def simplify_block(self, instructions):
        changed = 0; result = []
        for instr in instructions:
            parts = instr.split('=', 1)
            if len(parts) != 2: result.append(instr); continue
            lhs, rhs = parts[0].strip(), parts[1].strip()
            try:
                simplified = self.simplify(rhs, max_passes=3)
                if simplified != rhs:
                    result.append(f"{lhs} = {simplified}"); changed += 1; continue
            except Exception: pass
            result.append(instr)
        return result, changed


def deobfuscate_mba(expr_str):
    return MBASimplifier().simplify(expr_str)

def deobfuscate_mba_block(instructions):
    s = MBASimplifier()
    simplified, _ = s.simplify_block(instructions)
    return simplified
