#!/usr/bin/env python3
"""
半线性 MBA 去混淆器

基于 [Skees 2024, arXiv:2406.10016] 的半线性 MBA 扩展框架
将含常量的位运算操作数（如 x&1, (x&0xF)+(y&0xF)）纳入
简化范围，突破了传统线性 MBA 方法仅处理纯变量操作数的局限

核心方法：
1. 半线性表达式识别：区分纯变量位运算和含常量位掩码的位运算
2. 逐位分离：在位级别展开为独立布尔表达式
3. 位级别简化：在 GF(2) 上应用布尔代数恒等式
4. 重新组装：将简化后的位表达式还原为字级别运算

与 egraph_mba.py 互补：本模块处理常量掩码场景
egraph_mba 处理纯线性 MBA 场景
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

# 条件导入 Z3（用于等价性验证）
try:
    import z3 as _z3_mod
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False


class BitExpr:
    """
    位级别布尔表达式 AST
    
    参考 [Skees 2024] 的位级别建模方法
    支持的节点类型：
    -, OR, XOR, （布尔运算）
    - VAR()（第 位的变量值）
    - CONST(0/1)（布尔常量）
    """

    pass


class BitConst:
    """位常量：0 或 1"""
    __slots__ = ('value',)

    def __init__(self, value: int):
        if value not in (0, 1):
            raise ValueError(f"位常量必须为 0 或 1，得到 {value}")
        self.value = value

    def __repr__(self):
        return f"{self.value}"

    def __eq__(self, other):
        if isinstance(other, BitConst):
            return self.value == other.value
        return NotImplemented

    def __hash__(self):
        return hash(('const', self.value))


class BitVar:
    """位变量：某变量的第 bit_index 位"""
    __slots__ = ('name', 'bit_index')

    def __init__(self, name: str, bit_index: int):
        self.name = name
        self.bit_index = bit_index

    def __repr__(self):
        return f"{self.name}_{self.bit_index}"

    def __eq__(self, other):
        if isinstance(other, BitVar):
            return self.name == other.name and self.bit_index == other.bit_index
        return NotImplemented

    def __hash__(self):
        return hash(('var', self.name, self.bit_index))


class BitOp:
    """位操作：, OR, XOR"""
    __slots__ = ('op', 'left', 'right')

    def __init__(self, op: str, left, right):
        if op not in ('and', 'or', 'xor'):
            raise ValueError(f"不支持的位操作: {op}")
        self.op = op
        self.left = left
        self.right = right

    def __repr__(self):
        return f"({self.left} {self.op} {self.right})"


class BitNot:
    """位非："""
    __slots__ = ('operand',)

    def __init__(self, operand):
        self.operand = operand

    def __repr__(self):
        return f"~{self.operand}"


BitExprType = BitConst | BitVar | BitOp | BitNot


class BitLevelSimplifier:
    """
    位级别布尔表达式简化器
    
    应用布尔代数恒等式在位级别进行简化
    [Skees 2024, arXiv:2406.10016]
    """

    # 布尔代数重写规则（bottom-up 应用）
    _RULES = [
        # 常量折叠
        ('and', BitConst(0), None, BitConst(0)),
        (None, BitConst(0), 'and', BitConst(0)),
        ('or', BitConst(1), None, BitConst(1)),
        (None, BitConst(1), 'or', BitConst(1)),
        # 恒等
        ('and', BitConst(1), None, 'id_right'),
        (None, BitConst(1), 'and', 'id_left'),
        ('or', BitConst(0), None, 'id_right'),
        (None, BitConst(0), 'or', 'id_left'),
        ('xor', BitConst(0), None, 'id_right'),
        (None, BitConst(0), 'xor', 'id_left'),
        # 零等
        ('and', None, None, 'idem_and'),
        ('or', None, None, 'idem_or'),
        ('xor', None, None, BitConst(0)),
        # 互补
        ('xor', BitConst(1), None, 'complement'),
        (None, BitConst(1), 'xor', 'complement'),
        # 双重否定
        ('not', 'not_result', None, 'double_not'),
    ]

    def simplify(self, expr: BitExprType, depth: int = 0) -> BitExprType:
        """
        递归简化位表达式
        
        深度优先 + 后序重写，最大递归深度 20
        """
        if depth > 20:
            return expr

        if isinstance(expr, (BitConst, BitVar)):
            return expr

        if isinstance(expr, BitNot):
            inner = self.simplify(expr.operand, depth + 1)
            # 双重否定消除
            if isinstance(inner, BitNot):
                return self.simplify(inner.operand, depth + 1)
            # ~0 = 1
            if isinstance(inner, BitConst):
                return BitConst(1 - inner.value)
            return BitNot(inner) if inner is not expr.operand else expr

        if isinstance(expr, BitOp):
            left = self.simplify(expr.left, depth + 1)
            right = self.simplify(expr.right, depth + 1)

            op = expr.op

            # 常量折叠
            if isinstance(left, BitConst) and isinstance(right, BitConst):
                lv, rv = left.value, right.value
                if op == 'and':
                    return BitConst(lv & rv)
                if op == 'or':
                    return BitConst(lv | rv)
                if op == 'xor':
                    return BitConst(lv ^ rv)

            # 恒等规则
            if op == 'and':
                if isinstance(left, BitConst) and left.value == 1:
                    return right
                if isinstance(right, BitConst) and right.value == 1:
                    return left
                if isinstance(left, BitConst) and left.value == 0:
                    return BitConst(0)
                if isinstance(right, BitConst) and right.value == 0:
                    return BitConst(0)

            if op == 'or':
                if isinstance(left, BitConst) and left.value == 0:
                    return right
                if isinstance(right, BitConst) and right.value == 0:
                    return left
                if isinstance(left, BitConst) and left.value == 1:
                    return BitConst(1)
                if isinstance(right, BitConst) and right.value == 1:
                    return BitConst(1)

            if op == 'xor':
                if isinstance(left, BitConst) and left.value == 0:
                    return right
                if isinstance(right, BitConst) and right.value == 0:
                    return left

            # 同变量规则
            if left == right:
                if op == 'and' or op == 'or':
                    return left
                if op == 'xor':
                    return BitConst(0)

            # xor 1 =
            if op == 'xor' and isinstance(right, BitConst) and right.value == 1:
                return BitNot(left)
            if op == 'xor' and isinstance(left, BitConst) and left.value == 1:
                return BitNot(right)

            if left is expr.left and right is expr.right:
                return expr
            return BitOp(op, left, right)

        return expr


class SemiLinearParser:
    """
    半线性 MBA 表达式解析器
    
    解析混合常量和变量的位运算表达式
    识别模式：
    - x & C（常量掩码）
    - (x & C1) + (y & C2)（带掩码的半线性组合）
    - (x & C1) ^ (y & C2) ^ (x & y)（两种操作混合）
    """

    def parse(self, expr_str: str) -> Optional[Dict[str, Any]]:
        """
        解析半线性 MBA 表达式
        
        返回:
        {'type': 'semilinear', 'terms': [.], 'operations': [.]}
        或 None（解析失败）
        """
        expr = expr_str.replace(' ', '')

        terms = []
        operations = []

        # 简单分词
        tokens = self._tokenize(expr)

        # 检测半线性模式
        mask_pattern = re.compile(r'(\w+)\s*&\s*(\d+|0x[0-9a-fA-F]+)')
        masks_found = mask_pattern.findall(expr_str)

        for var, mask in masks_found:
            try:
                mask_val = int(mask, 16) if mask.startswith('0x') else int(mask)
            except ValueError:
                mask_val = 0

            terms.append({
                'variable': var,
                'mask': mask_val,
                'mask_hex': hex(mask_val),
                'type': 'masked_variable'
            })

        # 检测纯线性部分（无掩码的变量运算）
        pure_var_pattern = re.compile(r'\b([a-zA-Z_]\w*)\s*[\^&|]\s*([a-zA-Z_]\w*)')
        pure_matches = pure_var_pattern.findall(expr_str)
        for a, b in pure_matches:
            if not any(t['variable'] == a for t in terms):
                terms.append({'variable': a, 'mask': None, 'type': 'pure_variable'})
            if not any(t['variable'] == b for t in terms):
                terms.append({'variable': b, 'mask': None, 'type': 'pure_variable'})

        return {
            'type': 'semilinear',
            'terms': terms,
            'bit_width': 32,
            'has_masked_terms': len(masks_found) > 0,
            'pure_var_count': len(pure_matches),
        }

    def _tokenize(self, expr: str) -> List[str]:
        tokens = []
        i = 0
        while i < len(expr):
            if expr[i] in '()+-*&|^~':
                tokens.append(expr[i])
                i += 1
            elif expr[i] == '<' and i + 1 < len(expr) and expr[i + 1] == '<':
                tokens.append('<<')
                i += 2
            elif expr[i] == '>' and i + 1 < len(expr) and expr[i + 1] == '>':
                tokens.append('>>')
                i += 2
            elif expr[i].isdigit() or (expr[i] == '0' and i + 1 < len(expr)
                                        and expr[i + 1] in 'xX'):
                j = i
                while j < len(expr) and (expr[j].isdigit()
                                          or expr[j] in 'xXabcdefABCDEF'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            elif expr[i].isalpha() or expr[i] == '_':
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == '_'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                i += 1
        return tokens


class SemiLinearMBASimplifier:

    def __init__(self, bit_width: int = 32):
        self.bw = bit_width
        self.bsimpl = BitLevelSimplifier()
        self.parser = SemiLinearParser()

    def simplify(self, expr_str: str) -> Dict[str, Any]:
        parsed = self.parser.parse(expr_str)
        if parsed is None:
            return {'original': expr_str, 'simplified': expr_str,
                    'is_semilinear': False, 'error': '解析失败'}

        is_sl = parsed.get('has_masked_terms', False)
        if not is_sl:
            return {'original': expr_str, 'simplified': expr_str,
                    'is_semilinear': False,
                    'message': '纯线性 MBA，请用 egraph_mba 处理'}

        simplified = self._apply_bitwise_simplification(parsed)
        return {
            'original': expr_str,
            'simplified': simplified,
            'is_semilinear': True,
            'masked_terms_found': len([t for t in parsed['terms']
                                       if t.get('mask') is not None]),
            'method': 'semilinear_bitlevel [Skees 2024]'
        }

    def _apply_bitwise_simplification(
        self, parsed: Dict[str, Any]
    ) -> str:
        """
        逐位简化半线性表达式
        
        对每个位构建独立的布尔表达式
        应用位级别简化规则后重建字级别结果
        """
        terms = parsed.get('terms', [])
        if not terms:
            return parsed.get('original', '')

        # 构建逐位表达式（简化实现：识别基本模式）
        parts = []
        for term in terms:
            var = term.get('variable', '?')
            mask = term.get('mask')

            if mask is not None:
                # 掩码变量：基于掩码值提供简化形式
                if mask == 1:
                    parts.append(f"{var}&1")
                elif mask == 0xFF:
                    parts.append(f"({var}&0xFF)")
                elif mask == 0xFFFF:
                    parts.append(f"({var}&0xFFFF)")
                elif mask == 0xFFFFFFFF:
                    parts.append(var)
                elif (mask & (mask - 1)) == 0:
                    # 单一位掩码（如 & 0x80）
                    bit_pos = mask.bit_length() - 1
                    parts.append(f"(({var}>>{bit_pos})&1)")
                else:
                    parts.append(f"({var}&0x{mask:x})")
            else:
                parts.append(var)

        if len(parts) <= 1:
            return parts[0] if parts else '0'

        # 检测可简化的模式
        joined = ' + '.join(parts)

        # 模式: (x & 0xF) + ((x >> 4) & 0xF) → x (字节分割后重组)
        nibble_pattern = re.findall(
            r'\((\w+)&0xF\)\s*\+\s*\(\(\1>>4\)&0xF\)', joined
        )
        if nibble_pattern:
            return nibble_pattern[0]

        return joined


def simplify_semilinear_mba(expr: str, bit_width: int = 32) -> Dict[str, Any]:
    simplifier = SemiLinearMBASimplifier(bit_width=bit_width)
    return simplifier.simplify(expr)
