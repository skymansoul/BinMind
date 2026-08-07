"""
堆表达式解析器 — 反编译伪代码中的size表达式 → AffineInterval.

处理模式:
  - 常量: "0x40", "64" → affine_const(val)
  - sizeof: "sizeof(struct foo)" → 尝试从符号表查大小, 否则保守常量
  - 变量: "n", "size" → affine_var(name)
  - 仿射: "n * 4 + 8", "(size + 1) * 2" → AffineInterval(base, coefs)
  - 调用: "strlen(s)" → affine_unbounded() (保守)
  - 算术: "a + b", "a * b", "a << 2" → 逐级展开

与约束追踪的对接: 解析的 AffineInterval 直接嵌入 VRF 的不等式检查.
"""


import re
from typing import Dict, Optional, Tuple

from .symbolic_range import (
    AffineInterval, affine_const, affine_var, affine_unbounded)


# sizeof 常见类型大小 (保守)
_SIZEOF_TABLE: Dict[str, int] = {
    "char": 1, "short": 2, "int": 4, "long": 8, "float": 4,
    "double": 8, "void*": 8, "char*": 8, "int*": 8, "size_t": 8,
    "ssize_t": 8, "off_t": 8, "pid_t": 4, "uid_t": 4,
    "uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8,
}


class HeapExprParser:
    """将 size/offset 文本表达式解析为 AffineInterval."""

    # 函数调用的 size 解析: func(expr) → 剥离外函数
    _STRIP_FUNCS = {"strlen", "sizeof", "wcslen"}

    def parse(self, text: str) -> AffineInterval:
        """入口: 解析表达式文本为 AffineInterval."""
        text = text.strip()
        if not text:
            return affine_unbounded()

        # 十六进制常量
        if re.match(r'^0x[0-9a-fA-F]+$', text):
            return affine_const(int(text, 16))

        # 十进制常量
        if re.match(r'^\d+$', text):
            return affine_const(int(text))

        # sizeof(type)
        sm = re.match(r'sizeof\s*\((.+)\)', text)
        if sm:
            return self._parse_sizeof(sm.group(1))

        # func(expr) → 剥离已知函数
        for fn in self._STRIP_FUNCS:
            if text.startswith(fn + '(') and text.endswith(')'):
                inner = text[len(fn) + 1:-1]
                # strlen/... → 返回值大小未知, 保守返回无界
                if fn in ("strlen", "wcslen"):
                    return affine_unbounded()
                return self.parse(inner)

        # 仿射运算: expr * N + M
        aff = self._parse_affine(text)
        if aff is not None:
            return aff

        # 简单变量
        if re.match(r'^[a-zA-Z_]\w*$', text):
            return affine_var(text)

        return affine_unbounded()

    def _parse_sizeof(self, type_text: str) -> AffineInterval:
        """解析 sizeof(type)."""
        type_text = type_text.strip()
        # 去除 struct/enum/union 前缀
        for prefix in ("struct ", "enum ", "union ", "const "):
            if type_text.startswith(prefix):
                type_text = type_text[len(prefix):]
        # 指针: type * → void* size (8 on 64-bit)
        if type_text.endswith('*') or type_text.endswith('* const'):
            return affine_const(8)
        if type_text in _SIZEOF_TABLE:
            return affine_const(_SIZEOF_TABLE[type_text])
        # 未知结构体 → 保守下界
        return AffineInterval(base=1, lo=1, hi=None)

    def _parse_affine(self, text: str) -> Optional[AffineInterval]:
        """解析 n*K+M 形的仿射表达式."""
        # 模式: var * const + const
        m = re.match(
            r'^(\w+)\s*\*\s*(\d+)\s*\+\s*(\d+)$', text)
        if m:
            var, mul, add = m.group(1), int(m.group(2)), int(m.group(3))
            return AffineInterval(
                base=add, coefs={var: mul}, lo=None, hi=None)

        # 模式: (expr) * const
        m = re.match(r'^\((.+)\)\s*\*\s*(\d+)$', text)
        if m:
            inner = self.parse(m.group(1))
            return inner.mul_constant(int(m.group(2)))

        # 模式: var * const
        m = re.match(r'^(\w+)\s*\*\s*(\d+)$', text)
        if m:
            return AffineInterval(
                base=0, coefs={m.group(1): int(m.group(2))},
                lo=None, hi=None)

        # 模式: expr + const
        m = re.match(r'^(.+)\s*\+\s*(\d+)$', text)
        if m:
            inner = self.parse(m.group(1))
            return inner.add_constant(int(m.group(2)))

        # 模式: expr << const (左移=乘)
        m = re.match(r'^(\w+)\s*<<\s*(\d+)$', text)
        if m:
            return AffineInterval(
                base=0, coefs={m.group(1): 1 << int(m.group(2))},
                lo=None, hi=None)

        return None


def quick_parse_size(size_text: str) -> AffineInterval:
    """便捷函数: 解析 size 表达式."""
    parser = HeapExprParser()
    return parser.parse(size_text)
