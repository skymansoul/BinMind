"""
[DEPRECATED] 选择性符号执行, 已迁移至 analysis/selective_symexec.py.
仅保留向后兼容, 新代码从 analysis 导入。路径上限 128, 只符号化 size 参数。
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

def _match_paren(text: str, open_pos: int) -> str:
    """括号匹配: 返回匹配括号内文本, 处理嵌套。"""
    d, i = 1, open_pos + 1
    while i < len(text) and d > 0:
        if text[i] == '(': d += 1
        elif text[i] == ')': d -= 1
        i += 1
    return text[open_pos + 1:i - 1] if d == 0 else text[open_pos + 1:]


@dataclass
class SymVar:
    """符号变量: 表示一个未知但受范围约束的整数。"""
    name: str
    lo: int = 0
    hi: int = 2**31 - 1

    def __hash__(self): return hash(self.name)


@dataclass
class SymExpr:
    """符号表达式: const + Σ coef_i * sym_i。"""
    const: int = 0
    terms: Dict[str, int] = field(default_factory=dict)  # sym_name → coef

    @staticmethod
    def const_val(v: int) -> "SymExpr":
        return SymExpr(const=v)

    @staticmethod
    def sym(name: str) -> "SymExpr":
        return SymExpr(terms={name: 1})

    def evaluate(self, bindings: Dict[str, int]) -> int:
        val = self.const
        for sym, coef in self.terms.items():
            val += coef * bindings.get(sym, 0)
        return val

    def __add__(self, other: "SymExpr") -> "SymExpr":
        terms = dict(self.terms)
        for k, v in other.terms.items():
            terms[k] = terms.get(k, 0) + v
        return SymExpr(const=self.const + other.const, terms=terms)

    def __mul__(self, c: int) -> "SymExpr":
        return SymExpr(const=self.const * c,
                       terms={k: v * c for k, v in self.terms.items()})

    def __repr__(self):
        parts = [str(self.const)] if self.const else []
        for s, c in self.terms.items():
            parts.append(f"{c}*{s}" if c != 1 else s)
        return "+".join(parts) if parts else "0"


@dataclass
class HeapPath:
    """一条从 malloc 到 memcpy 的路径摘要。"""
    alloc_var: str
    alloc_size_expr: SymExpr         # malloc 的大小表达式 (可含符号变量)
    write_var: str
    write_size_expr: SymExpr         # memcpy 的大小表达式
    constraints: List[Tuple[str, str, int]]  # [(var, op, val), ...] 路径上的条件
    path_length: int  # 经过的基本块数


class SelectiveSymExec:
    """选择性符号执行: 输入反编译代码, 输出(malloc→memcpy)路径约束。路径上限128, 符号变量上限8。"""

    MAX_PATHS = 128
    MAX_SYM_VARS = 8

    def __init__(self):
        self._sym_vars: Dict[str, SymVar] = {}

    def analyze(self, code: str, func_name: str = "") -> List[HeapPath]:
        """分析函数中的堆操作路径。

        返回 HeapPath 列表, 每条表示一个可能的 malloc→write 通路。
        """
        self._sym_vars.clear()
        paths: List[HeapPath] = []

        # 提取所有 malloc 和 memcpy 调用
        allocs = self._extract_allocs(code)
        writes = self._extract_writes(code)

        if not allocs or not writes:
            return paths

        # 对每一对 (alloc, write) 检查它们在 CFG 上的可达性
        for alloc in allocs:
            for write in writes:
                if alloc['var'] != write['var']:
                    continue
                if write['lineno'] <= alloc['lineno']:
                    continue

                # 收集两点间的路径约束
                constraints = self._collect_constraints(
                    code, alloc['lineno'], write['lineno'])

                alloc_expr = self._parse_to_symexpr(alloc['size'])
                write_expr = self._parse_to_symexpr(write['size'])

                paths.append(HeapPath(
                    alloc_var=alloc['var'],
                    alloc_size_expr=alloc_expr,
                    write_var=write['var'],
                    write_size_expr=write_expr,
                    constraints=constraints,
                    path_length=write['lineno'] - alloc['lineno'],
                ))

                if len(paths) >= self.MAX_PATHS:
                    return paths

        return paths

    def verify_path(self, path: HeapPath) -> Tuple[str, float, str]:
        """验证单条路径是否产生真溢出。

        返回: (verdict, confidence, reason)
          verdict ∈ {"DEFINITE", "POSSIBLE", "SAFE"}
        """
        # 尝试用约束求解: 若存在一组符号变量赋值使得溢出, 则 POSSIBLE
        # 若对所有满足约束的赋值都溢出, 则 DEFINITE
        # 否则 SAFE

        sym_names = set(path.alloc_size_expr.terms.keys())
        sym_names |= set(path.write_size_expr.terms.keys())

        if not sym_names:
            # 无符号变量, 纯常量比较
            alloc_val = path.alloc_size_expr.const
            write_val = path.write_size_expr.const
            if write_val > alloc_val:
                return ("DEFINITE", 0.95,
                        f"constant overflow: {write_val} > {alloc_val}")
            return ("SAFE", 0.0,
                    f"safe: {write_val} <= {alloc_val}")

        # 有符号变量, 在约束下采样检查
        return self._verify_with_constraints(path, sym_names)

    def _verify_with_constraints(
        self, path: HeapPath, sym_names: Set[str]
    ) -> Tuple[str, float, str]:
        """在路径约束下验证溢出可能性。

        方法: 将约束转化为变量的取值区间, 然后做边界检查。
        """
        # 收集约束给出的变量范围
        bounds: Dict[str, Tuple[int, int]] = {}
        for var, op, val in path.constraints:
            if var not in sym_names:
                continue
            lo, hi = bounds.get(var, (0, 2**31 - 1))
            if op in ('<=', '<'):
                hi = min(hi, val - (1 if op == '<' else 0))
            elif op in ('>=', '>'):
                lo = max(lo, val + (1 if op == '>' else 0))
            elif op == '==':
                lo = max(lo, val)
                hi = min(hi, val)
            bounds[var] = (lo, hi)

        # 在约束范围内计算分配大小和写入大小的极值
        alloc_lo, alloc_hi = self._eval_range(path.alloc_size_expr, bounds)
        write_lo, write_hi = self._eval_range(path.write_size_expr, bounds)

        # 两边界均为 TOP → 无有效约束, 不可证安全, 保守保留
        MAX_BOUND = 2**31 - 2  # 略低于 TOP 值, 允许 1 单位容差
        both_unbounded = (alloc_hi >= MAX_BOUND and write_hi >= MAX_BOUND)

        if write_lo > alloc_hi:
            return ("DEFINITE", 0.90,
                    f"symbolic definite: min_write={write_lo} > max_alloc={alloc_hi}")
        if both_unbounded:
            return ("POSSIBLE", 0.40,
                    f"symbolic unbounded: both sides at TOP, conservative keep")
        if write_hi > alloc_hi:
            return ("POSSIBLE", 0.50,
                    f"symbolic possible: max_write={write_hi} > max_alloc={alloc_hi}")
        return ("SAFE", 0.0,
                f"symbolic safe: max_write={write_hi} <= max_alloc={alloc_hi}")

    def _eval_range(
        self, expr: SymExpr, bounds: Dict[str, Tuple[int, int]]
    ) -> Tuple[int, int]:
        """计算符号表达式在变元范围内的最值。"""
        lo = expr.const
        hi = expr.const
        for sym, coef in expr.terms.items():
            if sym in bounds:
                s_lo, s_hi = bounds[sym]
                if coef >= 0:
                    lo += coef * s_lo
                    hi += coef * s_hi
                else:
                    lo += coef * s_hi
                    hi += coef * s_lo
            else:
                # 未知变量: 退化为大范围
                lo += coef * 0 if coef >= 0 else coef * (2**31 - 1)
                hi += coef * (2**31 - 1) if coef >= 0 else coef * 0
        return (max(0, lo), min(2**31 - 1, hi))

    def _extract_allocs(self, code: str) -> List[dict]:
        results = []
        for i, line in enumerate(code.split('\n'), start=1):
            m = re.search(
                r'(\w[\w.\->]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(',
                line)
            if m:
                size_text = _match_paren(line, m.end() - 1)
                results.append({'var': m.group(1), 'func': m.group(2),
                               'size': size_text.strip(), 'lineno': i})
        return results

    def _extract_writes(self, code: str) -> List[dict]:
        from .heap_expr_parser import split_args
        results = []
        for i, line in enumerate(code.split('\n'), start=1):
            m = re.search(r'(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|memset|bcopy)\s*\(', line)
            if m:
                args = split_args(_match_paren(line, m.end() - 1))
                if len(args) >= 2:
                    results.append({
                        'var': args[0].strip(), 'call': m.group(1),
                        'size': args[-1].strip() if len(args) >= 3 else args[1].strip(),
                        'lineno': i,
                    })
        return results

    def _collect_constraints(self, code: str, start: int, end: int) -> List[Tuple[str, str, int]]:
        """收集 start 到 end 行之间的条件约束。"""
        constraints = []
        lines = code.split('\n')
        for i in range(start, min(end, len(lines))):
            line = lines[i].strip() if i < len(lines) else ""
            m = re.search(r'if\s*\(\s*(\w+)\s*(<|>|<=|>=|==|!=)\s*(\d+)\s*\)', line)
            if m:
                constraints.append((m.group(1), m.group(2), int(m.group(3))))
        return constraints

    def _parse_to_symexpr(self, text: str) -> SymExpr:
        """将文本表达式解析为 SymExpr (保守: 未知→⊤)。"""
        text = text.strip().replace(' ', '')
        if not text:
            return SymExpr.const_val(0)
        for parse_int in [lambda t: int(t), lambda t: int(t, 16)]:
            try:
                return SymExpr.const_val(parse_int(text))
            except ValueError:
                pass

        if re.match(r'^[a-zA-Z_]\w*$', text):
            return SymExpr.sym(text)
        for pat, coef_idx, const_idx in [
            (r'^([a-zA-Z_]\w*)\*(\d+)$', 1, None),
            (r'^(\d+)\*([a-zA-Z_]\w*)$', 0, None),
            (r'^([a-zA-Z_]\w*)\*(\d+)\+(\d+)$', 1, 2),
        ]:
            m = re.match(pat, text)
            if m:
                expr = SymExpr.sym(m.group(1 if coef_idx == 0 else 1)) * int(m.group(coef_idx + 1))
                if const_idx:
                    expr = expr + SymExpr.const_val(int(m.group(const_idx + 1)))
                return expr
        return SymExpr.const_val(2**31 - 1)
