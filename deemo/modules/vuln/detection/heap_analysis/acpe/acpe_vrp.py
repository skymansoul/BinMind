"""ACPE-VRP: 值域传播增强.

与原 ACPE 的本质区别:
  原 ACPE 只做常量提取的容量比较.
  ACPE-VRP 用区间传播在非常量场景提供区间估计,
  通过守卫约束钳位值域, 为 ACPE 提供更精确的溢出判定.
"""
import re
from typing import Dict, List, Optional, Tuple


class ValueRangePropagationEnhancer:
    """值域传播增强器, 为 ACPE 提供非常量场景的区间估计."""

    # 变量赋值: n = arg / n = 64 / n = size - 8
    _ASSIGN = re.compile(
        r'(\w+)\s*=\s*(.+?)(?:;|$)',
    )
    # 守卫: if(n > 64) return / if(n >= N) return
    _GUARD = re.compile(
        r'if\s*\(\s*(\w+)\s*(>=|>|<=|<|==)\s*(\w+)\s*\)\s*(?:return|break|continue)',
        re.IGNORECASE,
    )
    # 分配: p = malloc(n)
    _ALLOC = re.compile(
        r'(\w+)\s*=\s*(malloc|calloc)\s*\(\s*(\w+)',
        re.IGNORECASE,
    )
    # 写入: memcpy(p, src, n) / strcpy(p, src)
    _WRITE = re.compile(
        r'(memcpy|strcpy|memmove|strncpy|memset)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)',
        re.IGNORECASE,
    )

    _INF = float('inf')

    def __init__(self):
        self._ranges: Dict[str, Tuple[float, float]] = {}

    def propagate_ranges(self, pseudocode: str) -> Dict[str, Tuple[float, float]]:
        """从伪代码传播值域, 返回 {var_name: (lo, hi)}."""
        if not pseudocode:
            return {}

        ranges: Dict[str, Tuple[float, float]] = {}
        lines = pseudocode.split('\n')

        for raw in lines:
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            # 变量赋值
            m = self._ASSIGN.match(line)
            if m:
                var = m.group(1)
                expr = m.group(2).strip()
                lo, hi = self._eval_expr(expr, ranges)
                ranges[var] = (lo, hi)

                # 分配: p = malloc(n) → 记录 n 的值域作为 alloc_size
                m_alloc = self._ALLOC.match(line)
                if m_alloc:
                    size_var = m_alloc.group(3)
                    alloc_size_range = ranges.get(size_var, (0, self._INF))
                    ranges[var + '_alloc_size'] = alloc_size_range
                continue

            # 写入: memcpy(p, src, n) → 记录 n 的值域作为 write_size
            m_write = self._WRITE.search(line)
            if m_write:
                func, dst, size_var = m_write.groups()
                write_range = ranges.get(size_var, (0, self._INF))
                ranges[dst + '_write_size'] = write_range

        self._ranges = ranges
        return ranges

    def _eval_expr(self, expr: str,
                  ranges: Dict[str, Tuple[float, float]]) -> Tuple[float, float]:
        """评估表达式值域."""
        expr = expr.strip()

        # 常量
        if re.match(r'\d+$', expr):
            v = int(expr)
            return (float(v), float(v))
        if re.match(r'0x[0-9a-fA-F]+$', expr):
            v = int(expr, 16)
            return (float(v), float(v))

        # 变量
        if expr in ranges:
            return ranges[expr]

        # 变量 ± 常量
        m = re.match(r'(\w+)\s*([+\-*/])\s*(\d+)', expr)
        if m:
            var, op, const_str = m.groups()
            const = float(const_str)
            lo, hi = ranges.get(var, (0, self._INF))
            if op == '+':
                return (lo + const, hi + const if hi != self._INF else self._INF)
            elif op == '-':
                return (lo - const, hi - const if hi != self._INF else self._INF)
            elif op == '*':
                if lo >= 0 and const > 0:
                    return (lo * const, hi * const if hi != self._INF else self._INF)
            elif op == '/':
                if const > 0 and lo >= 0:
                    return (lo / const, hi / const if hi != self._INF else self._INF)

        # 函数调用 (如 strlen(s)): 估计 [0, 4096]
        if re.match(r'\w+\s*\(', expr):
            return (0.0, 4096.0)

        # 未知表达式: 宽区间
        return (0.0, self._INF)

    def refine_with_guards(self, ranges: dict,
                           pseudocode: str) -> Dict[str, Tuple[float, float]]:
        """用守卫约束精化值域."""
        if not pseudocode:
            return ranges

        for raw in pseudocode.split('\n'):
            line = raw.strip()
            if not line:
                continue

            m = self._GUARD.search(line)
            if not m:
                continue

            var, op, bound_str = m.groups()
            # 解析 bound
            if re.match(r'\d+$', bound_str):
                bound = float(bound_str)
            elif bound_str in ranges:
                bound = ranges[bound_str][1]  # 用上界
            else:
                continue

            lo, hi = ranges.get(var, (0, self._INF))

            # if(n > 64) return → n <= 64 (钳位上界)
            if op == '>' or op == '>=':
                ranges[var] = (lo, bound)
            # if(n < 64) return → n >= 64 (钳位下界)
            elif op == '<' or op == '<=':
                ranges[var] = (bound, hi)
            # if(n == 64) return → n != 64 (无法简单钳位)
            elif op == '==':
                pass

        self._ranges = ranges
        return ranges

    def compare_alloc_write(self, alloc_range: tuple,
                             write_range: tuple,
                             alloc_func: str) -> dict:
        """比较分配区间与写入区间."""
        alloc_lo, alloc_hi = alloc_range
        write_lo, write_hi = write_range

        if alloc_hi == self._INF or write_hi == self._INF:
            return {
                'verdict': 'UNCERTAIN',
                'confidence': 0.40,
                'reason': '值域上界无界',
                'alloc_range': alloc_range,
                'write_range': write_range,
            }

        if alloc_lo > write_hi:
            return {
                'verdict': 'SAFE',
                'confidence': 0.92,
                'reason': 'alloc_lo({}) > write_hi({})'.format(
                    alloc_lo, write_hi),
                'alloc_range': alloc_range,
                'write_range': write_range,
            }

        if alloc_hi < write_lo:
            return {
                'verdict': 'OVERFLOW',
                'confidence': 0.90,
                'reason': 'alloc_hi({}) < write_lo({})'.format(
                    alloc_hi, write_lo),
                'alloc_range': alloc_range,
                'write_range': write_range,
            }

        # 区间重叠
        return {
            'verdict': 'UNCERTAIN',
            'confidence': 0.50,
            'reason': '区间重叠: alloc=[{}, {}], write=[{}, {}]'.format(
                alloc_lo, alloc_hi, write_lo, write_hi),
            'alloc_range': alloc_range,
            'write_range': write_range,
        }

    def enhance_findings(self, findings: list,
                         pseudocode: str) -> list:
        """对已有 findings 做值域传播增强."""
        if not findings:
            return findings

        ranges = self.propagate_ranges(pseudocode)
        ranges = self.refine_with_guards(ranges, pseudocode)

        for f in findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_var = f.get('alloc_var', f.get('variable', ''))
            write_var = f.get('dst_var', f.get('variable', ''))

            # 查找值域
            alloc_range = ranges.get(
                alloc_var + '_alloc_size',
                ranges.get(alloc_var, (0, self._INF)))
            write_range = ranges.get(
                write_var + '_write_size',
                ranges.get(f.get('write_size_expr', ''), (0, self._INF)))

            result = self.compare_alloc_write(
                alloc_range, write_range,
                f.get('alloc_func', 'malloc'))
            f['vrp_range'] = result

            # 如果原 verdict 不明确但 VRP 能判定
            if result['verdict'] != 'UNCERTAIN' and \
                    f.get('confidence', 1.0) < 0.5:
                f['vrp_verdict'] = result['verdict']
                f['confidence'] = max(f.get('confidence', 0.5),
                                      result['confidence'])

        return findings

    @property
    def ranges(self) -> Dict[str, Tuple[float, float]]:
        return dict(self._ranges)
