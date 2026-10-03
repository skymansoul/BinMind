"""BIV-CTC: 跨类型约束传播.

与原 BIV (BidirectionalIntervalVerifier) 的本质区别:
  原 BIV 只做堆区间交汇 (alloc_lower/alloc_upper vs write_low/write_high).
  BIV-CTC 增加栈/全局缓冲区的区间交汇, 跨类型约束传播,
  区分堆溢出与栈溢出, 避免误将栈缓冲区写入当作堆溢出.
"""
import re
from collections import namedtuple
from typing import Dict, List, Optional, Tuple


CrossTypeConstraint = namedtuple(
    'CrossTypeConstraint',
    ['var', 'buf_type', 'lower', 'upper', 'section', 'line'],
)


class CrossTypeConstraintPropagator:
    """跨类型约束传播器, 在堆/栈/全局缓冲区间传播区间约束."""

    # 栈分配模式: char buf[64] / int arr[16]
    _STACK_ALLOC = re.compile(
        r'(?:char|int|unsigned\s+char|uint8_t|uint16_t|uint32_t|void)\s+'
        r'(\w+)\s*\[\s*(\d+)\s*\]',
    )
    # 堆分配: p = malloc(64)
    _HEAP_ALLOC = re.compile(
        r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(\s*(\d+)',
        re.IGNORECASE,
    )
    # 全局: static char buf[64] / char buf[64] = ...
    _GLOBAL_ALLOC = re.compile(
        r'(?:static\s+)?(char|int|unsigned\s+char)\s+(\w+)\s*\[\s*(\d+)\s*\]'
        r'\s*(?:=\s*[^{]|;|$)',
    )
    # 写入: memcpy(dst, src, n) / strcpy(dst, src)
    _WRITE_CALL = re.compile(
        r'(memcpy|strcpy|memmove|strncpy|memset|sprintf|snprintf)\s*'
        r'\(\s*(\w+)',
        re.IGNORECASE,
    )

    def __init__(self):
        self._heap_bufs: Dict[str, Tuple[int, int]] = {}
        self._stack_bufs: Dict[str, Tuple[int, int]] = {}
        self._global_bufs: Dict[str, Tuple[int, int, str]] = {}
        self._constraints: List[CrossTypeConstraint] = []

    def register_heap_alloc(self, var: str, size: int):
        self._heap_bufs[var] = (0, size)

    def register_stack_alloc(self, var: str, size: int):
        self._stack_bufs[var] = (0, size)

    def register_global_alloc(self, var: str, size: int, section: str):
        self._global_bufs[var] = (0, size, section)

    def _classify_buf(self, var: str) -> Tuple[str, int, int, str]:
        """返回 (buf_type, lower, upper, section)."""
        if var in self._heap_bufs:
            lo, hi = self._heap_bufs[var]
            return ('heap', lo, hi, '.heap')
        if var in self._stack_bufs:
            lo, hi = self._stack_bufs[var]
            return ('stack', lo, hi, '.stack')
        if var in self._global_bufs:
            lo, hi, sec = self._global_bufs[var]
            return ('global', lo, hi, sec)
        return ('unknown', 0, 0, '')

    def propagate_constraints(self, pseudocode: str) -> list:
        """从伪代码传播约束, 返回 CrossTypeConstraint 列表."""
        if not pseudocode:
            return []

        results = []
        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            # 检测栈分配
            for m in self._STACK_ALLOC.finditer(line):
                var, size_str = m.groups()
                size = int(size_str)
                self.register_stack_alloc(var, size)
                results.append(CrossTypeConstraint(
                    var=var, buf_type='stack',
                    lower=0, upper=size, section='.stack', line=lineno,
                ))

            # 检测堆分配
            m2 = self._HEAP_ALLOC.search(line)
            if m2:
                var, size_str = m2.groups()
                size = int(size_str)
                self.register_heap_alloc(var, size)
                results.append(CrossTypeConstraint(
                    var=var, buf_type='heap',
                    lower=0, upper=size, section='.heap', line=lineno,
                ))

            # 检测写入调用
            m3 = self._WRITE_CALL.search(line)
            if m3:
                func, dst = m3.groups()
                buf_type, lo, hi, sec = self._classify_buf(dst)
                if buf_type != 'unknown':
                    results.append(CrossTypeConstraint(
                        var=dst, buf_type=buf_type,
                        lower=lo, upper=hi, section=sec, line=lineno,
                    ))

        self._constraints = results
        return results

    def check_cross_type_overflow(self, findings: list) -> list:
        """检查跨类型溢出."""
        for f in findings:
            var = f.get('dst_var', f.get('variable', ''))
            if not var:
                continue
            buf_type, lo, hi, sec = self._classify_buf(var)
            if buf_type == 'unknown':
                continue
            f['cross_type'] = buf_type
            f['cross_type_section'] = sec
            # 如果是栈缓冲区但被当作堆溢出报告
            if buf_type == 'stack' and 'heap' in f.get('type', '').lower():
                f['cross_type_reclass'] = 'stack_overflow'
            elif buf_type == 'global' and 'heap' in f.get('type', '').lower():
                f['cross_type_reclass'] = 'global_overflow'
        return findings

    def verify(self, alloc_type: str, alloc_lower: int, alloc_upper: int,
               write_type: str, write_low: int, write_high: int,
               write_known: bool) -> dict:
        """区间交汇验证, 支持跨类型."""
        if alloc_upper <= alloc_lower:
            return {
                'verdict': 'UNCERTAIN',
                'confidence': 0.30,
                'reason': '无效的分配区间',
                'cross_type': False,
            }

        if not write_known:
            return {
                'verdict': 'UNCERTAIN',
                'confidence': 0.40,
                'reason': '写入区间未知',
                'cross_type': False,
            }

        if write_high <= alloc_upper:
            return {
                'verdict': 'SAFE',
                'confidence': 0.90,
                'reason': 'write_high({}) <= alloc_upper({})'.format(
                    write_high, alloc_upper),
                'cross_type': alloc_type != write_type,
            }

        if write_low > alloc_upper:
            return {
                'verdict': 'OVERFLOW',
                'confidence': 0.88,
                'reason': 'write_low({}) > alloc_upper({})'.format(
                    write_low, alloc_upper),
                'cross_type': alloc_type != write_type,
            }

        return {
            'verdict': 'OVERFLOW',
            'confidence': 0.75,
            'reason': 'write_high({}) > alloc_upper({})'.format(
                write_high, alloc_upper),
            'cross_type': alloc_type != write_type,
        }

    @property
    def constraints(self) -> List[CrossTypeConstraint]:
        return self._constraints
