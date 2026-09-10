"""PG-WBV-LSA: 循环结构感知写界.

与原 PG-WBV 的本质区别:
  原 PG-WBV 只检测 call 类 (memcpy/strcpy) 和 mov 类内存写入, 不解析循环结构.
  PG-WBV-LSA 解析循环回跳结构推断迭代写量上界,
  将循环中的单次写入放大为总写量, 发现原 PG-WBV 遗漏的循环型溢出.
"""
import re
from collections import namedtuple
from typing import Dict, List, Optional, Tuple


LoopRecord = namedtuple(
    'LoopRecord',
    ['kind', 'iter_var', 'iter_bound', 'bound_kind', 'body_write', 'line'],
)


class LoopStructureAwareVerifier:
    """循环结构感知写界验证器, 推断循环迭代的写量上界."""

    # for(i=0; i<N; i++) 循环
    _FOR_LOOP = re.compile(
        r'for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\w+)\s*;\s*\1\s*\+\+\s*\)',
        re.IGNORECASE,
    )
    # while(cond) 循环
    _WHILE_LOOP = re.compile(
        r'while\s*\(\s*(.+?)\s*\)',
        re.IGNORECASE,
    )
    # do { ... } while(cond) 循环
    _DO_WHILE_LOOP = re.compile(
        r'do\s*\{',
        re.IGNORECASE,
    )
    # 循环体写入: buf[i] = ... / *p++ = ...
    _BODY_WRITE = re.compile(
        r'(\w+)\s*\[\s*(\w+)\s*\]\s*=|'  # array[idx] =
        r'\*?(\w+)\+?\+?\s*=\s*',         # *p++ = val
        re.IGNORECASE,
    )
    # strlen 上界: while(*s) / for(; *s; s++)
    _STRLEN_BOUND = re.compile(
        r'\*\s*(\w+)|while\s*\(\s*\*(\w+)\s*\)',
        re.IGNORECASE,
    )

    def __init__(self):
        self._loops: List[LoopRecord] = []

    def detect_loop_structure(self, pseudocode: str) -> List[LoopRecord]:
        """从伪代码检测循环结构."""
        if not pseudocode:
            return []

        results = []
        lines = pseudocode.split('\n')
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line:
                continue

            # for 循环
            m = self._FOR_LOOP.search(line)
            if m:
                iter_var = m.group(1)
                bound_expr = m.group(2)
                # 判断上界类型
                if re.match(r'\d+$', bound_expr):
                    bound_kind = 'constant'
                elif re.match(r'strlen\s*\(', bound_expr, re.IGNORECASE):
                    bound_kind = 'strlen'
                else:
                    bound_kind = 'variable'

                # 查找循环体内的写入 (后续 5 行)
                body_write = 0
                for j in range(lineno, min(lineno + 5, len(lines))):
                    body_line = lines[j].strip() if j < len(lines) else ''
                    if self._BODY_WRITE.search(body_line):
                        body_write += 1
                    if body_line and body_line.startswith('}'):
                        break

                results.append(LoopRecord(
                    kind='for',
                    iter_var=iter_var,
                    iter_bound=bound_expr,
                    bound_kind=bound_kind,
                    body_write=body_write,
                    line=lineno,
                ))
                continue

            # while 循环
            m2 = self._WHILE_LOOP.search(line)
            if m2 and not m:
                cond = m2.group(1)
                # while(*s) — strlen 上界
                if self._STRLEN_BOUND.search(cond):
                    bound_kind = 'strlen'
                    bound_expr = 'strlen-like'
                elif '1' in cond or 'true' in cond.lower():
                    bound_kind = 'unbounded'
                    bound_expr = 'unbounded'
                else:
                    bound_kind = 'variable'
                    bound_expr = cond

                body_write = 0
                for j in range(lineno, min(lineno + 5, len(lines))):
                    body_line = lines[j].strip() if j < len(lines) else ''
                    if self._BODY_WRITE.search(body_line):
                        body_write += 1
                    if body_line and body_line.startswith('}'):
                        break

                results.append(LoopRecord(
                    kind='while',
                    iter_var='',
                    iter_bound=bound_expr,
                    bound_kind=bound_kind,
                    body_write=body_write,
                    line=lineno,
                ))

        self._loops = results
        return results

    def estimate_iteration_write(self, loop: dict,
                                 body_write_size: int) -> int:
        """估算循环总写量: iterations * body_write_size."""
        bound_kind = loop.get('bound_kind', 'variable')
        bound_expr = loop.get('iter_bound', 'unknown')
        body_write = loop.get('body_write', 1)

        if bound_kind == 'constant':
            try:
                iterations = int(bound_expr)
            except (ValueError, TypeError):
                    iterations = 0
            return iterations * body_write * body_write_size
        elif bound_kind == 'strlen':
            # strlen 上界: 假设平均 256 字符
            return 256 * body_write_size
        elif bound_kind == 'unbounded':
            # 无界循环: 返回 -1 表示无法定界
            return -1
        # 变量上界: 估计 128 (保守上界)
        return 128 * body_write * body_write_size

    def verify_write_bound(self, alloc_size: int,
                           write_pattern: dict) -> dict:
        """验证写入是否超出分配边界."""
        total_write = write_pattern.get('total_write', 0)
        iterations = write_pattern.get('iterations', 0)

        if total_write < 0:
            return {
                'verdict': 'UNCERTAIN',
                'confidence': 0.40,
                'reason': '无界循环, 无法定界',
                'total_write': -1,
                'iterations': iterations,
            }

        if alloc_size > 0 and total_write > alloc_size:
            return {
                'verdict': 'OVERFLOW',
                'confidence': 0.82,
                'reason': 'total_write({}) > alloc_size({})'.format(
                    total_write, alloc_size),
                'total_write': total_write,
                'iterations': iterations,
            }

        if alloc_size > 0 and total_write <= alloc_size:
            return {
                'verdict': 'SAFE',
                'confidence': 0.85,
                'reason': 'total_write({}) <= alloc_size({})'.format(
                    total_write, alloc_size),
                'total_write': total_write,
                'iterations': iterations,
            }

        return {
            'verdict': 'UNCERTAIN',
            'confidence': 0.50,
            'reason': 'alloc_size 或 total_write 未知',
            'total_write': total_write,
            'iterations': iterations,
        }

    def analyze_findings(self, findings: list,
                        pseudocode: str) -> list:
        """对已有 findings 做循环结构感知增强."""
        if not findings or not pseudocode:
            return findings

        loops = self.detect_loop_structure(pseudocode)
        if not loops:
            return findings

        for f in findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)

            # 找到 finding 附近的循环
            finding_line = f.get('line', 0)
            for loop in loops:
                # 只增强 finding 所在行附近的循环
                if abs(loop.line - finding_line) > 10 and finding_line > 0:
                    continue
                total = self.estimate_iteration_write(
                    loop._asdict(),
                    write_size if isinstance(write_size, int) and write_size > 0 else 1,
                )
                if total > 0 and isinstance(alloc_size, int) and alloc_size > 0:
                    result = self.verify_write_bound(alloc_size, {
                        'total_write': total,
                        'iterations': loop.iter_bound,
                    })
                    f['lsa_loop'] = {
                        'kind': loop.kind,
                        'iter_var': loop.iter_var,
                        'iter_bound': loop.iter_bound,
                        'bound_kind': loop.bound_kind,
                        'total_write': total,
                        'verdict': result['verdict'],
                        'confidence': result['confidence'],
                        'reason': result['reason'],
                    }
                    # 如果原 finding 未报溢出但循环总写量超界
                    if result['verdict'] == 'OVERFLOW' and \
                            f.get('severity', '').lower() not in ('high', 'critical'):
                        f['lsa_upgrade'] = (
                            '循环结构分析发现总写量超出分配大小')
                    break

        return findings

    @property
    def loops(self) -> List[LoopRecord]:
        return self._loops
