"""FC-VRA-PTA: 指针污点别名传播.

与原 FC-VRA 的本质区别:
  原 FC-VRA 用并查集式别名闭包传播, 不区分指针是否受控.
  FC-VRA-PTA 加入污点传播维度, 区分受控/不受控指针,
  只在受控指针场景触发溢出告警, 减少安全代码的误报.
"""
import re
from typing import Dict, List, Optional, Set, Tuple


class PointerTaintAliasTracker:
    """指针污点别名追踪器, 在别名传播中加入污点维度."""

    # 外部输入函数: 返回值受用户控制
    _TAINT_SOURCES = {
        'read', 'recv', 'scanf', 'gets', 'fgets', 'fread',
        'getenv', 'getopt', 'argv',
    }
    # 分配函数: 返回值不受控
    _ALLOC_FUNCS = {
        'malloc', 'calloc', 'realloc', 'aligned_alloc',
    }

    def __init__(self):
        self._taint_set: Set[str] = set()
        self._alloc_map: Dict[str, str] = {}
        self._alias_map: Dict[str, str] = {}
        self._size_map: Dict[str, str] = {}

    def track_pointer(self, var: str, alloc_func: str,
                      size_expr: str, is_tainted: bool = False):
        """记录指针变量来源."""
        self._alloc_map[var] = alloc_func
        self._size_map[var] = size_expr
        if is_tainted:
            self._taint_set.add(var)

    def add_alias(self, dst: str, src: str):
        """别名传播时继承污点属性."""
        canonical = self._find_canonical(src)
        self._alias_map[dst] = canonical
        if canonical in self._taint_set:
            self._taint_set.add(dst)

    def mark_tainted(self, var: str):
        """标记变量为受控 (来自外部输入)."""
        self._taint_set.add(var)
        # 传播到所有别名
        for alias, canonical in self._alias_map.items():
            if canonical == self._find_canonical(var):
                self._taint_set.add(alias)

    def _find_canonical(self, var: str) -> str:
        """查找变量的 canonical 根."""
        seen = set()
        current = var
        while current in self._alias_map and current not in seen:
            seen.add(current)
            current = self._alias_map[current]
        return current

    def resolve_alias(self, var: str) -> Tuple[str, bool]:
        """返回 (canonical_var, is_tainted)."""
        canonical = self._find_canonical(var)
        return (canonical, canonical in self._taint_set)

    def check_overflow(self, alloc_var: str, write_var: str,
                       alloc_size: int, write_size: int) -> dict:
        """检查是否存在堆溢出.

        返回 {verdict, reason, is_tainted, canonical}.
        """
        alloc_canon = self._find_canonical(alloc_var)
        write_canon = self._find_canonical(write_var)
        is_tainted = write_canon in self._taint_set

        if alloc_canon == write_canon:
            return {
                'verdict': 'SAFE',
                'reason': 'alloc 和 write 同根同源, 不会溢出',
                'is_tainted': is_tainted,
                'canonical': alloc_canon,
            }

        if isinstance(alloc_size, int) and isinstance(write_size, int):
            if alloc_size > 0 and write_size > alloc_size:
                if is_tainted:
                    return {
                        'verdict': 'OVERFLOW',
                        'reason': '受控指针写入超过分配大小',
                        'is_tainted': True,
                        'canonical': write_canon,
                    }
                return {
                    'verdict': 'OVERFLOW',
                    'reason': '写入超过分配大小 (非受控)',
                    'is_tainted': False,
                    'canonical': write_canon,
                }
            if alloc_size > 0 and write_size <= alloc_size:
                return {
                    'verdict': 'SAFE',
                    'reason': 'write_size <= alloc_size',
                    'is_tainted': is_tainted,
                    'canonical': alloc_canon,
                }

        if is_tainted:
            return {
                'verdict': 'UNCERTAIN',
                'reason': '受控指针但大小未知',
                'is_tainted': True,
                'canonical': write_canon,
            }
        return {
            'verdict': 'UNCERTAIN',
            'reason': '非受控指针且大小未知',
            'is_tainted': False,
            'canonical': write_canon,
        }

    def analyze_pseudocode(self, pseudocode: str) -> list:
        """从伪代码分析指针污点别名."""
        findings = []
        if not pseudocode:
            return findings

        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            # 分配: p = malloc(n)
            m = re.match(r'(\w+)\s*=\s*(malloc|calloc|realloc|aligned_alloc)\s*\(([^)]*)\)', line, re.IGNORECASE)
            if m:
                var, func, args = m.groups()
                self.track_pointer(var, func.lower(), args.split(',')[0].strip(),
                                   is_tainted=False)
                continue

            # 污点源: p = read(fd, buf, n) / n = recv(...)
            m2 = re.match(r'(\w+)\s*=\s*(read|recv|scanf|gets|fgets|fread|getenv)\s*\(', line, re.IGNORECASE)
            if m2:
                var = m2.group(1)
                self.mark_tainted(var)
                continue

            # 别名: q = p / q = p + offset / q = &p[i]
            m3 = re.match(r'(\w+)\s*=\s*(\w+)\s*([+\-].*)?$', line)
            if m3:
                dst = m3.group(1)
                src = m3.group(2)
                if src in self._alloc_map or src in self._alias_map:
                    self.add_alias(dst, src)
                continue

            # 写入检查: memcpy(p, src, n) / strcpy(p, src)
            m4 = re.match(r'(memcpy|strcpy|memmove|memset|strncpy)\s*\((\w+),\s*(\w+)(?:,\s*(\w+))?', line, re.IGNORECASE)
            if m4:
                func = m4.group(1).lower()
                dst = m4.group(2)
                src = m4.group(3)
                size_arg = m4.group(4)
                alloc_func = self._alloc_map.get(self._find_canonical(dst), '')
                if alloc_func:
                    size_expr = self._size_map.get(self._find_canonical(dst), '0')
                    finding = {
                        'type': 'heap_overflow',
                        'function': func,
                        'dst_var': dst,
                        'alloc_var': self._find_canonical(dst),
                        'write_var': src,
                        'alloc_func': alloc_func,
                        'size_expr': size_expr,
                        'write_size_expr': size_arg or 'unknown',
                        'line': lineno,
                    }
                    result = self.check_overflow(
                        self._find_canonical(dst),
                        src,
                        0, 0,  # 大小未知, 让 check_overflow 做 alias/taint 判断
                    )
                    finding['taint_verdict'] = result['verdict']
                    finding['is_tainted'] = result['is_tainted']
                    findings.append(finding)

        return findings
