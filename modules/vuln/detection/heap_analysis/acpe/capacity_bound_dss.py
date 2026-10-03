"""容量感知耦合边界验证-DSS: 动态slack减除.

与原 容量感知耦合边界验证 的本质区别:
  原 容量感知耦合边界验证 用固定 glibc 对齐公式 (align_up(N, 16)) 计算容量.
  容量感知耦合边界验证-DSS 根据分配函数类型 (malloc/calloc/realloc/aligned_alloc)
  动态计算 chunk 几何, 区分 slack 和 usable, 提高溢出判定精度.
"""
import re
from typing import Dict, List, Optional, Tuple

from modules.analysis.static.heap_alloc_model import (
    HeapAllocModel, AllocatorFamily,
)


class DynamicSlackSubtractor:
    """动态slack减除器, 根据分配函数类型计算真实 chunk 几何."""

    def __init__(self, alloc_model: HeapAllocModel = None):
        self._model = alloc_model or HeapAllocModel(AllocatorFamily.GLIBC)
        self._alloc_cache: Dict[str, dict] = {}

    def compute_usable(self, alloc_func: str, request_size: int) -> int:
        """根据分配函数类型计算实际可用容量."""
        if request_size < 0:
            return 0
        usable = self._model.usable_size(request_size)
        if alloc_func == 'calloc':
            # calloc 清零, usable = request_size (无 slack 利用)
            return request_size
        if alloc_func == 'realloc':
            # realloc 可能 in-place 扩展, usable 不变
            return usable
        # malloc: usable 含 prev_size 复用空间
        return usable

    def compute_chunk_geometry(self, alloc_func: str,
                               request_size: int) -> dict:
        """返回 chunk 完整几何信息."""
        chunk_size = self._model.actual_chunk_size(request_size)
        usable = self.compute_usable(alloc_func, request_size)
        # slack = 可写空间 - 请求大小 (glibc 中 prev_size 复用产生的额外空间)
        if alloc_func == 'calloc':
            slack = 0
            header_size = chunk_size - request_size
        else:
            slack = max(0, usable - request_size)
            header_size = chunk_size - usable

        return {
            'usable': usable,
            'chunk_size': chunk_size,
            'slack': slack,
            'header_size': header_size,
            'family': self._model.family.value,
            'alloc_func': alloc_func,
            'request_size': request_size,
        }

    def classify_overflow(self, alloc_func: str, alloc_size: int,
                          write_size: int) -> dict:
        """分类溢出: SAFE / OVERFLOW / UNCERTAIN.

        判定逻辑:
          write_size <= usable → SAFE
          write_size > usable + slack → OVERFLOW (越过 chunk 边界)
          usable < write_size <= usable + slack → UNCERTAIN (写入 slack 区)
        """
        geo = self.compute_chunk_geometry(alloc_func, alloc_size)
        usable = geo['usable']
        slack = geo['slack']

        if write_size <= usable:
            return {
                'verdict': 'SAFE',
                'usable': usable,
                'slack': slack,
                'overflow_bytes': 0,
                'reason': 'write_size({}) <= usable({})'.format(
                    write_size, usable),
            }

        if write_size > usable + slack:
            overflow_bytes = write_size - (usable + slack)
            return {
                'verdict': 'OVERFLOW',
                'usable': usable,
                'slack': slack,
                'overflow_bytes': overflow_bytes,
                'reason': 'write_size({}) > usable({}) + slack({})'.format(
                    write_size, usable, slack),
            }

        # 写入 slack 区: 不安全但不一定崩溃
        return {
            'verdict': 'UNCERTAIN',
            'usable': usable,
            'slack': slack,
            'overflow_bytes': 0,
            'reason': 'write_size({}) in slack zone [usable={}, usable+slack={}]'.format(
                write_size, usable, usable + slack),
        }

    def analyze_findings(self, findings: list,
                         pseudocode: str) -> list:
        """对已有 findings 做动态 slack 减除增强."""
        if not findings:
            return findings

        # 从伪代码提取分配函数类型
        alloc_funcs: Dict[str, str] = {}
        if pseudocode:
            for line in pseudocode.split('\n'):
                line = line.strip()
                m = re.match(
                    r'(\w+)\s*=\s*(malloc|calloc|realloc|aligned_alloc)\s*\(',
                    line, re.IGNORECASE)
                if m:
                    var = m.group(1)
                    func = m.group(2).lower()
                    alloc_funcs[var] = func

        for f in findings:
            if 'heap' not in f.get('type', '').lower():
                continue
            alloc_var = f.get('alloc_var', f.get('variable', ''))
            alloc_func = alloc_funcs.get(alloc_var, 'malloc')
            alloc_size = f.get('alloc_size', 0)
            write_size = f.get('write_size', 0)

            if isinstance(alloc_size, int) and isinstance(write_size, int) \
                    and alloc_size > 0:
                result = self.classify_overflow(
                    alloc_func, alloc_size, write_size)
                f['dss_geometry'] = result
                # 如果原 verdict 是 OVERFLOW 但 DSS 判为 SAFE (写入 slack)
                if result['verdict'] == 'SAFE' and \
                        f.get('severity', '').lower() in ('high', 'critical'):
                    f['dss_downgrade'] = (
                        '原判定为溢出但动态slack分析显示写入在可用范围内')
            else:
                # 大小未知, 只记录几何信息
                if isinstance(alloc_size, int) and alloc_size > 0:
                    geo = self.compute_chunk_geometry(
                        alloc_func, alloc_size)
                    f['dss_geometry'] = geo

        return findings

    @property
    def model(self) -> HeapAllocModel:
        return self._model
