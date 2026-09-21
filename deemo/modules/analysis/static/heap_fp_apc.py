"""堆溢出误报抑制-自适应优先级级联.

与原堆溢出误报抑制的本质区别:
  原堆溢出误报抑制固定三阶段过滤 (污点 → 大小 → 路径可达), 顺序固定.
  本模块根据告警的置信度和类型动态调整过滤阶段顺序和阈值.
"""
import re
from typing import Dict, List, Tuple


class AdaptivePriorityCascade:
    """自适应优先级级联过滤器, 根据告警特征动态编排过滤顺序."""

    # 置信度阈值
    HIGH_CONF = 0.80
    LOW_CONF = 0.50

    def __init__(self):
        self._stats = {'total': 0, 'filtered': 0, 'confirmed': 0}

    def cascade_filter(self, findings: list) -> list:
        """对每个 finding 根据其特征决定过滤链顺序."""
        if not findings:
            return findings

        result = []
        for f in findings:
            self._stats['total'] += 1
            order = self._select_filter_order(f)
            passed = True
            reason = ''
            for stage in order:
                ok, why = self._dispatch_filter(stage, f)
                if not ok:
                    passed = False
                    reason = why
                    break
            if passed:
                f['apc_passed_stages'] = order
                self._stats['confirmed'] += 1
                result.append(f)
            else:
                f['apc_filtered'] = reason
                self._stats['filtered'] += 1
        return result

    def _select_filter_order(self, finding: dict) -> List[str]:
        """根据告警置信度和类型选择过滤顺序."""
        conf = finding.get('confidence', 0.5)
        has_guard = 'guard' in finding.get('description', '').lower()
        ftype = finding.get('type', '').lower()

        if conf >= self.HIGH_CONF:
            # 高置信度: 先快速过滤同源安全, 再污点, 最后路径
            order = ['size', 'taint', 'path']
        elif conf < self.LOW_CONF:
            # 低置信度: 先快速排除死代码, 再污点, 最后大小
            order = ['path', 'taint', 'size']
        else:
            # 中等: 按标准顺序
            order = ['taint', 'size', 'path']

        # 如果有守卫信息, 插入守卫过滤
        if has_guard:
            order.insert(1, 'guard')

        return order

    def _dispatch_filter(self, stage: str, f: dict) -> Tuple[bool, str]:
        if stage == 'size':
            return self._filter_size(f)
        elif stage == 'taint':
            return self._filter_taint(f)
        elif stage == 'path':
            return self._filter_path(f)
        elif stage == 'guard':
            return self._filter_guard(f)
        return (True, '')

    def _filter_size(self, f: dict) -> Tuple[bool, str]:
        """大小验证: 分配大小 vs 写入大小."""
        alloc = f.get('alloc_size', 0)
        write = f.get('write_size', 0)
        if isinstance(alloc, int) and isinstance(write, int):
            if alloc > 0 and write > 0 and write <= alloc:
                return (False, 'write_size <= alloc_size (safe)')
        return (True, 'size check passed')

    def _filter_taint(self, f: dict) -> Tuple[bool, str]:
        """污点验证: 写入源是否受控."""
        desc = f.get('description', '').lower()
        if 'user' in desc or 'input' in desc or 'tainted' in desc:
            return (True, 'taint: source is user-controlled')
        return (True, 'taint: source not clearly tainted')

    def _filter_path(self, f: dict) -> Tuple[bool, str]:
        """路径可达性验证."""
        # 简化: 如果有 function 字段说明在可达路径上
        if f.get('function'):
            return (True, 'path: reachable')
        return (False, 'path: unreachable (no function context)')

    def _filter_guard(self, f: dict) -> Tuple[bool, str]:
        """守卫验证: 如果有守卫约束, 检查是否约束了写入."""
        desc = f.get('description', '').lower()
        if 'guard' in desc and 'safe' in desc:
            return (False, 'guard-protected write')
        return (True, 'guard: no blocking guard')

    @property
    def stats(self) -> dict:
        return dict(self._stats)
