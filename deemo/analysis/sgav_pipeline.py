"""
SGAV 管线编排器 — Stack Guard-Aware Verifier 主入口.
串联 buffer_resolver → guard_extractor → range_propagator →
write_detector → overflow_verifier.
"""
from __future__ import annotations
from typing import List, Dict, Optional
from analysis.sgav_types import (
    SoVerdict, SoResult, BufferDesc, WriteDesc,
    GuardConstraint, ValueRange)
from analysis.sgav_buffer_resolver import BufferResolver
from analysis.sgav_guard_extractor import GuardExtractor
from analysis.sgav_range_propagator import RangePropagator
from analysis.sgav_write_detector import WriteDetector
from analysis.sgav_overflow_verifier import OverflowVerifier


class SGAVVerifier:
    """栈守卫感知验证器 — Guard-Bounded Write Proof."""

    def __init__(self):
        self._resolver = BufferResolver()
        self._guard_ext = GuardExtractor()
        self._range_prop = RangePropagator()
        self._write_det = WriteDetector()
        self._verifier = OverflowVerifier()

    def verify(self, source: str) -> List[SoResult]:
        """对C源码执行SGAV验证，返回漏洞结果列表."""
        lines = source.splitlines()
        if not lines:
            return []
        # Phase 1: 缓冲区识别 + 别名闭包
        bufs = self._resolver.resolve(lines)
        if not bufs:
            return []
        # 构建别名映射
        alias_map: Dict[str, str] = {}
        for b in bufs:
            alias_map[b.name] = b.name
            for a in b.aliases:
                alias_map[a] = b.name
        # Phase 2: 守卫约束提取
        guards = self._guard_ext.extract(lines)
        # Phase 3: 值范围传播
        ranges = self._range_prop.propagate(lines, guards)
        # Phase 4: 写入检测
        writes = self._write_det.detect(lines, bufs, alias_map)
        # Phase 5: GBWP 验证
        results = self._verifier.verify(
            bufs, writes, guards, ranges, lines)
        return results

    def verify_ablated(self, source: str,
                       config: str = 'full') -> List[SoResult]:
        """消融实验: 按 config 禁用指定模块.
        configs:
          A0_pattern  — 仅正则模式匹配(等效旧SOSV)
          A1_alias    — +别名解析(无守卫/值范围)
          A2_guard    — +守卫约束(无值范围)
          A3_range    — +值范围传播
          A4_bounded  — +有界API分析
          full        — 全部启用
        """
        lines = source.splitlines()
        if not lines:
            return []
        if config == 'A0_pattern':
            return self._verify_pattern_only(lines)
        bufs = self._resolver.resolve(lines)
        if not bufs:
            return []
        alias_map: Dict[str, str] = {}
        for b in bufs:
            alias_map[b.name] = b.name
            for a in b.aliases:
                alias_map[a] = b.name
        # A0 起点仅正则, A1+ 有别名
        if config == 'A1_alias':
            guards = {}
            ranges = {}
        elif config in ('A2_guard',):
            guards = self._guard_ext.extract(lines)
            ranges = {}
        elif config in ('A3_range', 'A4_bounded'):
            guards = self._guard_ext.extract(lines)
            ranges = self._range_prop.propagate(lines, guards)
        else:  # full
            guards = self._guard_ext.extract(lines)
            ranges = self._range_prop.propagate(lines, guards)
        writes = self._write_det.detect(lines, bufs, alias_map)
        results = self._verifier.verify(
            bufs, writes, guards, ranges, lines)
        return results

    def _verify_pattern_only(self, lines: List[str]) -> List[SoResult]:
        """A0: 纯模式匹配, 无别名/守卫/值范围."""
        import re
        from analysis.sgav_types import BufferDesc
        bufs = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            for m in re.finditer(
                    r'(?:char|int|unsigned|int|short|long)\s+(\w+)\s*\[\s*(\d+)\s*\]', text):
                bufs.append(BufferDesc(
                    name=m.group(1), size=int(m.group(2)),
                    kind='fixed', line=i, base_buf=m.group(1)))
            vm = re.search(
                r'(?:char|int)\s+(\w+)\s*\[\s*(\w[\w]*)\s*\]', text)
            if vm and not vm.group(2).isdigit():
                bufs.append(BufferDesc(
                    name=vm.group(1), size=-1, kind='vla',
                    line=i, base_buf=vm.group(1)))
        buf_names = {b.name for b in bufs}
        results: List[SoResult] = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            for m in re.finditer(r'\bgets\s*\(\s*(\w+)', text):
                if m.group(1) in buf_names:
                    b = next(b for b in bufs if b.name == m.group(1))
                    results.append(SoResult(
                        verdict=SoVerdict.VULN, buffer_line=b.line,
                        write_line=i, buf_name=b.name, buf_size=b.size,
                        confidence=0.9,
                        reason=f"'{b.name}[{b.size}]': unbounded gets@L{i}"))
            for m in re.finditer(r'\bstrcpy\s*\(\s*(\w+)', text):
                if m.group(1) in buf_names:
                    b = next(b for b in bufs if b.name == m.group(1))
                    results.append(SoResult(
                        verdict=SoVerdict.VULN, buffer_line=b.line,
                        write_line=i, buf_name=b.name, buf_size=b.size,
                        confidence=0.9,
                        reason=f"'{b.name}[{b.size}]': unbounded strcpy@L{i}"))
            for m in re.finditer(r'\bsprintf\s*\(\s*(\w+)', text):
                if m.group(1) in buf_names:
                    b = next(b for b in bufs if b.name == m.group(1))
                    results.append(SoResult(
                        verdict=SoVerdict.VULN, buffer_line=b.line,
                        write_line=i, buf_name=b.name, buf_size=b.size,
                        confidence=0.9,
                        reason=f"'{b.name}[{b.size}]': unbounded sprintf@L{i}"))
        return results


__all__ = ['SGAVVerifier']
