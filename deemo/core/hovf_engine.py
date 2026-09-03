"""
HOVF 组合裁决引擎 — 对堆溢出候选执行分配器宽松感知的核验。
流程: 值流解析分配大小→ptmalloc2 可用空间宽松模型→守卫支配收紧→给出 FILTERED/CONFIRMED/UNCERTAIN。
常量偏移直接宽松判定, 循环/动态偏移仅在有确定上界时生效, 防止吞掉边界漏洞。
"""

import re
import time
from typing import List, Optional, Tuple

from core.heap_overflow_detector import (
    HeapAllocSite, HeapOverflowCandidate,
)
from core.hovf_crossfunc import CrossFuncSafetyCheck
from core.hovf_types import EvidenceRecord, HovfStats, ValueInterval, Verdict
from core.hovf_slack import allocator_usable, align_bound
from core.hovf_size_vflow import resolve_alloc_size
from core.hovf_guard_flow import GuardFlow
from core.hovf_write_extract import (
    extract_hovf_candidates, _strip_block_comments,
)

_ACCEPT_CONF = 0.40
_UNBOUNDED_COPY = frozenset(('strcpy', 'strcat', 'gets', 'scanf'))

class HovfEngine(CrossFuncSafetyCheck):

    def __init__(self, ir: List[str], allocator: str = 'glibc',
                 slack_loop_extent: bool = False,
                 slack_bound: str = 'align'):
        # 值流解析与守卫收集共用无注释行, 否则注释内嵌的
        # `if (base > 64)` 会污染钳位区间.
        self.ir = _strip_block_comments(ir)
        self.allocator = allocator
        self.guards = GuardFlow(self.ir)
        self.slack_loop_extent = slack_loop_extent
        self.slack_bound = slack_bound
        from core.hovf_crossfunc import CrossFuncResolver
        self.resolver = CrossFuncResolver(self.ir)

    def _usable(self, req: int) -> int:
        """宽松边界: 'align' 用 16 字节对齐上界 (与样本基准一致),
        'usable' 用 ptmalloc2 精确可用空间."""
        if self.slack_bound == 'usable':
            return allocator_usable(req, self.allocator)
        return align_bound(req)

    def _alloc_interval(self, alloc: HeapAllocSite) -> Optional[ValueInterval]:
        """分配大小区间: 静态常量直接用, 动态走值流.

        动态大小值流无法解析时返回 None, 表示分配下界无证据,
        宽松判定不适用, 防止 align(1)=16 之类的退化过滤.
        """
        if not alloc.size_is_dynamic and alloc.size_arg > 0:
            return ValueInterval(alloc.size_arg, alloc.size_arg)
        iv = None
        if getattr(alloc, 'size_expr', ''):
            iv = self._resolve_size_expr(alloc.size_expr, alloc.pc)
            if iv is None:
                # 基础通道候选的 pc 在压缩行空间, 与引擎 ir 错位;
                # 按 size_expr 定位真实分配行后重试.
                pc = self._locate_alloc_pc(alloc)
                if pc != alloc.pc:
                    iv = self._resolve_size_expr(alloc.size_expr, pc)
        return iv

    def _accumulates(self, var: str) -> bool:
        """偏移变量是否在代码中被累积修改.

        循环内 `offset += K` 使初始值解析出的区间对写范围不再
        构成可靠上界; 此类变量禁止参与宽松过滤, 否则会吞掉
        累积写入溢出 (cve_18/polkit 类).
        """
        # 累积模式覆盖: 复合赋值/正向自引用/反向自引用/间接指针修改
        pats = [
            rf'\b{re.escape(var)}\s*(?:\+=|-=|\*=|/=|<<=|>>=)',
            rf'\b{re.escape(var)}\s*=\s*{re.escape(var)}\s*[+\-*/]',
            rf'\b{re.escape(var)}\s*=\s*\S+\s*\+\s*{re.escape(var)}\b',
            r'\*\w+\s*=\s*\*\w+\s*[+\-]',
        ]
        pat = re.compile('|'.join(pats))
        return any(pat.search(line) for line in self.ir)

    def _write_extent(self, c: HeapOverflowCandidate) -> Optional[ValueInterval]:
        """写入范围区间. 返回 None 表示无法解析."""
        store = c.overflow_store
        sz = store.store_size if store.store_size > 0 else 1
        if not store.offset_is_dynamic:
            return ValueInterval(store.offset, store.offset + sz)
        extent_lo = getattr(c, '_hovf_extent_lo', None)
        extent_hi = getattr(c, '_hovf_extent_hi', None)
        if extent_lo is not None and extent_hi is not None:
            return ValueInterval(extent_lo, extent_hi + sz)
        offset_var = getattr(c, '_hovf_offset_var', '')
        if offset_var and not self._accumulates(offset_var):
            res = resolve_alloc_size(offset_var, self.ir, store.pc)
            if res.interval is not None:
                setattr(c, '_hovf_vflow_bounded', True)
                base = res.interval
                return ValueInterval(base.lo + store.offset,
                                     base.hi + store.offset + sz)
        if store.mnemonic in _UNBOUNDED_COPY:
            return ValueInterval(0, 2**31 - 1)
        if sz > 1 and not store.offset_is_dynamic:
            return ValueInterval(store.offset, store.offset + sz)
        return None

    def _guard_bind(self, c: HeapOverflowCandidate,
                    extent: ValueInterval) -> ValueInterval:
        """用守卫上界收紧写入范围, 保留更紧者."""
        var = getattr(c, '_hovf_offset_var', '')
        if not var:
            return extent
        gb = self.guards.bound_for(var, c.overflow_store.pc)
        if gb is None:
            return extent
        bound_end = gb.hi + c.overflow_store.store_size
        if bound_end < extent.hi:
            return ValueInterval(extent.lo, bound_end)
        return extent

    def _free_is_guarded(self, free_idx: int) -> bool:
        """free 是否位于分支/循环块内.

        从 free 指令向前回溯, 遇到 if/for/while/switch 控制头
        即判定受控; 遇到函数定义标签停止, 限制回溯于当前函数.
        """
        for i in range(free_idx - 1, -1, -1):
            line = self.ir[i]
            if re.search(r'\b(if|for|while|switch|case)\b', line):
                return True
            # 函数定义标签标记回溯边界
            if re.match(r'^\s*<\w+>:\s*$', line):
                break
        return False

    def _freed_before_write(self, base_var: str, store_pc: int) -> bool:
        """base_var 指向的分配是否在写入前已被 free.

        free 必须文本序上位于写入之前, 且不受分支控制: 分支内的
        free (如 `if (n>200) { free(buf); }`) 与写入互斥, 不是
        释放后写入. 常规样本 main 末尾 free(buf) 晚于写入, 不受影响.
        """
        if not base_var:
            return False
        pat = re.compile(r'free\s*\(\s*([^)]*?)\s*\)')
        token = re.compile(r'\b' + re.escape(base_var) + r'\b')
        for i, line in enumerate(self.ir):
            if i >= store_pc:
                break
            m = pat.search(line)
            if not m or not token.search(m.group(1)):
                continue
            if self._free_is_guarded(i):
                continue
            return True
        return False

    def _resolve_param_alloc(self, c: HeapOverflowCandidate) -> Optional[ValueInterval]:
        """base_var 为函数参数时, 从 caller 中追溯分配大小."""
        base_var = c.overflow_store.base_var
        if not base_var:
            return None
        caller_iv = self.resolver.resolve_param_size(base_var, c.overflow_store.pc)
        return caller_iv

    def _verdict(self, c: HeapOverflowCandidate,
                 alloc_iv: Optional[ValueInterval],
                 extent: Optional[ValueInterval],
                 evidence: EvidenceRecord) -> Verdict:
        """根据宽松与守卫证据裁决单个候选."""
        if c.overflow_store.mnemonic in _UNBOUNDED_COPY:
            evidence.reasons.append('无界拷贝写入固定缓冲, 保守确认')
            return Verdict.CONFIRMED
        reason = self._crossfunc_safe(c)
        if reason:
            evidence.reasons.append('写入大小与分配大小同源: ' + reason)
            return Verdict.FILTERED
        if extent is None:
            evidence.reasons.append('写入范围无法解析, 保留观察')
            return Verdict.UNCERTAIN
        # 跨函数分配-写入链: base_var 来自参数时查 caller 分配大小
        if alloc_iv is None:
            alloc_iv = self._resolve_param_alloc(c)
            if alloc_iv is not None:
                evidence.reasons.append('跨函数分配大小已解析')
            else:
                evidence.reasons.append('分配大小无值流下界, 宽松判定不适用')
                setattr(c, '_hovf_low_conf', True)
                return Verdict.UNCERTAIN
        if self._freed_before_write(c.overflow_store.base_var,
                                    c.overflow_store.pc):
            evidence.reasons.append('分配已在写入前释放, 宽松判定不适用')
            return Verdict.UNCERTAIN
        if self._is_stack_array(c.overflow_store.base_var):
            evidence.reasons.append('写入目标为栈数组声明, 非堆对象')
            return Verdict.FILTERED
        usable_lo = self._usable(alloc_iv.lo)
        usable_hi = self._usable(alloc_iv.hi)
        evidence.alloc_resolved = alloc_iv
        evidence.slack_usable = usable_lo
        evidence.write_extent = extent
        is_const = not c.overflow_store.offset_is_dynamic
        if extent.hi <= usable_lo:
            if is_const or self.slack_loop_extent or \
                    getattr(c, '_hovf_guard_applied', False) or \
                    getattr(c, '_hovf_vflow_bounded', False):
                evidence.reasons.append(
                    f'写入范围 {extent} 完全落在可用空间 {usable_lo} 内')
                return Verdict.FILTERED
            evidence.reasons.append(
                f'写入范围 {extent} 落在可用空间 {usable_lo} 内, '
                f'但为循环/动态偏移, 保守保留')
            return Verdict.UNCERTAIN
        if extent.hi > usable_hi:
            evidence.reasons.append(
                f'写入范围上界 {extent.hi} 越过可用边界 {usable_hi}')
            return Verdict.CONFIRMED
        evidence.reasons.append('写入范围位于可用边界附近, 证据不足')
        return Verdict.UNCERTAIN

    def refine(self, alloc_sites: List[HeapAllocSite],
               base_candidates: List[HeapOverflowCandidate]) -> Tuple[
                   List[HeapOverflowCandidate], List[EvidenceRecord],
                   HovfStats]:
        """核验全部候选, 返回 (保留候选, 证据记录, 统计)."""
        t0 = time.perf_counter()
        new_chan = extract_hovf_candidates(self.ir, alloc_sites)
        seen = {id(c) for c in base_candidates}
        merged = list(base_candidates) + [c for c in new_chan
                                          if id(c) not in seen]
        # 按写入位点 (base_var, pc) 去重, 防止同一位点重复评估.
        site_map: dict = {}
        for c in merged:
            key = (c.overflow_store.base_var, c.overflow_store.pc)
            site_map.setdefault(key, []).append(c)
        primaries: List[HeapOverflowCandidate] = []
        for key, cands in site_map.items():
            new_here = [c for c in cands if getattr(c, '_hovf_offset_var', '')
                        or c.overflow_store.mnemonic.startswith('hovf')]
            primary = new_here[0] if new_here else cands[0]
            primaries.append(primary)
        merged = primaries
        kept: List[HeapOverflowCandidate] = []
        evidence_records: List[EvidenceRecord] = []
        stats = HovfStats(base_candidates=len(base_candidates),
                          new_channel_added=len(new_chan))
        self._filtered_buffers: set = set()
        for c in merged:
            alloc_iv = self._alloc_interval(c.alloc_site)
            extent = self._write_extent(c)
            evidence = EvidenceRecord(
                verdict=Verdict.UNCERTAIN,
                alloc_requested=c.alloc_site.size_arg,
                provenance=getattr(c, 'description', ''),
                confidence=c.confidence,
            )
            if getattr(c, '_hovf_offset_var', ''):
                gb = self.guards.bound_for(getattr(c, '_hovf_offset_var', ''),
                                           c.overflow_store.pc)
                if gb is not None and gb.hi <= alloc_iv.lo:
                    setattr(c, '_hovf_guard_applied', True)
                    evidence.guard_bound = gb.hi
            if extent is not None:
                extent = self._guard_bind(c, extent)
            verdict = self._verdict(c, alloc_iv, extent, evidence)
            evidence.verdict = verdict
            if verdict == Verdict.FILTERED:
                stats.filtered += 1
                self._filtered_buffers.add(c.overflow_store.base_var)
                evidence_records.append(evidence)
                continue
            if verdict == Verdict.CONFIRMED:
                c.confidence = min(0.95, c.confidence + 0.10)
                stats.confirmed += 1
            else:
                # UNCERTAIN 细分: 写范围/分配下界缺失时降置信度至过滤阈值下
                if extent is None or getattr(c, '_hovf_low_conf', False):
                    c.confidence = 0.25
                else:
                    c.confidence = max(0.30, c.confidence - 0.05)
                stats.uncertain += 1
            setattr(c, '_hovf_evidence', evidence)
            evidence_records.append(evidence)
            if c.confidence >= _ACCEPT_CONF:
                kept.append(c)
        # 过滤传播: 新通道在同一缓冲区证明写范围落在可用空间内
        # (FILTERED) 时, 既有通道对该缓冲区的数组索引候选 (pc 指向
        # 循环头, 写范围无法解析) 一并抑制, 消除重复报告的误报.
        filtered_buffers = self._filtered_buffers
        if filtered_buffers:
            kept = [c for c in kept
                    if not (c.overflow_store.base_var in filtered_buffers
                            and c.overflow_store.mnemonic in
                            ('array_index', 'array_index_write'))]
        stats.fp_reduction_ratio = (
            stats.filtered / max(stats.base_candidates + stats.new_channel_added, 1))
        kept.sort(key=lambda x: -x.confidence)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000
        return kept, evidence_records, stats


def refine_heap_candidates(
    ir_lines: List[str],
    alloc_sites: List[HeapAllocSite],
    base_candidates: List[HeapOverflowCandidate],
    allocator: str = 'glibc',
    slack_loop_extent: bool = False,
    slack_bound: str = 'align',
) -> Tuple[List[HeapOverflowCandidate], HovfStats]:
    """HOVF 入口: 追加新检出通道候选并核验.

    返回 (保留候选, 统计). 原候选对象不被删除, 仅 FILTERED 项
    从返回列表排除, 证据记录附着于候选 `_hovf_evidence` 属性.
    """
    engine = HovfEngine(ir_lines, allocator=allocator,
                        slack_loop_extent=slack_loop_extent,
                        slack_bound=slack_bound)
    kept, _records, stats = engine.refine(alloc_sites, base_candidates)
    return kept, stats
