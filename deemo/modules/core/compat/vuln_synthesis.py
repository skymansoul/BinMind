# -*- coding: utf-8 -*-
"""
多检测器结果融合与去重 — 将 heap/uaf/format_string/stack_overflow 四个
检测器的独立输出合并为统一的漏洞报告, 去除跨检测器重复, 按置信度排序.

去重策略:
  同地址、同类型的多条检测合并为一条, 保留最高置信度.
  若同一地址被两个检测器报告为不同类型 (如 heap_overflow + uaf),
  保留两条但标注关联关系, 不丢失信息.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class UnifiedVuln:
    """统一的漏洞条目."""
    vuln_id: str              # 唯一标识: VULN-{addr:x}-{type}
    vuln_type: str            # heap_overflow | uaf | format_string | stack_overflow
    primary_addr: int         # 主要关联地址
    related_addrs: List[int]  # 关联地址 (分配点/释放点等)
    confidence: float
    cwe_id: str
    description: str
    source_detector: str      # 原始检测器名称
    exploitable: bool
    cve_refs: List[str] = field(default_factory=list)  # 可能的 CVE 引用
    correlated_with: List[str] = field(default_factory=list)  # 关联的其他 vuln_id


@dataclass
class SynthesisReport:
    vulns: List[UnifiedVuln]
    total_raw_findings: int     # 各检测器的原始发现总数
    after_dedup: int            # 去重后数量
    exploitable_count: int
    by_type: Dict[str, int]
    summary_text: str = ''


def _addr_key(addr: Any) -> int:
    """规范化地址为 int."""
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        try:
            return int(addr, 16) if addr.startswith('0x') else int(addr)
        except ValueError:
            return hash(addr) & 0xFFFFFFFF
    return hash(str(addr)) & 0xFFFFFFFF


def synthesize(
    heap_findings: Optional[List[Dict]] = None,
    uaf_findings: Optional[List[Dict]] = None,
    format_findings: Optional[List] = None,
    stack_findings: Optional[List] = None,
) -> SynthesisReport:
    """融合四个检测器的结果, 去重, 排序.

    各参数:
      heap_findings: heap_analyzer 的输出 [{exploitable, score, ...}, ...]
      uaf_findings:  uaf_detector 的输出 [{confidence, alloc_site, free_site, use_site}, ...]
      format_findings: format_string_detector 的输出 [FormatStringFinding, ...]
      stack_findings: stack_overflow_analyzer 的输出 [StackOverflowCandidate, ...]
    """
    vulns: List[UnifiedVuln] = []
    raw_count = 0
    vid_counter = [0]

    def _next_id() -> str:
        vid_counter[0] += 1
        return f'VULN-{vid_counter[0]:04d}'

    # Heap overflow
    for h in (heap_findings or []):
        if isinstance(h, dict):
            raw_count += 1
            addr = _addr_key(h.get('overflow_site', h.get('alloc_site', 0)))
            vulns.append(UnifiedVuln(
                vuln_id=_next_id(), vuln_type='heap_overflow',
                primary_addr=addr, related_addrs=[],
                confidence=h.get('score', h.get('confidence', 0.5)),
                cwe_id='CWE-122', description=h.get('reason', '堆溢出'),
                source_detector='heap_analyzer',
                exploitable=h.get('exploitable', False),
            ))

    # UAF
    for u in (uaf_findings or []):
        if isinstance(u, dict):
            raw_count += 1
            addr = _addr_key(u.get('use_site', u.get('alloc_site', 0)))
            free_addr = _addr_key(u.get('free_site', 0))
            vulns.append(UnifiedVuln(
                vuln_id=_next_id(), vuln_type='uaf',
                primary_addr=addr,
                related_addrs=[free_addr] if free_addr else [],
                confidence=u.get('confidence', 0.5),
                cwe_id='CWE-416', description=f'UAF: {u.get("type_hint", "unknown")}',
                source_detector='uaf_detector',
                exploitable=u.get('confidence', 0) >= 0.6,
            ))

    # Format string
    for f in (format_findings or []):
        raw_count += 1
        addr = getattr(f, 'call_site', 0)
        vulns.append(UnifiedVuln(
            vuln_id=_next_id(), vuln_type='format_string',
            primary_addr=addr, related_addrs=[],
            confidence=getattr(f, 'confidence', 0.5),
            cwe_id='CWE-134',
            description=f'格式化字符串: {getattr(f, "taint_source", "unknown")}',
            source_detector='format_string_detector',
            exploitable=getattr(f, 'exploitable', False),
        ))

    # Stack overflow
    for s in (stack_findings or []):
        raw_count += 1
        addr = getattr(s, 'write_site', getattr(s, 'func_addr', 0))
        vulns.append(UnifiedVuln(
            vuln_id=_next_id(), vuln_type='stack_overflow',
            primary_addr=addr, related_addrs=[],
            confidence=getattr(s, 'confidence', 0.5),
            cwe_id='CWE-121',
            description=getattr(s, 'detail', '栈溢出'),
            source_detector='stack_overflow_analyzer',
            exploitable=getattr(s, 'exploitable', False),
        ))

    # 去重: 同一 (primary_addr, vuln_type) 只保留置信度最高的一条
    deduped: Dict[Tuple[int, str], UnifiedVuln] = {}
    for v in vulns:
        key = (v.primary_addr, v.vuln_type)
        if key not in deduped or v.confidence > deduped[key].confidence:
            deduped[key] = v
    deduped_list = sorted(deduped.values(), key=lambda v: -v.confidence)

    # 检测跨类型关联: 同一地址被不同检测器报告
    addr_to_vulns: Dict[int, List[UnifiedVuln]] = defaultdict(list)
    for v in deduped_list:
        addr_to_vulns[v.primary_addr].append(v)
    for vlist in addr_to_vulns.values():
        if len(vlist) > 1:
            ids = [v.vuln_id for v in vlist]
            for v in vlist:
                v.correlated_with = [i for i in ids if i != v.vuln_id]

    exploitable = [v for v in deduped_list if v.exploitable]
    by_type: Dict[str, int] = defaultdict(int)
    for v in deduped_list:
        by_type[v.vuln_type] += 1

    report = SynthesisReport(
        vulns=deduped_list,
        total_raw_findings=raw_count,
        after_dedup=len(deduped_list),
        exploitable_count=len(exploitable),
        by_type=dict(by_type),
        summary_text=(
            f'{raw_count} raw findings → {len(deduped_list)} after dedup; '
            f'{len(exploitable)} exploitable; '
            f'by type: {dict(by_type)}'
        ),
    )
    return report
