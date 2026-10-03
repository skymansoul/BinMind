"""
DepLLM-Crypto 主流水线 — 依赖引导的 LLM 增强密码学误用检测。

  CRYPTBARA: 依赖上下文引导检测 → 本流水线依赖图/调用链。
  Beyond Static Pattern Matching?: LLM 语义验证消解假阳性。
  Auto. Gen. of Crypto Misuse Taxonomy: 判定缓存控制开销。
  Evaluating LLMs in Detecting Secrets: LLM+启发式互补。

流程:
  crypto_misuse 命中 → 依赖上下文 → 污点追踪 → 启发式置信度
  → (可选) LLM 语义验证(缓存) → 跨单元常量折叠传播 → DepFinding

既有 crypto_misuse 仅给出固定严重度；本流水线附加依赖上下文、
量化置信度，并通过语义验证滤除测试向量/查表/随机巧合类假阳性。
LLM 仅模式命中时触发，相同上下文判定缓存复用。
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..config import getConfig
from ..crypto_misuse import (CryptoMisuseDetector, Misuse,
                             _WEAK_IVS, _WEAK_KEYS_DES, _COMMON_SALTS)
from ..utils import safeReadBytes, shannon_entropy

from .dependency_graph import (DependencyGraph, NodeType, build_dependency_graph,
                               classify_api, trace_dependency_paths,
                               summarize_call_chain, TaintPath)
from .heuristic import adjust_with_llm, score_hit
from .llm_validator import LLMValidator
from .symbol_table import ConstantSymbol, ModuleSymbolTable
from .verdict_cache import Verdict, VerdictCache

_log = logging.getLogger(__name__)

# 依赖上下文窗口 — 命中点前后各 4KB
_DEFAULT_WINDOW = 4096
# 报告置信度阈值
_DEFAULT_MIN_CONFIDENCE = 0.40
# 常量类别 → 符号表类别
_CATEGORY_MAP = {'STATIC_IV': 'iv', 'WEAK_KEY': 'key', 'HARDCODED_SALT': 'salt'}

# 模块级共享符号表 — 跨实例/跨文件共享，支撑跨编译单元常量折叠传播
_SHARED_SYMBOL_TABLE = ModuleSymbolTable()

@dataclass
class DepFinding:
    """增强误用判定 — 在 Misuse 之上附加依赖证据."""
    misuse_type: str
    api: str
    address: str
    detail: str
    severity: str
    confidence: float
    llm_verdict: str
    llm_reason: str
    cached: bool
    cross_unit: bool
    cross_unit_origins: List[str] = field(default_factory=list)
    call_chain: str = ""
    upstream_apis: List[str] = field(default_factory=list)
    downstream_apis: List[str] = field(default_factory=list)
    region_entropy: float = 0.0
    repetition_count: int = 1
    heuristic_conf: float = 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            'type': self.misuse_type,
            'api': self.api,
            'address': self.address,
            'detail': self.detail,
            'severity': self.severity,
            'confidence': round(self.confidence, 3),
            'llm_verdict': self.llm_verdict,
            'llm_reason': self.llm_reason,
            'from_cache': self.cached,
            'cross_unit': self.cross_unit,
            'cross_unit_origins': list(self.cross_unit_origins),
            'call_chain': self.call_chain,
            'upstream_apis': list(self.upstream_apis),
            'downstream_apis': list(self.downstream_apis),
            'region_entropy': round(self.region_entropy, 3),
            'repetition_count': self.repetition_count,
        }

def build_dependency_context(data: bytes,
                             strings: List[Tuple[int, str]],
                             misuse: Misuse,
                             window: int = _DEFAULT_WINDOW) -> Dict[str, object]:
    """构建单个命中的依赖上下文。

    含: 上下游 API 字符串、邻近 API 计数、区域熵、重复次数。
    CRYPTBARA 依赖上下文的二进制近似 — 以命中点两侧 API 共现刻画数据流。
    """
    try:
        off = int(misuse.address, 16)
    except (ValueError, TypeError):
        off = -1

    upstream: List[str] = []
    downstream: List[str] = []
    n_source = 0
    n_sink = 0
    if off > 0:
        lo = off - window
        hi = off + window
        for soff, s in strings:
            if soff < 0:
                continue
            if lo <= soff < off:
                upstream.append(s)
                nt = classify_api(s)
                if nt == NodeType.SOURCE:
                    n_source += 1
                elif nt == NodeType.SINK:
                    n_sink += 1
            elif off < soff <= hi:
                downstream.append(s)
                nt = classify_api(s)
                if nt == NodeType.SOURCE:
                    n_source += 1
                elif nt == NodeType.SINK:
                    n_sink += 1

    # 命中点 ±64B 窗口熵，区分数据节常量与随机/压缩数据
    if off > 0:
        region = data[max(0, off - 64): off + 64]
        ent = shannon_entropy(region)
    else:
        ent = 0.5

    # API 邻近度: 加密源/汇数量 → [0,1]
    prox = min(1.0, (n_source + n_sink) * 0.4 + (0.3 if n_sink > 0 else 0.0))

    return {
        'misuse_type': misuse.type,
        'api': misuse.api,
        'severity': misuse.severity,
        'address': misuse.address,
        'offset': off,
        'upstream_apis': upstream[:24],
        'downstream_apis': downstream[:24],
        'api_proximity': round(prox, 3),
        'region_entropy': round(ent, 3),
        'repetition_count': 1,
        'call_chain': '',
        'aggregate': off <= 0,
    }

def _extract_constant_value(data: bytes, misuse: Misuse) -> Optional[bytes]:
    """从命中地址回读常量字节值。

    STATIC_IV / WEAK_KEY / HARDCODED_SALT 有效；字符串类命中返回 None。
    """
    mt = misuse.type
    if mt not in _CATEGORY_MAP:
        return None
    try:
        off = int(misuse.address, 16)
    except (ValueError, TypeError):
        return None
    if off <= 0 or off >= len(data):
        return None
    if mt == 'STATIC_IV':
        for iv in _WEAK_IVS:
            if data[off:off + len(iv)] == iv:
                return iv
        return None
    if mt == 'WEAK_KEY':
        for wk in _WEAK_KEYS_DES:
            if data[off:off + len(wk)] == wk:
                return wk
        return None
    if mt == 'HARDCODED_SALT':
        for salt in _COMMON_SALTS:
            if data[off:off + len(salt)] == salt:
                return salt
        return None
    return None

def filter_findings(findings: List[DepFinding],
                    min_conf: float = _DEFAULT_MIN_CONFIDENCE) -> List[DepFinding]:
    """按置信度阈值过滤 (默认 0.40)."""
    return [f for f in findings if f.confidence >= min_conf]

class DepLLMCryptoAnalyzer:
    """依赖增强密码学误用分析器。

    参数:
      base_url / model / api_key: LLM 端点，未配置 → 纯启发式路径。
      window:          上下文窗口
      min_confidence:  报告阈值
      cache_size:      判定缓存上限
      symbol_table:    符号表，默认共享实例，支撑跨单元传播
    """

    def __init__(self,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout: Optional[float] = None,
                 max_tokens: Optional[int] = None,
                 window: int = _DEFAULT_WINDOW,
                 min_confidence: float = _DEFAULT_MIN_CONFIDENCE,
                 cache_size: int = 256,
                 symbol_table: Optional[ModuleSymbolTable] = None) -> None:
        self.window = window
        self.min_confidence = min_confidence
        self.symbol_table = symbol_table if symbol_table is not None else _SHARED_SYMBOL_TABLE
        self._configured = False

        # 配置优先级: 显式参数 > 环境变量 > config 文件
        cfg = getConfig().get('depllm', {})
        b_url = base_url or os.environ.get('DEPLLM_BASE_URL') or cfg.get('base_url')
        mdl = model or os.environ.get('DEPLLM_MODEL') or cfg.get('model')
        key = api_key or os.environ.get('DEPLLM_API_KEY') or cfg.get('api_key')
        timeout = timeout or cfg.get('timeout', 30)
        max_tokens = max_tokens or cfg.get('max_tokens', 256)

        self.validator = LLMValidator(b_url, mdl, key, timeout, max_tokens)
        self.cache = VerdictCache(maxsize=cache_size)
        self.stats = {
            'analyzed': 0, 'confirmed': 0, 'rejected': 0,
            'uncertain': 0, 'heuristic_only': 0, 'cached': 0,
        }

# 入口

    def analyze(self, binary, misuses: Optional[list] = None,
                source: str = '') -> List[DepFinding]:
        """依赖增强误用判定。

        binary: 文件路径(str) 或原始字节(bytes)
        misuses: 预扫描列表；None → 内部执行 CryptoMisuseDetector
        source:  来源标识
        """
        if isinstance(binary, str):
            data = safeReadBytes(binary)
            if data is None:
                _log.warning("DepLLM-Crypto: cannot read %s", binary)
                return []
            src = source or binary
        else:
            data = binary if isinstance(binary, bytes) else b''
            src = source or 'memory'
            if not data:
                return []

        det = CryptoMisuseDetector()
        det_result = det.scan(data)
        strings = det._strings
        misuse_list = list(misuses) if misuses is not None else list(det_result)

        graph, anchor_ids = build_dependency_graph(data, strings, misuse_list,
                                                   window=self.window)
        findings: List[DepFinding] = []
        for idx, mu in enumerate(misuse_list):
            anchor = anchor_ids[idx]
            finding = self._judge(data, strings, graph, mu, anchor, src)
            findings.append(finding)
            self.stats['analyzed'] += 1
            self.stats[finding.llm_verdict] = self.stats.get(finding.llm_verdict, 0) + 1
            if finding.cached:
                self.stats['cached'] += 1
        return findings

    def analyze_file(self, path: str) -> List[DepFinding]:
        return self.analyze(path, source=path)

    def analyze_bytes(self, data: bytes, misuses: Optional[list] = None) -> List[DepFinding]:
        return self.analyze(data, misuses=misuses, source='memory')

    def report(self, findings: Optional[List[DepFinding]] = None) -> List[Dict[str, object]]:
        """可报告判定列表 (供 CLI/序列化)."""
        src = findings if findings is not None else []
        return [f.to_dict() for f in filter_findings(src, self.min_confidence)]

# 判定

    def _judge(self, data: bytes, strings: List[Tuple[int, str]],
               graph: DependencyGraph, mu: Misuse,
               anchor: Optional[int], source: str) -> DepFinding:
        """单命中 → 依赖增强判定."""
        ctx = build_dependency_context(data, strings, mu, self.window)
        aggregate = bool(ctx.get('aggregate'))
        off = int(ctx.get('offset') or 0)

        # 1. 污点传播路径
        call_chain = ''
        if anchor is not None:
            path: TaintPath = trace_dependency_paths(graph, anchor)
            call_chain = summarize_call_chain(path)

        # 2. 常量值提取 + 跨单元折叠传播 + 重复度
        value = _extract_constant_value(data, mu)
        repetition_count = 1
        cross_unit = False
        cross_origins: List[str] = []
        if value is not None:
            repetition_count = max(1, data.count(value))
            if off > 0:
                self.symbol_table.record(value, _CATEGORY_MAP[mu.type], source, off)
                cu, others = self.symbol_table.cross_unit(value, source)
                cross_unit = cu
                cross_origins = ['{}@{}'.format(s.origin_source, hex(s.origin_offset))
                                 for s in others]

        ctx['call_chain'] = call_chain
        ctx['repetition_count'] = repetition_count

        # 3. 启发式置信度 (无 LLM 降级)
        heur = score_hit(mu,
                         api_proximity=float(ctx.get('api_proximity', 0.0)),
                         region_entropy=float(ctx.get('region_entropy', 0.5)),
                         repetition_count=repetition_count,
                         cross_unit=cross_unit,
                         aggregate=aggregate)
        heuristic_conf = float(heur['confidence'])

        # 4. LLM 语义验证 (仅非聚合 + 已配置)
        llm_verdict = 'heuristic_only'
        llm_reason = ''
        from_cache = False
        if not aggregate and self.validator.is_configured():
            cached = self.cache.get(ctx)
            if cached is not None:
                llm_verdict, llm_reason, from_cache = cached.verdict, cached.reason, True
            else:
                res = self.validator.validate(ctx)
                llm_verdict, llm_reason = res.verdict, res.reason
                self.cache.put(ctx, Verdict(llm_verdict, llm_reason))
        final_conf = adjust_with_llm(heuristic_conf, llm_verdict)

        return DepFinding(
            misuse_type=mu.type, api=mu.api, address=mu.address,
            detail=mu.detail, severity=mu.severity,
            confidence=round(final_conf, 3),
            llm_verdict=llm_verdict, llm_reason=llm_reason,
            cached=from_cache, cross_unit=cross_unit,
            cross_unit_origins=cross_origins, call_chain=call_chain,
            upstream_apis=list(ctx.get('upstream_apis') or []),
            downstream_apis=list(ctx.get('downstream_apis') or []),
            region_entropy=float(ctx.get('region_entropy', 0.0)),
            repetition_count=repetition_count,
            heuristic_conf=round(heuristic_conf, 3),
        )

    def cache_stats(self) -> Dict[str, object]:
        return self.cache.stats()

    def symbol_stats(self) -> Dict[str, object]:
        return self.symbol_table.stats()

def detect_dep_llm_misuse(binary, misuses: Optional[list] = None,
                          source: str = '') -> List[DepFinding]:
    """便捷入口 — 单次调用完成依赖增强误用判定."""
    return DepLLMCryptoAnalyzer().analyze(binary, misuses=misuses, source=source)

__all__ = ['DepLLMCryptoAnalyzer', 'DepFinding', 'build_dependency_context',
           'filter_findings', 'detect_dep_llm_misuse']
