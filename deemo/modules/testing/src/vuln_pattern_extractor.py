# 漏洞模式提取器 — 从已知崩溃中提取CFG结构签名, 扫描二进制发现变体
#
# 核心问题:
#   发现一个漏洞后, 如何回答 "代码中还有类似的地方吗?"
#   现有克隆检测 (BinDiff, Diaphora, 代码克隆工具) 依赖:
#     a) 精确图同构——对编译器优化敏感, 同一源码在不同优化级别下可能不匹配
#     b) 指令级特征——寄存器重分配、指令重排导致假阴性
#     c) 完整函数匹配——无法发现函数内部的部分结构重用 (如同一解析模式)
#
# 本模块的方法 — CFG结构邻域签名:
#   1. 从漏洞点的 CFG 中提取半径 r 的邻域子图 (默认 r=3: 前后各3个基本块)
#   2. 计算邻域子图的归一化12维结构签名
#      (前9维标准CFG熵 + 后3维邻域特有特征)
#   3. 对整个二进制中的所有函数提取同维度签名
#   4. 余弦相似度排序 → 候选变体位置
#   5. 对高相似度候选做API重叠验证
#
# 为什么用邻域签名而非完整函数签名:
#   - 漏洞通常是局部的: 一个缺失的边界检查、一个错误的大小计算
#   - 完整函数签名会被函数其余部分的差异稀释
#   - 邻域签名聚焦于漏洞点周围的控制流上下文
#   - 跨函数匹配: 同一漏洞模式可能出现在不同函数中 (如多个解析回调)
#
# 文件结构:
#   本文件: 变体扫描的业务逻辑 (VariantScanner + 报告)
#   cfg_neighborhood.py: CFG邻域提取与12维签名计算
#
# 技术依据:
#   - Kalinin & Gribkov 2024, "Syntactic-Semantic Clone Detection for IoT"
#     — Siamese GNN 做跨架构克隆检测; 本项目以熵替代GNN
#   - Arutunian et al. 2025, "PDG-based Clone Detection for CVE Identification"
#     — 基于程序依赖图的克隆检测; 本项目以CFG邻域替代PDG
#   - Zheng et al. 2025, "AST Mutation for Vulnerability Sample Generation"
#     — 本项目取其"变体"概念但用于发现而非生成

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .cfg_neighborhood import (
    CFGNeighborhoodExtractor,
    NeighborhoodSignatureBuilder,
)


@dataclass
class VulnSignature:
    """漏洞位置的CFG邻域结构签名"""
    vuln_id: str
    func_name: str = ""
    vuln_addr: int = 0
    signature: List[float] = field(default_factory=lambda: [0.0] * 12)
    neighborhood_radius: int = 3
    num_blocks_in_neighborhood: int = 0
    api_calls: List[str] = field(default_factory=list)
    error_patterns: List[str] = field(default_factory=list)


@dataclass
class VariantCandidate:
    """潜在漏洞变体——函数中与已知漏洞签名匹配的位置"""
    func_name: str
    match_addr: int
    similarity: float                # 余弦相似度 [0, 1]
    signature_distance: float = 0.0  # 1 - similarity
    api_overlap: float = 0.0
    neighborhood_size_match: float = 1.0
    is_high_confidence: bool = False
    rationale: str = ""


@dataclass
class VariantScanReport:
    """漏洞变体扫描完整报告"""
    source_vuln: VulnSignature
    total_functions_scanned: int = 0
    total_locations_scanned: int = 0
    candidates: List[VariantCandidate] = field(default_factory=list)
    high_confidence_count: int = 0
    scan_time_s: float = 0.0
    summary: str = ""


class VariantScanner:
    """漏洞变体扫描器——在整个二进制中搜索与已知漏洞签名匹配的CFG邻域。

    典型用法:
        scanner = VariantScanner()
        scanner.add_function_cfg("func_a", func_a_adjacency, func_a_sizes)
        scanner.add_function_cfg("func_b", func_b_adjacency, func_b_sizes)
        sig = scanner.extract_signature(
            vuln_id="CVE-2025-001", func_name="func_a", vuln_addr=0x401200)
        report = scanner.scan(sig, min_similarity=0.75)
    """

    def __init__(self, neighborhood_radius: int = 3,
                 min_similarity: float = 0.75):
        self._radius = neighborhood_radius
        self._min_similarity = min_similarity
        self._extractor = CFGNeighborhoodExtractor(radius=neighborhood_radius)
        # func_name → {block_addr → [successors]}
        self._func_cfgs: Dict[str, Dict[int, List[int]]] = {}
        self._func_block_sizes: Dict[str, Dict[int, int]] = {}

    def add_function_cfg(self, func_name: str,
                          adjacency: Dict[int, List[int]],
                          block_sizes: Optional[Dict[int, int]] = None) -> None:
        self._func_cfgs[func_name] = adjacency
        self._func_block_sizes[func_name] = block_sizes or {}

    def extract_signature(self, vuln_id: str, func_name: str,
                           vuln_addr: int,
                           api_calls: Optional[List[str]] = None,
                           error_patterns: Optional[List[str]] = None,
                           ) -> Optional[VulnSignature]:
        """从已知漏洞位置提取邻域签名"""
        cfg = self._func_cfgs.get(func_name)
        if cfg is None:
            return None

        subgraph, neighborhood = self._extractor.extract(
            cfg, vuln_addr, self._func_block_sizes.get(func_name))
        if not subgraph:
            return None

        sizes = self._extractor.subgraph_block_sizes(
            subgraph, self._func_block_sizes.get(func_name, {}))

        return VulnSignature(
            vuln_id=vuln_id,
            func_name=func_name,
            vuln_addr=vuln_addr,
            signature=NeighborhoodSignatureBuilder.compute(
                subgraph, vuln_addr, sizes, self._radius),
            neighborhood_radius=self._radius,
            num_blocks_in_neighborhood=len(neighborhood),
            api_calls=api_calls or [],
            error_patterns=error_patterns or [],
        )

    def scan(self, source: VulnSignature,
              min_similarity: Optional[float] = None,
              ) -> VariantScanReport:
        """扫描所有已注册函数, 寻找与源签名匹配的邻域"""
        threshold = min_similarity or self._min_similarity
        t0 = time.perf_counter()
        candidates: List[VariantCandidate] = []
        total_funcs = len(self._func_cfgs)
        total_locs = 0

        src_vec = source.signature
        src_norm = math.sqrt(sum(x * x for x in src_vec))

        for func_name, cfg in self._func_cfgs.items():
            sizes = self._func_block_sizes.get(func_name, {})
            total_locs += len(cfg)

            for block_addr in cfg:
                subgraph, neighborhood = self._extractor.extract(
                    cfg, block_addr, sizes)
                if not subgraph or len(neighborhood) < 2:
                    continue

                sub_sizes = self._extractor.subgraph_block_sizes(
                    subgraph, sizes)
                cand_vec = NeighborhoodSignatureBuilder.compute(
                    subgraph, block_addr, sub_sizes, self._radius)

                dot = sum(a * b for a, b in zip(src_vec, cand_vec))
                cand_norm = math.sqrt(sum(x * x for x in cand_vec))
                if src_norm < 1e-12 or cand_norm < 1e-12:
                    continue
                similarity = max(-1.0, min(1.0,
                    dot / (src_norm * cand_norm)))

                if similarity < threshold:
                    continue

                api_overlap = self._api_call_overlap(
                    func_name, block_addr, source.api_calls)
                size_match = min(
                    len(neighborhood) / max(1, source.num_blocks_in_neighborhood),
                    source.num_blocks_in_neighborhood / max(1, len(neighborhood)),
                )
                is_high = similarity > 0.9 and api_overlap > 0.3

                candidates.append(VariantCandidate(
                    func_name=func_name,
                    match_addr=block_addr,
                    similarity=similarity,
                    signature_distance=1.0 - similarity,
                    api_overlap=api_overlap,
                    neighborhood_size_match=size_match,
                    is_high_confidence=is_high,
                    rationale=self._build_rationale(
                        func_name, block_addr, similarity,
                        api_overlap, is_high),
                ))

        candidates.sort(key=lambda c: -c.similarity)
        candidates = self._deduplicate_neighbors(candidates)

        high_conf = sum(1 for c in candidates if c.is_high_confidence)
        elapsed = time.perf_counter() - t0

        return VariantScanReport(
            source_vuln=source,
            total_functions_scanned=total_funcs,
            total_locations_scanned=total_locs,
            candidates=candidates,
            high_confidence_count=high_conf,
            scan_time_s=elapsed,
            summary=self._build_report_summary(
                source, candidates, high_conf, total_locs, elapsed),
        )

    def _api_call_overlap(self, func_name: str, block_addr: int,
                           source_apis: List[str]) -> float:
        if not source_apis:
            return 0.0
        score = 0.0
        func_lower = func_name.lower()
        for api in source_apis:
            if api.lower() in func_lower:
                score += 1.0
        return score / len(source_apis)

    @staticmethod
    def _deduplicate_neighbors(
            candidates: List[VariantCandidate]) -> List[VariantCandidate]:
        if len(candidates) <= 1:
            return candidates
        result: List[VariantCandidate] = []
        for c in candidates:
            too_close = any(
                c.func_name == e.func_name
                and abs(c.match_addr - e.match_addr) < 16
                for e in result)
            if not too_close:
                result.append(c)
        return result

    @staticmethod
    def _build_rationale(func_name: str, addr: int,
                          similarity: float, api_overlap: float,
                          is_high: bool) -> str:
        conf = "高" if is_high else "中"
        return (f"{func_name} @ {addr:#x}: sim={similarity:.3f}, "
                f"API重叠={api_overlap:.2f} [{conf}]")

    @staticmethod
    def _build_report_summary(source: VulnSignature,
                               candidates: List[VariantCandidate],
                               high_conf: int,
                               total_locs: int, elapsed: float) -> str:
        lines = [
            f"变体扫描: {source.vuln_id} ({source.func_name} @ "
            f"{source.vuln_addr:#x})",
            f"扫描 {total_locs} 位置, {len(candidates)} 候选, "
            f"{high_conf} 高置信度, {elapsed:.2f}s",
        ]
        for c in candidates[:10]:
            marker = " ***" if c.is_high_confidence else ""
            lines.append(f"  {c.rationale}{marker}")
        return "\n".join(lines)


def quick_scan(vuln_func_cfg: Dict[int, List[int]],
                vuln_addr: int,
                other_cfgs: Dict[str, Dict[int, List[int]]],
                vuln_id: str = "unknown",
                ) -> VariantScanReport:
    """便捷入口: 给定漏洞CFG和其他函数CFG, 快速扫描变体"""
    scanner = VariantScanner()
    scanner.add_function_cfg("_vuln_func_", vuln_func_cfg)
    for name, cfg in other_cfgs.items():
        scanner.add_function_cfg(name, cfg)
    sig = scanner.extract_signature(
        vuln_id=vuln_id, func_name="_vuln_func_", vuln_addr=vuln_addr)
    if sig is None:
        return VariantScanReport(
            source_vuln=VulnSignature(vuln_id=vuln_id),
            summary="无法提取漏洞签名")
    return scanner.scan(sig)
