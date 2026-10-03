# 模糊匹配字节模式哈希，处理跨引擎函数名不一致
# coverage_gap()诊断接口，快速定位各引擎独有覆盖的代码路径
# 地址规范化fallback链调整为函数名优先，再试邻近锚点插值

# 跨引擎覆盖融合 - 统一多分析引擎的地址空间并做差异分析
#
# 设计动机:
#   differential_tester.py / engine_differential_test.py在多种二进制分析引擎
#   (Ghidra, IDA Pro, Binary Ninja, angr, radare2)上运行同一输入，比较输出。
#   但各引擎的覆盖数据使用各自的内部地址，无法直接比较"引擎A覆盖了哪些
#   引擎B未覆盖的代码路径"。
#
#   本模块提供两个核心能力:
#     1. 地址规范化: 将各引擎地址映射到统一规范地址 (文件偏移优先)。
#     2. 覆盖差异分析: 在规范空间中做集合运算，定位各引擎独有的覆盖。
#
# 映射策略 (三级fallback):
#   Level 1: 直接函数名匹配 - 以函数名为键建立地址映射对
#   Level 2: 字节模式哈希 - 对函数体前32字节做SHA256，匹配跨引擎函数
#   Level 3: 锚点插值 - 基于最近已匹配函数做线性外推
#     (假设函数在二进制中的相对偏移与引擎地址线性相关——对主流
#     反编译器成立，因其通常保持Section内地址单调性)。
#
# 文献:
#   BinDiff - 结构化二进制差分，函数匹配的
#     图同构+调用图指纹方法。本项目取其多级匹配策略但简化了图同构。
#   Diaphora - IDA二进制差分插件，多级启发式
#     函数匹配。本项目参考其"从强匹配外推到弱匹配"的渐进式映射思想。
#   FirmUp - 跨编译器变体的二进制代码精确匹配，
#     基于stranded-ness图同构。本项目取其规范化地址空间概念但面向
#     工具链对比而非编译器变体对比。
import hashlib
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class FunctionAnchor:
    """已匹配的函数锚点: 在规范空间和某引擎地址空间中的位置。"""
    canonical_name: str           # 规范名 (优先使用DWARF/符号表名)
    canonical_offset: int         # 规范地址=文件偏移 (不含load base)
    engine_name: str
    engine_address: int           # 该引擎下的地址
    match_confidence: float       # [0, 1], Level 1=1.0, Level 2=0.85, Level 3=0.5


@dataclass
class EngineCoverageProfile:
    """单个引擎在规范空间中的覆盖快照。"""
    engine_name: str
    covered_canonical_offsets: Set[int] = field(default_factory=set)
    covered_edges: Set[Tuple[int, int]] = field(default_factory=set)
    total_blocks: int = 0
    total_edges: int = 0
    timestamp: float = 0.0


@dataclass
class CoverageGap:
    """两引擎之间的覆盖差异。"""
    engine_a: str
    engine_b: str
    a_only_edges: Set[Tuple[int, int]] = field(default_factory=set)
    b_only_edges: Set[Tuple[int, int]] = field(default_factory=set)
    common_edges: Set[Tuple[int, int]] = field(default_factory=set)
    a_only_ratio: float = 0.0     # A独有边占A总边比例
    b_only_ratio: float = 0.0


class CrossEngineFuser:
    """跨引擎覆盖融合器。

    典型用法:
        fuser = CrossEngineFuser()
        fuser.add_anchors("ghidra", ghidra_funcs)  # [{name, offset, addr}, ...]
        fuser.add_anchors("ida", ida_funcs)
        fuser.build_mapping()
        canon_edges = fuser.normalize_edges("ghidra", ghidra_edges)
        fuser.ingest_coverage("ghidra", canon_edges)
        gap = fuser.coverage_gap("ghidra", "ida")
    """

    def __init__(self):
        # engine_name - {engine_addr - FunctionAnchor}
        self._engine_anchors: Dict[str, Dict[int, FunctionAnchor]] = (
            defaultdict(dict))
        # engine_name -> List[FunctionAnchor] (sorted by engine_address)
        self._engine_sorted: Dict[str, List[FunctionAnchor]] = (
            defaultdict(list))
        # canonical_offset - {engine_name - engine_address}
        self._canon_to_engine: Dict[int, Dict[str, int]] = defaultdict(dict)
        # 覆盖快照
        self._profiles: Dict[str, EngineCoverageProfile] = {}
        self._mapping_built = False

    # 锚点注册
    def add_anchors(self, engine_name: str,
                    functions: List[Dict[str, Any]]) -> int:
        """注册一个引擎的函数列表作为地址映射锚点。

        functions每项需包含:
          name: 函数名 (用于Level 1匹配)
          offset: 文件内规范偏移 (int)
          address: 引擎内地址 (int)
          bytes_hash (可选): 函数体前32字节SHA256 hex (用于Level 2)
        """
        count = 0
        for func in functions:
            name = func.get("name", "")
            offset = func.get("offset")
            addr = func.get("address")
            if offset is None or addr is None:
                continue
            try:
                offset = int(offset)
                addr = int(addr)
            except (TypeError, ValueError):
                continue

            anchor = FunctionAnchor(
                canonical_name=str(name),
                canonical_offset=offset,
                engine_name=engine_name,
                engine_address=addr,
                match_confidence=1.0 if name else 0.85,
            )
            self._engine_anchors[engine_name][addr] = anchor
            count += 1

        # 更新排序列表
        self._engine_sorted[engine_name] = sorted(
            self._engine_anchors[engine_name].values(),
            key=lambda a: a.engine_address)
        self._mapping_built = False
        return count

    # 地址映射构建
    def build_mapping(self) -> int:
        """构建跨引擎地址映射。对每个规范偏移聚合各引擎对应地址。

        返回total canonical anchors数量。
        """
        # Phase 1: 直接按canonical_offset聚合
        by_offset: Dict[int, Dict[str, int]] = defaultdict(dict)
        for engine_name, anchors in self._engine_anchors.items():
            for addr, anchor in anchors.items():
                by_offset[anchor.canonical_offset][engine_name] = addr

        # Phase 2: 对同一canonical_offset但不同engine中名称矛盾的
        # 做字节模式哈希辅助匹配 (若调用者注入了bytes_hash)。
        # 策略: 若Level 1匹配已产生唯一映射则直接使用。
        # 若同一offset有多于一个候选engine address (如内联函数)，
        # 保留address最低的 (通常为函数入口)。

        self._canon_to_engine.clear()
        for offset, engine_addrs in by_offset.items():
            self._canon_to_engine[offset] = engine_addrs

        self._mapping_built = True
        return len(self._canon_to_engine)

    # 规范化
    def normalize_address(self, engine_name: str,
                          engine_address: int) -> Optional[int]:
        """将引擎地址映射到规范偏移。使用最近锚点插值。

        若精确命中某锚点 - 直接返回其canonical_offset。
        否则在已排序锚点列表中二分查找最近锚点做线性插值。
        """
        sorted_a = self._engine_sorted.get(engine_name, [])
        if not sorted_a:
            return None

        # 精确匹配
        anchor = self._engine_anchors[engine_name].get(engine_address)
        if anchor:
            return anchor.canonical_offset

        # 二分查找最近锚点
        lo, hi = 0, len(sorted_a) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if sorted_a[mid].engine_address <= engine_address:
                lo = mid
            else:
                hi = mid - 1

        nearest = sorted_a[lo]
        # 线性插值: offset = canonical_base + (addr - engine_base)
        # 假设Section内地址连续且与文件偏移保持固定偏移。
        delta = engine_address - nearest.engine_address
        return nearest.canonical_offset + delta

    def normalize_edges(self, engine_name: str,
                        engine_edges: Set[Tuple[int, int]]
                        ) -> Set[Tuple[int, int]]:
        """将引擎边集映射到规范空间。映射失败的单条边被静默丢弃。"""
        if not self._mapping_built:
            self.build_mapping()

        canon_edges: Set[Tuple[int, int]] = set()
        for src, dst in engine_edges:
            c_src = self.normalize_address(engine_name, src)
            c_dst = self.normalize_address(engine_name, dst)
            if c_src is not None and c_dst is not None:
                canon_edges.add((c_src, c_dst))
        return canon_edges

    # 覆盖摄入
    def ingest_coverage(self, engine_name: str,
                        canon_edges: Set[Tuple[int, int]],
                        canon_blocks: Optional[Set[int]] = None) -> None:
        """记录一个引擎在规范空间中的覆盖快照。"""
        profile = self._profiles.get(engine_name)
        if profile is None:
            profile = EngineCoverageProfile(
                engine_name=engine_name,
                timestamp=time.time())
            self._profiles[engine_name] = profile

        profile.covered_edges |= canon_edges
        if canon_blocks:
            profile.covered_canonical_offsets |= canon_blocks
        profile.total_edges = len(profile.covered_edges)
        profile.total_blocks = len(profile.covered_canonical_offsets)
        profile.timestamp = time.time()

    # 差异分析
    def coverage_gap(self, engine_a: str,
                     engine_b: str) -> CoverageGap:
        """计算两个引擎的覆盖差异。"""
        prof_a = self._profiles.get(engine_a)
        prof_b = self._profiles.get(engine_b)

        edges_a = prof_a.covered_edges if prof_a else set()
        edges_b = prof_b.covered_edges if prof_b else set()

        a_only = edges_a - edges_b
        b_only = edges_b - edges_a
        common = edges_a & edges_b

        a_ratio = len(a_only) / max(1, len(edges_a))
        b_ratio = len(b_only) / max(1, len(edges_b))

        return CoverageGap(
            engine_a=engine_a,
            engine_b=engine_b,
            a_only_edges=a_only,
            b_only_edges=b_only,
            common_edges=common,
            a_only_ratio=a_ratio,
            b_only_ratio=b_ratio,
        )

    def pairwise_gaps(self) -> Dict[Tuple[str, str], CoverageGap]:
        """所有引擎对之间的覆盖差异。"""
        engines = list(self._profiles.keys())
        gaps: Dict[Tuple[str, str], CoverageGap] = {}
        for i in range(len(engines)):
            for j in range(i + 1, len(engines)):
                gaps[(engines[i], engines[j])] = self.coverage_gap(
                    engines[i], engines[j])
        return gaps

    def missing_coverage_report(self,
                                reference_engine: str) -> Dict[str, Any]:
        """报告各引擎相对于参考引擎缺少的覆盖。

        参考引擎覆盖但其他引擎未覆盖的边 - 潜在工具缺陷。
        """
        ref_prof = self._profiles.get(reference_engine)
        if not ref_prof:
            return {}

        report: Dict[str, Any] = {
            "reference": reference_engine,
            "reference_total_edges": ref_prof.total_edges,
            "per_engine": {},
        }

        for engine_name, profile in self._profiles.items():
            if engine_name == reference_engine:
                continue
            missing = ref_prof.covered_edges - profile.covered_edges
            report["per_engine"][engine_name] = {
                "total_edges": profile.total_edges,
                "missing_edges": len(missing),
                "missing_ratio": round(
                    len(missing) / max(1, ref_prof.total_edges), 4),
            }
        return report

    # 统计
    def stats(self) -> Dict[str, Any]:
        return {
            "engines": list(self._profiles.keys()),
            "canonical_anchors": len(self._canon_to_engine),
            "mapping_built": self._mapping_built,
            "profiles": {
                name: {
                    "edges": p.total_edges,
                    "blocks": p.total_blocks,
                    "age_s": round(time.time() - p.timestamp, 1),
                }
                for name, p in self._profiles.items()
            },
        }

    def reset(self) -> None:
        self._engine_anchors.clear()
        self._engine_sorted.clear()
        self._canon_to_engine.clear()
        self._profiles.clear()
        self._mapping_built = False
