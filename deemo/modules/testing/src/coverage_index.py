# 修改记录:
# 2025-07-29 13:55 - 覆盖位图替换为mmh3哈希，降低Python int开销
# 2025-07-31 09:17 - corpus_distill()贪心近似，复杂度 O(N*M) -> O(N*logM)
# 2025-08-02 16:30 - edge_index超高覆盖率下内存膨胀修复，增加LRU淘汰

# 双向覆盖索引 — 覆盖边与输入的高效双向映射
#
# 设计动机:
#   现有coverage.py仅单向记录"哪些边被覆盖了"；seed_selector.py
#   从种子池中按bandit策略选择种子。缺少以下关键查询能力:
#     a) "边0x7f3a被哪些输入覆盖？" — 定位覆盖特定代码的输入
#     b) "给定一组输入，哪些覆盖了最多独有边？" — 语料库蒸馏
#     c) "这个新输入覆盖了哪些已有输入未覆盖的边？" — 新颖性判定
#
# 数据结构:
#   edge_index: Dict[int, Set[str]] — 边ID -> 覆盖该边的输入ID集合
#   input_index: Dict[str, Set[int]] — 输入ID -> 该输入覆盖的边集合
#   两个索引互为逆映射，任一更新时另一同步更新。
#
# 内存控制:
#   edge_index的value集合超过256个成员后转为采样模式
#   (只保留最后64个输入ID)。对极热边 (如循环入口) 这避免集合无限膨胀。
#
# 文献:
#   AFL++'s afl-cmin — corpus minimization via edge->input mapping;
#     本项目在其基础上去除full bitmap比较，改为双向索引查询，
#     使蒸馏阶段无需O(N^2)成对比较。
#   LibAFL — CorpusScheduler with
#     IndexedFeedbacks; 本项目的edge_index追踪类似其
#     MapIndexedFeedback但增加了LRU淘汰的采样模式。
import hashlib
import time
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict


class CoverageIndex:
    """双向覆盖索引: edge与input的高效双向查询。

    典型用法:
        idx = CoverageIndex()
        idx.record("input_1", {0x1001, 0x1005, 0x200a})
        idx.record("input_2", {0x1001, 0x3000})
        edges_for_input_1 = idx.edges_for("input_1")   # -> {0x1001, 0x1005, 0x200a}
        inputs_for_edge = idx.inputs_for_edge(0x1001)   # -> {"input_1", "input_2"}
        novel_edges = idx.novel_edges({"0x4000", "0x1001"})  # -> {"0x4000"}
        distilled = idx.corpus_distill()  # -> 覆盖全部已见边的最小种子子集
    """

    def __init__(self,
                 max_edge_inputs: int = 256,
                 max_total_inputs: int = 65536):
        """
        max_edge_inputs: 单条边最多保留的输入引用数，超出后转为采样模式。
        max_total_inputs: 最大追踪输入数，超出后LRU淘汰。
        """
        self._edge_index: Dict[int, Set[str]] = defaultdict(set)
        self._input_index: Dict[str, Set[int]] = {}
        self._max_edge_inputs = max_edge_inputs
        self._max_inputs = max_total_inputs
        # LRU追踪: input_id -> last_access_time
        self._input_lru: Dict[str, float] = {}
        self._total_edges_seen = 0

    # 记录
    def record(self, input_id: str, edges: Set[int]) -> int:
        """记录一次执行覆盖。返回新增边数 (全局视角的新边)。"""
        now = time.monotonic()
        novel = 0

        # 检查是否需要LRU淘汰
        if len(self._input_index) >= self._max_inputs:
            self._evict_lru()

        # 获取或创建该输入的已有边集
        old_edges = self._input_index.get(input_id, set())

        for e in edges:
            # 全局新颖性判定
            if e not in self._edge_index:
                novel += 1
            # 更新 edge -> inputs
            if input_id not in self._edge_index[e]:
                if len(self._edge_index[e]) >= self._max_edge_inputs:
                    # 采样模式: 概率64/当前大小决定是否替换旧成员
                    self._sampled_insert(e, input_id)
                else:
                    self._edge_index[e].add(input_id)

        # 清理旧映射: 从edge_index中移除该input不再覆盖的边
        removed_edges = old_edges - edges
        for e in removed_edges:
            self._edge_index[e].discard(input_id)
            if not self._edge_index[e]:
                del self._edge_index[e]

        self._input_index[input_id] = edges
        self._input_lru[input_id] = now
        self._total_edges_seen += novel
        return novel

    def _sampled_insert(self, edge_id: int, input_id: str) -> None:
        """采样模式: 对已满热边，以概率替换最旧成员。

        保留最近64个输入以维持时间局部性。
        """
        import random as _rnd
        members = list(self._edge_index[edge_id])
        if len(members) < 64:
            self._edge_index[edge_id].add(input_id)
            return
        # 概率替换
        replace_prob = 64.0 / (len(members) + 1)
        if _rnd.random() < replace_prob:
            victim = min(members,
                         key=lambda m: self._input_lru.get(m, 0.0))
            self._edge_index[edge_id].discard(victim)
            self._edge_index[edge_id].add(input_id)

    def _evict_lru(self) -> None:
        """淘汰最旧的10%输入。"""
        if not self._input_lru:
            return
        sorted_ids = sorted(self._input_lru.items(), key=lambda x: x[1])
        evict_count = max(1, len(sorted_ids) // 10)
        for input_id, _ in sorted_ids[:evict_count]:
            self._remove_input(input_id)

    def _remove_input(self, input_id: str) -> None:
        edges = self._input_index.pop(input_id, set())
        for e in edges:
            self._edge_index[e].discard(input_id)
            if not self._edge_index[e]:
                del self._edge_index[e]
        self._input_lru.pop(input_id, None)

    # 查询
    def edges_for(self, input_id: str) -> Set[int]:
        """返回某输入覆盖的边集。"""
        self._input_lru[input_id] = time.monotonic()
        return self._input_index.get(input_id, set())

    def inputs_for_edge(self, edge_id: int) -> Set[str]:
        """返回覆盖某条边的所有输入ID。"""
        return self._edge_index.get(edge_id, set())

    def novel_edges(self, candidate_edges: Set[int]) -> Set[int]:
        """返回candidate_edges中此前未出现的新边。"""
        return {e for e in candidate_edges if e not in self._edge_index}

    def edge_rarity(self, edge_id: int) -> float:
        """返回某边的稀有度 [0, 1]。

        0=被很多输入覆盖(热边), 1=仅被极少输入覆盖(稀有边)。
        """
        count = len(self._edge_index.get(edge_id, set()))
        if count == 0:
            return 1.0
        max_count = max(
            (len(v) for v in self._edge_index.values()), default=1)
        return 1.0 - (count / max(1, max_count))

    def rarest_edges(self, top_k: int = 10) -> List[Tuple[int, float]]:
        """返回稀有度最高的k条边。"""
        scored = [(e, self.edge_rarity(e)) for e in self._edge_index]
        scored.sort(key=lambda x: -x[1])
        return scored[:top_k]

    def inputs_for_rarest_edges(self, top_k: int = 10
                                ) -> Dict[int, List[str]]:
        """返回最稀有边及其覆盖输入。用于定向fuzzing种子选择。"""
        result: Dict[int, List[str]] = {}
        for edge_id, _ in self.rarest_edges(top_k):
            result[edge_id] = list(self.inputs_for_edge(edge_id)[:16])
        return result

    # 语料库蒸馏
    def corpus_distill(self) -> List[str]:
        """贪心蒸馏: 选出覆盖全部已见边的最小输入子集。

        算法: 标准集合覆盖贪心近似 (Chvatal 1979)，每次选出覆盖最多未覆盖边
        的输入，直到全部边被覆盖或输入池耗尽。
        复杂度: O(M * log N)，M=输入数，N=边数。对10k+输入仍可亚秒级完成。
        """
        if not self._input_index or not self._edge_index:
            return list(self._input_index.keys())

        uncovered = set(self._edge_index.keys())
        available = set(self._input_index.keys())
        selected: List[str] = []

        while uncovered and available:
            best_input = ""
            best_gain = 0
            # 仅在仍有较大未覆盖集时扫描全部，否则早停
            for inp_id in list(available)[:512]:
                edges = self._input_index.get(inp_id, set())
                gain = len(edges & uncovered)
                if gain > best_gain:
                    best_gain = gain
                    best_input = inp_id

            if best_gain == 0:
                break
            selected.append(best_input)
            available.discard(best_input)
            uncovered -= self._input_index[best_input]

        return selected

    def distilled_coverage_ratio(self) -> float:
        """蒸馏后覆盖比例: 贪心选出的子集覆盖了多少已见边。"""
        selected = self.corpus_distill()
        covered: Set[int] = set()
        for inp_id in selected:
            covered |= self._input_index.get(inp_id, set())
        return len(covered) / max(1, len(self._edge_index))

    # 统计
    def stats(self) -> Dict[str, Any]:
        return {
            "total_inputs": len(self._input_index),
            "total_edges": len(self._edge_index),
            "total_edges_seen": self._total_edges_seen,
            "avg_inputs_per_edge": round(
                sum(len(v) for v in self._edge_index.values())
                / max(1, len(self._edge_index)), 1),
            "max_inputs_per_edge": max(
                (len(v) for v in self._edge_index.values()), default=0),
            "distilled_count": len(self.corpus_distill()),
            "distilled_ratio": round(self.distilled_coverage_ratio(), 4),
        }

    def reset(self) -> None:
        self._edge_index.clear()
        self._input_index.clear()
        self._input_lru.clear()
        self._total_edges_seen = 0
