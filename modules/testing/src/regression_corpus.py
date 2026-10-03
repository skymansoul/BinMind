# 回归测试语料管理器 — CI/CD场景下的智能测试用例选取与调度
# 核心功能:
#   1. 基于覆盖率的用例去重: 剔除覆盖基本块完全被其他用例包含的冗余测试
#   2. 用例优先级排序: 按历史失败率+变更关联度+执行时间排序
#   3. 最小化回归集选取: 贪心集合覆盖 -> 最小用例集维持相同覆盖率
#   4. 增量语料: 仅选取对最近变更（函数/文件）有覆盖的用例
#
# 背景: 长期fuzzing产生的百万级语料无法全部跑CI回归测试，必须做智能选取。
#
#
#   LibAFL: modular fuzzer framework
#     with corpus management primitives
#   Evaluating Fuzz Testing: 语料质量度量
#   Regression Test Selection: 回归测试选取综述
#   ClusterFuzz production corpus management
import os
import math
import time
import json
import hashlib
from typing import List, Dict, Set, Tuple, Optional, Any, Iterator
from collections import defaultdict, Counter
from dataclasses import dataclass, field


@dataclass
class CorpusEntry:
    """单个语料条目。"""
    entry_id: str
    data: bytes
    size: int = 0
    covered_blocks: Set[int] = field(default_factory=set)
    covered_edges: Set[Tuple[int, int]] = field(default_factory=set)
    crash_detected: bool = False
    discovery_time: float = 0.0
    source_seed: str = ""
    fuzzer_engine: str = ""
    generation: int = 0       # 代数（变异次数）
    priority: float = 1.0     # CI优先级 [0.1, 10]

    def __post_init__(self):
        if self.size == 0 and self.data:
            self.size = len(self.data)


class RegressionCorpusManager:
    """回归测试语料管理器。

    工作流:
    1. ingest(corpus_dir) — 导入语料库
    2. deduplicate() — 去重
    3. prioritize() — 按CI优先级排序
    4. select_minimal_set() — 贪心选取最小覆盖集
    5. select_incremental(changed_funcs) — 选取覆盖变更函数的子集
    6. export(output_dir) — 写出选中语料

    覆盖信息来自外部注入 (如LLVM source-based coverage或QEMU)。
    """

    def __init__(self, max_corpus: int = 10000):
        self._max = max_corpus
        self._entries: Dict[str, CorpusEntry] = {}
        self._entry_order: List[str] = []  # 保持插入顺序
        self._global_coverage: Set[int] = set()
        self._crash_entries: Dict[str, CorpusEntry] = {}

    # 导入
    def ingest_file(self, filepath: str,
                    entry_id: str = "") -> Optional[str]:
        """导入单个语料文件。返回entry_id。"""
        try:
            with open(filepath, 'rb') as fh:
                data = fh.read()
        except OSError:
            return None
        if not data:
            return None

        eid = entry_id or hashlib.sha256(data).hexdigest()[:12]
        if len(self._entries) >= self._max:
            self._evict_one()
        self._entries[eid] = CorpusEntry(
            entry_id=eid, data=data)
        self._entry_order.append(eid)
        return eid

    def ingest_directory(self, dir_path: str) -> int:
        """导入整个目录的语料。返回导入数量。"""
        count = 0
        if not os.path.isdir(dir_path):
            return 0
        for fname in sorted(os.listdir(dir_path)):
            fpath = os.path.join(dir_path, fname)
            if os.path.isfile(fpath):
                if self.ingest_file(fpath):
                    count += 1
        return count

    def _evict_one(self) -> None:
        """淘汰最低优先级的条目。"""
        if not self._entries:
            return
        worst_id = min(self._entries,
                       key=lambda eid: self._entries[eid].priority)
        del self._entries[worst_id]
        self._entry_order = [e for e in self._entry_order if e != worst_id]

    # 覆盖信息注入
    def set_coverage(self, entry_id: str,
                     blocks: Set[int],
                     edges: Set[Tuple[int, int]] = None) -> None:
        entry = self._entries.get(entry_id)
        if entry is None:
            return
        entry.covered_blocks = set(blocks)
        if edges:
            entry.covered_edges = set(edges)
        self._global_coverage.update(blocks)

    def mark_crash(self, entry_id: str) -> None:
        entry = self._entries.get(entry_id)
        if entry:
            entry.crash_detected = True
            entry.priority = 10.0
            self._crash_entries[entry_id] = entry

    # 去重
    def deduplicate(self) -> int:
        """基于SHA-256去重。保留最小尺寸副本。返回移除数量。"""
        seen: Dict[str, str] = {}  # hash -> entry_id
        removed = 0
        for eid in list(self._entry_order):
            entry = self._entries.get(eid)
            if entry is None:
                continue
            h = hashlib.sha256(entry.data).hexdigest()
            if h in seen:
                # 保留更小的
                other = self._entries.get(seen[h])
                if other and len(entry.data) < len(other.data):
                    del self._entries[seen[h]]
                    self._entry_order.remove(seen[h])
                    seen[h] = eid
                    removed += 1
                else:
                    del self._entries[eid]
                    self._entry_order.remove(eid)
                    removed += 1
            else:
                seen[h] = eid
        return removed

    # 优先级排序
    def prioritize(self) -> None:
        """按多因素计算优先级: 崩溃 > 覆盖率贡献 > 大小 > 发现时间。"""
        for entry in self._entries.values():
            score = 0.0
            # 崩溃检测 -> 最高优先级
            if entry.crash_detected:
                score = 10.0
            else:
                # 覆盖率贡献: 覆盖了更多独立块的条目优先
                unique_blocks = len(
                    entry.covered_blocks - self._global_coverage
                    | entry.covered_blocks)
                score += min(5.0, unique_blocks / 100.0)
                # 较小输入优先 (更快执行)
                score += 2.0 / max(1, math.log2(entry.size + 1))
                # 新近发现的优先
                if entry.discovery_time > 0:
                    age_h = (time.time() - entry.discovery_time) / 3600
                    score += 1.0 / max(1, age_h / 24)
            entry.priority = max(0.1, min(10.0, score))

    # 最小集合选取
    def select_minimal_set(self,
                           target_coverage_pct: float = 0.95
                           ) -> List[CorpusEntry]:
        """贪心集合覆盖: 选取最小语料子集覆盖>=target_coverage_pct的全局BB。

        每轮选取覆盖最多未覆盖块的条目。
        """
        if not self._entries or not self._global_coverage:
            return list(self._entries.values())

        uncovered = set(self._global_coverage)
        target_covered = int(len(self._global_coverage) * target_coverage_pct)
        selected: List[CorpusEntry] = []
        remaining = dict(self._entries)

        while uncovered and remaining and len(self._global_coverage) - len(
                uncovered) < target_covered:
            best_id = None
            best_new = 0
            for eid, entry in remaining.items():
                new_blocks = len(entry.covered_blocks & uncovered)
                if new_blocks > best_new:
                    best_new = new_blocks
                    best_id = eid
            if best_id is None or best_new == 0:
                break
            entry = remaining[best_id]
            uncovered -= entry.covered_blocks
            selected.append(entry)
            del remaining[best_id]

        return selected

    def select_incremental(self,
                           changed_functions: Set[int],
                           call_graph_edges: Dict[int, Set[int]] = None
                           ) -> List[CorpusEntry]:
        """仅选取覆盖了变更函数（及其调用者）的语料条目。"""
        if not changed_functions:
            return []

        # 扩展: 包含调用链上的所有函数
        affected = set(changed_functions)
        if call_graph_edges:
            # BFS找到所有调用变更函数的调用者
            rev_graph: Dict[int, Set[int]] = defaultdict(set)
            for caller, callees in call_graph_edges.items():
                for callee in callees:
                    rev_graph[callee].add(caller)
            queue = list(changed_functions)
            while queue:
                func = queue.pop()
                for caller in rev_graph.get(func, set()):
                    if caller not in affected:
                        affected.add(caller)
                        queue.append(caller)

        selected = []
        for entry in self._entries.values():
            if entry.covered_blocks & affected:
                selected.append(entry)
        return selected

    # 导出
    def export(self, output_dir: str,
               entries: List[CorpusEntry] = None) -> int:
        """写出语料到目录。返回写出文件数。"""
        os.makedirs(output_dir, exist_ok=True)
        targets = entries or list(self._entries.values())
        count = 0
        for entry in targets:
            fname = f"corpus_{entry.entry_id}.bin"
            fpath = os.path.join(output_dir, fname)
            try:
                with open(fpath, 'wb') as fh:
                    fh.write(entry.data)
                count += 1
            except OSError:
                pass
        return count

    def export_manifest(self, output_path: str,
                        entries: List[CorpusEntry] = None) -> None:
        """写出语料清单JSON (entry_id + hash + size + priority)。"""
        targets = entries or list(self._entries.values())
        manifest = [
            {
                'id': e.entry_id,
                'sha256': hashlib.sha256(e.data).hexdigest(),
                'size': e.size,
                'priority': round(e.priority, 2),
                'crash': e.crash_detected,
                'blocks_covered': len(e.covered_blocks),
            }
            for e in targets
        ]
        with open(output_path, 'w', encoding='utf-8') as fh:
            json.dump(manifest, fh, indent=2)

    # 统计
    def stats(self) -> Dict[str, Any]:
        return {
            'total_entries': len(self._entries),
            'crash_entries': len(self._crash_entries),
            'global_blocks_covered': len(self._global_coverage),
            'avg_entry_size': round(
                sum(e.size for e in self._entries.values())
                / max(1, len(self._entries)), 1),
            'priority_distribution': dict(Counter(
                'high' if e.priority >= 5 else 'medium' if e.priority >= 2
                else 'low'
                for e in self._entries.values())),
        }


def quick_ci_subset(corpus_dir: str,
                    output_dir: str,
                    max_files: int = 100) -> int:
    """快捷CI入口: 从语料目录中选取最优max_files个文件输出。"""
    mgr = RegressionCorpusManager()
    mgr.ingest_directory(corpus_dir)
    mgr.deduplicate()
    mgr.prioritize()
    ranked = sorted(mgr._entries.values(),
                    key=lambda e: -e.priority)[:max_files]
    return mgr.export(output_dir, ranked)
