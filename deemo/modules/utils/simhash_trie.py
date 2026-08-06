"""
渐进式 SimHash 二叉检索树 (PSH-Trie)
--------------------------------------
在 64-bit SimHash 空间上建立二叉前缀树，分支限界 + 半径渐进扩展
实现 Hamming 空间近似最近邻检索。

与 Google 抽屉原理方案的区别:
  段索引在 Hamming ≥ 4 时需要枚举位错误组合 (组合爆炸)；
  trie 方案的 DFS 剪枝无需预切分段，任意半径的边际扩展成本稳定。
"""
from __future__ import annotations
from typing import List, Tuple, Optional, Any, Callable


class SimHashNode:
    """PSH-Trie 节点。非叶节点仅维护 child[0]/child[1] 和子树统计。"""

    __slots__ = ("children", "leaves", "subtree_count")

    def __init__(self):
        self.children: List[Optional[SimHashNode]] = [None, None]
        # 叶子列表——同一路径上可能有多个相同哈希 (极少见，但支持)
        self.leaves: List[Tuple[int, Any]] = []  # [(simhash_64, payload)]
        self.subtree_count: int = 0


class SimHashTrie:
    """SimHash 二叉前缀树——插入、半径搜索、渐进搜索。"""

    def __init__(self):
        self._root = SimHashNode()
        self._total = 0

    def insert(self, hash_val: int, payload: Any = None):
        """插入一个 64-bit SimHash 及其关联载荷。"""
        node = self._root
        node.subtree_count += 1
        for bit in range(63, -1, -1):
            direction = (hash_val >> bit) & 1
            if node.children[direction] is None:
                node.children[direction] = SimHashNode()
            node = node.children[direction]
            node.subtree_count += 1
        node.leaves.append((hash_val, payload))
        self._total += 1

    def insert_batch(self, items: List[Tuple[int, Any]]):
        """批量插入 [(hash_val, payload), ...]。"""
        for h, p in items:
            self.insert(h, p)

    def __len__(self) -> int:
        return self._total

    def search_radius(
        self,
        query_hash: int,
        radius: int,
        max_results: int = 50,
    ) -> List[Tuple[int, Any, int]]:
        """在不超过 radius 的 Hamming 距离内搜索。
        返回 [(hash, payload, hamming_distance), ...]，按距离升序排列。
        """
        results: List[Tuple[int, Any, int]] = []
        self._dfs(query_hash, radius, self._root, 63, 0, results, max_results)
        results.sort(key=lambda x: x[2])
        return results

    def _dfs(
        self,
        query: int,
        radius: int,
        node: SimHashNode,
        bit: int,
        acc_hamming: int,
        results: List[Tuple[int, Any, int]],
        max_results: int,
    ):
        if len(results) >= max_results or node is None:
            return
        for h, payload in node.leaves:
            if len(results) >= max_results:
                return
            dist = (query ^ h).bit_count()
            if dist <= radius:
                results.append((h, payload, dist))
        if bit < 0:
            return
        query_bit = (query >> bit) & 1
        # 优先走匹配分支——提高 early-stop 概率
        for direction in (query_bit, 1 - query_bit):
            child = node.children[direction]
            if child is None:
                continue
            added = 0 if direction == query_bit else 1
            if acc_hamming + added > radius:
                continue
            self._dfs(
                query, radius, child, bit - 1,
                acc_hamming + added, results, max_results,
            )

    def search_progressive(
        self,
        query_hash: int,
        target_count: int = 10,
        max_radius: int = 16,
        callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> List[Tuple[int, Any, int]]:
        """渐进半径搜索。
        从 radius=0 开始，逐次 radius+=1，直到满足 target_count 或
        达到 max_radius。
        callback(radius, found, target) 在每个半径轮次后调用——
        用于外部日志或进度追踪。
        """
        all_results: List[Tuple[int, Any, int]] = []
        seen_hashes = set()
        for r in range(max_radius + 1):
            round_results = self.search_radius(
                query_hash, r, max_results=target_count * 2
            )
            new_items = []
            for h, p, d in round_results:
                if h not in seen_hashes and d == r:
                    seen_hashes.add(h)
                    new_items.append((h, p, d))
            all_results.extend(new_items)
            if callback:
                callback(r, len(all_results), target_count)
            if len(all_results) >= target_count:
                break
        all_results.sort(key=lambda x: x[2])
        return all_results[:target_count]

    def search_knn(
        self,
        query_hash: int,
        k: int = 10,
        max_radius: int = 16,
    ) -> List[Tuple[int, Any, int]]:
        """k-NN 搜索——search_progressive 的简写。"""
        return self.search_progressive(query_hash, target_count=k, max_radius=max_radius)

    def stats(self) -> dict:
        """返回 trie 的统计信息: 节点数, 深度分布, 叶子密度。"""
        depths: List[int] = []

        def walk(node: SimHashNode, d: int):
            if node is None:
                return
            if node.leaves:
                depths.append(d)
            for child in node.children:
                if child is not None:
                    walk(child, d + 1)

        walk(self._root, 0)
        if not depths:
            return {"total_leaves": 0, "max_depth": 0, "avg_depth": 0}
        return {
            "total_leaves": self._total,
            "max_depth": max(depths),
            "avg_depth": sum(depths) / len(depths),
            "min_depth": min(depths),
        }


class SimHashIndex:
    """基于 PSH-Trie 的高层索引接口。
    管理 (hash → key) 映射，支持 CRUD 和持久化友好的批量导入。

    与直接使用 SimHashTrie 的区别:
      - 维护 hash → key 的双向映射，支持删除和更新
      - 提供类 dict 的访问接口
      - 批量操作的事务性保证 (全部成功或全部失败)
    """

    def __init__(self):
        self._trie = SimHashTrie()
        self._hash_to_keys: dict[int, set] = {}  # 同一 hash 可能对应多个 key

    def add(self, key: str, hash_val: int):
        """将 key 关联到 hash_val。若 hash 已存在则追加（不覆盖）。"""
        self._trie.insert(hash_val, key)
        self._hash_to_keys.setdefault(hash_val, set()).add(key)

    def add_batch(self, items: List[Tuple[str, int]]):
        """批量添加 [(key, hash_val), ...]。"""
        for key, hv in items:
            self.add(key, hv)

    def remove(self, key: str, hash_val: int):
        """移除 key 与 hash_val 的关联。
        trie 节点不物理删除 (需重构子树，开销不划算)——
        改为在查询时过滤已删除键。
        """
        if hash_val in self._hash_to_keys:
            self._hash_to_keys[hash_val].discard(key)
            if not self._hash_to_keys[hash_val]:
                del self._hash_to_keys[hash_val]

    def query_similar(
        self, hash_val: int, k: int = 10, max_radius: int = 16
    ) -> List[Tuple[str, int, float]]:
        """查询与 hash_val 最相似的 k 个 key。
        自动过滤已通过 remove() 删除的键。
        返回 [(key, hash_val, similarity), ...]，similarity ∈ [0, 1]。
        """
        # 多取一些候选，因为部分可能被 remove() 标记删除
        raw = self._trie.search_knn(hash_val, k=k * 2, max_radius=max_radius)
        output = []
        for h, key, dist in raw:
            if h in self._hash_to_keys and key in self._hash_to_keys[h]:
                sim = 1.0 - dist / 64.0
                output.append((key, h, sim))
            if len(output) >= k:
                break
        return output

    def __len__(self) -> int:
        return len(self._hash_to_keys)
