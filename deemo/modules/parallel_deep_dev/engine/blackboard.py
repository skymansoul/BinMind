"""
修改记录:
  2025-07-14 16:52 - query() 增加 token_overlap 阈值过滤，低于阈值的条目不返回
  2025-07-17 09:15 - 增加 _dedup_key，用 SHA-256 防止同一发现被多个 worker 重复存入
  2025-07-21 14:08 - 增加 TTL 懒惰过期：query/deposit 时清理，避免后台线程开销

跨 Worker 知识共享黑板（Blackboard）。
并行 worker 通过黑板交换中间发现：代码模式、API 错误原因、接口约定、设计决策。
每个 worker 在发起 API 调用前查询黑板——若已有相关发现，可跳过调用或调整 prompt。

黑板条目的有效期（TTL）防止过期知识污染新决策。去重基于内容的 SHA-256，
同一发现被多个 worker 存入时仅保留首次。

ref: bMAS/LbMAS — LLM 多智能体系统的
     黑板架构，本项目将其适配到并行代码生成场景而非自然语言推理
ref: D³MAS — 分层协调减少 46% 知识重复，本项目借鉴其
     去重策略并简化为内容哈希比对
ref: flock (github.com/whiteducksoftware/flock) — 事件驱动黑板编排框架，
     本项目借鉴其 typed artifact 设计但改为线程安全的过程式接口
"""

from __future__ import annotations

import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BlackboardEntry:
    """单条黑板记录。source_module 标识来源 worker。"""
    key: str              # 唯一标识（SHA-256 前 16 字符）
    entry_type: str       # 'finding' | 'error' | 'pattern' | 'interface' | 'decision'
    content: str          # 自由文本——worker 写入的发现内容
    source_module: str    # 哪个子模块写入的
    tags: list[str]       # 用于检索的关键词标签
    timestamp: float      # 存入时间 (time.time())
    ttl_seconds: float    # 有效期
    meta: dict            # 附加结构化数据

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return (now - self.timestamp) > self.ttl_seconds


class Blackboard:
    """线程安全的共享知识黑板。典型用法：
        bb = get_blackboard()
        bb.deposit('finding', 'ROP gadget 搜索已优化', source='exploit', tags=['ROP', 'search'])
        results = bb.query('ROP 小配件', entry_type='finding', min_score=0.3)
    """

    def __init__(self, default_ttl: float = 1800.0):
        self._entries: list[BlackboardEntry] = []
        self._lock = threading.Lock()
        self._default_ttl = default_ttl

    # 写入

    def deposit(
        self,
        entry_type: str,
        content: str,
        source_module: str = "",
        tags: list[str] | None = None,
        ttl_seconds: float | None = None,
        meta: dict | None = None,
    ) -> str | None:
        """存入一条发现。返回 entry key；若与已有条目重复则返回 None 并跳过。"""
        dedup_key = self._make_dedup_key(content)
        if ttl_seconds is None:
            ttl_seconds = self._default_ttl

        with self._lock:
            self._expire_stale()
            # 去重
            for e in self._entries:
                if e.key == dedup_key:
                    return None
            entry = BlackboardEntry(
                key=dedup_key,
                entry_type=entry_type,
                content=content,
                source_module=source_module,
                tags=tags or [],
                timestamp=time.time(),
                ttl_seconds=ttl_seconds,
                meta=meta or {},
            )
            self._entries.append(entry)
            return dedup_key

    # 查询

    def query(
        self,
        query_text: str = "",
        entry_type: str | None = None,
        tags: list[str] | None = None,
        source_module: str | None = None,
        min_score: float = 0.15,
        max_results: int = 10,
    ) -> list[BlackboardEntry]:
        """按相关性检索。空 query_text 返回所有（受 max_results 限制）。
        相关性 = token_overlap(query, entry.content + tags)，简单但无外部依赖。"""
        with self._lock:
            self._expire_stale()
            candidates = self._entries

            if entry_type:
                candidates = [e for e in candidates if e.entry_type == entry_type]
            if source_module:
                candidates = [e for e in candidates if e.source_module == source_module]
            if tags:
                tagset = set(tags)
                candidates = [e for e in candidates if tagset & set(e.tags)]

            if not query_text:
                return candidates[-max_results:]

            # Token overlap 评分（TF-IDF 简化版，避免 numpy 依赖）
            query_tokens = set(query_text.lower().split())
            scored: list[tuple[float, BlackboardEntry]] = []
            for e in candidates:
                doc = f"{e.content} {' '.join(e.tags)}".lower()
                doc_tokens = set(doc.split())
                if not query_tokens or not doc_tokens:
                    continue
                overlap = len(query_tokens & doc_tokens)
                # Dice 系数：2|A∩B|/(|A|+|B|)
                score = 2 * overlap / (len(query_tokens) + len(doc_tokens))
                if score >= min_score:
                    scored.append((score, e))

            scored.sort(key=lambda x: x[0], reverse=True)
            return [e for _, e in scored[:max_results]]

    # 统计

    def stats(self) -> dict:
        """返回黑板统计信息。"""
        with self._lock:
            self._expire_stale()
            type_counts: dict[str, int] = {}
            source_counts: dict[str, int] = {}
            for e in self._entries:
                type_counts[e.entry_type] = type_counts.get(e.entry_type, 0) + 1
                source_counts[e.source_module] = source_counts.get(e.source_module, 0) + 1
            return {
                "total_entries": len(self._entries),
                "by_type": type_counts,
                "by_source": source_counts,
            }

    def clear(self) -> None:
        """清空黑板。"""
        with self._lock:
            self._entries.clear()

    # 内部

    def _expire_stale(self) -> None:
        now = time.time()
        self._entries = [e for e in self._entries if not e.is_expired(now)]

    @staticmethod
    def _make_dedup_key(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


# 全局单例 — 跨所有 worker 共享

_blackboard_instance: Blackboard | None = None
_bb_lock = threading.Lock()


def get_blackboard() -> Blackboard:
    """返回全局黑板单例。首次调用时初始化。"""
    global _blackboard_instance
    if _blackboard_instance is None:
        with _bb_lock:
            if _blackboard_instance is None:
                _blackboard_instance = Blackboard()
    return _blackboard_instance
