"""
创建: 2024-10-11
修改:
  2025-08-03 - 持久化路径统一到 _data_dir()
跨会话知识结晶 — 三层知识模型 (L1事件/L2模式/L3规则)，持久化到磁盘。

与 TiMem/DeltaMem 对话记忆不同，本模块提取代码生成模式并跨会话复用。
L2→L3 晋升条件：>=3 次会话观察且成功率 >80%。
填补 Experience Compression Spectrum 指出的 L1/L2/L3 "缺失对角线"
在代码生成领域的空白。
"""

from __future__ import annotations

import ast
import json
import hashlib
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from ._io import safe_read


# 持久化路径: 统一使用 .parallel_deep_data/ 目录
from ..config import _data_dir
_CRYSTAL_PATH = os.path.join(_data_dir(), "knowledge_crystal.json")


@dataclass
class CrystalEntry:
    """单条结晶知识。"""
    entry_id: str            # SHA-256(content) 前12字符
    level: int               # 1=event, 2=pattern, 3=rule
    category: str            # import_pattern | error_pattern | arch_decision | quality_signal
    content: str             # 人类可读的知识描述
    source_sessions: list[str]  # 观察到该模式的会话ID列表
    observation_count: int   # 被观察到的总次数
    success_count: int       # 关联产出通过质量检查的次数
    first_seen: float        # 首次观察时间戳
    last_seen: float         # 最近观察时间戳
    meta: dict = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.observation_count == 0:
            return 0.0
        return self.success_count / self.observation_count

    @property
    def is_stable(self) -> bool:
        """是否满足 L2→L3 晋升条件。"""
        return (
            self.level >= 2
            and len(self.source_sessions) >= 3
            and self.success_rate > 0.8
        )


class KnowledgeCrystal:
    """跨会话知识结晶存储。线程安全。

    写入路径：
      session.record_pattern() → 存入 L2
      session.finalize() → 扫描 L2，触发 L2→L3 晋升
    读取路径：
      session.load_crystals(level=3) → 获取所有 L3 规则用于 prompt 增强

    持久化：每次 finalize() 后自动写入磁盘 JSON。
    """

    def __init__(self, session_id: str | None = None):
        self.session_id = session_id or f"session_{int(time.time())}"
        self._entries: dict[str, CrystalEntry] = {}
        self._lock = threading.Lock()
        self._dirty = False
        self._load_from_disk()

    # 写入

    def record_observation(
        self, category: str, content: str,
        success: bool = True, meta: dict | None = None,
    ) -> str:
        """记录一次 L2 观察。"""
        entry_id = hashlib.sha256(
            f"{category}:{content}".encode("utf-8")
        ).hexdigest()[:12]

        now = time.time()
        with self._lock:
            if entry_id in self._entries:
                e = self._entries[entry_id]
                e.observation_count += 1
                if success:
                    e.success_count += 1
                e.last_seen = now
                if self.session_id not in e.source_sessions:
                    e.source_sessions.append(self.session_id)
                # 检查晋升条件
                if e.is_stable and e.level == 2:
                    e.level = 3
            else:
                self._entries[entry_id] = CrystalEntry(
                    entry_id=entry_id, level=2, category=category,
                    content=content,
                    source_sessions=[self.session_id],
                    observation_count=1,
                    success_count=1 if success else 0,
                    first_seen=now, last_seen=now,
                    meta=meta or {},
                )
            self._dirty = True
        return entry_id

    def record_rule(self, category: str, content: str, meta: dict | None = None) -> str:
        """直接写入 L3 规则。"""
        entry_id = hashlib.sha256(
            f"rule:{category}:{content}".encode("utf-8")
        ).hexdigest()[:12]
        now = time.time()
        with self._lock:
            self._entries[entry_id] = CrystalEntry(
                entry_id=entry_id, level=3, category=category,
                content=content,
                source_sessions=[self.session_id],
                observation_count=1, success_count=1,
                first_seen=now, last_seen=now,
                meta=meta or {},
            )
            self._dirty = True
        return entry_id

    # 读取

    def query(
        self,
        category: str | None = None,
        min_level: int = 2,
        min_success_rate: float = 0.0,
        max_results: int = 20,
    ) -> list[CrystalEntry]:
        """查询结晶知识。按成功率和观察次数降序排列。"""
        with self._lock:
            candidates = list(self._entries.values())
            if category:
                candidates = [e for e in candidates if e.category == category]
            candidates = [
                e for e in candidates
                if e.level >= min_level and e.success_rate >= min_success_rate
            ]
            candidates.sort(
                key=lambda e: (e.success_rate, e.observation_count), reverse=True,
            )
            return candidates[:max_results]

    def get_prompt_context(self, max_entries: int = 10) -> str:
        """获取 L3 规则用于 prompt 增强。"""
        rules = self.query(min_level=3, min_success_rate=0.7, max_results=max_entries)
        if not rules:
            return ""

        parts = ["\n### 历史会话知识结晶（经验规则）\n"]
        for r in rules:
            parts.append(
                f"- [{r.category}] {r.content} "
                f"(成功率: {r.success_rate:.0%}, 观察: {r.observation_count}次)"
            )
        return "\n".join(parts)

    # 会话生命周期

    def extract_patterns_from_files(
        self, filepaths: list[str], quality_reports: dict | None = None,
    ) -> int:
        """从产出文件提取 L2 模式（高频导入组合等）。返回提取数。"""
        count = 0
        import_freq: dict[str, int] = defaultdict(int)

        for fpath in filepaths:
            if not fpath.endswith(".py") or not os.path.isfile(fpath):
                continue
            source = safe_read(fpath)
            if source is None:
                continue

            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        key = alias.name.split(".")[0]
                        import_freq[key] += 1
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        key = node.module.split(".")[0]
                        import_freq[key] += 1

        # 记录高频导入（>=3次）
        for mod, freq in import_freq.items():
            if freq >= 3:
                self.record_observation(
                    "import_pattern",
                    f"高频导入: {mod} (本会话 {freq} 次)",
                    success=True,
                    meta={"module": mod, "frequency": freq},
                )
                count += 1

        return count

    def finalize(self) -> int:
        """会话结束时的收尾：触发晋升检查并持久化。返回 L3 规则数。"""
        promoted = 0
        with self._lock:
            for e in self._entries.values():
                if e.is_stable and e.level == 2:
                    e.level = 3
                    promoted += 1
            self._dirty = True

        self._save_to_disk()
        return promoted

    # 持久化

    def _save_to_disk(self) -> None:
        with self._lock:
            if not self._dirty:
                return
            payload = {
                "version": 1,
                "updated_at": time.time(),
                "entries": [
                    {
                        "entry_id": e.entry_id, "level": e.level,
                        "category": e.category, "content": e.content,
                        "source_sessions": e.source_sessions,
                        "observation_count": e.observation_count,
                        "success_count": e.success_count,
                        "first_seen": e.first_seen, "last_seen": e.last_seen,
                        "meta": e.meta,
                    }
                    for e in self._entries.values()
                ],
            }
        try:
            os.makedirs(os.path.dirname(_CRYSTAL_PATH), exist_ok=True)
            with open(_CRYSTAL_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def _load_from_disk(self) -> None:
        if not os.path.isfile(_CRYSTAL_PATH):
            return
        try:
            with open(_CRYSTAL_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return

        entries_data = payload.get("entries", [])
        for d in entries_data:
            e = CrystalEntry(
                entry_id=d["entry_id"], level=d["level"],
                category=d["category"], content=d["content"],
                source_sessions=d.get("source_sessions", []),
                observation_count=d.get("observation_count", 0),
                success_count=d.get("success_count", 0),
                first_seen=d.get("first_seen", 0.0),
                last_seen=d.get("last_seen", 0.0),
                meta=d.get("meta", {}),
            )
            self._entries[e.entry_id] = e

    def stats(self) -> dict:
        with self._lock:
            by_level = defaultdict(int)
            for e in self._entries.values():
                by_level[f"L{e.level}"] += 1
            return {"total_entries": len(self._entries),
                    "by_level": dict(by_level),
                    "stable_rules": sum(1 for e in self._entries.values() if e.is_stable)}
