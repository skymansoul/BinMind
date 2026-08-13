# 增量分析缓存: 代码相似度分析结果重用/三级粒度(文件/函数/基本块)
# Meng & Liu "SimFuzz: Conflict-Aware Parallel Fuzzing via Incremental Path Similarity" (ISSRE 2025)
#       Orion "Fuzzing Workflow Automation" ( [待验证], 2025)
#       Khorrami et al. "Binary Diff Summarization using LLMs" ( [待验证])
import hashlib, json, logging, os, struct, time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import OrderedDict
from pathlib import Path
from contextlib import suppress

log = logging.getLogger(__name__)

# 16字节滑动token
_CHUNK = 16
# LSH桶/行配置
_LSH_BANDS = 8
_LSH_ROWS  = 16


@dataclass
class AnalysisArtifact:
    """分析产物: 对应一个分析目标的结果快照."""
    target_id: str
    target_hash: str                 # 原始字节SHA-256
    simhash: int = 0                 # SimHash指纹 [Charikar 2002]
    lsh_key: str = ""                # LSH桶键
    findings: List[Dict] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    analysis_duration_ms: float = 0.0
    cached_from: Optional[str] = None  # 相似继承来源


def _compute_simhash(data: bytes) -> int:
    """SimHash: 64位加权哈希 [Charikar 2002]，快速相似度筛选."""
    v = [0] * 64
    for i in range(0, len(data) - _CHUNK, _CHUNK):
        chunk = data[i:i + _CHUNK]
        h = int(hashlib.md5(chunk).hexdigest()[:16], 16)
        for bit in range(64):
            if h & (1 << bit):
                v[bit] += 1
            else:
                v[bit] -= 1
    result = 0
    for bit in range(64):
        if v[bit] > 0:
            result |= (1 << bit)
    return result


def _hamming_distance(a: int, b: int) -> int:
    xor = a ^ b; d = 0
    while xor:
        d += 1; xor &= xor - 1
    return d


def _lsh_key_from_simhash(sh: int) -> str:
    """64-bit SimHash分BANDS段，每段作为LSH桶键 [Indyk & Motwani 1998]."""
    keys = []
    for band in range(_LSH_BANDS):
        mask = ((1 << _LSH_ROWS) - 1) << (band * _LSH_ROWS)
        val = (sh & mask) >> (band * _LSH_ROWS)
        keys.append(f"{band}:{val:04x}")
    return "|".join(keys)


class IncrementalAnalysisCache:
    # 三级粒度: G1=SHA-256精确 | G2=SimHash邻域(Hamming<8) | G3=LSH桶碰撞
    # 存储: SQLite+WAL+内存LRU. 参考SimFuzz (ISSRE 2025)增量相似度
    def __init__(self, db_path: str = ".binmind_cache/incremental.db",
                 hamming_threshold: int = 8, lru_cap: int = 512):
        import sqlite3
        self._hamming_threshold = hamming_threshold
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS artifacts (
            target_id TEXT PRIMARY KEY, target_hash TEXT, simhash INTEGER,
            lsh_key TEXT, findings TEXT, metrics TEXT,
            timestamp REAL, duration_ms REAL, cached_from TEXT)""")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON artifacts(target_hash)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_simhash ON artifacts(simhash)")
        self._conn.commit()

        self._lru: OrderedDict = OrderedDict()
        self._lru_cap = lru_cap
        # SimHash内存索引→快速邻居搜索
        self._sh_index: Dict[int, List[str]] = {}
        self._build_simhash_index()

    def _build_simhash_index(self):
        rows = self._conn.execute("SELECT simhash, target_id FROM artifacts WHERE simhash != 0").fetchall()
        for sh, tid in rows:
            self._sh_index.setdefault(sh, []).append(tid)

    # G1: 精确SHA-256匹配
    def lookup_exact(self, target_id: str, raw_bytes: bytes) -> Optional[AnalysisArtifact]:
        target_hash = hashlib.sha256(raw_bytes).hexdigest()
        if target_id in self._lru:
            art = self._lru[target_id]
            if art.target_hash == target_hash:
                self._lru.move_to_end(target_id); return art
        row = self._conn.execute(
            "SELECT * FROM artifacts WHERE target_id = ? AND target_hash = ?",
            (target_id, target_hash)).fetchone()
        if row:
            art = self._row_to_artifact(row)
            self._cache_lru(target_id, art); return art
        return None

    # G2: SimHash邻域
    def lookup_similar(self, raw_bytes: bytes) -> List[Tuple[AnalysisArtifact, int]]:
        """Hamming distance <= threshold候选，按距离排序."""
        sh = _compute_simhash(raw_bytes)
        candidates: List[Tuple[AnalysisArtifact, int]] = []

        for index_sh, tids in self._sh_index.items():
            d = _hamming_distance(sh, index_sh)
            if d <= self._hamming_threshold:
                for tid in tids:
                    if (art := self._resolve_artifact(tid)):
                        candidates.append((art, d))
        candidates.sort(key=lambda x: x[1])
        return candidates[:20]

    # G3: LSH桶碰撞
    def lookup_lsh(self, raw_bytes: bytes) -> List[AnalysisArtifact]:
        sh = _compute_simhash(raw_bytes)
        keys = _lsh_key_from_simhash(sh).split("|")
        matched: Dict[str, int] = {}  # target_id→碰撞计数
        for k in keys:
            rows = self._conn.execute(
                "SELECT target_id FROM artifacts WHERE lsh_key LIKE ?", (f"%{k}%",)).fetchall()
            for (tid,) in rows:
                matched[tid] = matched.get(tid, 0) + 1
        # 碰撞≥2的候选 (降低误报)
        result = []
        for tid, cnt in sorted(matched.items(), key=lambda x: x[1], reverse=True):
            if cnt >= 2 and (art := self._resolve_artifact(tid)):
                result.append(art)
        return result[:20]

    def store(self, art: AnalysisArtifact):
        art.simhash = art.simhash or _compute_simhash(b"")  # 未计算则补齐
        art.lsh_key = art.lsh_key or _lsh_key_from_simhash(art.simhash)
        findings_json = json.dumps(art.findings, ensure_ascii=False)
        metrics_json = json.dumps(art.metrics)
        self._conn.execute(
            "INSERT OR REPLACE INTO artifacts VALUES (?,?,?,?,?,?,?,?,?)",
            (art.target_id, art.target_hash, art.simhash, art.lsh_key,
             findings_json, metrics_json, art.timestamp, art.analysis_duration_ms,
             art.cached_from))
        self._conn.commit()
        self._sh_index.setdefault(art.simhash, []).append(art.target_id)
        self._cache_lru(art.target_id, art)

    def invalidate(self, target_id: str):
        self._conn.execute("DELETE FROM artifacts WHERE target_id = ?", (target_id,))
        self._conn.commit()
        self._lru.pop(target_id, None)

    def stats(self) -> Dict:
        total = self._conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        reused = self._conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE cached_from IS NOT NULL").fetchone()[0]
        return {'total_cached': total, 'reused_from_similar': reused,
                'lru_size': len(self._lru)}

    def _cache_lru(self, tid: str, art: AnalysisArtifact):
        if tid in self._lru:
            del self._lru[tid]
        elif len(self._lru) >= self._lru_cap:
            self._lru.popitem(last=False)
        self._lru[tid] = art

    def _resolve_artifact(self, tid: str) -> Optional[AnalysisArtifact]:
        if tid in self._lru:
            return self._lru[tid]
        row = self._conn.execute("SELECT * FROM artifacts WHERE target_id = ?", (tid,)).fetchone()
        if row:
            art = self._row_to_artifact(row)
            self._cache_lru(tid, art); return art
        return None

    @staticmethod
    def _row_to_artifact(row) -> AnalysisArtifact:
        return AnalysisArtifact(
            target_id=row[0], target_hash=row[1], simhash=row[2], lsh_key=row[3],
            findings=json.loads(row[4]) if row[4] else [],
            metrics=json.loads(row[5]) if row[5] else {},
            timestamp=row[6], analysis_duration_ms=row[7], cached_from=row[8]
        )

    def close(self):
        if self._conn:
            self._conn.close()


# 增量分析调度器

class IncrementalAnalysisScheduler:
    """增量分析: 检测变更→复用缓存→仅重分析变更目标.
    与ScanOrchestrator集成，参考Orion反馈驱动增量循环.
    """

    def __init__(self, cache: IncrementalAnalysisCache = None):
        self.cache = cache or IncrementalAnalysisCache()
        self._change_log: List[Dict] = []  # 每次调度变更记录

    def partition_targets(self, targets: Dict[str, bytes]) -> Tuple[
            List[str], List[str], Dict[str, AnalysisArtifact]]:
        """目标分三类: 未变更(复用)/相似(候选复用)/新目标(重分析).

        Returns:
            unchanged: 精确匹配可跳过
            changed: 需重分析
            similar_matches: {target_id: best_candidate_artifact}
        """
        unchanged = []
        changed = []
        similar_matches: Dict[str, AnalysisArtifact] = {}

        for tid, raw in targets.items():
            if (art := self.cache.lookup_exact(tid, raw)):
                unchanged.append(tid)
                continue

            candidates = self.cache.lookup_similar(raw)
            if candidates:
                best, distance = candidates[0]
                similar_matches[tid] = best
                changed.append(tid)
                log.debug("近似匹配: %s -> %s (Hamming=%d)", tid, best.target_id, distance)
            else:
                changed.append(tid)

        self._change_log.append({
            'timestamp': time.time(), 'total': len(targets),
            'unchanged': len(unchanged), 'changed': len(changed) - len(similar_matches),
            'similar_candidates': len(similar_matches)
        })
        return unchanged, changed, similar_matches

    def get_change_stats(self) -> List[Dict]:
        return self._change_log[-20:]


# 全局实例
_cache_instance: IncrementalAnalysisCache = None

def get_incremental_cache() -> IncrementalAnalysisCache:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = IncrementalAnalysisCache()
    return _cache_instance
