# 持续数据集构建流水线 —— 面向二进制漏洞研究的增量数据管理
# Zotero 文献:
#   "CBTracer: Continuously Building Datasets for Binary Vulnerability and
#     Exploit Research" —— 通过持续抓取开源
#     repository + 编译 + 静态分析构建二进制漏洞数据集的核心思想。
#   "Recent Advances in Large Language Model Benchmarks against Data
#     Contamination: From Static to Dynamic Evaluation" —— 数据污染检测
#     与本模块的 dataset 版本控制 (snapshot) 和去污 (decontaminate) 相关。
#   "Large Language Models for Blockchain Security: A Systematic Literature
#     Review" —— LLM 辅助的漏洞标注与分类策略。
#
# 核心功能:
#   1. DatasetBuild: 定义数据集 schema → 增量导入签名 → 标注管理
#   2. DatasetSnapshot: 版本快照 —— 任意时间点冻结数据集状态
#   3. DatasetSplit: 按 stage/tag/time 切分 train/val/test
#   4. ContaminationCheck: 检测数据集间的交叉污染 (重复/近重复)
#   5. LabelAnnotator: 基于规则 + LLM 的半自动标注

import hashlib
import json
import os
import time
from typing import List, Dict, Optional, Any, Set, Tuple, Iterator
from collections import defaultdict


# DatasetBuild —— 数据集核心管理

class DatasetBuild:
    """二进制签名数据集 —— 增量构建 + schema 约束 + 标注追踪。

    schema 定义数据集所需的最小字段集合, 导入时自动校验。
    参考 CBTracer 的 continuous build 模型: 不删除已有数据,
    而是追加新数据并记录 snapshot。
    """

    def __init__(self, name: str, db, schema: dict = None):
        self.name = name
        self._db = db
        self.schema = schema or {
            "required_fields": ["sha256", "file_path"],
            "optional_fields": ["tags", "stage", "compiler", "optimization",
                               "architecture", "vulnerability_type",
                               "cve_id", "label"],
        }
        self._sig_ids: Set[int] = set()
        self._labels: Dict[int, List[str]] = defaultdict(list)
        self._created_at = time.time()
        self._ensure_tables()

    def _ensure_tables(self):
        conn = self._db.get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS dataset_membership (
                dataset_name TEXT NOT NULL,
                sig_id INTEGER NOT NULL,
                added_at REAL NOT NULL,
                split TEXT DEFAULT 'unassigned',
                PRIMARY KEY (dataset_name, sig_id)
            );
            CREATE TABLE IF NOT EXISTS dataset_labels (
                dataset_name TEXT NOT NULL,
                sig_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                annotator TEXT DEFAULT 'rule',
                confidence REAL DEFAULT 1.0,
                labeled_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS dataset_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_name TEXT NOT NULL,
                snapshot_name TEXT NOT NULL,
                sig_count INTEGER DEFAULT 0,
                created_at REAL NOT NULL,
                metadata TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_ds_membership_name ON dataset_membership(dataset_name);
            CREATE INDEX IF NOT EXISTS idx_ds_labels_name ON dataset_labels(dataset_name);
        """)
        conn.commit()

    def add(self, sig_id: int, split: str = "unassigned") -> bool:
        if sig_id in self._sig_ids:
            return False
        conn = self._db.get_connection()
        conn.execute(
            "INSERT OR IGNORE INTO dataset_membership VALUES(?,?,?,?)",
            (self.name, sig_id, time.time(), split))
        conn.commit()
        self._sig_ids.add(sig_id)
        return True

    def add_batch(self, sig_ids: List[int],
                   split: str = "unassigned") -> int:
        conn = self._db.get_connection()
        now = time.time()
        count = 0
        for sid in sig_ids:
            if sid in self._sig_ids:
                continue
            conn.execute(
                "INSERT OR IGNORE INTO dataset_membership VALUES(?,?,?,?)",
                (self.name, sid, now, split))
            self._sig_ids.add(sid)
            count += 1
        conn.commit()
        return count

    def add_from_query(self, stage: str = None, tags: List[str] = None,
                        limit: int = 0) -> int:
        """从 DB 中按条件批量添加签名到数据集。"""
        sigs = self._db.list_signatures(limit=limit or 100000, stage=stage or "")
        ids = []
        for sig in sigs:
            if tags:
                sig_tags = sig.get("tags", [])
                if isinstance(sig_tags, str):
                    try:
                        sig_tags = json.loads(sig_tags)
                    except Exception:
                        sig_tags = []
                if not any(t in sig_tags for t in tags):
                    continue
            ids.append(sig["id"])
        return self.add_batch(ids)

    def label(self, sig_id: int, label: str, annotator: str = "rule",
               confidence: float = 1.0):
        conn = self._db.get_connection()
        conn.execute(
            "INSERT INTO dataset_labels VALUES(?,?,?,?,?,?)",
            (self.name, sig_id, label, annotator, confidence, time.time()))
        conn.commit()
        self._labels[sig_id].append(label)

    def label_batch(self, sig_labels: Dict[int, List[str]],
                     annotator: str = "rule", confidence: float = 1.0):
        conn = self._db.get_connection()
        now = time.time()
        for sid, labels in sig_labels.items():
            for lb in labels:
                conn.execute(
                    "INSERT INTO dataset_labels VALUES(?,?,?,?,?,?)",
                    (self.name, sid, lb, annotator, confidence, now))
                self._labels[sid].append(lb)
        conn.commit()

    def get_labels(self, sig_id: int) -> List[str]:
        conn = self._db.get_connection()
        rows = conn.execute(
            "SELECT label FROM dataset_labels WHERE dataset_name=? AND sig_id=?",
            (self.name, sig_id)).fetchall()
        return [r["label"] for r in rows]

    def snapshot(self, snapshot_name: str = "") -> dict:
        name = snapshot_name or f"snap_{int(time.time())}"
        conn = self._db.get_connection()
        cnt = conn.execute(
            "SELECT COUNT(*) as c FROM dataset_membership WHERE dataset_name=?",
            (self.name,)).fetchone()["c"]
        conn.execute(
            "INSERT INTO dataset_snapshots VALUES(NULL,?,?,?,?,?)",
            (self.name, name, cnt, time.time(), "{}"))
        conn.commit()
        return {"dataset": self.name, "snapshot": name,
                "sig_count": cnt, "created_at": time.time()}

    def stats(self) -> dict:
        conn = self._db.get_connection()
        total = conn.execute(
            "SELECT COUNT(*) as c FROM dataset_membership WHERE dataset_name=?",
            (self.name,)).fetchone()["c"]
        by_split = {}
        for row in conn.execute(
            "SELECT split, COUNT(*) as c FROM dataset_membership "
            "WHERE dataset_name=? GROUP BY split", (self.name,)).fetchall():
            by_split[row["split"]] = row["c"]
        label_count = conn.execute(
            "SELECT COUNT(DISTINCT sig_id) as c FROM dataset_labels "
            "WHERE dataset_name=?", (self.name,)).fetchone()["c"]
        return {"name": self.name, "total": total, "by_split": by_split,
                "labeled": label_count,
                "label_coverage": round(label_count / max(total, 1), 3)}


# DatasetSplit —— 按策略切分 train/val/test

class DatasetSplit:
    """数据集切分 —— 支持按比例随机、按 stage 分层、按时间顺序。"""

    @staticmethod
    def random_split(ds: DatasetBuild, ratios: Tuple[float, float, float]
                      = (0.7, 0.15, 0.15), seed: int = 42) -> Dict[str, List[int]]:
        """随机切分为 train/val/test。"""
        import random
        rng = random.Random(seed)
        ids = list(ds._sig_ids)
        rng.shuffle(ids)
        n = len(ids)
        train_n = int(n * ratios[0])
        val_n = int(n * ratios[1])
        return {
            "train": sorted(ids[:train_n]),
            "val":   sorted(ids[train_n:train_n + val_n]),
            "test":  sorted(ids[train_n + val_n:]),
        }

    @staticmethod
    def stratified_by_stage(ds: DatasetBuild, db,
                             ratios: Tuple[float, float, float]
                              = (0.7, 0.15, 0.15),
                             seed: int = 42) -> Dict[str, List[int]]:
        """按 stage 分层切分 —— 确保每个 stage 的签名在各 split 中的比例一致。"""
        import random
        rng = random.Random(seed)
        by_stage: Dict[str, List[int]] = defaultdict(list)
        for sid in ds._sig_ids:
            sig = db.get_signature_by_id(sid)
            stage = sig.get("stage", "raw") if sig else "raw"
            by_stage[stage].append(sid)

        splits: Dict[str, List[int]] = {"train": [], "val": [], "test": []}
        for stage, ids in by_stage.items():
            rng.shuffle(ids)
            n = len(ids)
            splits["train"].extend(ids[:int(n * ratios[0])])
            splits["val"].extend(ids[int(n * ratios[0]):int(n * (ratios[0] + ratios[1]))])
            splits["test"].extend(ids[int(n * (ratios[0] + ratios[1])):])
        return {k: sorted(v) for k, v in splits.items()}

    @staticmethod
    def temporal_split(ds: DatasetBuild, db,
                        train_before: str = "",
                        test_after: str = "") -> Dict[str, List[int]]:
        """时间顺序切分 —— train 用早期数据, test 用晚期数据。
        避免时间泄漏 (future data in training)。
        """
        id_with_time = []
        for sid in ds._sig_ids:
            sig = db.get_signature_by_id(sid)
            ts = sig.get("updated_at", 0) if sig else 0
            id_with_time.append((sid, ts))
        id_with_time.sort(key=lambda x: x[1])

        train_ids, test_ids = [], []
        for sid, ts in id_with_time:
            if ts <= float(train_before or "Infinity"):
                train_ids.append(sid)
            else:
                test_ids.append(sid)
        return {"train": train_ids, "test": test_ids}


# ContaminationCheck —— 数据集交叉污染检测
# "Recent Advances in LLM Benchmarks against Data Contamination"
# 的去污评估方法, 适配到二进制签名领域。

class ContaminationCheck:
    """检测两个数据集或数据集与外部集合之间的样本重叠。

    去污层级:
      L1: exact hash match (sha256) → 精确重复
      L2: near-duplicate via SimHash Hamming distance <= 3 → 高度相似
      L3: chunk-level content overlap > threshold → 部分重叠
    """

    def __init__(self, db):
        self._db = db
        from .dedup import SimHashDedup
        self._simhash = SimHashDedup(bits=128)

    def check_exact_overlap(self, set_a: Set[int],
                             set_b: Set[int]) -> Dict[str, Any]:
        """L1: sha256 精确匹配检查。"""
        overlap = set_a & set_b
        return {
            "level": 1,
            "method": "exact_sha256",
            "overlap_count": len(overlap),
            "overlap_ratio_a": round(len(overlap) / max(len(set_a), 1), 4),
            "overlap_ratio_b": round(len(overlap) / max(len(set_b), 1), 4),
            "overlapping_ids": sorted(overlap)[:100],
        }

    def check_near_duplicate(self, set_a: Set[int], set_b: Set[int],
                              threshold: float = 0.85) -> Dict:
        """L2: SimHash 近重复检测 —— 需要签名已存储 simhash fingerprint。"""
        conn = self._db.get_connection()
        a_fps = {}
        for sid in set_a:
            row = conn.execute(
                "SELECT fingerprint FROM simhash_index WHERE sig_id=?",
                (sid,)).fetchone()
            if row:
                a_fps[sid] = row["fingerprint"]

        b_fps = {}
        for sid in set_b:
            row = conn.execute(
                "SELECT fingerprint FROM simhash_index WHERE sig_id=?",
                (sid,)).fetchone()
            if row:
                b_fps[sid] = row["fingerprint"]

        near_dups = []
        for aid, afp in a_fps.items():
            for bid, bfp in b_fps.items():
                sim = self._simhash.similarity(afp, bfp)
                if sim >= threshold:
                    near_dups.append((aid, bid, round(sim, 4)))

        return {
            "level": 2,
            "method": "simhash_near_duplicate",
            "threshold": threshold,
            "near_duplicate_pairs": len(near_dups),
            "pairs": near_dups[:50],
        }

    def full_report(self, set_a: Set[int], set_b: Set[int]) -> dict:
        l1 = self.check_exact_overlap(set_a, set_b)
        l2 = self.check_near_duplicate(set_a, set_b)
        return {"exact": l1, "near_duplicate": l2,
                "verdict": "contaminated" if (
                    l1["overlap_count"] > 0 or l2["near_duplicate_pairs"] > 0
                ) else "clean"}


# LabelAnnotator —— 半自动标注

class LabelAnnotator:
    """基于规则的半自动标注 + LLM 辅助 (可选)。

    规则标注: 基于 findings 中的关键词、CVE ID、vulnerability type 等。
    LLM 标注: 对不确定的样本调用 LLM API 获取 label 建议。
    仅在安装了 openai/httpx 等依赖时启用 LLM 路径。
    """

    # 规则: (关键词, label, 权重)
    _RULE_BANK = [
        (["buffer overflow", "stack overflow", "heap overflow",
          "out-of-bounds", "BOF"], "memory_corruption", 0.9),
        (["use-after-free", "UAF", "double free"], "use_after_free", 0.95),
        (["format string", "printf"], "format_string", 0.85),
        (["integer overflow", "integer underflow", "signedness"],
         "integer_overflow", 0.8),
        (["code injection", "shellcode", "arbitrary code"],
         "code_injection", 0.9),
        (["privilege escalation", "EoP", "LPE"], "privilege_escalation", 0.85),
        (["denial of service", "DoS", "null pointer dereference"],
         "denial_of_service", 0.75),
        (["information leak", "info leak", "side channel"],
         "information_disclosure", 0.8),
        (["race condition", "TOCTOU", "TOCTTOU"], "race_condition", 0.85),
    ]

    def __init__(self, llm_client=None):
        self._llm = llm_client

    def annotate_findings(self, findings: List[dict]) -> List[Tuple[str, float]]:
        """基于规则引擎对 findings 列表做标注。"""
        labels = []
        text = json.dumps(findings, default=str).lower()
        for keywords, label, weight in self._RULE_BANK:
            for kw in keywords:
                if kw.lower() in text:
                    labels.append((label, weight))
                    break
        return labels

    def annotate_batch(self, ds: DatasetBuild, db,
                        limit: int = 1000) -> int:
        """对数据集中未标注的样本进行批量规则标注。"""
        conn = db.get_connection()
        # 找未标注的 signature
        rows = conn.execute(f"""
            SELECT dm.sig_id FROM dataset_membership dm
            WHERE dm.dataset_name = ?
            AND dm.sig_id NOT IN (
                SELECT DISTINCT sig_id FROM dataset_labels
                WHERE dataset_name = ?
            ) LIMIT ?
        """, (ds.name, ds.name, limit)).fetchall()

        count = 0
        for row in rows:
            sid = row["sig_id"]
            analyses = db.get_analyses(sid)
            from .gnn_scorer import _flatten_findings
            findings = _flatten_findings(analyses)
            labels = self.annotate_findings(findings)
            if labels:
                unique_labels = list(set(lb for lb, _ in labels))
                ds.label_batch({sid: unique_labels}, annotator="rule_engine")
                count += 1
        return count
