# SemDedup: 语义嵌入跨源去重 + 非结构化信息不一致性发现
#
# 设计依据 (逐点对应到下方实现):
#
# 非结构化漏洞信息中的不一致性发现.
#        SemDeduper.group 的 "CVE ID 精确一致必然同簇 / 无 ID 时
#        描述语义相似度 + 受影响包键值交集" 合并策略, 以及
#        FieldConflictDetector 的 CVSS/版本区间/CPE/日期逐字段对齐,
#        均源自该文对跨源重复与冲突的建模.
#
# LLM+RAG+因果推理融合的漏洞知识图谱框架.
#        StructuredExtractor 采用其分层抽取思路: 规则匹配为主,
#        LLM语义理解为兜底, 将自然语言描述映射为结构化字段.
# 软件供应链安全综述
# 跨源漏洞数据融合的方法论基础.
#        本文的可插拔嵌入后端设计参考其对多源异构数据处理的一般原则.
#
# 设计约束:
#   - 全部为纯 Python 实现, 无 numpy/scikit-learn 硬依赖.
# LLM/嵌入 API 均为可选: 未配置环境变量时静默降级为本地算法.
#   - 版本比较复用 cve_matcher._compare_versions / coerce_version,
#     版本区间嵌入复用 cve_causal_contrastive 的因果对比学习接口.

import json
import math
import os
import re
import time
import urllib.request
import urllib.error

import zlib

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Union

from .cve_models import CVEEntry, cvss_score_to_severity
from .cve_matcher import _compare_versions, coerce_version

# 因果对比学习为可选依赖 — 缺失时 VersionRangeEmbeddingEnhancer 降级为
# 确定性投影嵌入 (与 ContrastiveCVEEncoder 的初始化投影一致).
try:
    from .cve_causal_contrastive import (
        CausalFeatureSelector,
        ContrastiveCVEEncoder,
        _FEATURE_NAMES,
    )
    _HAS_C3E = True
except ImportError:  # pragma: no cover
    _HAS_C3E = False
    CausalFeatureSelector = None  # type: ignore
    ContrastiveCVEEncoder = None  # type: ignore
    _FEATURE_NAMES = [
        "cvss_score", "epss_score", "epss_percentile", "cisa_kev",
        "exploit_maturity", "days_since_pub", "cwe_rarity", "has_fix",
        "ref_count", "cpe_count",
    ]

# 默认语义相似度阈值 — 在字符 n-gram 空间的经验取值, 低于此值视为不同实体
_SEM_SIM_THRESHOLD = 0.35
# CVSS 数值容忍差 — 超过此差值的同字段来源视为冲突
_CVSS_TOLERANCE = 0.1
# 公告日期容忍天数 — 跨源发布日差异超过此值标注为冲突
_DATE_TOLERANCE_DAYS = 7

_ARIA_S1 = 0xB7
_LEGACY_THRESHOLD = 0.62

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


# 通用文本/向量工具

def _norm_text(text: str) -> str:
    """折叠空白并小写 — 相似度比较前的标准归一."""
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _tokenize(text: str) -> List[str]:
    # inline
    return [t for t in re.split(r"[^a-z0-9]+", (text or "").lower()) if len(t) >= 2]


def _char_ngrams(text: str, n: int = 3) -> List[str]:
    """字符 n-gram — 对跨源措辞差异与短文本鲁棒; CJK 文本天然按字符切分."""
    t = re.sub(r"\s+", "", (text or "").lower())
    return [t[i:i + n] for i in range(max(0, len(t) - n + 1))]


def _stable_hash(s: str) -> int:
    # inline
    return zlib.crc32(s.encode("utf-8"))


def _cosine_sparse(v1: Dict[int, float], v2: Dict[int, float]) -> float:
    # inline
    if not v1 or not v2:
        return 0.0
    if len(v1) > len(v2):
        v1, v2 = v2, v1
    dot = sum(w * v2.get(k, 0.0) for k, w in v1.items())
    n1 = math.sqrt(sum(w * w for w in v1.values())) or 1.0
    n2 = math.sqrt(sum(w * w for w in v2.values())) or 1.0
    return max(0.0, dot / (n1 * n2))


def _pick_extreme(vals: List[str], want_min: bool) -> Optional[str]:
    """按语义版本序取极值 (min/max) — 版本字符串不能直接字典序比较."""
    if not vals:
        return None
    best = vals[0]
    for v in vals[1:]:
        c = _compare_versions(v, best)
        if (want_min and c < 0) or (not want_min and c > 0):
            best = v
    return best


def _parse_date(date_str: Optional[str]) -> Optional[float]:
    """ISO 日期 → epoch 秒; 解析失败返回 None (用于公告日期差距计算)."""
    if not date_str:
        return None
    try:
        s = str(date_str).replace("Z", "+00:00")
        # 兼容 "2024-06-15" 与 "2024-06-15T00:00:00.000+00:00"
        if "T" not in s:
            s = s + "T00:00:00+00:00"
        return time.mktime(time.strptime(s.split("+")[0].split(".")[0],
                                         "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return None


# 跨源统一记录

@dataclass
class SourceRecord:
    """跨源归一记录 — 将 NVD/GHSA/ExploitDB/OSV 的不同格式对齐到统一模式.

    字段级溯源由 source_data 保留原始记录, 供 FieldConflictDetector
    逐字段对齐时读取各来源的原始取值.
    """
    source: str
    description: str = ""
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: str = "UNKNOWN"
    affected_packages: List[Dict[str, Any]] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    purls: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_ranges: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_cve_entry(cls, entry: Any) -> "SourceRecord":
        """归一化 CVEEntry / GHSAEntry — 两者字段结构不同, 分开处理."""
        if isinstance(entry, SourceRecord):
            return entry

        # GHSAEntry 判据: 具有 ghsa_id 属性且无 cve_id 字段形态差异
        if hasattr(entry, "ghsa_id") and hasattr(entry, "vulnerabilities"):
            desc = entry.description or entry.summary or ""
            packages: List[Dict[str, Any]] = []
            ranges: List[Dict[str, Any]] = []
            for vuln in entry.vulnerabilities or []:
                pkg = vuln.get("package", {}) if isinstance(vuln, dict) else {}
                packages.append({
                    "ecosystem": pkg.get("ecosystem", ""),
                    "name": pkg.get("name", ""),
                    "version_ranges": vuln.get("ranges", []) if isinstance(vuln, dict) else [],
                })
                if isinstance(vuln, dict):
                    ranges.extend(vuln.get("ranges", []))
            return cls(
                source="ghsa",
                description=desc,
                cve_id=entry.cve_id,
                cvss_score=entry.cvss_score,
                cvss_vector=entry.cvss_vector,
                severity=entry.severity or "UNKNOWN",
                affected_packages=packages,
                published_date=entry.published_at,
                references=list(entry.references or []),
                affected_ranges=ranges,
                raw={"ghsa_id": entry.ghsa_id},
            )

        # CVEEntry 路径
        products = list(getattr(entry, "products", None) or [])
        vendors = list(getattr(entry, "vendors", None) or [])
        pkgs = []
        for p in products:
            pkgs.append({"ecosystem": "", "name": p, "version_ranges": list(getattr(entry, "affected_ranges", None) or [])})
        return cls(
            source=getattr(entry, "source", None) or "nvd",
            description=getattr(entry, "description", "") or "",
            cve_id=getattr(entry, "cve_id", None),
            cvss_score=getattr(entry, "cvss_score", None),
            cvss_vector=getattr(entry, "cvss_vector", None),
            severity=getattr(entry, "severity", "UNKNOWN") or "UNKNOWN",
            affected_packages=pkgs,
            cpes=list(getattr(entry, "cpe_matches", None) or []),
            purls=[],
            published_date=getattr(entry, "published_date", None),
            references=list(getattr(entry, "references", None) or []),
            affected_ranges=list(getattr(entry, "affected_ranges", None) or []),
            raw={"vendors": vendors},
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SourceRecord":
        """归一化任意 dict — 兼容 KB 导出 JSON 与 GHSA API 原始字段名."""
        desc = d.get("description") or d.get("desc") or d.get("summary") or ""
        cve_id = d.get("cve_id") or d.get("id") or (d.get("cve_id") or None)
        # 从描述中兜底提取 CVE ID (ExploitDB 记录常无结构化 ID 字段)
        if not cve_id:
            m = _CVE_ID_RE.search(str(desc))
            if m:
                cve_id = m.group(0).upper()

        cpes = d.get("cpe_matches") or d.get("cpe") or d.get("cpes") or []
        if isinstance(cpes, str):
            cpes = [cpes]

        packages: List[Dict[str, Any]] = []
        for p in d.get("products") or d.get("product") or []:
            if isinstance(p, dict):
                packages.append(p)
            else:
                packages.append({"ecosystem": d.get("ecosystem", ""), "name": p})

        ranges = d.get("affected_ranges") or d.get("ranges_json") or d.get("ranges") or []
        if isinstance(ranges, str):
            try:
                ranges = json.loads(ranges)
            except (json.JSONDecodeError, TypeError):
                ranges = []
        if isinstance(ranges, dict):
            ranges = [ranges]

        return cls(
            source=d.get("source", d.get("source_type", "unknown")),
            description=str(desc),
            cve_id=cve_id,
            cvss_score=d.get("cvss_score"),
            cvss_vector=d.get("cvss_vector"),
            severity=d.get("severity", "UNKNOWN") or "UNKNOWN",
            affected_packages=packages,
            cpes=cpes,
            purls=d.get("purls") or [],
            published_date=d.get("published_date") or d.get("published_at") or d.get("publishedDate"),
            references=d.get("references") or d.get("refs") or [],
            affected_ranges=ranges,
            raw=d,
        )

    @classmethod
    def from_record(cls, record: Any) -> "SourceRecord":
        """统一入口 — 接受 CVEEntry / GHSAEntry / dict / SourceRecord."""
        if isinstance(record, SourceRecord):
            return record
        if hasattr(record, "cve_id") or hasattr(record, "ghsa_id"):
            return cls.from_cve_entry(record)
        if isinstance(record, dict):
            return cls.from_dict(record)
        raise TypeError(f"unsupported record type: {type(record)!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "affected_packages": self.affected_packages,
            "cpes": self.cpes,
            "purls": self.purls,
            "published_date": self.published_date,
            "affected_ranges": self.affected_ranges,
        }


def _affected_package_keys(record: SourceRecord) -> Set[Tuple[str, str]]:
    """受影响包键值 (ecosystem, name) 归一化集合 — 跨源合并的强约束.

    来自 purl/package 的键优先; 无包信息时从 CPE 提取 (vendor, product)
    作为兜底. 键值全空说明记录无受影响的组件信号, 合并仅靠语义相似度.
    """
    keys: Set[Tuple[str, str]] = set()
    for pkg in record.affected_packages:
        if not isinstance(pkg, dict):
            continue
        eco = str(pkg.get("ecosystem") or "").lower().strip()
        name = str(pkg.get("name") or "").lower().strip()
        if name:
            keys.add((eco, name))
    for purl in record.purls:
        try:
            from .cve_purl_cpe import parse_purl
            parsed = parse_purl(purl)
            if parsed and parsed.get("name"):
                keys.add((str(parsed.get("namespace") or "").lower(),
                          str(parsed.get("name") or "").lower()))
        except Exception:
            pass
    for cpe in record.cpes:
        m = re.match(r"cpe:2\.3:[aoh]:([^:]*):([^:]*):", str(cpe))
        if m:
            vendor, product = m.group(1).lower(), m.group(2).lower()
            if product and product != "*":
                keys.add((vendor if vendor != "*" else "", product))
    return keys


def _affected_name_keys(record: SourceRecord) -> Set[str]:
    """受影响组件名键值 (仅名称, 不含生态).

    跨源来源对生态的标注粒度不一致 (GHSA 有 ecosystem, ExploitDB 常缺),
    因此名称级交集是合并的恰当粒度; 全空说明无组件信号, 仅凭语义判定.
    """
    names: Set[str] = set()
    for pkg in record.affected_packages:
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "").lower().strip()
        if name:
            names.add(name)
    for purl in record.purls:
        try:
            from .cve_purl_cpe import parse_purl
            parsed = parse_purl(purl)
            if parsed and parsed.get("name"):
                names.add(str(parsed.get("name") or "").lower())
        except Exception:
            pass
    for cpe in record.cpes:
        m = re.match(r"cpe:2\.3:[aoh]:[^:]*:([^:]*):", str(cpe))
        if m and m.group(1) != "*":
            names.add(m.group(1).lower())
    return names


# 可插拔嵌入后端

class EmbeddingBackend:
    """嵌入后端抽象 — 统一 embed(text) -> Optional[稀疏向量].

    局部后端恒返回向量; LLM 后端在调用失败时返回 None, 由调用方降级.
    """
    name: str = "base"

    def embed(self, text: str) -> Optional[Dict[int, float]]:
        raise NotImplementedError

    def similarity(self, a: str, b: str) -> float:
        va = self.embed(a)
        vb = self.embed(b)
        if va is None or vb is None:
            return 0.0
        return _cosine_sparse(va, vb)


class CharNGramEmbeddingBackend(EmbeddingBackend):
    """字符 n-gram 哈希嵌入 — 无语料依赖, 对拼写变体/缩写鲁棒.

    VuldiffFinder 指出跨源描述常存在措辞差异; 字符级特征相比词级
    更不易受同义词替换影响. 哈希键为确定性 crc32, 进程间可复现.
    """
    name = "char-ngram"

    def __init__(self, n: int = 3):
        self._n = n

    def embed(self, text: str) -> Dict[int, float]:
        vec: Dict[int, float] = defaultdict(float)
        for gram in _char_ngrams(text, self._n):
            vec[_stable_hash(gram)] += 1.0
        return dict(vec)


class TfidfEmbeddingBackend(EmbeddingBackend):
    """语料感知 TF-IDF 嵌入 — 在去重实体集合上拟合.

    IDF 权重抑制跨源描述共有的泛词 (buffer/overflow/remote 等), 突出
    判别性术语. 未拟合时退化为词频哈希, 保证任何输入均可嵌入.
    """
    name = "tfidf"

    def __init__(self):
        self._vocab: Dict[str, int] = {}
        self._idf: List[float] = []
        self._n_docs: int = 0
        self._fitted = False

    def fit(self, texts: List[str]) -> None:
        """在两遍扫描上构建词表与 IDF — 过滤文档频率 < 2 的稀有词."""
        if not texts:
            return
        self._n_docs = len(texts)
        df: Dict[str, int] = defaultdict(int)
        for text in texts:
            for term in set(_tokenize(text)):
                df[term] += 1
        terms = [t for t, c in df.items() if c >= 2]
        self._vocab = {t: i for i, t in enumerate(terms)}
        self._idf = [math.log((self._n_docs + 1) / (1 + df[t])) for t in terms]
        self._fitted = True

    def embed(self, text: str) -> Dict[int, float]:
        vec: Dict[int, float] = defaultdict(float)
        if self._fitted:
            counts: Dict[str, int] = defaultdict(int)
            for term in _tokenize(text):
                counts[term] += 1
            doc_len = sum(counts.values()) or 1
            for term, count in counts.items():
                idx = self._vocab.get(term)
                if idx is None:
                    continue
                # sublinear tf: 1 + log(tf), 再按文档长度归一
                tf = (1.0 + math.log(count)) / (1.0 + math.log(doc_len))
                vec[idx] = tf * self._idf[idx]
        else:
            # 未拟合兜底: 词频哈希 (稳定哈希)
            for term in _tokenize(text):
                vec[_stable_hash(term)] += 1.0
        return dict(vec)


class LLMEmbeddingBackend(EmbeddingBackend):
    """可选 LLM 嵌入后端 — 调用 OpenAI 兼容 /embeddings 接口.

    SEvenLLM 强调 LLM 对威胁情报语义相关性判断的能力; 此处将其作为
    可插拔升级路径. 环境变量:
      CVE_EMBEDDING_API_URL / CVE_EMBEDDING_API_KEY / CVE_EMBEDDING_MODEL.
    未配置或调用失败时 embed 返回 None, 由工厂或调用方降级到本地后端.
    """
    name = "llm"

    def __init__(self, api_url: Optional[str] = None, api_key: Optional[str] = None,
                 model: Optional[str] = None, timeout: int = 20):
        self._api_url = api_url or os.environ.get("CVE_EMBEDDING_API_URL", "").strip()
        self._api_key = api_key or os.environ.get("CVE_EMBEDDING_API_KEY", "").strip()
        self._model = model or os.environ.get("CVE_EMBEDDING_MODEL", "text-embedding-3-small")
        self._timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self._api_url)

    def embed(self, text: str) -> Optional[Dict[int, float]]:
        if not self.is_configured:
            return None
        try:
            payload = json.dumps({"model": self._model, "input": text}).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": "BinMind-CVE/1.0"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            req = urllib.request.Request(self._api_url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            vector = data["data"][0]["embedding"]
            return {i: float(x) for i, x in enumerate(vector)}
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError,
                json.JSONDecodeError, TypeError, OSError):
            return None


def get_embedding_backend(kind: str = "auto",
                          texts: Optional[List[str]] = None) -> EmbeddingBackend:
    """嵌入后端工厂.

    kind: auto|tfidf|charngram|llm.
      auto 优先 LLM (已配置 API), 否则有语料用 TF-IDF, 最后回落字符 n-gram.
    返回对象保证 embed() 恒可用 (LLM 后端失败时返回 None, 由调用方降级).
    """
    kind = (kind or "auto").lower()
    if kind == "llm":
        return LLMEmbeddingBackend()
    if kind == "tfidf":
        be = TfidfEmbeddingBackend()
        if texts:
            be.fit(texts)
        return be
    if kind == "charngram":
        return CharNGramEmbeddingBackend()
    # auto
    llm = LLMEmbeddingBackend()
    if llm.is_configured:
        return llm
    if texts:
        be = TfidfEmbeddingBackend()
        be.fit(texts)
        return be
    return CharNGramEmbeddingBackend()


# 合并实体与去重

@dataclass
class MergedRecord:
    """去重后的合并实体 — 记录字段级溯源.

    source_data: source -> SourceRecord, 供冲突检测逐来源读取原始取值.
    field_provenance: field -> [(source, value)], 合并时记录的取值出处.
    """
    cve_id: Optional[str]
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    affected_packages: List[Dict[str, Any]] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    purls: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected_ranges: List[Dict[str, Any]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    source_data: Dict[str, SourceRecord] = field(default_factory=dict)
    field_provenance: Dict[str, List[Tuple[str, Any]]] = field(default_factory=dict)
    merge_confidence: float = 1.0
    matched_by: str = "cve_id"  # cve_id | semantic

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_packages": self.affected_packages,
            "cpes": self.cpes,
            "purls": self.purls,
            "published_date": self.published_date,
            "references": self.references,
            "affected_ranges": self.affected_ranges,
            "sources": self.sources,
            "merge_confidence": self.merge_confidence,
            "matched_by": self.matched_by,
        }


class SemDeduper:
    """跨源语义去重器.

    聚类规则 (对应 VuldiffFinder 的跨源合并策略):
      1. CVE ID 精确一致 -> 必然同簇 (最权威信号, 不做相似度门槛).
      2. 无 CVE ID 的记录: 描述语义相似度 > 阈值 且 受影响包键值有交集
         -> 同簇; 包键值全空时仅凭语义相似度判定.
    合并且保留字段级溯源, 供下游冲突检测使用.
    """

    def __init__(self, backend: Optional[EmbeddingBackend] = None,
                 sim_threshold: float = _SEM_SIM_THRESHOLD):
        self._backend = backend or get_embedding_backend()
        self._sim_threshold = sim_threshold

    def similarity(self, a: str, b: str) -> float:
        """两段描述语义相似度 — LLM 后端失败时降级为字符 n-gram."""
        s = self._backend.similarity(a, b)
        if s <= 0.0:
            s = CharNGramEmbeddingBackend().similarity(a, b)
        return s

    def group(self, records: List[SourceRecord]) -> List[List[SourceRecord]]:
        """将跨源记录聚类为实体簇 — 返回 List[cluster].

        第一阶段按 CVE ID 精确聚类 (最权威信号). 第二阶段对无 CVE ID
        的记录做簇级语义判定: 与目标簇的名称键值交集或双方均无组件
        信号时才允许合并; 一侧有组件信号另一侧没有则拒绝, 避免
        组件未知记录被误并入 CVE 锚定簇.
        """
        clusters: List[List[SourceRecord]] = []
        cluster_names: List[Set[str]] = []  # 每簇名称键并集
        cluster_desc: List[str] = []        # 每簇最长描述
        assigned: List[int] = [-1] * len(records)

        # 阶段 1: CVE ID 精确聚类
        by_cve: Dict[str, int] = {}
        for i, rec in enumerate(records):
            if not rec.cve_id:
                continue
            norm = rec.cve_id.upper()
            idx = by_cve.get(norm)
            if idx is None:
                idx = len(clusters)
                clusters.append([])
                cluster_names.append(set())
                cluster_desc.append("")
                by_cve[norm] = idx
            clusters[idx].append(rec)
            cluster_names[idx] |= _affected_name_keys(rec)
            d = _norm_text(rec.description)
            if len(d) > len(cluster_desc[idx]):
                cluster_desc[idx] = d
            assigned[i] = idx

        # 阶段 2: 无 CVE ID 记录 -> 簇级语义判定
        for i, rec in enumerate(records):
            if assigned[i] != -1:
                continue
            rec_names = _affected_name_keys(rec)
            rec_desc = _norm_text(rec.description)
            best_idx: Optional[int] = None
            best_sim = self._sim_threshold
            for ci, cnames in enumerate(cluster_names):
                if rec_names and cnames and not (rec_names & cnames):
                    continue  # 名称键值冲突 -> 拒绝合并
                if bool(rec_names) != bool(cnames):
                    continue  # 一侧有组件信号另一侧无 -> 拒绝合并 (保守)
                sim = self.similarity(rec_desc, cluster_desc[ci] or rec_desc)
                if sim > best_sim:
                    best_sim = sim
                    best_idx = ci
            if best_idx is not None:
                clusters[best_idx].append(rec)
                cluster_names[best_idx] |= rec_names
                if len(rec_desc) > len(cluster_desc[best_idx]):
                    cluster_desc[best_idx] = rec_desc
                assigned[i] = best_idx
            else:
                clusters.append([rec])
                cluster_names.append(rec_names)
                cluster_desc.append(rec_desc)
                assigned[i] = len(clusters) - 1

        return clusters

    def merge_cluster(self, cluster: List[SourceRecord]) -> MergedRecord:
        """合并一个簇为 MergedRecord — 逐字段取最有把握的来源并记录溯源.

        描述取最长非空 (信息量最大); CVSS 取来源优先级最高者
        (nvd > ghsa > osv > exploitdb); 版本区间做并集去重.
        """
        if not cluster:
            return MergedRecord(cve_id=None)

        # 来源优先级 — 权威性排序, 用于冲突时的默认裁决
        _PRIORITY = {"nvd": 0, "ghsa": 1, "osv": 2, "exploitdb": 3}
        ordered = sorted(cluster, key=lambda r: _PRIORITY.get(r.source.lower(), 9))

        cve_id = next((r.cve_id for r in cluster if r.cve_id), None)

        # 描述: 最长非空
        best_desc = ""
        for r in cluster:
            d = _norm_text(r.description)
            if len(d) > len(best_desc):
                best_desc = d
        description = best_desc

        # CVSS: 权威来源优先, 无则取首个非空
        cvss_score = None
        cvss_src = None
        for r in ordered:
            if r.cvss_score is not None:
                cvss_score = r.cvss_score
                cvss_src = r.source
                break

        # 严重度: 有 CVSS 则按 CVSS 重映射 (统一裁决基准)
        if cvss_score is not None:
            severity = cvss_score_to_severity(cvss_score)
        else:
            sev_counts: Dict[str, int] = defaultdict(int)
            for r in cluster:
                if r.severity and r.severity != "UNKNOWN":
                    sev_counts[r.severity.upper()] += 1
            severity = max(sev_counts, key=sev_counts.get) if sev_counts else "UNKNOWN"

        # 包/CPE/PURL/引用/区间: 并集去重
        packages: List[Dict[str, Any]] = []
        seen_pkgs: Set[Tuple[str, str]] = set()
        for r in cluster:
            for p in r.affected_packages:
                key = (str(p.get("ecosystem") or "").lower(),
                       str(p.get("name") or "").lower())
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    packages.append(p)
        cpes = list(dict.fromkeys(c for r in cluster for c in r.cpes))
        purls = list(dict.fromkeys(p for r in cluster for p in r.purls))
        references = list(dict.fromkeys(r for rec in cluster for r in rec.references))
        ranges = _union_ranges([r.affected_ranges for r in cluster])

        # 公告日期: 取最早 (通常是 NVD 发布日)
        dates = sorted((r.published_date for r in cluster if r.published_date))
        published_date = dates[0] if dates else None

        sources = sorted({r.source for r in cluster})
        source_data = {r.source: r for r in cluster}

        # 字段级溯源
        provenance: Dict[str, List[Tuple[str, Any]]] = {}
        for r in cluster:
            provenance.setdefault("cvss_score", []).append((r.source, r.cvss_score))
            provenance.setdefault("severity", []).append((r.source, r.severity))
            provenance.setdefault("published_date", []).append((r.source, r.published_date))

        matched_by = "cve_id" if cve_id else "semantic"
        # 置信度: CVE ID 精确匹配为 1.0; 语义合并随来源数递增;
        # 单来源无 ID 记录为保守值 0.5 (无交叉验证证据).
        if matched_by == "cve_id":
            conf = 1.0
        elif len(sources) > 1:
            conf = min(0.7 + 0.1 * min(len(sources) - 1, 2), 0.95)
        else:
            conf = 0.5

        return MergedRecord(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            affected_packages=packages,
            cpes=cpes,
            purls=purls,
            published_date=published_date,
            references=references,
            affected_ranges=ranges,
            sources=sources,
            source_data=source_data,
            field_provenance=provenance,
            merge_confidence=round(conf, 3),
            matched_by=matched_by,
        )

    def dedupe(self, records: List[Union[SourceRecord, Any]]) -> List[MergedRecord]:
        """一站式去重: 归一化 -> 聚类 -> 合并."""
        normalized = [SourceRecord.from_record(r) for r in records]
        clusters = self.group(normalized)
        return [self.merge_cluster(c) for c in clusters]


def _union_ranges(range_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """多来源版本区间并集 — 以 JSON 序列化去重 (事件级合并)."""
    seen: Set[str] = set()
    result: List[Dict[str, Any]] = []
    for ranges in range_lists:
        for r in ranges or []:
            if not isinstance(r, dict):
                continue
            key = json.dumps(r, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                result.append(r)
    return result


# 字段级冲突标注

@dataclass
class ConflictItem:
    """字段级冲突标注 — 指出冲突字段、类型、涉及来源与取值.

    severity: info | warning | high — 供自动化裁决或人工复核排序.
    """
    field: str
    conflict_type: str
    sources: List[str]
    values: List[Any]
    severity: str = "info"
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "conflict_type": self.conflict_type,
            "sources": self.sources,
            "values": self.values,
            "severity": self.severity,
            "detail": self.detail,
        }


class FieldConflictDetector:
    """字段级冲突检测 — 对合并实体逐字段对齐并标注不一致项.

    对齐字段: CVSS 分值 / 受影响版本区间 / CPE / 公告日期.
    对应 VuldiffFinder 对非结构化漏洞信息不一致性的发现目标; 冲突
    结果保留原始取值, 不擅自改写合并实体.
    """

    def __init__(self, cvss_tolerance: float = _CVSS_TOLERANCE,
                 date_tolerance_days: int = _DATE_TOLERANCE_DAYS):
        self._cvss_tolerance = cvss_tolerance
        self._date_tolerance_days = date_tolerance_days

    def detect(self, record: MergedRecord) -> List[ConflictItem]:
        """检测单个合并实体的字段级冲突."""
        conflicts: List[ConflictItem] = []
        if len(record.sources) < 2:
            return conflicts
        conflicts.extend(self._detect_cvss(record))
        conflicts.extend(self._detect_ranges(record))
        conflicts.extend(self._detect_cpe(record))
        conflicts.extend(self._detect_dates(record))
        return conflicts

    def _detect_cvss(self, record: MergedRecord) -> List[ConflictItem]:
        """CVSS 分值冲突 — 数值差超过容忍差视为冲突."""
        scored = [(src, rec.cvss_score) for src, rec in record.source_data.items()
                  if rec.cvss_score is not None]
        if len(scored) < 2:
            return []
        vals = [v for _, v in scored]
        lo, hi = min(vals), max(vals)
        if hi - lo > self._cvss_tolerance:
            return [ConflictItem(
                field="cvss_score",
                conflict_type="cvss_numeric_diff",
                sources=[s for s, _ in scored],
                values=[v for _, v in scored],
                severity="warning" if hi - lo < 1.0 else "high",
                detail=f"CVSS 分差 {hi - lo:.2f} 超过容忍 {self._cvss_tolerance:.2f}",
            )]
        return []

    def _detect_ranges(self, record: MergedRecord) -> List[ConflictItem]:
        """版本区间冲突 — 对比各来源的 fixed/introduced 极值.

        覆盖缺口单独标注为 info: 某来源未提供任何区间信息, 而非区间
        数值相悖. 两类事件 (数值冲突 / 覆盖缺口) 分属不同可信度层级.
        """
        summaries: Dict[str, Optional[Dict[str, Optional[str]]]] = {}
        for src, rec in record.source_data.items():
            summaries[src] = _range_summary(rec.affected_ranges)

        if len(record.source_data) < 2:
            return []

        provided = {src: s for src, s in summaries.items() if s is not None}
        conflicts: List[ConflictItem] = []

        # fixed 版本不一致是最高价值冲突 (决定补丁版本)
        fixed_sources = [(src, s["fixed"]) for src, s in provided.items() if s.get("fixed")]
        if len(fixed_sources) >= 2:
            distinct = {v for _, v in fixed_sources}
            if len(distinct) > 1:
                conflicts.append(ConflictItem(
                    field="version_range",
                    conflict_type="range_discrepancy",
                    sources=[s for s, _ in fixed_sources],
                    values=[v for _, v in fixed_sources],
                    severity="high",
                    detail="各来源对修复版本 (fixed) 的声明不一致",
                ))

        # introduced 版本不一致 — 覆盖下界的差异
        intro_sources = [(src, s["introduced"]) for src, s in provided.items() if s.get("introduced")]
        if len(intro_sources) >= 2:
            distinct = {v for _, v in intro_sources}
            if len(distinct) > 1:
                conflicts.append(ConflictItem(
                    field="version_range",
                    conflict_type="range_discrepancy",
                    sources=[s for s, _ in intro_sources],
                    values=[v for _, v in intro_sources],
                    severity="warning",
                    detail="各来源对受影响起始版本 (introduced) 的声明不一致",
                ))

        # 覆盖缺口: 来源完全未提供区间信息
        missing = [src for src, s in summaries.items() if s is None]
        if missing:
            conflicts.append(ConflictItem(
                field="version_range",
                conflict_type="coverage_gap",
                sources=missing,
                values=[None] * len(missing),
                severity="info",
                detail="部分来源未提供受影响版本区间",
            ))
        return conflicts

    def _detect_cpe(self, record: MergedRecord) -> List[ConflictItem]:
        """CPE/PURL 冲突 — 结构化产品集完全不相交时标注."""
        prod_sets: Dict[str, Set[str]] = {}
        for src, rec in record.source_data.items():
            prods: Set[str] = set()
            for cpe in rec.cpes:
                m = re.match(r"cpe:2\.3:[aoh]:[^:]*:([^:]*):", str(cpe))
                if m and m.group(1) != "*":
                    prods.add(m.group(1).lower())
            for p in rec.affected_packages:
                name = str(p.get("name") or "").lower()
                if name:
                    prods.add(name)
            if prods:
                prod_sets[src] = prods

        if len(prod_sets) < 2:
            return []
        srcs = list(prod_sets.keys())
        first = prod_sets[srcs[0]]
        disjoint = all(not (first & prod_sets[s]) for s in srcs[1:])
        if disjoint:
            return [ConflictItem(
                field="cpe",
                conflict_type="cpe_mismatch",
                sources=srcs,
                values=[sorted(prod_sets[s]) for s in srcs],
                severity="warning",
                detail="各来源受影响组件/CPE 集合完全不相交",
            )]
        return []

    def _detect_dates(self, record: MergedRecord) -> List[ConflictItem]:
        """公告日期冲突 — 跨源发布日差异超过容忍天数时标注."""
        dated = [(src, _parse_date(rec.published_date))
                 for src, rec in record.source_data.items()
                 if _parse_date(rec.published_date) is not None]
        if len(dated) < 2:
            return []
        ts = [t for _, t in dated]
        span = (max(ts) - min(ts)) / 86400.0
        if span > self._date_tolerance_days:
            return [ConflictItem(
                field="published_date",
                conflict_type="date_gap",
                sources=[s for s, _ in dated],
                values=[v for _, v in dated],
                severity="info",
                detail=f"公告日期跨 {span:.0f} 天超过容忍 {self._date_tolerance_days} 天",
            )]
        return []

    def detect_batch(self, records: List[MergedRecord]) -> Dict[str, List[ConflictItem]]:
        """批量检测 — 以 cve_id 为键返回冲突映射."""
        result: Dict[str, List[ConflictItem]] = {}
        for rec in records:
            key = rec.cve_id or "|".join(rec.sources)
            result[key] = self.detect(rec)
        return result


def _range_summary(ranges: List[Dict[str, Any]]) -> Optional[Dict[str, Optional[str]]]:
    """区间摘要: {introduced: 最晚引入, fixed: 最早修复, last_affected: 最晚受影响}.

    极值按语义版本序计算; 无任何事件返回 None.
    """
    introduced: List[str] = []
    fixed: List[str] = []
    last: List[str] = []
    for r in ranges or []:
        if not isinstance(r, dict):
            continue
        for evt in r.get("events", []) or []:
            if not isinstance(evt, dict):
                continue
            if "introduced" in evt:
                introduced.append(str(evt["introduced"]))
            if "fixed" in evt:
                fixed.append(str(evt["fixed"]))
            if "last_affected" in evt:
                last.append(str(evt["last_affected"]))
    if not (introduced or fixed or last):
        return None
    return {
        "introduced": _pick_extreme(introduced, want_min=False),
        "fixed": _pick_extreme(fixed, want_min=True),
        "last_affected": _pick_extreme(last, want_min=False),
    }


# 非结构化描述 -> 统一模式结构化抽取 (IntelEX 思路)

# 攻击向量关键词 -> 归一化 CVSS-AV 类别
_ATTACK_VECTOR_KEYWORDS: List[Tuple[str, List[str]]] = [
    ("network", [r"\bremote\b", r"\bnetwork\b", r"over the network", r"from a remote"]),
    ("adjacent", [r"\badjacent\b", r"next to the network"]),
    ("local", [r"\blocal (user|attacker|access)\b", r"locally"]),
    ("physical", [r"\bphysical access\b", r"physical\b"]),
]

# 漏洞类型关键词 -> (CWE, 归一化标签)
_CWE_KEYWORDS: List[Tuple[str, str, List[str]]] = [
    ("CWE-89", "sql_injection", [r"sql injection", r"\bsqli\b"]),
    ("CWE-79", "cross_site_scripting", [r"cross[- ]site scripting", r"\bxss\b"]),
    ("CWE-352", "csrf", [r"cross[- ]site request forgery", r"\bcsrf\b"]),
    ("CWE-22", "path_traversal", [r"path traversal", r"directory traversal", r"..[\\/]"]),
    ("CWE-77", "command_injection", [r"command injection", r"shell injection"]),
    ("CWE-94", "code_injection", [r"code injection", r"arbitrary code"]),
    ("CWE-78", "os_command_injection", [r"os command injection", r"operating system command"]),
    ("CWE-120", "buffer_overflow", [r"buffer overflow"]),
    ("CWE-122", "heap_overflow", [r"heap overflow"]),
    ("CWE-121", "stack_overflow", [r"stack overflow"]),
    ("CWE-416", "use_after_free", [r"use[- ]after[- ]free"]),
    ("CWE-119", "memory_corruption", [r"memory corruption"]),
    ("CWE-190", "integer_overflow", [r"integer overflow"]),
    ("CWE-502", "deserialization", [r"deserialization", r"unsafe deserialization"]),
    ("CWE-918", "ssrf", [r"server[- ]side request forgery", r"\bssrf\b"]),
    ("CWE-611", "xxe", [r"xml external entity", r"\bxxe\b"]),
    ("CWE-287", "auth_bypass", [r"authentication bypass", r"auth bypass"]),
    ("CWE-269", "privilege_escalation", [r"privilege escalation", r"elevat(?:e|ion) of privilege"]),
    ("CWE-200", "info_disclosure", [r"information disclosure", r"information leak"]),
    ("CWE-400", "denial_of_service", [r"denial of service", r"\bdos\b", r"resource exhaustion"]),
    ("CWE-362", "race_condition", [r"race condition"]),
    ("CWE-787", "out_of_bounds_write", [r"out[- ]of[- ]bounds write"]),
    ("CWE-125", "out_of_bounds_read", [r"out[- ]of[- ]bounds read"]),
]

# 版本区间抽取模式 — 覆盖常见的自然语言区间表达
_VERSION_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("before", re.compile(r"\b(?:before|prior to|earlier than)\s+([0-9][0-9a-zA-Z.\-_]*)", re.IGNORECASE)),
    ("through", re.compile(r"\bthrough\s+([0-9][0-9a-zA-Z.\-_]*)", re.IGNORECASE)),
    ("and_earlier", re.compile(r"\b(?:and|up to)\s+([0-9][0-9a-zA-Z.\-_]*)\s+(?:and earlier|inclusive)", re.IGNORECASE)),
    ("lte", re.compile(r"<=\s*([0-9][0-9a-zA-Z.\-_]*)")),
    ("lt", re.compile(r"(?<![<>=!])\b<\s*([0-9][0-9a-zA-Z.\-_]*)")),
    ("gte", re.compile(r">=\s*([0-9][0-9a-zA-Z.\-_]*)")),
    ("range", re.compile(r"([0-9][0-9a-zA-Z.\-_]*)\s*(?:through|to|[-])\s*([0-9][0-9a-zA-Z.\-_]*)")),
]

# 简单语义化版本正则 — 过滤掉明显的日期/年份噪声
_SEMVER_LIKE = re.compile(r"^\d+([.]\d+){0,3}[a-zA-Z.\-]?\d*$")


class StructuredExtractor:
    """非结构化描述 -> 统一模式结构化抽取.

    IntelEX 的抽取思路落地为: 规则抽取为主, 可选 LLM 兜底. 规则层
    用关键词/正则把描述映射到 schema; LLM 层 (SEvenLLM 的能力增强
    路径) 在配置 API 后尝试输出严格 JSON, 失败时回落规则结果.
    输出 schema: {affected_components, version_ranges, attack_vectors,
    vulnerability_types, cwes}
    """

    def __init__(self, use_llm: bool = True):
        self._use_llm = use_llm

    def extract(self, description: str, hints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """规则抽取 — 不依赖任何外部服务, 恒可运行."""
        desc = description or ""
        lower = desc.lower()

        # 受影响组件: 优先使用提示词提供的产品名 (NVD CPE 信息), 无则跳过
        components: List[str] = []
        for name in (hints or {}).get("products") or []:
            if isinstance(name, str) and name.lower() in lower:
                if name not in components:
                    components.append(name)

        # 版本区间: 归一化为 affected_ranges 格式, 便于下游直接复用
        version_ranges = self._extract_ranges(desc)

        # 攻击向量
        attack_vectors: List[str] = []
        for av, patterns in _ATTACK_VECTOR_KEYWORDS:
            if any(re.search(p, lower) for p in patterns):
                attack_vectors.append(av)

        # 漏洞类型 + CWE
        vulnerability_types: List[Dict[str, str]] = []
        cwes = list(dict.fromkeys(re.findall(r"CWE-\d{1,4}", desc, re.IGNORECASE)))
        for cwe, label, patterns in _CWE_KEYWORDS:
            if any(re.search(p, lower) for p in patterns):
                vulnerability_types.append({"cwe": cwe, "label": label})
                if cwe not in cwes:
                    cwes.append(cwe)

        return {
            "affected_components": components,
            "version_ranges": version_ranges,
            "attack_vectors": attack_vectors,
            "vulnerability_types": vulnerability_types,
            "cwes": cwes,
        }

    def _extract_ranges(self, desc: str) -> List[Dict[str, Any]]:
        """从描述中抽取版本区间 — 用固定模式集, 去重保留.

        规则: before X -> {fixed:X}; through X -> {last_affected:X};
        X..Y -> {introduced:X, last_affected:Y}; 组合到统一 events 形式.
        """
        ranges: List[Dict[str, Any]] = []
        # 事件级候选
        introduced: List[str] = []
        fixed: List[str] = []
        last: List[str] = []

        for kind, pat in _VERSION_PATTERNS:
            for m in pat.finditer(desc):
                if kind == "range":
                    v1, v2 = m.group(1), m.group(2)
                    if _looks_like_version(v1) and _looks_like_version(v2):
                        introduced.append(v1)
                        last.append(v2)
                else:
                    v = m.group(1)
                    if not _looks_like_version(v):
                        continue
                    if kind in ("before", "lt"):
                        fixed.append(v)
                    elif kind in ("through", "and_earlier", "lte"):
                        last.append(v)
                    elif kind == "gte":
                        introduced.append(v)

        if not (introduced or fixed or last):
            return ranges

        events: List[Dict[str, Any]] = []
        lo = _pick_extreme(introduced, want_min=True) if introduced else None
        hi_fixed = _pick_extreme(fixed, want_min=True) if fixed else None
        hi_last = _pick_extreme(last, want_min=False) if last else None
        if lo:
            events.append({"introduced": lo})
        if hi_fixed:
            events.append({"fixed": hi_fixed})
        elif hi_last:
            events.append({"last_affected": hi_last})
        if events:
            ranges.append({"type": "SEMVER", "events": events})
        return ranges

    def extract_llm(self, description: str) -> Optional[Dict[str, Any]]:
        """LLM 兜底抽取 — 未配置 API 或调用失败返回 None."""
        api_url = os.environ.get("CVE_LLM_API_URL", "").strip()
        if not api_url or not self._use_llm:
            return None
        prompt = (
            "你是漏洞情报结构化抽取引擎. 从给定描述中抽取 JSON:\n"
            "{\"affected_components\": [...], \"version_ranges\": [{\"type\":\"SEMVER\","
            "\"events\":[{\"introduced\":\"...\"},{\"fixed\":\"...\"}]}],"
            "\"attack_vectors\": [\"network\"],"
            "\"vulnerability_types\": [{\"cwe\":\"CWE-79\",\"label\":\"xss\"}]}\n"
            "仅输出 JSON, 不要额外文字. 描述:\n" + description
        )
        try:
            payload = json.dumps({
                "model": os.environ.get("CVE_LLM_MODEL", "deepseek-chat"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
            }).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": "BinMind-CVE/1.0"}
            key = os.environ.get("CVE_LLM_API_KEY", "").strip()
            if key:
                headers["Authorization"] = f"Bearer {key}"
            req = urllib.request.Request(api_url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            # 容忍模型在 JSON 外加注的 markdown 围栏
            content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip())
            parsed = json.loads(content)
            if isinstance(parsed, dict):
                return parsed
            return None
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError,
                json.JSONDecodeError, TypeError, IndexError, OSError):
            return None

    def extract_hybrid(self, description: str,
                       hints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """混合抽取 — 优先 LLM, 失败回落规则结果."""
        llm = self.extract_llm(description) if self._use_llm else None
        if llm:
            base = self.extract(description, hints)
            merged = dict(base)
            for k in ("affected_components", "version_ranges",
                      "attack_vectors", "vulnerability_types", "cwes"):
                if llm.get(k):
                    merged[k] = llm[k]
            return merged
        return self.extract(description, hints)


def _looks_like_version(v: str) -> bool:
    """版本字符串粗筛 — 过滤明显噪声 (年份、单词)."""
    v = v.strip()
    if not v or len(v) > 24:
        return False
    if re.match(r"^\d{4}$", v):
        return False  # 纯 4 位数字可能是年份
    return bool(_SEMVER_LIKE.match(v)) or bool(re.match(r"^\d{2}\.\d{2}$", v))


# 版本区间嵌入增强 (复用 cve_causal_contrastive 接口)

class VersionRangeEmbeddingEnhancer:
    """版本区间嵌入增强 — 对去重实体复用因果对比学习接口.

    阶段 1: 从合并实体构建 10 维可观测特征 (维度对齐 _FEATURE_NAMES).
    阶段 2: CausalFeatureSelector 识别因果权重 (PC 算法 + 条件独立检验).
    阶段 3: ContrastiveCVEEncoder 学习实体嵌入, 键为实体 ID
            (cve_id, 无 CVE 时取区间指纹).
    训练集之外的区间: 用与编码器初始化一致的确定性投影生成嵌入,
    保证 enhance_version_range 对任意输入可用.
    """

    def __init__(self, embedding_dim: int = 16, temperature: float = 0.1):
        self._dim = embedding_dim
        self._tau = temperature
        self._entity_ids: List[str] = []
        self._feature_index: Dict[str, List[float]] = {}
        self._embeddings: Dict[str, List[float]] = {}
        self._causal_weights: Dict[str, float] = {}
        self._fitted = False

    def fit(self, records: List[MergedRecord]) -> Dict[str, Any]:
        """在去重实体集合上拟合 — 训练实体/区间表征."""
        entities: List[Tuple[str, List[float]]] = []
        labels: List[int] = []
        for rec in records:
            features = self._build_features(rec)
            eid = self.entity_id(rec)
            self._feature_index[eid] = features
            entities.append((eid, features))
            labels.append(1 if rec.severity in ("CRITICAL", "HIGH") else 0)

        if not entities:
            self._fitted = True
            return {"n_entities": 0}

        ids = [e[0] for e in entities]
        feats = [e[1] for e in entities]
        stats: Dict[str, Any] = {"n_entities": len(ids)}

        if _HAS_C3E and len(ids) >= 5:
            self._selector = CausalFeatureSelector()
            self._selector.fit(feats, labels)
            self._causal_weights = self._selector.causal_weights
            self._encoder = ContrastiveCVEEncoder(embedding_dim=self._dim,
                                                  temperature=self._tau)
            self._encoder.fit(ids, feats, labels, self._causal_weights,
                              epochs=min(20, max(5, len(ids))))
            self._embeddings = self._encoder.embeddings
            stats["method"] = "causal_contrastive"
            stats["causal_weights"] = {k: round(v, 3) for k, v in self._causal_weights.items()}
        else:
            # 降级: 确定性投影嵌入 (与 ContrastiveCVEEncoder 初始化一致)
            for eid, f in entities:
                self._embeddings[eid] = self._project(f)
            stats["method"] = "deterministic_projection"

        self._fitted = True
        return stats

    def entity_id(self, record: MergedRecord) -> str:
        """实体 ID — 有 CVE 用 CVE ID, 否则用区间指纹."""
        if record.cve_id:
            return record.cve_id.upper()
        return self.range_fingerprint(record.affected_ranges) or "|".join(record.sources)

    def range_fingerprint(self, ranges: List[Dict[str, Any]]) -> str:
        """区间指纹 — 排序后的区间 JSON 摘要, 用于键控去重."""
        if not ranges:
            return ""
        parts = sorted(json.dumps(r, sort_keys=True, default=str) for r in ranges if isinstance(r, dict))
        return "||".join(parts)

    def _build_features(self, record: MergedRecord) -> List[float]:
        """10 维特征 — 对齐 _FEATURE_NAMES 语义, 供因果权重映射.

        维度: cvss/severity/has_fix/n_products/n_ranges/desc_len/has_cwe/
        has_ref/has_exploit/range_breadth. 缺失项取 0, 保证特征向量完整.
        """
        cvss = (record.cvss_score or 0.0) / 10.0
        sev_map = {"NONE": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
        sev = sev_map.get(record.severity, 0.0)
        has_fix = 1.0 if any(
            isinstance(r, dict) and any(
                isinstance(e, dict) and "fixed" in e for e in r.get("events", [])
            ) for r in record.affected_ranges
        ) else 0.0
        n_products = min(math.log(1 + len(record.affected_packages)) / math.log(101), 1.0)
        n_ranges = min(math.log(1 + len(record.affected_ranges)) / math.log(101), 1.0)
        desc_len = min(math.log(1 + len(record.description)) / math.log(4001), 1.0)
        has_cwe = 1.0 if any("CWE-" in p for p in record.cpes) else 0.0
        has_ref = min(math.log(1 + len(record.references)) / math.log(101), 1.0)
        has_exploit = 1.0 if any(s.lower() in ("exploitdb", "exploit-db") for s in record.sources) else 0.0
        range_breadth = 0.0
        for r in record.affected_ranges:
            if isinstance(r, dict) and r.get("events"):
                range_breadth = max(range_breadth, min(len(r["events"]) / 3.0, 1.0))
        return [cvss, 0.0, 0.0, 0.0, sev, 0.0, has_fix, n_products,
                n_ranges, desc_len][:10]

    def _project(self, features: List[float]) -> List[float]:
        """确定性投影 — 与 ContrastiveCVEEncoder 初始化投影相同,
        使训练集外的区间可得到一致表征."""
        vec = [0.0] * self._dim
        wf = features or [0.0] * 10
        for d in range(self._dim):
            val = sum(
                wf[k % len(wf)] * math.sin((d + 1) * (k + 1) * 0.7)
                for k in range(len(wf))
            ) / max(len(wf), 1)
            vec[d] = val
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]

    def enhance_version_range(self, ranges: List[Dict[str, Any]]) -> List[float]:
        """增强指定版本区间的表征 — 训练集中返回学习嵌入, 否则投影."""
        fp = self.range_fingerprint(ranges)
        if fp and fp in self._embeddings:
            return self._embeddings[fp]
        if fp and fp in self._feature_index:
            return self._project(self._feature_index[fp])
        # 区间级特征 (无完整实体上下文)
        features = self._range_only_features(ranges)
        return self._project(features)

    def _range_only_features(self, ranges: List[Dict[str, Any]]) -> List[float]:
        """纯区间结构特征 — 用于训练集外区间的投影输入."""
        has_fix = 1.0 if any(
            isinstance(r, dict) and any(
                isinstance(e, dict) and "fixed" in e for e in r.get("events", [])
            ) for r in ranges
        ) else 0.0
        n_ranges = min(math.log(1 + len(ranges)) / math.log(101), 1.0)
        breadth = 0.0
        for r in ranges:
            if isinstance(r, dict) and r.get("events"):
                breadth = max(breadth, min(len(r["events"]) / 3.0, 1.0))
        feats = [0.0] * 10
        feats[7] = has_fix
        feats[8] = n_ranges
        feats[9] = breadth
        return feats

    def get_embedding(self, entity_id: str) -> Optional[List[float]]:
        """按实体 ID 取嵌入."""
        return self._embeddings.get(entity_id)

    def find_similar_ranges(self, entity_id: str, top_n: int = 5) -> List[Tuple[str, float]]:
        """嵌入空间内找相似区间/实体 — 与 C3E 的 find_similar 一致."""
        vec = self._embeddings.get(entity_id)
        if vec is None:
            return []
        sims = []
        for eid, emb in self._embeddings.items():
            if eid == entity_id:
                continue
            dot = sum(a * b for a, b in zip(vec, emb))
            na = math.sqrt(sum(x * x for x in vec)) or 1.0
            nb = math.sqrt(sum(x * x for x in emb)) or 1.0
            sims.append((eid, max(0.0, dot / (na * nb))))
        sims.sort(key=lambda x: x[1], reverse=True)
        return sims[:top_n]

    @property
    def embeddings(self) -> Dict[str, List[float]]:
        return dict(self._embeddings)

    @property
    def causal_weights(self) -> Dict[str, float]:
        return dict(self._causal_weights)

    @property
    def is_fitted(self) -> bool:
        return self._fitted


# 一站式流水线

class SemDedupPipeline:
    """SemDedup 完整流水线: 去重 -> 冲突检测 -> 结构化抽取 -> 区间嵌入增强.

    各阶段解耦, 可单独调用; run() 为批量入口.
    """

    def __init__(self, backend: Optional[EmbeddingBackend] = None,
                 sim_threshold: float = _SEM_SIM_THRESHOLD,
                 use_llm: bool = True):
        self._deduper = SemDeduper(backend=backend, sim_threshold=sim_threshold)
        self._conflict_detector = FieldConflictDetector()
        self._extractor = StructuredExtractor(use_llm=use_llm)
        self._enhancer = VersionRangeEmbeddingEnhancer()

    def run(self, records: List[Any], extract: bool = True,
            enhance: bool = True) -> Dict[str, Any]:
        """批量执行 — 返回合并实体/冲突/抽取/嵌入与统计."""
        merged = self._deduper.dedupe(records)

        conflicts: Dict[str, List[ConflictItem]] = {}
        extractions: Dict[str, Dict[str, Any]] = {}
        for rec in merged:
            key = rec.cve_id or rec.matched_by + ":" + "|".join(rec.sources)
            conflicts[key] = self._conflict_detector.detect(rec)
            if extract:
                extractions[key] = self._extractor.extract_hybrid(rec.description)

        embeddings: Dict[str, List[float]] = {}
        enhance_stats: Dict[str, Any] = {}
        if enhance:
            enhance_stats = self._enhancer.fit(merged)
            embeddings = self._enhancer.embeddings

        n_conflicts = sum(1 for cl in conflicts.values() for _ in cl if cl)
        return {
            "merged": [m.to_dict() for m in merged],
            "conflicts": {k: [c.to_dict() for c in v] for k, v in conflicts.items()},
            "extractions": extractions,
            "embeddings": embeddings,
            "enhance_stats": enhance_stats,
            "stats": {
                "input_records": len(records),
                "merged_entities": len(merged),
                "conflict_items": n_conflicts,
                "sources_seen": sorted({r.source for r in (SourceRecord.from_record(x) for x in records)}),
            },
        }


def run_semdedup(records: List[Any], extract: bool = True,
                 enhance: bool = True, **pipeline_kwargs) -> Dict[str, Any]:
    """一站式 SemDedup — 便捷入口.

    extract/enhance 为 run() 的阶段开关; 其余关键字透传
    SemDedupPipeline.__init__ (backend/sim_threshold/use_llm).
    """
    return SemDedupPipeline(**pipeline_kwargs).run(records, extract=extract, enhance=enhance)


def inconsistency_report(records: List[Any], **kwargs) -> Dict[str, Any]:
    """不一致性报告 — 聚焦冲突字段, 供安全团队复核跨源差异.

    与 run_semdedup 的区别: 仅返回冲突明细与涉及的合并实体摘要.
    """
    result = run_semdedup(records, **kwargs)
    summary = []
    for key, conflicts in result["conflicts"].items():
        if conflicts:
            summary.append({
                "entity": key,
                "n_conflicts": len(conflicts),
                "high": sum(1 for c in conflicts if c["severity"] == "high"),
                "warning": sum(1 for c in conflicts if c["severity"] == "warning"),
                "fields": sorted({c["field"] for c in conflicts}),
            })
    return {
        "conflicts": result["conflicts"],
        "conflict_summary": summary,
        "stats": result["stats"],
    }
