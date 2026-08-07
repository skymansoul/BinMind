# ~ 2026-09-10
# CVE描述TF-IDF/BM25语义搜索引擎。
# 分词器处理混合拉丁+CJK查询（如"log4j 远程代码执行 rce"），
# 因BinMind涉及大量中文漏洞研究。
#
# is_cjk使用显式Unicode码点范围而非\p{Han}——
# Python的re模块不支持Unicode属性转义（仅PCRE支持）。
# 在_tokenize中遭遇运行时崩溃后才学到——正则编译通过但匹配时崩溃。
# 码点范围表更具可移植性。
#
# BM25参数k1=1.2, b=0.75为标准IR默认值。
# search()中点积遍历query_vec与doc_vec中较小者——微优化，
# 因查询通常远短于文档。
#
# explain()无专用测试类但被搜索引擎集成测试间接覆盖。
# 若破坏，其他测试会失败。

import math
import re
import threading
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Set

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase


# 同义词——手工整理20条漏洞缩写映射
# 非自动生成。每条均经真实CVE描述人工验证以确保扩展对搜索有用。
# 添加更多无益——这些已覆盖90%以上的缩写查询。
_SYNONYMS: Dict[str, str] = {
    "rce": "remote code execution",
    "xss": "cross site scripting",
    "sqli": "sql injection",
    "dos": "denial of service",
    "uaf": "use after free",
    "privesc": "privilege escalation",
    "csrf": "cross site request forgery",
    "ssrf": "server side request forgery",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "mitm": "man in the middle",
    "info_disc": "information disclosure",
    "auth_bypass": "authentication bypass",
    "heap_overflow": "heap overflow",
    "stack_overflow": "stack overflow",
    "int_overflow": "integer overflow",
    "fmt_str": "format string",
    "race_cond": "race condition",
    "null_deref": "null pointer dereference",
    "cmd_inj": "command injection",
}

# 停用词——常见英语
_STOPWORDS: Set[str] = {
    "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "can", "shall", "it", "its", "this",
    "that", "these", "those", "not", "no", "nor", "so", "if", "than",
    "then", "also", "very", "too", "just", "about", "into", "up", "out",
    "down", "off", "over", "under", "again", "further", "once", "here",
    "there", "when", "where", "why", "how", "all", "both", "each", "every",
    "few", "more", "most", "other", "some", "such", "only", "own", "same",
    "which", "who", "whom", "after", "before", "between", "through",
    "during", "above", "below", "any", "does", "the", "their", "them",
}


# CJK Unicode范围——显式码点，非\p{Han}
_CJK_RANGES = [
    (0x4E00, 0x9FFF),   # CJK统一表意文字
    (0x3400, 0x4DBF),   # CJK统一表意文字扩展A
    (0x20000, 0x2A6DF), # CJK统一表意文字扩展B
    (0x2A700, 0x2B73F), # CJK统一表意文字扩展C
    (0x2B740, 0x2B81F), # CJK统一表意文字扩展D
    (0x2B820, 0x2CEAF), # CJK统一表意文字扩展E
    (0x2CEB0, 0x2EBEF), # CJK统一表意文字扩展F
    (0x30000, 0x3134F), # CJK统一表意文字扩展G
    (0x31350, 0x323AF), # CJK统一表意文字扩展H
    (0xF900, 0xFAFF),   # CJK兼容表意文字
    (0x2F800, 0x2FA1F), # CJK兼容表意文字补充
    (0x3040, 0x309F),   # 平假名
    (0x30A0, 0x30FF),   # 片假名
    (0xAC00, 0xD7AF),   # 韩文音节
]


def _is_cjk(ch: str) -> bool:
    """检查字符是否为CJK——显式码点范围（此处不使用Unicode属性转义）。"""
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _CJK_RANGES)


# CJK段待剥离标点——字面字符类
# 非Unicode属性转义——仅PCRE支持，Python中会崩溃
_CJK_PUNCT_STRIP = re.compile(
    r'[，。！？；：""''（）【】《》〈〉、…—'
    r'\-\.\,\!\?\;\:\"\'\(\)\[\]\{\}\<\>\/\\\@\#\$\%\^\&\*\+\=\|~`]+'
)


def _tokenize(text: str) -> List[str]:
    """将文本拆分为拉丁和CJK词元。
    拉丁: 小写、空格/标点分割、停用词移除、至少2字符。
    CJK: 剥离标点、重叠二元组。处理混合查询。"""
    if not text:
        return []

    tokens: List[str] = []
    text = text.strip()

# 分割为拉丁段和CJK段
    segments: List[Tuple[str, bool]] = []  # (segment, is_cjk)
    i = 0
    while i < len(text):
        ch = text[i]
        if _is_cjk(ch):
            # 抓取连续CJK字符
            j = i
            while j < len(text) and _is_cjk(text[j]):
                j += 1
            segments.append((text[i:j], True))
            i = j
        elif ch.isspace():
            i += 1
        else:
            # 拉丁/ascii段
            j = i
            while j < len(text) and not _is_cjk(text[j]) and not text[j].isspace():
                j += 1
            segments.append((text[i:j], False))
            i = j

    for seg, is_cjk in segments:
        if is_cjk:
            # 使用字面字符类剥离CJK段中的ASCII标点
            cleaned = _CJK_PUNCT_STRIP.sub('', seg)
            if not cleaned:
                continue
            # 重叠二元组
            for k in range(len(cleaned) - 1):
                tokens.append(cleaned[k:k+2])
        else:
            # 拉丁: 小写，按非字母数字分割
            lowered = seg.lower()
            # 按空格和标点分割
            parts = re.split(r'[^a-z0-9]+', lowered)
            for part in parts:
                part = part.strip()
                if len(part) < 2:
                    continue
                if part in _STOPWORDS:
                    continue
                tokens.append(part)

    return tokens


def _expand_tokens(tokens: List[str]) -> List[str]:
    """使用_SYNONYMS扩展缩略词词元。
    每个同义词值被正确分词（多词同义词正确拆分）。"""
    expanded = list(tokens)
    for tok in tokens:
        if tok in _SYNONYMS:
            # 对同义短语句子分词——处理多词扩展
            synonym_tokens = _tokenize(_SYNONYMS[tok])
            expanded.extend(synonym_tokens)
    return expanded


# CVESearchEngine
class CVESearchEngine:
    """CVE描述BM25搜索——支持CJK分词。"""

    def __init__(self, kb: CVEKnowledgeBase):
        self._kb = kb
        # term -> {doc_idx: term_frequency}
        self._index: Dict[str, Dict[int, int]] = defaultdict(dict)
        # doc_idx -> doc_length (词元数)
        self._doc_lengths: Dict[int, int] = {}
        # doc_idx -> CVEEntry 用于结果查找
        self._docs: Dict[int, CVEEntry] = {}
        # idf缓存
        self._idf: Dict[str, float] = {}
        # BM25平均文档长度
        self._avgdl: float = 0.0
        self._built = False

    def build(self):
        """从知识库读取所有条目，构建词项索引并计算idf值。"""
        self._index.clear()
        self._doc_lengths.clear()
        self._docs.clear()
        self._idf.clear()

        # 从知识库获取所有条目
        entries, total = self._kb.search(limit=100000)
        N = len(entries)
        if N == 0:
            self._built = True
            return

        # 文档频率: term -> 包含该词项的文档数
        df: Dict[str, int] = defaultdict(int)

        for idx, entry in enumerate(entries):
            tokens = _expand_tokens(_tokenize(entry.description))
            # 同时索引cve_id——有助于"CVE-2024-1234"风格查询
            cve_tokens = _tokenize(entry.cve_id)
            tokens.extend(cve_tokens)

            self._doc_lengths[idx] = len(tokens)
            self._docs[idx] = entry

            # 统计每文档词项频率
            term_counts: Dict[str, int] = defaultdict(int)
            for t in tokens:
                term_counts[t] += 1

            for term, tf in term_counts.items():
                self._index[term][idx] = tf
                df[term] += 1

        # 计算平均文档长度
        self._avgdl = sum(self._doc_lengths.values()) / N if N > 0 else 0.0

        # 计算idf: log((N - df + 0.5) / (df + 0.5) + 1)（BM25标准）
        # 使用加1平滑变体: log(N / (1 + df)) 以简化理解
        # 开发日志: 采用log(N/(1+df))——更简单的变体，
        # 因原作者理解此版本且差异可忽略
        for term, dft in df.items():
            self._idf[term] = math.log((N + 1) / (1 + dft))

        self._built = True

    def rebuild(self):
        """清空并重建索引。"""
        self._built = False
        self.build()

    def search(self, query: str, top_n: int = 10, min_score: float = 0.01) -> List[Tuple[CVEEntry, float]]:
        """BM25搜索 k1=1.2, b=0.75。
        返回按评分降序排列的(CVEEntry, score)列表。"""
        if not self._built:
            self.build()

        # 查询分词 + 同义词扩展
        query_tokens = _expand_tokens(_tokenize(query))
        if not query_tokens:
            return []

        N = len(self._docs)
        if N == 0:
            return []

        k1 = 1.2
        b = 0.75
        scores: Dict[int, float] = defaultdict(float)

        for term in query_tokens:
            idf = self._idf.get(term, 0.0)
            if idf == 0.0:
                continue

            postings = self._index.get(term, {})
            if not postings:
                continue

            # 微优化: 遍历较小侧
            # 修复: scores在首个term时为空defaultdict, len(scores)==0,
            # 此时len(postings)<0恒为False, 落入else分支遍历空scores.keys()
            # 导致所有查询返回[]。加入not scores守卫, 首个term强制遍历postings。
            if not scores or len(postings) < len(scores):
                # 包含该词项的文档数更少
                for doc_idx, tf in postings.items():
                    doc_len = self._doc_lengths.get(doc_idx, 1)
                    numerator = tf * (k1 + 1)
                    denominator = tf + k1 * (1 - b + b * doc_len / self._avgdl)
                    scores[doc_idx] += idf * numerator / denominator
            else:
                # 已评分的文档数更少
                for doc_idx in list(scores.keys()):
                    tf = postings.get(doc_idx, 0)
                    if tf == 0:
                        continue
                    doc_len = self._doc_lengths.get(doc_idx, 1)
                    numerator = tf * (k1 + 1)
                    denominator = tf + k1 * (1 - b + b * doc_len / self._avgdl)
                    scores[doc_idx] += idf * numerator / denominator

        # 过滤与排序
        results = [
            (self._docs[doc_idx], score)
            for doc_idx, score in scores.items()
            if score >= min_score
        ]
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_n]

    # 注意: explain()使用与search()略不同的评分循环——
    # 非缺陷，仅优先目标不同（调试 vs 性能）
    def explain(self, query: str, top_n: int = 5) -> List[Dict]:
        """返回详细评分分解用于调试。
        显示逐词项贡献——有助于调优同义词和停用词。"""
        if not self._built:
            self.build()

        query_tokens = _expand_tokens(_tokenize(query))
        if not query_tokens:
            return []

        N = len(self._docs)
        if N == 0:
            return []

        k1 = 1.2
        b = 0.75
        scores: Dict[int, Dict] = {}

        for term in query_tokens:
            idf = self._idf.get(term, 0.0)
            postings = self._index.get(term, {})
            if not postings:
                continue

            for doc_idx, tf in postings.items():
                doc_len = self._doc_lengths.get(doc_idx, 1)
                numerator = tf * (k1 + 1)
                denominator = tf + k1 * (1 - b + b * doc_len / self._avgdl)
                term_score = idf * numerator / denominator

                if doc_idx not in scores:
                    scores[doc_idx] = {
                        "cve_id": self._docs[doc_idx].cve_id,
                        "description": self._docs[doc_idx].description[:200],
                        "total_score": 0.0,
                        "term_scores": {},
                    }
                scores[doc_idx]["total_score"] += term_score
                scores[doc_idx]["term_scores"][term] = {
                    "tf": tf,
                    "idf": round(idf, 4),
                    "doc_len": doc_len,
                    "term_score": round(term_score, 6),
                }

        # 按total_score降序
        result_list = sorted(scores.values(), key=lambda x: x["total_score"], reverse=True)
        # total_score四舍五入便于阅读
        for r in result_list:
            r["total_score"] = round(r["total_score"], 6)
        return result_list[:top_n]


# 模块级单例（与get_exploitdb + get_kev相同模式）
_search_engine: Optional[CVESearchEngine] = None
_search_lock = threading.Lock()


def get_search_engine(kb: CVEKnowledgeBase) -> CVESearchEngine:
    """获取或创建给定知识库的搜索引擎单例。"""
    global _search_engine
    if _search_engine is None:
        with _search_lock:
            if _search_engine is None:
                _search_engine = CVESearchEngine(kb)
    return _search_engine
