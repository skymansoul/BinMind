from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


class SearchMode(Enum):
    SEMANTIC = "semantic"
    KEYWORD = "keyword"
    VECTOR = "vector"
    HYBRID = "hybrid"


class VulnerabilityPattern(Enum):
    OVERFLOW = "overflow"
    INJECTION = "injection"
    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"


class TFIDFVectorizer:
    """TF-IDF 向量化器 - 词频加权与逆文档频率。"""

    def __init__(self) -> None:
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.vocabulary_: Dict[str, int] = {}  # 兼容 sklearn 风格命名

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r'[a-z_]+', text.lower())

    def fit(self, documents: List[str]) -> None:
        doc_freq: Dict[str, int] = {}
        for doc in documents:
            tokens = set(self._tokenize(doc))
            for tok in tokens:
                doc_freq[tok] = doc_freq.get(tok, 0) + 1
        self.vocabulary = {tok: idx for idx, tok in enumerate(doc_freq)}
        self.vocabulary_ = self.vocabulary
        n = len(documents)
        self.idf = {
            tok: math.log((1 + n) / (1 + freq)) + 1.0
            for tok, freq in doc_freq.items()
        }

    def transform(self, documents: List[str]) -> np.ndarray:
        n_docs = len(documents)
        n_terms = len(self.vocabulary)
        matrix = np.zeros((n_docs, n_terms), dtype=np.float64)
        for i, doc in enumerate(documents):
            tokens = self._tokenize(doc)
            counts: Dict[str, int] = {}
            for tok in tokens:
                counts[tok] = counts.get(tok, 0) + 1
            total = max(sum(counts.values()), 1)
            for tok, cnt in counts.items():
                if tok in self.vocabulary:
                    tf = cnt / total
                    matrix[i, self.vocabulary[tok]] = tf * self.idf.get(tok, 1.0)
        return matrix

    def fit_transform(self, documents: List[str]) -> np.ndarray:
        self.fit(documents)
        return self.transform(documents)


@dataclass
class FunctionVector:
    function_name: str = ""
    function_address: int = 0
    binary_path: str = ""
    pseudocode: str = ""
    assembly: str = ""
    vector: List[float] = field(default_factory=list)


@dataclass
class SearchResult:
    function_name: str = ""
    function_address: int = 0
    binary_path: str = ""
    similarity_score: float = 0.0
    matched_keywords: List[str] = field(default_factory=list)
    highlighted_code: str = ""
    vulnerability_indicators: List[str] = field(default_factory=list)
    match_reason: str = ""


@dataclass
class SemanticSearchResult:
    query: str = ""
    search_mode: SearchMode = SearchMode.HYBRID
    total_results: int = 0
    results: List[SearchResult] = field(default_factory=list)
    search_time: float = 0.0
    index_info: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class SearchIndex:
    total_functions: int = 0
    _functions: List[FunctionVector] = field(default_factory=list)


class SemanticVulnSearcher:
    """语义漏洞搜索器。

    TF-IDF 向量化 + 关键词加权 + 漏洞模式标注，
    支持索引的构建、保存、加载与查询。
    """

    _PATTERN_PATTERNS = [
        (VulnerabilityPattern.BUFFER_OVERFLOW,
         [r'\bmemcpy\s*\(', r'\bstrcpy\s*\(', r'\bstrcat\s*\(']),
        (VulnerabilityPattern.FORMAT_STRING,
         [r'\bprintf\s*\([^,]*[,]', r'\bsprintf\s*\(', r'\bvsprintf\s*\(']),
        (VulnerabilityPattern.INJECTION,
         [r'\bsystem\s*\(', r'\bpopen\s*\(', r'\bexec[lv]p?\s*\(']),
        (VulnerabilityPattern.USE_AFTER_FREE,
         [r'\bfree\s*\([^)]*\)[\s\S]{0,80}\*\w+\s*=']),
        (VulnerabilityPattern.OVERFLOW,
         [r'\bmalloc\s*\([^)]*\)[\s\S]{0,60}\bmemcpy\s*\(']),
    ]

    def __init__(self) -> None:
        self.tfidf_vectorizer = TFIDFVectorizer()
        self.search_index: Optional[SearchIndex] = None
        self._index_path: Optional[str] = None
        self._functions: List[FunctionVector] = []

    def _extract_keywords(self, code: str) -> List[str]:
        return re.findall(r'[a-z_]+', (code or '').lower())

    def _detect_vulnerability_patterns(self, code: str) -> List[str]:
        indicators: List[str] = []
        for pattern, regexes in self._PATTERN_PATTERNS:
            if any(re.search(rx, code or '') for rx in regexes):
                indicators.append(pattern.value)
        return indicators

    @staticmethod
    def _compute_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        n1 = np.linalg.norm(vec1)
        n2 = np.linalg.norm(vec2)
        if n1 == 0 or n2 == 0:
            return 0.0
        return float(np.dot(vec1, vec2) / (n1 * n2))

    @staticmethod
    def _compute_keyword_score(query_keywords: List[str], func_keywords: List[str]) -> float:
        if not query_keywords or not func_keywords:
            return 0.0
        qset = set(query_keywords)
        fset = set(func_keywords)
        overlap = qset & fset
        return len(overlap) / max(len(qset), 1)

    def _encode_function(self, function_name: str = "", address: int = 0,
                         binary_path: str = "", pseudocode: str = "",
                         assembly: str = "") -> FunctionVector:
        text = f"{function_name} {pseudocode} {assembly}"
        vec = self.tfidf_vectorizer.transform([text])
        if vec.shape[1] > 0:
            vector = vec[0].tolist()
        else:
            vector = []
        return FunctionVector(
            function_name=function_name,
            function_address=address,
            binary_path=binary_path,
            pseudocode=pseudocode,
            assembly=assembly,
            vector=vector,
        )

    def build_index(self, functions: List[Dict[str, Any]], index_path: Optional[str] = None) -> SearchIndex:
        texts = []
        for fn in functions:
            texts.append(f"{fn.get('function_name', '')} {fn.get('pseudocode', '')} {fn.get('assembly', '')}")
        self.tfidf_vectorizer.fit(texts)

        encoded = []
        for fn in functions:
            encoded.append(self._encode_function(
                function_name=fn.get('function_name', ''),
                address=fn.get('address', 0),
                binary_path=fn.get('binary_path', ''),
                pseudocode=fn.get('pseudocode', ''),
                assembly=fn.get('assembly', ''),
            ))
        self._functions = encoded
        self.search_index = SearchIndex(total_functions=len(encoded), _functions=encoded)
        self._index_path = index_path
        return self.search_index

    def _vectorize(self, text: str) -> np.ndarray:
        vec = self.tfidf_vectorizer.transform([text])
        if vec.shape[1] > 0:
            return vec[0]
        return np.zeros(0)

    def search(self, query: str, max_results: int = 10) -> SemanticSearchResult:
        start = __import__('time').time()
        if not self.search_index or self.search_index.total_functions == 0:
            return SemanticSearchResult(
                query=query, search_mode=SearchMode.HYBRID, total_results=0,
                results=[], search_time=0.0,
                index_info={'total_indexed': 0}, suggestions=[],
            )

        q_keywords = self._extract_keywords(query)
        q_vec = self._vectorize(query)
        funcs = self.search_index._functions
        func_vectors = [f.vector for f in funcs]
        if func_vectors and len(func_vectors[0]) > 0:
            matrix = np.array(func_vectors, dtype=np.float64)
            if matrix.shape[1] == q_vec.shape[0]:
                scores = np.dot(matrix, q_vec)
            else:
                scores = np.zeros(len(funcs))
        else:
            scores = np.zeros(len(funcs))

        scored = []
        for i, fn in enumerate(funcs):
            f_keywords = self._extract_keywords(fn.pseudocode + ' ' + fn.function_name)
            kw_score = self._compute_keyword_score(q_keywords, f_keywords)
            sim = float(scores[i]) if len(scores) else 0.0
            combined = 0.7 * sim + 0.3 * kw_score
            indicators = self._detect_vulnerability_patterns(fn.pseudocode)
            scored.append((combined, fn, kw_score, indicators))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[SearchResult] = []
        for combined, fn, kw_score, indicators in scored[:max_results]:
            highlighted = self._highlight_code(fn.pseudocode, q_keywords)
            matched = [k for k in q_keywords if k in
                       self._extract_keywords(fn.pseudocode + ' ' + fn.function_name)]
            results.append(SearchResult(
                function_name=fn.function_name,
                function_address=fn.function_address,
                binary_path=fn.binary_path,
                similarity_score=round(combined, 4),
                matched_keywords=matched,
                highlighted_code=highlighted,
                vulnerability_indicators=indicators,
                match_reason='semantic similarity' if sim >= kw_score else 'keyword match',
            ))

        elapsed = __import__('time').time() - start
        return SemanticSearchResult(
            query=query, search_mode=SearchMode.HYBRID, total_results=len(results),
            results=results, search_time=round(elapsed, 4),
            index_info={'total_indexed': len(funcs)},
            suggestions=self._generate_suggestions(query, results),
        )

    def _highlight_code(self, code: str, keywords: List[str]) -> str:
        if not code:
            return code
        lowered = code.lower()
        for kw in keywords:
            if kw and kw in lowered:
                code = re.sub(rf'\b{re.escape(kw)}\b',
                              lambda m: f"**{m.group(0)}**", code, flags=re.IGNORECASE)
        return code

    def _generate_suggestions(self, query: str, results: List[SearchResult]) -> List[str]:
        suggestions = []
        for r in results:
            for ind in r.vulnerability_indicators:
                suggestion = f"检查 {r.function_name} 的{ind}风险"
                if suggestion not in suggestions:
                    suggestions.append(suggestion)
        if not suggestions:
            suggestions.append("扩大检索范围或补充更多函数入库")
        return suggestions

    def save_index(self) -> str:
        path = self._index_path
        if not path:
            raise ValueError("index_path 未配置")
        os.makedirs(path, exist_ok=True)
        data_path = os.path.join(path, 'index.json')
        payload = {
            'total_functions': self.search_index.total_functions if self.search_index else 0,
            'functions': [
                {
                    'function_name': f.function_name,
                    'function_address': f.function_address,
                    'binary_path': f.binary_path,
                    'pseudocode': f.pseudocode,
                    'assembly': f.assembly,
                    'vector': f.vector,
                }
                for f in self._functions
            ],
        }
        with open(data_path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh)
        return data_path

    def load_index(self, path: str) -> SearchIndex:
        with open(path, 'r', encoding='utf-8') as fh:
            payload = json.load(fh)
        funcs = [
            FunctionVector(
                function_name=fn.get('function_name', ''),
                function_address=fn.get('function_address', 0),
                binary_path=fn.get('binary_path', ''),
                pseudocode=fn.get('pseudocode', ''),
                assembly=fn.get('assembly', ''),
                vector=fn.get('vector', []),
            )
            for fn in payload.get('functions', [])
        ]
        self._functions = funcs
        self.search_index = SearchIndex(total_functions=len(funcs), _functions=funcs)
        self._index_path = os.path.dirname(path)
        if funcs:
            texts = [f"{f.function_name} {f.pseudocode} {f.assembly}" for f in funcs]
            self.tfidf_vectorizer.fit(texts)
        return self.search_index


def semantic_search(query: str, max_results: int = 10) -> SemanticSearchResult:
    """便捷入口 - 无索引时返回空结果。"""
    searcher = SemanticVulnSearcher()
    return searcher.search(query, max_results=max_results)


def format_search_report(result: SemanticSearchResult) -> str:
    """将搜索结果格式化为可读报告。"""
    lines = [
        "语义漏洞搜索报告",
        "=" * 40,
        f"查询: {result.query}",
        f"模式: {result.search_mode.value}",
        f"结果数: {result.total_results}",
        f"耗时: {result.search_time}s",
        f"索引规模: {result.index_info.get('total_indexed', 0)}",
        "-" * 40,
    ]
    for r in result.results:
        lines.append(f"  [{r.similarity_score:.3f}] {r.function_name} @ 0x{r.function_address:X}")
        if r.matched_keywords:
            lines.append(f"      关键词: {', '.join(r.matched_keywords)}")
        if r.vulnerability_indicators:
            lines.append(f"      风险: {', '.join(r.vulnerability_indicators)}")
    for s in result.suggestions:
        lines.append(f"建议: {s}")
    return "\n".join(lines)
