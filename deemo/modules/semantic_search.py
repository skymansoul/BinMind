#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
二进制语义漏洞搜索引擎模块

提供基于语义代码搜索的漏洞发现能力：
- 使用预训练代码语义模型（如GraphCodeBERT）
- 自然语言查询转换为向量
- 函数语义相似度搜索
- 与漏洞数据库集成
"""

import logging
import os
import json
import time
import hashlib
import numpy as np
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
TRANSFORMERS_AVAILABLE = False
TORCH_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch未安装，语义搜索功能将受限")

try:
    from transformers import AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers未安装，将使用TF-IDF替代方案")


class SearchMode(Enum):
    """搜索模式"""
    SEMANTIC = "semantic"       # 语义搜索
    KEYWORD = "keyword"        # 关键词搜索
    VECTOR = "vector"          # 向量相似度搜索
    HYBRID = "hybrid"          # 混合搜索


class VulnerabilityPattern(Enum):
    """漏洞模式"""
    OVERFLOW = "overflow"
    INJECTION = "injection"
    RACE_CONDITION = "race_condition"
    MEMORY_LEAK = "memory_leak"
    USE_AFTER_FREE = "use_after_free"
    BUFFER_OVERFLOW = "buffer_overflow"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"


@dataclass
class FunctionVector:
    """函数向量表示"""
    function_name: str
    function_address: int
    binary_path: str
    pseudocode: str
    assembly: str
    vector: Optional[np.ndarray] = None
    keywords: List[str] = field(default_factory=list)
    vulnerability_patterns: List[VulnerabilityPattern] = field(default_factory=list)


@dataclass
class SearchResult:
    """搜索结果"""
    function_name: str
    function_address: int
    binary_path: str
    similarity_score: float
    matched_keywords: List[str] = field(default_factory=list)
    highlighted_code: str = ""
    vulnerability_indicators: List[str] = field(default_factory=list)
    match_reason: str = ""


@dataclass
class SearchIndex:
    """搜索索引"""
    index_path: str
    functions: List[FunctionVector] = field(default_factory=list)
    index_metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0
    total_functions: int = 0


@dataclass
class SemanticSearchResult:
    """语义搜索结果"""
    query: str
    search_mode: SearchMode
    total_results: int
    results: List[SearchResult]
    search_time: float
    index_info: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)


class TFIDFVectorizer:
    """
    TF-IDF向量化器（当transformers不可用时的替代方案）

    基于TF-IDF的文本向量化实现
    """

    def __init__(self):
        """初始化向量化器"""
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_count = 0

    def fit(self, documents: List[str]) -> 'TFIDFVectorizer':
        """
        训练TF-IDF模型

        Args:
            documents: 文档列表

        Returns:
            self
        """
        self.doc_count = len(documents)

        # 构建词汇表
        word_doc_freq = defaultdict(int)
        for doc in documents:
            words = self._tokenize(doc)
            for word in set(words):
                word_doc_freq[word] += 1

        # 构建词汇表和IDF
        self.vocabulary = {}
        idx = 0,
        for word, freq in sorted(word_doc_freq.items()):
            if freq >= 2:  # 过滤低频词
                self.vocabulary[word] = idx
                self.idf[word] = np.log(self.doc_count / (freq + 1

                idx += 1

        return self

    def transform(self, documents: List[str]) -> np.ndarray:
        """
        将文档转换为TF-IDF向量

        Args:
            documents: 文档列表

        Returns:
            文档向量矩阵
        """
        vectors = []

        for doc in documents:
            words = self._tokenize(doc)
            word_freq = defaultdict(int)
            for word in words:
                word_freq[word] += 1

            # 计算TF-IDF
            vector = np.zeros(len(self.vocabulary

            for word, freq in word_freq.items():
                if word in self.vocabulary:
                    tf = freq / len(words) if words else 0
                    vector[self.vocabulary[word]] = tf * self.idf.get(word, 0)

            vectors.append(vector)

        return np.array(vectors)

    def fit_transform(self, documents: List[str]) -> np.ndarray:
        """
        训练并转换

        Args:
            documents: 文档列表

        Returns:
            文档向量矩阵
        """
        self.fit(documents)
        return self.transform(documents)

    def _tokenize(self, text: str) -> List[str]:
        """
        分词

        Args:
            text: 输入文本

        Returns:
            词列表
        """
        # 简单分词：转小写，提取单词和数字序列
        import re
        text = text.lower()
        tokens = re.findall(r'[a-z_][a-z0-9_]*', text)
        return tokens


class SemanticVulnSearcher:
    """
    语义漏洞搜索引擎

    功能：
    1. 函数向量化
    2. 语义索引构建
    3. 自然语言查询
    4. 相似度匹配
    5. 漏洞模式识别
    """

    def __init__(self, model_name: str = "microsoft/graphcodebert-base"):
        """
        初始化语义搜索器

        Args:
            model_name: 预训练模型名称
        """
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.tfidf_vectorizer = TFIDFVectorizer()
        self.search_index: Optional[SearchIndex] = None
        self.index_path = "./data/semantic_index"

        # 漏洞关键词映射
        self.vulnerability_keywords = {
            VulnerabilityPattern.OVERFLOW: ['overflow', 'overrun', 'overwrite', 'buffer', 'size'],
            VulnerabilityPattern.INJECTION: ['injection', 'execute', 'eval', 'parse', 'command'],
            VulnerabilityPattern.RACE_CONDITION: ['race', 'concurrent', 'thread', 'mutex', 'lock'],
            VulnerabilityPattern.MEMORY_LEAK: ['leak', 'allocate', 'free', 'malloc', 'alloc'],
            VulnerabilityPattern.USE_AFTER_FREE: ['free', 'use', 'dangling', 'pointer', 'invalid'],
            VulnerabilityPattern.BUFFER_OVERFLOW: ['buffer', 'overflow', 'copy', 'strcpy', 'memcpy'],
            VulnerabilityPattern.SQL_INJECTION: ['sql', 'query', 'database', 'execute', 'input'],
            VulnerabilityPattern.XSS: ['html', 'script', 'xss', 'escape', 'sanitize'],
            VulnerabilityPattern.COMMAND_INJECTION: ['command', 'exec', 'system', 'shell', 'popen'],
        }

        self._init_model()

    def _init_model(self):
        """初始化模型"""
        if TRANSFORMERS_AVAILABLE and TORCH_AVAILABLE:
            try:
                logger.info(f"加载预训练模型: {self.model_name}")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModel.from_pretrained(self.model_name)
                self.model.eval()
                logger.info("模型加载成功")
            except Exception as e:
                logger.warning(f"模型加载失败: {e}，使用TF-IDF替代方案")
                self.model = None
        else:
            logger.info("使用TF-IDF替代方案进行语义搜索")

    def _compute_code_embedding(self, code: str) -> np.ndarray:
        """
        计算代码的语义向量表示

        Args:
            code: 代码文本

        Returns:
            嵌入向量
        """
        if self.model and self.tokenizer:
            try:
                with torch.no_grad():
                    inputs = self.tokenizer(code, return_tensors="pt")
                                          truncation=True, max_length=512
                    outputs = self.model(**inputs)
                    # 使用[CLS]标记的输出作为句子表示
                    embedding = outputs.last_hidden_state[:, 0, :].numpy()
                    return embedding[0]
            except Exception as e:
                logger.warning(f"模型推理失败: {e}")

        # 使用TF-IDF作为后备方案
        return self._compute_tfidf_embedding(code)

    def _compute_tfidf_embedding(self, code: str) -> np.ndarray:
        """
        使用TF-IDF计算嵌入

        Args:
            code: 代码文本

        Returns:
            TF-IDF向量
        """
        vector = self.tfidf_vectorizer.transform([code])
        return vector[0] if len(vector) > 0 else np.zeros(100)

    def _extract_keywords(self, code: str) -> List[str]:
        """
        从代码中提取关键词

        Args:
            code: 代码文本

        Returns:
            关键词列表
        """
        import re

        # 提取标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', code.lower(


        # 过滤常见关键字
        keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
            'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
            'struct', 'union', 'enum', 'const', 'static', 'extern',
            'void', 'char', 'short', 'int', 'long', 'float', 'double',
            'signed', 'unsigned', 'volatile', 'register', 'inline',
            'public', 'private', 'protected', 'class', 'virtual', 'new', 'delete',
            'try', 'catch', 'throw', 'catch', 'finally', 'async', 'await'
        }

        identifiers = [i for i in identifiers if i not in keywords and len(i) > 2]

        # 提取CVE相关关键词
        security_keywords = [
            'overflow', 'underflow', 'injection', 'xss', 'sql', 'command',
            'buffer', 'heap', 'stack', 'race', 'leak', 'use', 'after', 'free',
            'format', 'string', 'null', 'pointer', 'memory', 'corruption'
        ]

        all_keywords = set(identifiers) | set(security_keywords)

        return list(all_keywords)[:20]

    def _detect_vulnerability_patterns(self, code: str) -> List[VulnerabilityPattern]:
        """
        检测代码中的漏洞模式

        Args:
            code: 代码文本

        Returns:
            检测到的漏洞模式列表
        """
        detected = []
        code_lower = code.lower()

        for pattern, keywords in self.vulnerability_keywords.items():
            matches = sum(1 for kw in keywords if kw in code_lower)
            if matches >= 2:
                detected.append(pattern)

        return detected

    def _encode_function(self, function_name: str, address: int, binary_path: str, pseudocode: str, assembly: str = "") -> FunctionVector:
        """
        对函数进行编码

        Args:
            function_name: 函数名
            address: 函数地址
            binary_path: 二进制路径
            pseudocode: 伪代码
            assembly: 汇编代码

        Returns:
            FunctionVector
        """
        # 合并代码文本
        code_text = f"{function_name} {pseudocode} {assembly}"

        # 计算向量
        vector = self._compute_code_embedding(code_text)

        # 提取关键词
        keywords = self._extract_keywords(code_text)

        # 检测漏洞模式
        patterns = self._detect_vulnerability_patterns(code_text)

        return FunctionVector(
            function_name=function_name,
            function_address=address,
            binary_path=binary_path,
            pseudocode=pseudocode,
            assembly=assembly,
            vector=vector,
            keywords=keywords,
            vulnerability_patterns=patterns)
        


    def build_index(self, functions: List[Dict[str, Any]], index_path: Optional[str] = None) -> SearchIndex:
        """
        构建搜索索引

        Args:
            functions: 函数列表，每个字典包含 function_name, address, binary_path, pseudocode, assembly
            index_path: 索引保存路径

        Returns:
            SearchIndex
        """
        if index_path:
            self.index_path = index_path

        os.makedirs(self.index_path, exist_ok=True)

        logger.info(f"开始构建语义索引，共 {len(functions)} 个函数")

        # 编码所有函数
        function_vectors: List[FunctionVector] = []
        for func in functions:
            fv = self._encode_function()
                function_name=func.get('function_name', ''),
                address=func.get('address', 0),
                binary_path=func.get('binary_path', ''),
                pseudocode=func.get('pseudocode', ''),
                assembly=func.get('assembly', '')
            
            function_vectors.append(fv)

        # 训练TF-IDF（用于后备搜索）
        all_codes = [f"{f.pseudocode} {f.assembly}" for f in function_vectors]
        self.tfidf_vectorizer = TFIDFVectorizer()
        self.tfidf_vectorizer.fit(all_codes)

        # 创建索引
        self.search_index = SearchIndex()
            index_path=self.index_path,
            functions=function_vectors,
            index_metadata={
                'model_name': self.model_name if TRANSFORMERS_AVAILABLE else 'tfidf',
                'total_functions': len(functions),
                'binary_paths': list(set(f.binary_path for f in function_vectors

            },
            created_at=time.time(),
            total_functions=len(functions)
        

        logger.info(f"索引构建完成，共索引 {len(function_vectors)} 个函数")

        return self.search_index

    def save_index(self, output_path: Optional[str] = None) -> str:
        """
        保存索引到磁盘

        Args:
            output_path: 输出路径

        Returns:
            保存的路径
        """
        if not self.search_index:
            raise ValueError("没有可保存的索引")

        if output_path:
            self.index_path = output_path

        os.makedirs(self.index_path, exist_ok=True)

        # 保存函数数据（不含向量）
        functions_data = []
        for fv in self.search_index.functions:
            functions_data.append({)
                'function_name': fv.function_name,
                'function_address': fv.function_address,
                'binary_path': fv.binary_path,
                'pseudocode': fv.pseudocode,
                'assembly': fv.assembly,
                'keywords': fv.keywords,
                'vulnerability_patterns': [p.value for p in fv.vulnerability_patterns]
            }

        with open(os.path.join(self.index_path, 'functions.json'), 'w', encoding='utf-8') as f:
            json.dump(functions_data, f, ensure_ascii=False, indent=2)

        # 保存元数据
        metadata = {
            'model_name': self.search_index.index_metadata.get('model_name', 'unknown'),
            'total_functions': self.search_index.total_functions,
            'binary_paths': self.search_index.index_metadata.get('binary_paths', []),
            'created_at': self.search_index.created_at
        }

        with open(os.path.join(self.index_path, 'metadata.json'), 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

        logger.info(f"索引已保存到: {self.index_path}")

        return self.index_path

    def load_index(self, index_path: str) -> SearchIndex:
        """
        从磁盘加载索引

        Args:
            index_path: 索引路径

        Returns:
            SearchIndex
        """
        self.index_path = index_path

        # 加载函数数据
        functions_path = os.path.join(index_path, 'functions.json')
        with open(functions_path, 'r', encoding='utf-8') as f:
            functions_data = json.load(f)

        # 重新构建函数向量
        function_vectors = []
        for fd in functions_data:
            fv = FunctionVector()
                function_name=fd['function_name'],
                function_address=fd['function_address'],
                binary_path=fd['binary_path'],
                pseudocode=fd['pseudocode'],
                assembly=fd['assembly'],
                keywords=fd.get('keywords', []),
                vulnerability_patterns=[
                    VulnerabilityPattern(p) for p in fd.get('vulnerability_patterns', [])
                ]
            

            # 重新计算向量
            code_text = f"{fv.pseudocode} {fv.assembly}"
            fv.vector = self._compute_code_embedding(code_text)

            function_vectors.append(fv)

        # 加载元数据
        metadata_path = os.path.join(index_path, 'metadata.json')
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)

        self.search_index = SearchIndex()
            index_path=index_path,
            functions=function_vectors,
            index_metadata=metadata,
            created_at=metadata.get('created_at', 0),
            total_functions=len(function_vectors)
        

        logger.info(f"索引已加载，共 {len(function_vectors)} 个函数")

        return self.search_index

    def _compute_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """
        计算向量余弦相似度

        Args:
            vec1: 向量1
            vec2: 向量2

        Returns:
            相似度分数 [0, 1]
        """
        if vec1 is None or vec2 is None:
            return 0.0

        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(np.dot(vec1, vec2) / (norm1 * norm2


    def _compute_keyword_score(self, query_keywords: List[str], func_keywords: List[str]) -> float:
        """
        计算关键词匹配分数

        Args:
            query_keywords: 查询关键词
            func_keywords: 函数关键词

        Returns:
            匹配分数 [0, 1]
        """
        if not query_keywords or not func_keywords:
            return 0.0

        matches = sum(1 for qk in query_keywords if qk in func_keywords)
        return matches / len(query_keywords)

    def search(self, query: str, max_results: int = 10, min_similarity: float = 0.3) -> SemanticSearchResult:
        """
        执行语义搜索

        Args:
            query: 查询字符串（自然语言或关键词）
            max_results: 最大返回结果数
            min_similarity: 最小相似度阈值

        Returns:
            SemanticSearchResult
        """
        start_time = time.time()

        if not self.search_index:
            return SemanticSearchResult(
                query=query,
                search_mode=SearchMode.SEMANTIC,
                total_results=0,
                results=[],
                search_time=0,
                suggestions=["请先构建或加载索引"])
            


        # 提取查询关键词
        query_keywords = self._extract_keywords(query)

        # 检测查询中的漏洞模式
        query_patterns = self._detect_vulnerability_patterns(query)

        # 计算查询向量
        query_vector = self._compute_code_embedding(query)

        # 搜索匹配
        results: List[SearchResult] = []

        for func in self.search_index.functions:
            # 语义相似度
            semantic_score = self._compute_similarity(query_vector, func.vector)

            # 关键词匹配分数
            keyword_score = self._compute_keyword_score(query_keywords, func.keywords)

            # 漏洞模式匹配
            pattern_score = 0.0,
            if query_patterns:
                pattern_matches = sum(1 for p in query_patterns if p in func.vulnerability_patterns)
                pattern_score = pattern_matches / len(query_patterns)

            # 综合分数
            combined_score = (semantic_score * 0.5 +)
                            keyword_score * 0.3 +
                            pattern_score * 0.2

            if combined_score >= min_similarity:
                # 构建匹配原因
                match_reasons = []
                if semantic_score >= 0.5:
                    match_reasons.append("语义相似")
                if keyword_score >= 0.5:
                    match_reasons.append("关键词匹配")
                if pattern_score >= 0.5:
                    match_reasons.append("漏洞模式相似")

                # 高亮代码
                highlighted = self._highlight_code(func.pseudocode, query_keywords)

                result = SearchResult()
                    function_name=func.function_name,
                    function_address=func.function_address,
                    binary_path=func.binary_path,
                    similarity_score=combined_score,
                    matched_keywords=[kw for kw in query_keywords if kw in func.keywords],
                    highlighted_code=highlighted,
                    vulnerability_indicators=[p.value for p in func.vulnerability_patterns],
                    match_reason="、".join(match_reasons) if match_reasons else "模糊匹配"
                
                results.append(result)

        # 按分数排序
        results.sort(key=lambda x: x.similarity_score, reverse=True)

        # 截取最大结果数
        results = results[:max_results]

        # 生成建议
        suggestions = self._generate_suggestions(query, results)

        return SemanticSearchResult(
            query=query,
            search_mode=SearchMode.HYBRID,
            total_results=len(results),
            results=results,
            search_time=time.time() - start_time,
            index_info={
                'total_indexed': self.search_index.total_functions,
                'index_path': self.search_index.index_path
            },
            suggestions=suggestions)
        


    def _highlight_code(self, code: str, keywords: List[str]) -> str:
        """
        在代码中高亮关键词

        Args:
            code: 代码文本
            keywords: 关键词列表

        Returns:
            高亮后的代码
        """
        highlighted = code

        for kw in keywords:
            # 简单实现：在匹配词前后添加标记
            import re
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            highlighted = pattern.sub(f"**{kw.upper()}**", highlighted)

        # 截取前20行
        lines = highlighted.split('\n')[:20]
        if len(highlighted.split('\n')) > 20:
            lines.append('...')

        return '\n'.join(lines)

    def _generate_suggestions(self, query: str, results: List[SearchResult]) -> List[str]:
        """
        生成搜索建议

        Args:
            query: 查询字符串
            results: 搜索结果

        Returns:
            建议列表
        """
        suggestions = []

        if not results:
            suggestions.append("未找到匹配结果，尝试使用更通用的术语")
            suggestions.append("检查拼写或尝试同义词")
        elif len(results) < 3:
            suggestions.append("结果较少，尝试扩展搜索范围")

        # 基于检测到的漏洞模式建议
        query_patterns = self._detect_vulnerability_patterns(query)
        if query_patterns:
            suggestions.append(f"已检测到漏洞模式: {[p.value for p in query_patterns]}")

        return suggestions


def semantic_search(query: str, index_path: str = None, max_results: int = 10) -> SemanticSearchResult:
    """
    执行语义搜索的便捷函数

    Args:
        query: 查询字符串
        index_path: 索引路径
        max_results: 最大结果数

    Returns:
        SemanticSearchResult
    """
    searcher = SemanticVulnSearcher()

    if index_path and os.path.exists(index_path):
        searcher.load_index(index_path)
    elif not searcher.search_index:
        logger.warning("没有可用的索引，请先构建索引")

    return searcher.search(query, max_results)


def format_search_report(result: SemanticSearchResult) -> str:
    """
    格式化搜索报告

    Args:
        result: 搜索结果

    Returns:
        格式化的报告字符串
    """
    parts = [
        "# 语义漏洞搜索报告",
        "",
        f"查询: {result.query}",
        f"搜索模式: {result.search_mode.value}",
        f"搜索时间: {result.search_time:.2f}秒",
        f"索引函数总数: {result.index_info.get('total_indexed', 0)}",
        "",
        f"找到 {result.total_results} 个匹配结果",
        ""
    ]

    if result.results:
        parts.append("## 匹配结果")
        for i, r in enumerate(result.results, 1):
            parts.extend([)
                f"\n### {i}. {r.function_name}",
                f"- 地址: {hex(r.function_address)}",
                f"- 二进制: {r.binary_path}",
                f"- 相似度: {r.similarity_score:.2%}",
                f"- 匹配原因: {r.match_reason}",
            ]

            if r.matched_keywords:
                parts.append(f"- 匹配关键词: {', '.join(r.matched_keywords)}")

            if r.vulnerability_indicators:
                parts.append(f"- 漏洞指标: {', '.join(r.vulnerability_indicators)}")

            parts.append(f"\n```\n{r.highlighted_code}\n```")
    else:
        parts.append("未找到匹配结果")

    if result.suggestions:
        parts.extend(["", "## 建议"])
        for s in result.suggestions:
            parts.append(f"- {s}")

    return "\n".join(parts)))))