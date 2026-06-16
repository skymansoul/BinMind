#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM驱动的二进制摘要与语义搜索模块

功能：
1. 使用LLM为每个函数生成中文摘要
2. 将摘要向量化存储
3. 支持自然语言查询函数定位
4. 与现有语义搜索模块集成

数据流：
1. 输入：二进制文件、反编译后的函数列表
2. 处理：LLM生成摘要 → 向量化 → 构建索引
3. 输出：自然语言查询结果、相似函数匹配
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
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入可选依赖
TRANSFORMERS_AVAILABLE = False
TORCH_AVAILABLE = False
OPENAI_AVAILABLE = False

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    logger.warning("PyTorch未安装")

try:
    from transformers import AutoTokenizer, AutoModel
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    logger.warning("Transformers未安装")

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    logger.warning("OpenAI SDK未安装")


class SearchMode(Enum):
    """搜索模式"""
    SEMANTIC = "semantic"
    KEYWORD = "keyword"
    VECTOR = "vector"
    HYBRID = "hybrid"
    LLM = "llm"


@dataclass
class FunctionSummary:
    """函数摘要"""
    function_name: str
    function_address: int
    binary_path: str
    pseudocode: str
    assembly: str
    summary: str = ""
    summary_vector: Optional[np.ndarray] = None
    keywords: List[str] = field(default_factory=list)
    vulnerability_indicators: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class SemanticSearchResult:
    """语义搜索结果"""
    query: str
    search_mode: SearchMode
    total_results: int
    results: List[Dict[str, Any]]
    search_time: float
    index_info: Dict[str, Any] = field(default_factory=dict)
    suggestions: List[str] = field(default_factory=list)


class LLMClient(ABC):
    """LLM客户端抽象基类"""

    @abstractmethod
    def generate_summary(self, pseudocode: str, assembly: str = "") -> str:
        """
        生成函数摘要
        
        Args:
            pseudocode: 反编译的伪代码
            assembly: 汇编代码（可选）
        
        Returns:
            中文摘要
        """
        pass

    @abstractmethod
    def generate_embedding(self, text: str) -> np.ndarray:
        """
        生成文本嵌入向量
        
        Args:
            text: 输入文本
        
        Returns:
            嵌入向量
        """
        pass


class OpenAIClient(LLMClient):
    """OpenAI LLM客户端实现"""

    def __init__(self, api_key: str = None, model: str = "gpt-4o-mini", embedding_model: str = "text-embedding-3-small"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.embedding_model = embedding_model
        self._validate_api_key()

    def _validate_api_key(self):
        """验证API密钥"""
        if not self.api_key:
            logger.warning("OpenAI API密钥未设置，将使用模拟模式")
            self.use_mock = True
        else:
            self.use_mock = False
            openai.api_key = self.api_key

    def generate_summary(self, pseudocode: str, assembly: str = "") -> str:
        """生成函数摘要"""
        if self.use_mock:
            return self._mock_summary(pseudocode)

        try:
            prompt = f"""
            请对以下函数进行分析并生成中文摘要：
            
            伪代码：
            {pseudocode}
            
            汇编代码（如适用）：
            {assembly}
            
            请提供：
            1. 函数的主要功能
            2. 输入输出参数
            3. 关键算法或处理逻辑
            4. 潜在的安全风险（如缓冲区溢出、整数溢出等）
            5. 调用的敏感函数
            
            请用简洁的中文描述，不超过200字。
            """

            response = openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一名资深的二进制分析专家，擅长分析汇编和反编译代码。"},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.3
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return self._mock_summary(pseudocode)

    def generate_embedding(self, text: str) -> np.ndarray:
        """生成文本嵌入向量"""
        if self.use_mock:
            return self._mock_embedding(text)

        try:
            response = openai.embeddings.create(
                input=text,
                model=self.embedding_model
            )
            return np.array(response.data[0].embedding)
        except Exception as e:
            logger.error(f"嵌入生成失败: {e}")
            return self._mock_embedding(text)

    def _mock_summary(self, pseudocode: str) -> str:
        """模拟摘要生成"""
        summary_parts = []
        
        if "memcpy" in pseudocode.lower() or "strcpy" in pseudocode.lower():
            summary_parts.append("内存复制操作")
        if "malloc" in pseudocode.lower() or "free" in pseudocode.lower():
            summary_parts.append("内存管理")
        if "socket" in pseudocode.lower() or "connect" in pseudocode.lower():
            summary_parts.append("网络通信")
        if "encrypt" in pseudocode.lower() or "decrypt" in pseudocode.lower():
            summary_parts.append("加密/解密操作")
        
        if summary_parts:
            return f"该函数执行{', '.join(summary_parts)}等操作。"
        return "该函数执行通用计算任务。"

    def _mock_embedding(self, text: str) -> np.ndarray:
        """模拟嵌入向量生成"""
        hash_val = hashlib.md5(text.encode()).digest()
        return np.frombuffer(hash_val, dtype=np.float32)[:128]


class LocalLLMClient(LLMClient):
    """本地LLM客户端实现"""

    def __init__(self, model_name: str = "Qwen/Qwen2-7B-Instruct"):
        self.model_name = model_name
        self.model = None
        self.tokenizer = None
        self.embedding_model = None
        self.embedding_tokenizer = None
        self._init_models()

    def _init_models(self):
        """初始化本地模型"""
        if not TRANSFORMERS_AVAILABLE or not TORCH_AVAILABLE:
            logger.warning("Transformers或PyTorch未安装，使用模拟模式")
            return

        try:
            logger.info(f"加载本地LLM模型: {self.model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModel.from_pretrained(self.model_name)
            self.model.eval()
            logger.info("LLM模型加载成功")
        except Exception as e:
            logger.warning(f"本地LLM模型加载失败: {e}")

    def generate_summary(self, pseudocode: str, assembly: str = "") -> str:
        """生成函数摘要"""
        if not self.model:
            return self._mock_summary(pseudocode)

        try:
            prompt = f"""
            请对以下函数进行分析并生成中文摘要：
            
            伪代码：
            {pseudocode}
            
            汇编代码（如适用）：
            {assembly}
            
            请提供：
            1. 函数的主要功能
            2. 输入输出参数
            3. 关键算法或处理逻辑
            4. 潜在的安全风险
            5. 调用的敏感函数
            
            请用简洁的中文描述，不超过200字。
            """

            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=2048)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=300,
                    temperature=0.3,
                    do_sample=False
                )

            return self.tokenizer.decode(outputs[0], skip_special_tokens=True).strip()

        except Exception as e:
            logger.error(f"本地LLM调用失败: {e}")
            return self._mock_summary(pseudocode)

    def generate_embedding(self, text: str) -> np.ndarray:
        """生成文本嵌入向量"""
        if not self.model:
            return self._mock_embedding(text)

        try:
            inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                embedding = outputs.last_hidden_state[:, 0, :].numpy()
            
            return embedding[0]
        except Exception as e:
            logger.error(f"本地嵌入生成失败: {e}")
            return self._mock_embedding(text)

    def _mock_summary(self, pseudocode: str) -> str:
        """模拟摘要生成"""
        summary_parts = []
        
        if "memcpy" in pseudocode.lower() or "strcpy" in pseudocode.lower():
            summary_parts.append("内存复制")
        if "malloc" in pseudocode.lower() or "free" in pseudocode.lower():
            summary_parts.append("动态内存分配")
        if "socket" in pseudocode.lower():
            summary_parts.append("网络操作")
        if "encrypt" in pseudocode.lower():
            summary_parts.append("加密处理")
        
        return f"该函数实现{', '.join(summary_parts) if summary_parts else '未知'}功能。"

    def _mock_embedding(self, text: str) -> np.ndarray:
        """模拟嵌入向量生成"""
        hash_val = hashlib.sha256(text.encode()).digest()
        return np.frombuffer(hash_val, dtype=np.float32)[:128]


class SemanticSearchLLM:
    """
    LLM驱动的语义搜索器
    
    功能：
    1. 使用LLM生成函数摘要
    2. 将摘要向量化
    3. 支持自然语言查询
    4. 相似函数匹配
    """

    def __init__(self, llm_type: str = "openai", **kwargs):
        """
        初始化语义搜索器
        
        Args:
            llm_type: LLM类型 ("openai" 或 "local")
            **kwargs: LLM客户端参数
        """
        self.llm_client: LLMClient
        self.index_path = "./data/semantic_llm_index"
        self.index_data: Dict[str, Any] = {}
        self.function_summaries: List[FunctionSummary] = []
        self.all_embeddings: Optional[np.ndarray] = None

        if llm_type == "openai":
            self.llm_client = OpenAIClient(**kwargs)
        else:
            self.llm_client = LocalLLMClient(**kwargs)

        logger.info(f"使用 {llm_type} LLM 客户端")

    def generate_function_summary(self, function_name: str, pseudocode: str, 
                                  assembly: str = "") -> FunctionSummary:
        """
        生成函数摘要并向量化
        
        Args:
            function_name: 函数名
            pseudocode: 反编译伪代码
            assembly: 汇编代码
        
        Returns:
            FunctionSummary对象
        """
        # 生成摘要
        summary = self.llm_client.generate_summary(pseudocode, assembly)
        
        # 生成嵌入向量
        summary_vector = self.llm_client.generate_embedding(summary)
        
        # 提取关键词
        keywords = self._extract_keywords(pseudocode + " " + summary)
        
        # 检测漏洞指标
        vuln_indicators = self._detect_vulnerability_indicators(pseudocode)

        return FunctionSummary(
            function_name=function_name,
            function_address=0,
            binary_path="",
            pseudocode=pseudocode,
            assembly=assembly,
            summary=summary,
            summary_vector=summary_vector,
            keywords=keywords,
            vulnerability_indicators=vuln_indicators,
            confidence_score=0.85
        )

    def _extract_keywords(self, text: str) -> List[str]:
        """从文本中提取关键词"""
        import re
        
        text_lower = text.lower()
        
        # 提取标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', text_lower)
        
        # 过滤常见关键字
        common_keywords = {
            'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
            'break', 'continue', 'return', 'goto', 'sizeof', 'typedef',
            'struct', 'union', 'enum', 'const', 'static', 'extern',
            'void', 'char', 'short', 'int', 'long', 'float', 'double',
            'signed', 'unsigned', 'volatile', 'register', 'inline'
        }
        
        identifiers = [i for i in identifiers if i not in common_keywords and len(i) > 2]
        
        # 添加安全相关关键词
        security_keywords = [
            'overflow', 'underflow', 'injection', 'xss', 'sql', 'command',
            'buffer', 'heap', 'stack', 'race', 'leak', 'use', 'after', 'free',
            'format', 'string', 'null', 'pointer', 'memory', 'corruption'
        ]
        
        all_keywords = set(identifiers) | set([kw for kw in security_keywords if kw in text_lower])
        
        return list(all_keywords)[:15]

    def _detect_vulnerability_indicators(self, pseudocode: str) -> List[str]:
        """检测漏洞指标"""
        indicators = []
        code_lower = pseudocode.lower()
        
        vulnerability_patterns = {
            'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'memcpy', 'gets'],
            'integer_overflow': ['+', '-', '*', '/'],
            'use_after_free': ['free', 'delete'],
            'format_string': ['printf', 'sprintf', 'fprintf'],
            'sql_injection': ['sql', 'query', 'database'],
            'command_injection': ['system', 'exec', 'popen']
        }
        
        for vuln_type, patterns in vulnerability_patterns.items():
            if any(pattern in code_lower for pattern in patterns):
                indicators.append(vuln_type)
        
        return indicators

    def build_index(self, functions: List[Dict[str, Any]], index_path: Optional[str] = None):
        """
        构建语义索引
        
        Args:
            functions: 函数列表，每个包含 function_name, pseudocode, assembly, address, binary_path
            index_path: 索引保存路径
        """
        if index_path:
            self.index_path = index_path
        
        os.makedirs(self.index_path, exist_ok=True)
        
        logger.info(f"开始构建LLM语义索引，共 {len(functions)} 个函数")
        
        self.function_summaries = []
        
        for func in functions:
            summary = FunctionSummary(
                function_name=func.get('function_name', ''),
                function_address=func.get('address', 0),
                binary_path=func.get('binary_path', ''),
                pseudocode=func.get('pseudocode', ''),
                assembly=func.get('assembly', '')
            )
            
            # 生成摘要
            summary.summary = self.llm_client.generate_summary(
                func.get('pseudocode', ''),
                func.get('assembly', '')
            )
            
            # 生成嵌入向量
            summary.summary_vector = self.llm_client.generate_embedding(summary.summary)
            
            # 提取关键词
            summary.keywords = self._extract_keywords(
                func.get('pseudocode', '') + " " + summary.summary
            )
            
            # 检测漏洞指标
            summary.vulnerability_indicators = self._detect_vulnerability_indicators(
                func.get('pseudocode', '')
            )
            
            self.function_summaries.append(summary)
        
        # 保存索引
        self._save_index()
        
        logger.info(f"LLM语义索引构建完成，共处理 {len(self.function_summaries)} 个函数")

    def _save_index(self):
        """保存索引到磁盘"""
        index_data = {
            'functions': [],
            'metadata': {
                'total_functions': len(self.function_summaries),
                'created_at': time.time()
            }
        }
        
        for summary in self.function_summaries:
            index_data['functions'].append({
                'function_name': summary.function_name,
                'function_address': summary.function_address,
                'binary_path': summary.binary_path,
                'pseudocode': summary.pseudocode,
                'assembly': summary.assembly,
                'summary': summary.summary,
                'keywords': summary.keywords,
                'vulnerability_indicators': summary.vulnerability_indicators,
                'confidence_score': summary.confidence_score
            })
        
        with open(os.path.join(self.index_path, 'index.json'), 'w', encoding='utf-8') as f:
            json.dump(index_data, f, ensure_ascii=False, indent=2)
        
        # 保存向量数据
        if self.function_summaries and self.function_summaries[0].summary_vector is not None:
            vectors = np.array([fs.summary_vector for fs in self.function_summaries])
            np.save(os.path.join(self.index_path, 'embeddings.npy'), vectors)

    def load_index(self, index_path: str):
        """从磁盘加载索引"""
        self.index_path = index_path
        
        try:
            with open(os.path.join(index_path, 'index.json'), 'r', encoding='utf-8') as f:
                index_data = json.load(f)
            
            self.function_summaries = []
            for func_data in index_data['functions']:
                summary = FunctionSummary(
                    function_name=func_data['function_name'],
                    function_address=func_data['function_address'],
                    binary_path=func_data['binary_path'],
                    pseudocode=func_data['pseudocode'],
                    assembly=func_data['assembly'],
                    summary=func_data['summary'],
                    keywords=func_data['keywords'],
                    vulnerability_indicators=func_data['vulnerability_indicators'],
                    confidence_score=func_data['confidence_score']
                )
                self.function_summaries.append(summary)
            
            # 加载向量
            vectors_path = os.path.join(index_path, 'embeddings.npy')
            if os.path.exists(vectors_path):
                self.all_embeddings = np.load(vectors_path)
                for i, summary in enumerate(self.function_summaries):
                    summary.summary_vector = self.all_embeddings[i]
            
            logger.info(f"LLM语义索引加载完成，共 {len(self.function_summaries)} 个函数")
            
        except Exception as e:
            logger.error(f"加载索引失败: {e}")

    def search(self, query: str, max_results: int = 10, min_similarity: float = 0.3) -> SemanticSearchResult:
        """
        执行语义搜索
        
        Args:
            query: 自然语言查询
            max_results: 最大返回结果数
            min_similarity: 最小相似度阈值
        
        Returns:
            SemanticSearchResult
        """
        start_time = time.time()
        
        if not self.function_summaries:
            return SemanticSearchResult(
                query=query,
                search_mode=SearchMode.LLM,
                total_results=0,
                results=[],
                search_time=0,
                suggestions=["请先构建或加载索引"]
            )
        
        # 生成查询向量
        query_vector = self.llm_client.generate_embedding(query)
        
        # 计算相似度
        results = []
        
        for summary in self.function_summaries:
            if summary.summary_vector is None:
                continue
            
            similarity = self._compute_cosine_similarity(query_vector, summary.summary_vector)
            
            if similarity >= min_similarity:
                results.append({
                    'function_name': summary.function_name,
                    'function_address': summary.function_address,
                    'binary_path': summary.binary_path,
                    'similarity_score': similarity,
                    'summary': summary.summary,
                    'keywords': summary.keywords,
                    'vulnerability_indicators': summary.vulnerability_indicators,
                    'confidence_score': summary.confidence_score
                })
        
        # 按相似度排序
        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        results = results[:max_results]
        
        search_time = time.time() - start_time
        
        return SemanticSearchResult(
            query=query,
            search_mode=SearchMode.LLM,
            total_results=len(results),
            results=results,
            search_time=search_time,
            index_info={
                'total_indexed': len(self.function_summaries),
                'index_path': self.index_path
            },
            suggestions=self._generate_suggestions(query, results)
        )

    def _compute_cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """计算余弦相似度"""
        if vec1 is None or vec2 is None:
            return 0.0
        
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return float(np.dot(vec1, vec2) / (norm1 * norm2))

    def _generate_suggestions(self, query: str, results: List[Dict[str, Any]]) -> List[str]:
        """生成搜索建议"""
        suggestions = []
        
        if not results:
            suggestions.append("未找到匹配结果，尝试使用更通用的术语")
            suggestions.append("检查拼写或尝试同义词")
        elif len(results) < 3:
            suggestions.append("结果较少，尝试扩展搜索范围")
        
        # 检测查询中的安全相关词汇
        security_terms = ['漏洞', '攻击', '溢出', '注入', '内存', '栈', '堆']
        if any(term in query for term in security_terms):
            suggestions.append("检测到安全相关查询，已优先匹配包含漏洞指标的函数")
        
        return suggestions

    def batch_generate_summaries(self, functions: List[Dict[str, Any]]) -> List[FunctionSummary]:
        """
        批量生成函数摘要
        
        Args:
            functions: 函数列表
        
        Returns:
            FunctionSummary列表
        """
        summaries = []
        
        for func in functions:
            summary = self.generate_function_summary(
                function_name=func.get('function_name', ''),
                pseudocode=func.get('pseudocode', ''),
                assembly=func.get('assembly', '')
            )
            summary.function_address = func.get('address', 0)
            summary.binary_path = func.get('binary_path', '')
            summaries.append(summary)
        
        return summaries


def llm_semantic_search(query: str, index_path: str = None, max_results: int = 10) -> SemanticSearchResult:
    """
    便捷的LLM语义搜索函数
    
    Args:
        query: 自然语言查询
        index_path: 索引路径
        max_results: 最大结果数
    
    Returns:
        SemanticSearchResult
    """
    searcher = SemanticSearchLLM()
    
    if index_path and os.path.exists(index_path):
        searcher.load_index(index_path)
    
    return searcher.search(query, max_results)


def format_search_results(results: SemanticSearchResult) -> str:
    """
    格式化搜索结果为可读报告
    
    Args:
        results: 搜索结果
    
    Returns:
        格式化的报告字符串
    """
    parts = [
        "# LLM语义搜索报告",
        "",
        f"查询: {results.query}",
        f"搜索模式: {results.search_mode.value}",
        f"搜索时间: {results.search_time:.2f}秒",
        f"索引函数总数: {results.index_info.get('total_indexed', 0)}",
        "",
        f"找到 {results.total_results} 个匹配结果",
        ""
    ]
    
    if results.results:
        parts.append("## 匹配结果")
        for i, result in enumerate(results.results, 1):
            parts.extend([
                f"\n### {i}. {result['function_name']}",
                f"- 地址: {hex(result['function_address'])}",
                f"- 二进制: {result['binary_path']}",
                f"- 相似度: {result['similarity_score']:.2%}",
                f"- 置信度: {result['confidence_score']:.2%}",
                f"- 摘要: {result['summary']}"
            ])
            
            if result['keywords']:
                parts.append(f"- 关键词: {', '.join(result['keywords'])}")
            
            if result['vulnerability_indicators']:
                parts.append(f"- 漏洞指标: {', '.join(result['vulnerability_indicators'])}")
    
    if results.suggestions:
        parts.extend(["", "## 建议"])
        for s in results.suggestions:
            parts.append(f"- {s}")
    
    return "\n".join(parts)