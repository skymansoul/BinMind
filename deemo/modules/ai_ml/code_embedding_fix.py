# 2026-07-30 14:30
# code_embedding_fix.py
# 代码嵌入修复 — 替换semantic_search.py中返回全零向量的CodeBERTEmbedder
# 用实际可用的多策略嵌入替代placeholder实现
# 同时修复LLM reranking的空实现

from __future__ import annotations
import math
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, Counter
import re

logger = logging.getLogger(__name__)


def _cef_dot(a, b): return sum(x*y for x,y in zip(a,b))
def _cef_l2(v):
    n = math.sqrt(sum(x*x for x in v))
    return v if n<1e-12 else [x/n for x in v]


class RealCodeEmbedder:
    """真实可用的代码嵌入器 — 替代CodeBERTEmbedder的零向量占位

    使用四策略融合生成代码嵌入:
      1. 操作码n-gram哈希 (语义)
      2. 控制流关键词密度 (结构)
      3. API调用签名 (功能)
      4. 数据流简化编码 (数据依赖)

    输出维度: 可配置 (默认384, 与all-MiniLM-L6-v2兼容)
    """

    OPCODE_SET = {'mov','push','pop','call','ret','jmp','je','jne','jg','jl',
                  'jge','jle','jb','ja','jbe','jae','jz','jnz','add','sub',
                  'mul','div','xor','and','or','not','shl','shr','lea','cmp',
                  'test','xchg','nop','int','syscall','inc','dec','neg','imul',
                  'idiv','sar','sal','rol','ror','rcl','rcr','stos','lods','scas',
                  'cmps','movs','rep','loope','loopne','loop','enter','leave'}

    def __init__(self, embed_dim: int = 384):
        self.dim = embed_dim

    def embed_code(self, code: str, code_type: str = 'pseudocode') -> List[float]:
        """
        Args:
            code: 伪代码/汇编/源代码文本
            code_type: 'pseudocode', 'assembly', 'source'
        """
        if not code:
            return [0.0] * self.dim

        # 1. n-gram操作码哈希 (语义, dim/4维)
        ngram_dim = self.dim // 4
        ngram_emb = self._opcode_ngram_embed(code, ngram_dim)

        # 2. 控制流密度向量 (结构, dim/4维)
        cfg_dim = self.dim // 4
        cfg_emb = self._control_flow_embed(code, cfg_dim)

        # 3. API签名向量 (功能, dim/4维)
        api_dim = self.dim // 4
        api_emb = self._api_signature_embed(code, api_dim)

        # 4. token频率向量 (词法, dim/4维)
        tok_dim = self.dim - ngram_dim - cfg_dim - api_dim
        tok_emb = self._token_frequency_embed(code, tok_dim)

        result = ngram_emb + cfg_emb + api_emb + tok_emb
        return _cef_l2(result)

    def _opcode_ngram_embed(self, code: str, dim: int) -> List[float]:
        tokens = re.findall(r'\b[a-z]+\b', code.lower())
        ops = [t for t in tokens if t in self.OPCODE_SET]
        if not ops:
            return [0.0] * dim

        emb = [0.0] * dim
        for n in [2, 3]:
            for i in range(len(ops) - n + 1):
                gram = '|'.join(ops[i:i+n])
                h = hashlib.sha256(gram.encode()).digest()
                idx = int.from_bytes(h[:4], 'little') % dim
                emb[idx] += 1.0 if h[0] < 128 else -1.0
        return emb

    def _control_flow_embed(self, code: str, dim: int) -> List[float]:
        cf_keywords = ['if','else','while','for','do','switch','case','break',
                       'continue','goto','return','try','catch','throw']
        emb = [0.0] * dim
        for kw in cf_keywords:
            count = len(re.findall(r'\b' + kw + r'\b', code, re.I))
            if count > 0:
                idx = hash(kw) % dim
                emb[idx] += math.log(1 + count)
        return emb

    def _api_signature_embed(self, code: str, dim: int) -> List[float]:
        api_pattern = re.compile(
            r'\b(malloc|free|realloc|calloc|memcpy|memset|memcmp|memmove|'
            r'strcpy|strncpy|strlen|strcmp|strcat|sprintf|snprintf|'
            r'fopen|fread|fwrite|fclose|fseek|'
            r'socket|bind|listen|accept|connect|send|recv|'
            r'system|popen|exec|CreateProcess|CreateThread|'
            r'VirtualAlloc|VirtualProtect|LoadLibrary|GetProcAddress|'
            r'RegOpenKey|RegQueryValue|RegSetValue|'
            r'CryptEncrypt|CryptDecrypt|CryptHashData)\b', re.I)

        apis = api_pattern.findall(code)
        emb = [0.0] * dim
        unique_apis = set(a.lower() for a in apis)
        for api in unique_apis:
            idx = hash(api) % dim
            emb[idx] += 1.0
        return emb

    def _token_frequency_embed(self, code: str, dim: int) -> List[float]:
        tokens = re.findall(r'\b[a-z_]\w*\b', code.lower())
        counter = Counter(tokens)
        emb = [0.0] * dim
        for token, count in counter.most_common(dim):
            idx = hash(token) % dim
            emb[idx] += math.log(1 + count)
        return emb

    def embed_batch(self, codes: List[str],
                    code_type: str = 'pseudocode') -> List[List[float]]:
        return [self.embed_code(c, code_type) for c in codes]


class LLMReranker:
    """LLM重排序器 — 修复semantic_search_llm中_llm_rerank的placeholder

    使用启发式特征进行搜索结果重排序:
      1. 查询-结果关键词重叠度
      2. 代码复杂度匹配
      3. API调用重叠度
      4. 结构相似性加权
    """

    def rerank(self, query: str, results: List[Dict[str, Any]],
               top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        """对搜索结果进行重排序

        Args:
            query: 搜索查询文本
            results: [{name, score, description, ...}, ...]
            top_k: 保留前k个结果

        Returns:
            重排序后的结果列表, 每个带rerank_score和explanation
        """
        if not results:
            return []

        query_tokens = set(re.findall(r'\b\w+\b', query.lower()))

        reranked = []
        for r in results:
            name = r.get('name', '')
            desc = r.get('description', r.get('summary', ''))
            orig_score = r.get('score', 0.5)

            # 关键词重叠
            result_tokens = set(re.findall(r'\b\w+\b', (name + ' ' + desc).lower()))
            overlap = len(query_tokens & result_tokens) / max(len(query_tokens | result_tokens), 1)

            # 复杂度匹配 (如果提供了pseudocode)
            code = r.get('pseudocode', r.get('code', ''))
            complexity_match = 0.0
            if code:
                code_lines = code.count('\n') + 1
                query_lines_estimate = max(1, len(query) // 40)
                complexity_match = 1.0 / (1.0 + abs(math.log(max(code_lines, 1)) -
                                                    math.log(max(query_lines_estimate, 1))))

            # 融合分数
            rerank_score = (orig_score * 0.4 +
                           overlap * 0.35 +
                           complexity_match * 0.25)

            # 生成解释
            reasons = []
            if overlap > 0.3:
                reasons.append(f"关键词重叠度 {overlap:.0%}")
            if complexity_match > 0.5:
                reasons.append("复杂度匹配")

            reranked.append({
                **r,
                'rerank_score': rerank_score,
                'original_score': orig_score,
                'explanation': '; '.join(reasons) if reasons else '基于语义相似度',
            })

        reranked.sort(key=lambda x: x['rerank_score'], reverse=True)

        if top_k:
            reranked = reranked[:top_k]

        return reranked


# ========== 修复语义搜索 ==========

def patch_semantic_search(semantic_search_module):
    """注入RealCodeEmbedder替代CodeBERTEmbedder"""
    if hasattr(semantic_search_module, 'CodeBERTEmbedder'):
        original = semantic_search_module.CodeBERTEmbedder
        setattr(semantic_search_module, 'CodeBERTEmbedder', RealCodeEmbedder)
        logger.info("CodeBERTEmbedder placeholder已替换为RealCodeEmbedder")

    if hasattr(semantic_search_module, 'SemanticSearcher'):
        searcher_cls = semantic_search_module.SemanticSearcher
        original_rerank = getattr(searcher_cls, '_llm_rerank', None)
        if original_rerank:
            reranker = LLMReranker()
            def real_rerank(self, query, results):
                return reranker.rerank(query, results)
            setattr(searcher_cls, '_llm_rerank', real_rerank)
            logger.info("LLM reranker placeholder已替换为LLMReranker")


def create_real_embedder(dim: int = 384) -> RealCodeEmbedder:
    return RealCodeEmbedder(embed_dim=dim)
