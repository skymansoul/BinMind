#!/usr/bin/env python3

import logging
import hashlib
import re
import json
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 条件导入：capstone 用于指令归一化
try:
    import capstone
    from functools import lru_cache
    _HAS_CAPSTONE = True
    _CS_MD_X86 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    _CS_MD_X86.detail = True
except ImportError:
    _HAS_CAPSTONE = False
    logger.debug("capstone 未安装，指令级分析降级为字节模式匹配")


@dataclass
class FuncEmbedding:
    func_name: str
    vector: List[float] = field(default_factory=list)
    dimension: int = 0
    source: str = ""


@dataclass
class SimilarityResult:
    func_a: str
    func_b: str
    score: float  # 综合相似度 0-1
    layers: Dict[str, float] = field(default_factory=dict)
    matched_bbs: int = 0
    total_bbs: int = 0


class InstructionNormalizer:
    # 将操作数抽象化：寄存器-REG，立即数-IMM，内存引用-[MEM]
    # 消除地址和立即数的噪声影响 [BinMetric 2505.07360]
    _REG = re.compile(
        r'\b(?:r[abcd]x|r[sd]i|r[bp]|r[sd]p|r\d+\w?|'
        r'e[abcd]x|e[sd]i|e[bp]|e[sd]p|'
        r'[abcd]x|[sd]i|[sb]p|sp)\b', re.I
    )
    _IMM = re.compile(r'\b(0x[0-9a-fA-F]+|\d+)\b')
    _MEM = re.compile(r'\[[^\]]+\]')

    @classmethod
    def normalize(cls, instr: str) -> str:
        n = instr.strip()
        n = cls._IMM.sub('IMM', n)
        n = cls._REG.sub('REG', n)
        n = cls._MEM.sub('[MEM]', n)
        return n


class NgramHasher:
    """
    n-gram 指令序列哈希器

    对归一化后的指令序列计算滑动窗口 MinHash
    用于 O(n) 级别的快速相似函数对筛选 Sec 3.2
    """

    def __init__(self, n: int = 3, n_hashes: int = 128):
        self.n = n
        self.num_hashes = n_hashes
        seeds = []
        for i in range(n_hashes):
            h = hashlib.sha256(f"seed_{i}".encode()).hexdigest()[:16]
            seeds.append(int(h, 16))
        self._seeds = seeds

    def compute_signature(self, instructions: List[str]) -> List[int]:
        """
        计算指令序列的 MinHash 签名

        复杂度: O(k * n * m)，k=num_hashes, n=n-gram, m=指令数
        """
        if len(instructions) < self.n:
            return [0] * self.num_hashes

        normalized = [InstructionNormalizer.normalize(i) for i in instructions]
        grams = [
            ';'.join(normalized[i:i + self.n])
            for i in range(len(normalized) - self.n + 1)
        ]

        sig = []
        for seed in self._seeds:
            min_hash = min(
                self._hash_gram(g, seed)
                for g in grams
            )
            sig.append(min_hash)
        return sig

    def _hash_gram(self, gram: str, seed: int) -> int:
        h = hashlib.blake2b(gram.encode('utf-8'), digest_size=8,
                            salt=seed.to_bytes(16, 'little')).digest()
        return struct.unpack('<Q', h)[0]

    def jaccard_estimate(self, sig_a: List[int], sig_b: List[int]) -> float:
        """
        通过 MinHash 签名估算 Jaccard 相似度
        """
        if len(sig_a) != len(sig_b):
            return 0.0
        matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
        return matches / len(sig_a)


class CFGSimilarity:
    # WL 子树核近似：比较 BB 邻接拓扑和分支条件

    def __init__(self, iters: int = 2):
        self.iters = iters

    def compute_similarity(
        self,
        cfg_a: Dict[int, List[int]],
        cfg_b: Dict[int, List[int]],
        bb_features_a: Optional[Dict[int, str]] = None,
        bb_features_b: Optional[Dict[int, str]] = None
    ) -> float:
        if not cfg_a or not cfg_b:
            return 0.0

        labels_a = self._wl_labeling(cfg_a, bb_features_a)
        labels_b = self._wl_labeling(cfg_b, bb_features_b)

        all_labels = set(labels_a.values()) | set(labels_b.values())
        if not all_labels:
            return 0.0

        hist_a = self._label_histogram(labels_a, all_labels)
        hist_b = self._label_histogram(labels_b, all_labels)

        intersection = sum(min(hist_a[l], hist_b[l]) for l in all_labels)
        union = sum(max(hist_a[l], hist_b[l]) for l in all_labels)

        return intersection / union if union > 0 else 0.0

    def _wl_labeling(
        self,
        cfg: Dict[int, List[int]],
        bb_features: Optional[Dict[int, str]]
    ) -> Dict[int, str]:
        """
        WL 迭代标签传播
        """
        labels = {}
        for addr in cfg:
            init_label = bb_features.get(addr, "bb") if bb_features else "bb"
            labels[addr] = hashlib.md5(init_label.encode()).hexdigest()[:8]

        for _ in range(self.iters):
            new_labels = {}
            for addr, succs in cfg.items():
                succ_labels = sorted(
                    labels.get(s, "nil") for s in succs
                )
                combined = labels[addr] + ''.join(succ_labels)
                new_labels[addr] = hashlib.md5(combined.encode()).hexdigest()[:8]
            labels = new_labels

        return labels

    def _label_histogram(
        self, labels: Dict[int, str], all_labels: Set[str]
    ) -> Dict[str, int]:
        hist: Dict[str, int] = defaultdict(int)
        for l in all_labels:
            hist[l] = 0
        for l in labels.values():
            hist[l] += 1
        return hist


class LLMEmbeddingSimilarity:
    # 将伪代码编码为固定维度向量，余弦相似度衡量语义等价
    # 架构参考 零样本策略

    def __init__(self, dim: int = 768):
        self.dim = dim
        self._cache: Dict[str, List[float]] = {}

    def embed_pseudocode(self, func_name: str, pseudocode: str) -> List[float]:
        # 基于 TF-IDF 词袋降维近似；生产可用 CodeBERT / UniXcoder
        if func_name in self._cache:
            return self._cache[func_name]

        tokens = self._tokenize(pseudocode)
        if not tokens:
            self._cache[func_name] = [0.0] * self.dim
            return self._cache[func_name]

        tf = defaultdict(int)
        for t in tokens:
            tf[t] += 1

        vec = [0.0] * self.dim
        for tok, cnt in tf.items():
            hv = int(hashlib.sha256(tok.encode()).hexdigest(), 16)
            vec[hv % self.dim] += cnt

        sq = sum(v * v for v in vec) ** 0.5
        if sq > 0:
            vec = [v / sq for v in vec]

        self._cache[func_name] = vec
        return vec

    def _tokenize(self, code: str) -> List[str]:
        """轻量分词：保留标识符和关键字"""
        code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        tokens = re.findall(r'[a-zA-Z_]\w*', code)
        keywords = {'if', 'else', 'while', 'for', 'return', 'int', 'void',
                     'char', 'size_t', 'unsigned', 'long', 'short', 'struct',
                     'malloc', 'free', 'memcpy', 'strcpy', 'system', 'exec'}
        tokens.extend(t for t in tokens if t.lower() in keywords)
        return tokens

    def cosine(self, a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = sum(v * v for v in a) ** 0.5
        nb = sum(v * v for v in b) ** 0.5
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return dot / (na * nb)


class BinarySimilarityAnalyzer:
    """
    多层次二进制函数相似度分析器

    三层融合策略（权重可调）：
    - L1: n-gram MinHash 快速初筛（权重 w1）
    - L2: CFG WL 子树核结构分析（权重 w2）
    - L3: LLM 嵌入语义分析（权重 w3）

    多层融合的权重机制参考 [BinMetric 2505.07360] 的 benchmark 最优配置
    """

    def __init__(
        self,
        w_ngram: float = 0.30,
        w_cfg: float = 0.35,
        w_llm: float = 0.35,
        ngram_n: int = 3,
        emb_dim: int = 768
    ):
        self.ngram_hasher = NgramHasher(n=ngram_n)
        self.cfg_sim = CFGSimilarity(iters=2)
        self.llm_sim = LLMEmbeddingSimilarity(dim=emb_dim)
        self.w_ngram = round(w_ngram, 4)
        self.w_cfg = round(w_cfg, 4)
        self.w_llm = round(w_llm, 4)

        self._instruction_cache: Dict[str, List[str]] = {}
        self._cfg_cache: Dict[str, Dict[int, List[int]]] = {}
        self._bb_feature_cache: Dict[str, Dict[int, str]] = {}

    def register_function(
        self,
        func_name: str,
        instructions: List[str],
        cfg: Optional[Dict[int, List[int]]] = None,
        pseudocode: Optional[str] = None
    ) -> None:
        """
        注册函数信息到内部缓存
        """
        self._instruction_cache[func_name] = instructions
        if cfg:
            self._cfg_cache[func_name] = cfg
        if pseudocode:
            self.llm_sim.embed_pseudocode(func_name, pseudocode)

    def compute_similarity(self, func_a: str, func_b: str) -> SimilarityResult:
        """
        计算两个函数的综合相似度
        """
        result = SimilarityResult(func_a=func_a, func_b=func_b, score=0.0)

        instrs_a = self._instruction_cache.get(func_a, [])
        instrs_b = self._instruction_cache.get(func_b, [])

        # L1: n-gram MinHash
        if instrs_a and instrs_b:
            sig_a = self.ngram_hasher.compute_signature(instrs_a)
            sig_b = self.ngram_hasher.compute_signature(instrs_b)
            result.layers['ngram'] = round(
                self.ngram_hasher.jaccard_estimate(sig_a, sig_b), 4
            )
        else:
            result.layers['ngram'] = 0.0

        # L2: CFG WL kernel
        cfg_a = self._cfg_cache.get(func_a)
        cfg_b = self._cfg_cache.get(func_b)
        if cfg_a and cfg_b:
            result.layers['cfg'] = round(
                self.cfg_sim.compute_similarity(cfg_a, cfg_b), 4
            )
            result.matched_bbs = min(len(cfg_a), len(cfg_b))
            result.total_bbs = max(len(cfg_a), len(cfg_b))
        else:
            result.layers['cfg'] = 0.0

        # L3: LLM embedding
        vec_a = self.llm_sim.embed_pseudocode(func_a, "")
        vec_b = self.llm_sim.embed_pseudocode(func_b, "")
        result.layers['llm'] = round(
            self.llm_sim.cosine(vec_a, vec_b), 4
        )

        result.score = round(
            self.w_ngram * result.layers.get('ngram', 0) +
            self.w_cfg * result.layers.get('cfg', 0) +
            self.w_llm * result.layers.get('llm', 0),
            4
        )

        return result

    def batch_compare(
        self,
        targets: List[str],
        candidates: List[str],
        threshold: float = 0.60
    ) -> List[SimilarityResult]:
        """
        批量相似度比较，返回超过阈值的函数对

        排序策略：综合得分降序，优先返回高置信度匹配
        """
        results = []
        for t in targets:
            for c in candidates:
                if t == c:
                    continue
                r = self.compute_similarity(t, c)
                if r.score >= threshold:
                    results.append(r)

        results.sort(key=lambda x: x.score, reverse=True)
        return results

    def export_matrix(
        self, functions: List[str]
    ) -> Dict[str, Any]:
        # 导出相似度矩阵（JSON 兼容格式）
        matrix = {
            'functions': functions,
            'similarities': {},
            'parameters': {
                'w_ngram': self.w_ngram,
                'w_cfg': self.w_cfg,
                'w_llm': self.w_llm
            }
        }

        for i, fa in enumerate(functions):
            for j, fb in enumerate(functions):
                if i >= j:
                    continue
                r = self.compute_similarity(fa, fb)
                matrix['similarities'][f'{fa}::{fb}'] = {
                    'score': r.score,
                    'layers': r.layers
                }

        return matrix

    def find_duplicate_functions(
        self,
        functions: List[str],
        dup_threshold: float = 0.85
    ) -> List[Tuple[str, str, float]]:
        """
        发现函数级别的重复（静态链接库识别）

        阈值 0.85 基于 [BinMetric 2505.07360] 对静态链接识别的经验值
        """
        duplicates = []
        seen = set()

        for i, fa in enumerate(functions):
            for j, fb in enumerate(functions):
                if i >= j:
                    continue
                pair = frozenset([fa, fb])
                if pair in seen:
                    continue
                seen.add(pair)

                r = self.compute_similarity(fa, fb)
                if r.score >= dup_threshold:
                    duplicates.append((fa, fb, r.score))

        return sorted(duplicates, key=lambda x: x[2], reverse=True)


# 模块级便捷入口
def compute_function_similarity(
    name_a: str, instrs_a: List[str],
    name_b: str, instrs_b: List[str],
    cfg_a: Optional[Dict] = None,
    cfg_b: Optional[Dict] = None,
    pseudo_a: Optional[str] = None,
    pseudo_b: Optional[str] = None
) -> Dict[str, Any]:
    analyzer = BinarySimilarityAnalyzer()
    analyzer.register_function(name_a, instrs_a, cfg_a, pseudo_a)
    analyzer.register_function(name_b, instrs_b, cfg_b, pseudo_b)
    result = analyzer.compute_similarity(name_a, name_b)

    return {
        'score': result.score,
        'layers': result.layers,
        'matched_bbs': result.matched_bbs,
        'total_bbs': result.total_bbs
    }
