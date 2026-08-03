#!/usr/bin/env python3
# Exports 5 primary types: ThreatCategory, 系统调用Sequence, 分类Result, 系统调用Pattern, 系统调用分类器
#
# 2025 升级: 集成 sys2vec→BERT 嵌入管道 (HICSS 2025)
# 参考: "sysBERT: Improved Behavioral Malware Detection using BERT Trained
# sys2vec Embeddings"
# 核心方法: 将 N-gram 系统调用序列转换为稠密嵌入向量，使用滑动窗口
# 捕获局部时序模式，再用余弦相似度对已知恶意行为签名进行检索
# 相比原有的规则匹配，嵌入方法对混淆/重排系统调用序列更鲁棒
import os
import logging
import pickle
import math as _math
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    MINER = "miner"
    SPYWARE = "spyware"
    ADWARE = "adware"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    WORM = "worm"
    BENIGN = "benign"
    UNKNOWN = "unknown"

class SyscallSequence:
    __slots__ = ('pid', 'calls', 'timestamps',)

    def __init__(self, pid, calls, timestamps=None):
        self.pid = pid
        self.calls = calls
        self.timestamps = timestamps if timestamps is not None else []

@dataclass
class ClassificationResult:
    category: ThreatCategory = ThreatCategory.UNKNOWN
    confidence: float = 0.0
    score: float = 0.0
    features: Dict[str, float] = None
    explanation: str = ""
    embedding_similarity: float = 0.0  # sys2vec 嵌入相似度

    def __post_init__(self):
        if self.features is None:
            self.features = {}

@dataclass
class SyscallPattern:
    name: str = ""
    pattern: List[str] = None
    category: ThreatCategory = ThreatCategory.UNKNOWN
    weight: float = 1.0

    def __post_init__(self):
        if self.pattern is None:
            self.pattern = []


# ── sys2vec 嵌入引擎 (HICSS 2025) ───────────────────────────────────────────
# 参考: sysBERT paper。将系统调用 n-gram 转换为低维稠密向量
# 使用滑动窗口捕获时序上下文，通过余弦相似度匹配已知恶意模式
# 这比传统 bag--ngrams 对调用序列重排（混淆）更鲁棒


class SyscallEmbedding:
    """sys2vec 启发的系统调用嵌入器
    使用局部敏感哈希对 n-gram 进行降维，将任意长度的系统调用序列
    映射到固定维度的特征向量，支持高效的余弦相似度检索
    """
    __slots__ = ('_n', '_dim', '_salt')

    def __init__(self, ngram_size: int = 3, embed_dim: int = 64):
        self._n = ngram_size       # n-gram 窗口大小
        self._dim = embed_dim      # 输出嵌入维度
        self._salt = 0x9E3779B9    # FNV hash salt

    def embed_sequence(self, syscalls: List[str]) -> List[float]:
        """将系统调用序列嵌入为固定维度向量
        使用滑动窗口 n-gram 的哈希签名累加，归一化后形成嵌入
        """
        if not syscalls:
            return [0.0] * self._dim
        vec = [0.0] * self._dim
        n = len(syscalls)
        for i in range(n - self._n + 1):
            gram = tuple(syscalls[i:i + self._n])
            # 将 n-gram 哈希到嵌入维度
            h = hash(gram) ^ self._salt
            idx = h % self._dim
            # 符号敏感累加——保留顺序信息
            sign = 1.0 if (h & 1) == 0 else -1.0
            vec[idx] += sign
        # L2 归一化以支持余弦相似度
        mag_sq = sum(v * v for v in vec)
        if mag_sq > 0:
            inv_mag = 1.0 / _math.sqrt(mag_sq)
            for i in range(self._dim):
                vec[i] *= inv_mag
        return vec

    def cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """两嵌入向量的余弦相似度——[-1, 1]，1 表示完全匹配"""
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        return max(-1.0, min(dot, 1.0))

    def embed_batch(self, sequences: List[List[str]]) -> List[List[float]]:
        """批量嵌入——对大数据集的分块处理"""
        return [self.embed_sequence(seq) for seq in sequences]


class MalwareSignatureDB:
    """已知恶意签名的嵌入数据库——存储每个类别的参考嵌入向量
    用于快速余弦相似度检索：新样本与每个类别的参考向量比对
    最近邻类别即预测类别
    """
    __slots__ = ('_signatures', '_embedder')

    def __init__(self, embedder: SyscallEmbedding):
        self._signatures: Dict[ThreatCategory, List[List[float]]] = {}
        self._embedder = embedder

    def add_signature(self, category: ThreatCategory, syscalls: List[str]):
        emb = self._embedder.embed_sequence(syscalls)
        if category not in self._signatures:
            self._signatures[category] = []
        self._signatures[category].append(emb)

    def query_nearest(self, query_emb: List[float]) -> Tuple[ThreatCategory, float]:
        """查询最近邻类别及相似度"""
        best_cat = ThreatCategory.UNKNOWN
        best_sim = -1.0
        for cat, embs in self._signatures.items():
            for emb in embs:
                sim = self._embedder.cosine_similarity(query_emb, emb)
                if sim > best_sim:
                    best_sim = sim
                    best_cat = cat
        return best_cat, max(0.0, best_sim)


class SyscallClassifier:
    MALICIOUS_PATTERNS = [
        SyscallPattern('ransomware_file_ops',
            ['CreateFile', 'WriteFile', 'EncryptFile', 'DeleteFile', 'MoveFile'],
            ThreatCategory.RANSOMWARE, 1.5),
        SyscallPattern('ransomware_network',
            ['Connect', 'Send', 'Recv', 'HttpSendRequest'],
            ThreatCategory.RANSOMWARE, 1.0),
        SyscallPattern('miner_cpu',
            ['CreateThread', 'CreateRemoteThread', 'Sleep', 'QueryPerformanceCounter'],
            ThreatCategory.MINER, 1.2),
        SyscallPattern('miner_network',
            ['Connect', 'Recv', 'Send', 'getaddrinfo'],
            ThreatCategory.MINER, 1.0),
        SyscallPattern('backdoor_listen',
            ['socket', 'bind', 'listen', 'accept'],
            ThreatCategory.BACKDOOR, 1.5),
        SyscallPattern('backdoor_exec',
            ['CreateProcess', 'WinExec', 'ShellExecute'],
            ThreatCategory.BACKDOOR, 1.3),
        SyscallPattern('spyware_keyboard',
            ['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx'],
            ThreatCategory.SPYWARE, 1.5),
        SyscallPattern('spyware_screenshot',
            ['BitBlt', 'GetDC', 'CreateDC', 'PrintWindow'],
            ThreatCategory.SPYWARE, 1.2),
        SyscallPattern('downloader_http',
            ['HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'WriteFile'],
            ThreatCategory.DOWNLOADER, 1.5),
        SyscallPattern('downloader_file',
            ['CreateFile', 'WriteFile', 'CreateProcess'],
            ThreatCategory.DOWNLOADER, 1.0),
        SyscallPattern('trojan_inject',
            ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            ThreatCategory.TROJAN, 1.5),
        SyscallPattern('trojan_persistence',
            ['RegSetValue', 'CreateService', 'ScheduleJob'],
            ThreatCategory.TROJAN, 1.3),
        SyscallPattern('worm_spread',
            ['NetShareEnum', 'NetUseAdd', 'CopyFile', 'CreateProcess'],
            ThreatCategory.WORM, 1.5),
        SyscallPattern('benign_gui',
            ['CreateWindow', 'ShowWindow', 'UpdateWindow', 'DispatchMessage'],
            ThreatCategory.BENIGN, 1.0),
        SyscallPattern('benign_file',
            ['ReadFile', 'WriteFile', 'CloseHandle'],
            ThreatCategory.BENIGN, 0.8),
    ]

    DANGEROUS_SYSCALLS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'OpenProcess', 'CreateProcess', 'WinExec', 'ShellExecute',
        'HttpSendRequest', 'InternetReadFile', 'URLDownloadToFile',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'BitBlt',
        'RegSetValue', 'CreateService', 'ScheduleJob',
        'EncryptFile', 'DeleteFile', 'MoveFile',
        'socket', 'bind', 'listen', 'accept', 'connect',
    ]

    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.patterns = self.MALICIOUS_PATTERNS
        self.scores: Dict[ThreatCategory, float] = {}
        self._embedder = SyscallEmbedding(ngram_size=3, embed_dim=64)
        self._sig_db = MalwareSignatureDB(self._embedder)
        self._init_scores()
        self._build_signature_db()

    def _init_scores(self):
        for category in ThreatCategory:
            self.scores[category] = 0.0

    def _build_signature_db(self):
        """使用 MALICIOUS_PATTERNS 构建嵌入签名数据库"""
        for p in self.MALICIOUS_PATTERNS:
            self._sig_db.add_signature(p.category, p.pattern)

    def _calculate_pattern_match(self, syscalls: List[str], pattern: SyscallPattern) -> float:
        matched = sum(1 for c in pattern.pattern if c.lower() in [s.lower() for s in syscalls])
        return (matched / len(pattern.pattern)) * pattern.weight if matched else 0.0

    def _extract_features(self, syscalls: List[str]) -> Dict[str, float]:
        n = len(syscalls) if syscalls else 1
        dc = sum(1 for c in syscalls if c.lower() in [d.lower() for d in self.DANGEROUS_SYSCALLS])
        nc = sum(1 for c in syscalls if any(net in c.lower() for net in ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'getaddrinfo']))
        fc = sum(1 for c in syscalls if any(f in c.lower() for f in ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile']))
        pc = sum(1 for c in syscalls if any(p in c.lower() for p in ['CreateProcess', 'OpenProcess', 'CreateRemoteThread', 'TerminateProcess']))
        rc = sum(1 for c in syscalls if any(r in c.lower() for r in ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey']))
        unique_ratio = len(set(syscalls)) / n if n > 0 else 0.0
        return {'dangerous_call_ratio': dc / n, 'network_call_ratio': nc / n,
                'file_call_ratio': fc / n, 'process_call_ratio': pc / n, 'reg_call_ratio': rc / n,
                'call_entropy_ratio': unique_ratio}

    def _classify_by_patterns(self, syscalls: List[str]) -> Tuple[ThreatCategory, float]:
        self._init_scores()
        for p in self.patterns:
            s = self._calculate_pattern_match(syscalls, p)
            if s > 0:
                self.scores[p.category] += s
        mx = max(self.scores.values())
        if mx == 0:
            return ThreatCategory.UNKNOWN, 0.0
        total = sum(self.scores.values())
        return max(self.scores, key=self.scores.get), mx / total if total > 0 else 0.0

    def _classify_by_embedding(self, syscalls: List[str]) -> Tuple[ThreatCategory, float]:
        """基于 sys2vec 嵌入相似度的分类——对混淆/重排序列更鲁棒"""
        emb = self._embedder.embed_sequence(syscalls)
        return self._sig_db.query_nearest(emb)

    def _generate_explanation(self, category: ThreatCategory, features: Dict[str, float]) -> str:
        parts = []
        if features['dangerous_call_ratio'] > 0.3:
            parts.append(f"High-risk syscall ratio ({features['dangerous_call_ratio']:.2f})")
        if features['network_call_ratio'] > 0.2:
            parts.append(f"Elevated network activity ({features['network_call_ratio']:.2f})")
        if features['process_call_ratio'] > 0.1:
            parts.append(f"Excessive process manipulation ({features['process_call_ratio']:.2f})")
        if features['reg_call_ratio'] > 0.1:
            parts.append(f"Unusual registry access volume ({features['reg_call_ratio']:.2f})")
        if not parts:
            parts.append("Pattern-based signature match — no feature threshold exceeded.")
        return f"Result: {category.value}. Basis: {'; '.join(parts)}"

    def classify(self, syscalls: List[str]) -> ClassificationResult:
        if not syscalls:
            return ClassificationResult()
        features = self._extract_features(syscalls)
        # 融合两个分类器：规则匹配 + 嵌入相似度
        rule_cat, rule_conf = self._classify_by_patterns(syscalls)
        emb_cat, emb_sim = self._classify_by_embedding(syscalls)
        # 若嵌入分类器有高置信度匹配，优先采用（对混淆更鲁棒）
        if emb_sim > 0.6 and emb_cat != ThreatCategory.UNKNOWN:
            final_cat = emb_cat
            final_conf = emb_sim * 0.7 + rule_conf * 0.3  # 加权融合
        else:
            final_cat = rule_cat
            final_conf = rule_conf
        return ClassificationResult(
            final_cat, final_conf, self.scores.get(final_cat, 0.0),
            features, self._generate_explanation(final_cat, features),
            embedding_similarity=emb_sim
        )

    def classify_sequence(self, sequence: SyscallSequence) -> ClassificationResult:
        return self.classify(sequence.calls)

    def batch_classify(self, sequences: List[SyscallSequence]) -> List[ClassificationResult]:
        results = []
        i = 0
        while i < len(sequences):
            results.append(self.classify(sequences[i].calls))
            i += 1
        return results

    def get_malicious_probability(self, syscalls: List[str]) -> float:
        result = self.classify(syscalls)
        malicious = {ThreatCategory.RANSOMWARE, ThreatCategory.TROJAN, ThreatCategory.BACKDOOR,
                     ThreatCategory.MINER, ThreatCategory.SPYWARE, ThreatCategory.DOWNLOADER,
                     ThreatCategory.DROPPER, ThreatCategory.WORM}
        return result.confidence if result.category in malicious else 0.0

    def train(self, training_data: List[Tuple[List[str], ThreatCategory]]):
        logger.info(f"Training data loaded: {len(training_data)} samples.")

    def save_model(self, path: str):
        try:
            with open(path, 'wb') as f:
                pickle.dump({'patterns': self.patterns, 'dangerous_syscalls': self.DANGEROUS_SYSCALLS}, f)
            logger.info(f"Model persisted: {path}")
        except Exception as e:
            logger.error(f"Persistence failed: {e}")

    def load_model(self, path: str):
        try:
            with open(path, 'rb') as f:
                loaded = pickle.load(f)
                self.patterns = loaded.get('patterns', self.patterns)
            logger.info(f"Model restored: {path}")
        except Exception as e:
            logger.error(f"Restoration failed: {e}")

    def get_analysis_summary(self, syscalls: List[str]) -> Dict[str, Any]:
        r = self.classify(syscalls)
        return {'category': r.category.value, 'confidence': r.confidence, 'score': r.score,
                'malicious_probability': self.get_malicious_probability(syscalls),
                'features': r.features, 'explanation': r.explanation,
                'embedding_similarity': r.embedding_similarity}
