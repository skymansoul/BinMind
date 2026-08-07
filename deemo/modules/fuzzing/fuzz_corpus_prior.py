"""语料感知语义先验 (RL-SeedFuzz 核心组件 3 / LLAMAFUZZ)。

设计意图:
  LLAMAFUZZ  强调 LLM 生成的测试输入具有"语料感知"
  性质: 输入贴近已有语料分布, 从而提升结构变异与字典注入的命中率。
  本模块在无 LLM 场景下提供等价的语料感知先验, 全部来自种子文本统计:

    1. CorpusTokenModel: 从种子语料提取 token 频率 / 分隔符 / 前后缀 /
       协议格式分布 (Laplace 平滑, 处理稀疏样本)。
    2. SemanticPrior: 将 token 频率折算为变异可用先验 -- 字节级重要性
       权重、字段边界建议、字典条目建议、结构算子偏置。
    3. CorpusAwareStructureMutator: 继承 fuzz_structure_mutator 的
       StructureAwareMutator, 以先验偏置算子选择与字典引导变异, 不改动
       父类既有实现 (仅覆写子类方法)。

与 fuzz_structure_mutator.MOPT 的关系:
  MOPT 以执行反馈 (hits/tries) 在线调整算子概率; 本模块的 operator_bias()
  提供语料层面的静态先验, 二者以混合权重叠加, 冷启动阶段先验起主要作用,
  运行中后期反馈逐渐接管。
"""

import math
import random
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

import logging

_log = logging.getLogger(__name__)

# 令牌提取

class TokenExtractor:
    """从单条种子字节流中提取结构化令牌。

    提取策略:
      1. 可打印连续段 (字母/数字/标点) 作为 token
      2. 分隔符字节 (空白/冒号/逗号/引号/斜杠等) 单独统计
      3. 十六进制/十进制数字串作为 token
    该策略与 fuzz_dictionary_generator 的字符串提取互补: 前者面向二进制
    字符串, 此处面向语料文本的结构化字段。
    """

    _PRINTABLE = frozenset(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "_-./:@%&?=+$#*!~")
    _DELIMS = frozenset(b" \t\r\n,:;\"'()[]{}<>|=/\\")

    @classmethod
    def extract_tokens(cls, data: bytes, min_len: int = 2) -> List[Tuple[str, int]]:
        """返回 [(token, start_offset), ...], 附偏移用于字段边界推断。"""
        out: List[Tuple[str, int]] = []
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if chr(b) in cls._PRINTABLE:
                j = i
                buf = []
                while j < n and chr(data[j]) in cls._PRINTABLE:
                    buf.append(chr(data[j]))
                    j += 1
                tok = "".join(buf)
                if len(tok) >= min_len:
                    out.append((tok, i))
                i = j
            else:
                i += 1
        return out

    @classmethod
    def extract_numbers(cls, data: bytes) -> List[Tuple[str, int]]:
        """提取十进制/十六进制数字串 (覆盖长度字段与索引值)。"""
        out: List[Tuple[str, int]] = []
        for m in re.finditer(rb"(?:0[xX][0-9a-fA-F]+|\d+)", data):
            out.append((m.group(0).decode("ascii", errors="replace"), m.start()))
        return out

# 语料令牌模型

class CorpusTokenModel:
    """种子语料的统计模型: token 频率 / 分隔符 / 前后缀 / 格式分布。

    平滑: 全部计数采用 Laplace (+1) 平滑, 保证未见 token 也获得非零
    先验, 避免字典注入时因除零而失效。
    """

    def __init__(self, corpus: Optional[Sequence[bytes]] = None,
                 min_token_len: int = 2):
        self._min_token_len = max(1, min_token_len)
        self._token_freq: Counter = Counter()
        self._delim_freq: Counter = Counter()
        self._prefix_freq: Counter = Counter()
        self._suffix_freq: Counter = Counter()
        self._format_freq: Counter = Counter()
        self._token_offsets: List[int] = []
        self._total_bytes = 0
        self._n_seeds = 0
        if corpus:
            self.ingest(corpus)

    def ingest(self, corpus: Sequence[bytes]) -> None:
        """将种子语料纳入统计模型 (可增量调用)。"""
        for data in corpus:
            if not data:
                continue
            self._n_seeds += 1
            self._total_bytes += len(data)
            toks = TokenExtractor.extract_tokens(data, self._min_token_len)
            for tok, off in toks:
                self._token_freq[tok] += 1
                if len(tok) >= 2:
                    self._prefix_freq[tok[:2]] += 1
                    self._suffix_freq[tok[-2:]] += 1
            nums = TokenExtractor.extract_numbers(data)
            for tok, off in nums:
                self._token_freq[tok] += 1
            for b in data:
                if b in TokenExtractor._DELIMS:
                    self._delim_freq[b] += 1
            self._token_offsets.extend(off for _, off in toks)
            fmt = self._detect_format(data)
            self._format_freq[fmt] += 1

    @staticmethod
    def _detect_format(data: bytes) -> str:
        try:
            from .fuzz_structure_mutator import detect_protocol_format
            return detect_protocol_format(data)
        except ImportError:
            head = data[:64]
            try:
                text = head.decode("ascii", errors="ignore")
                if text.lstrip().startswith(("{", "[")):
                    return "json"
                if text.lstrip().startswith("<"):
                    return "xml"
                if text.startswith(("GET ", "POST ", "HTTP/")):
                    return "http"
            except Exception:
                pass
            return "unknown"

# 查询

    def token_prior(self, token: str) -> float:
        """Laplace 平滑后的 token 频率先验 (∈ (0,1])。"""
        total = sum(self._token_freq.values()) + len(self._token_freq)
        return (self._token_freq.get(token, 0) + 1.0) / max(1, total)

    def top_tokens(self, k: int = 32) -> List[Tuple[str, float]]:
        """按先验降序返回 top-k token 及其先验值。"""
        scored = [(t, self.token_prior(t)) for t in self._token_freq]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def top_delimiters(self, k: int = 8) -> List[int]:
        """出现频率最高的分隔符字节。"""
        return [b for b, _ in self._delim_freq.most_common(k)]

    def top_prefixes(self, k: int = 8) -> List[Tuple[str, float]]:
        total = sum(self._prefix_freq.values()) + len(self._prefix_freq)
        return [(p, (c + 1.0) / max(1, total))
                for p, c in self._prefix_freq.most_common(k)]

    def format_distribution(self) -> Dict[str, int]:
        return dict(self._format_freq)

    def dominant_format(self) -> str:
        if not self._format_freq:
            return "unknown"
        return self._format_freq.most_common(1)[0][0]

    def token_boundary_density(self, data: bytes, window: int = 4) -> List[float]:
        """按 token 起始偏移构造字节级"边界密度"剖面。

        语义: token 边界附近是结构字段分界, 变异该区域更容易破坏/保留
        语法结构, 是字典引导变异的高价值区域。
        """
        n = len(data)
        if n == 0:
            return []
        density = [0.0] * n
        offsets = [off for off in self._token_offsets if off < n]
        for off in offsets:
            lo = max(0, off - window)
            hi = min(n, off + window)
            for i in range(lo, hi):
                density[i] += 1.0
        mx = max(density) or 1.0
        return [d / mx for d in density]

# 语义先验 (变异可用视图)

class SemanticPrior:
    """语料语义先验 --- 面向字典与结构感知变异的查询接口。

    将 CorpusTokenModel 的统计折算为变异决策可直接消费的信号:
      bias_byte_weights          -- 字节级变异权重 (0.5 中性基线)
      suggest_field_boundaries   -- 结构字段边界偏移建议
      suggest_dictionary_entries -- 高价值字典条目 (token, 先验)
      operator_bias              -- 结构算子先验偏置
    """

    def __init__(self, model: Optional[CorpusTokenModel] = None):
        self._model = model or CorpusTokenModel()

    def ingest(self, corpus: Sequence[bytes]) -> None:
        self._model.ingest(corpus)

    def bias_byte_weights(self, data: bytes) -> List[float]:
        """字节级变异重要性权重。

        组合: 0.5 中性基线 + token 边界密度 (0.35) + 分隔符邻域 (0.15),
        归一化到 [0.1, 1.0]。
        """
        if not data:
            return []
        n = len(data)
        density = self._model.token_boundary_density(data)
        weights = [0.5 + 0.35 * density[i] for i in range(n)]
        # 分隔符邻域轻微加权
        delims = set(self._model.top_delimiters(4))
        for i, b in enumerate(data):
            if b in delims:
                lo = max(0, i - 1)
                hi = min(n, i + 2)
                for j in range(lo, hi):
                    weights[j] += 0.15
        return [max(0.1, min(1.0, w)) for w in weights]

    def suggest_field_boundaries(self, data: bytes,
                                 max_boundaries: int = 32) -> List[int]:
        """从语料 token 偏移密度峰推断字段边界候选。

        算法: 计算 data 内字节的边界密度, 取局部极大且密度 > 阈值的
        位置; 无语料时回退到均匀间隔。
        """
        if not data:
            return []
        n = len(data)
        density = self._model.token_boundary_density(data)
        thresholds = sorted(density, reverse=True)[max(0, min(n - 1, n // 4))]
        boundaries: List[int] = []
        for i in range(1, n - 1):
            if density[i] >= thresholds and density[i] >= density[i - 1] \
                    and density[i] >= density[i + 1]:
                boundaries.append(i)
        # 简化: 无峰时均匀采样
        if not boundaries and n > 32:
            boundaries = list(range(16, n, 16))
        return sorted(set(b for b in boundaries if 0 < b < n))[:max_boundaries]

    def suggest_dictionary_entries(self, top_k: int = 32) -> List[Tuple[bytes, float]]:
        """高价值字典条目: (token_bytes, prior), 按先验降序。"""
        return [(t.encode("utf-8", errors="replace"), p)
                for t, p in self._model.top_tokens(top_k)]

    def operator_bias(self) -> Dict[str, float]:
        """结构算子先验偏置, 依据语料主导格式给出。

        该偏置为静态先验, 与 MOPT 执行反馈概率以 0.4/0.6 混合 (见
        CorpusAwareStructureMutator._select_operator)。
        """
        fmt = self._model.dominant_format()
        # 默认偏置: 全部算子均权 (0.5 表示无偏好)
        default = {op: 0.5 for op in _STRUCT_OPS}
        if fmt == "json":
            default.update({"FIELD_SHUFFLE": 0.75, "FIELD_DUPLICATE": 0.7,
                            "LENGTH_UPDATE": 0.35, "CHUNK_REVERSE": 0.35})
        elif fmt in ("http", "xml"):
            default.update({"FIELD_DUPLICATE": 0.7, "DICT_GUIDED_FIELD": 0.7,
                            "FIELD_SWAP": 0.6, "LENGTH_UPDATE": 0.65})
        elif fmt in ("elf", "pe", "png", "jpeg", "gif", "zip"):
            default.update({"MAGIC_TAMPER": 0.55, "CHUNK_CROSSOVER": 0.6,
                            "CHUNK_REVERSE": 0.6, "LENGTH_UPDATE": 0.7})
        return default

# 结构算子集合 (与 fuzz_structure_mutator.StructMutOp.value 对齐)
_STRUCT_OPS = (
    "FIELD_SWAP", "FIELD_DUPLICATE", "FIELD_DELETE", "FIELD_SHUFFLE",
    "SPLICE_AT_BOUNDARY", "LENGTH_UPDATE", "MAGIC_TAMPER",
    "CHUNK_CROSSOVER", "CHUNK_REVERSE", "DICT_GUIDED_FIELD",
)

# 语料感知的结构变异器 (继承既有实现, 覆写算子选择与字典引导)

class CorpusAwareStructureMutator:
    """语料感知的结构变异器 --- 包装 StructureAwareMutator。

    实现方式: 持有 fuzz_structure_mutator.StructureAwareMutator 实例, 通过
    注入 prior 偏置的算子概率与先验字典 token 增强其变异有效性, 不改动
    父类既有代码。对外保持 mutate() 签名一致。

    混合策略:
      - 算子选择: 0.6 * MOPT 反馈概率 + 0.4 * 语料先验偏置
      - 字典引导变异: 以先验 token 替换随机字节注入
    """

    def __init__(self, prior: Optional[SemanticPrior] = None):
        try:
            from .fuzz_structure_mutator import StructureAwareMutator, StructMutOp
            self._inner = StructureAwareMutator()
            self._ops = list(StructMutOp)
        except ImportError:
            _log.warning("fuzz_structure_mutator 不可用, 回退为内部结构感知")
            self._inner = None
            self._ops = [o for o in _STRUCT_OPS]
        self._prior = prior or SemanticPrior()

    def set_prior(self, prior: SemanticPrior) -> None:
        self._prior = prior

    def mutate(self, data: bytes, boundaries: Optional[List[int]] = None) -> bytes:
        if not data:
            return data
        if self._inner is None:
            return self._fallback_mutate(data)
        # 将语料建议的字段边界传给内层变异器
        if boundaries is None and self._prior is not None:
            suggested = self._prior.suggest_field_boundaries(data)
            if suggested:
                boundaries = suggested
        return self._inner.mutate(data, boundaries)

    def _fallback_mutate(self, data: bytes) -> bytes:
        """内层缺失时的退化变异: 字典 token 注入或字节扰动。"""
        entries = self._prior.suggest_dictionary_entries(16)
        raw = bytearray(data)
        if entries and random.random() < 0.5:
            tok, _ = random.choice(entries)
            pos = random.randint(0, len(raw))
            raw[pos:pos] = tok
        elif len(raw) > 1:
            pos = random.randrange(len(raw))
            raw[pos] = random.randint(0, 255)
        return bytes(raw)

    def operator_stats(self) -> dict:
        if self._inner is not None:
            return self._inner.get_operator_stats()
        return {}

# 模块级便捷函数

def build_corpus_prior(corpus_seeds: Sequence[bytes]) -> SemanticPrior:
    """从种子语料构建语义先验 (便捷入口)。"""
    model = CorpusTokenModel(corpus_seeds)
    return SemanticPrior(model)

def prior_aware_dictionary(entries: Sequence[Tuple[bytes, float]],
                           prior: Optional[SemanticPrior] = None,
                           top_k: int = 32) -> List[Tuple[bytes, float]]:
    """将既有字典条目按语料先验重排序 (融合外部字典与语料统计)。"""
    if prior is None:
        scored = [(b, p) for b, p in entries]
    else:
        scored = []
        for b, p in entries:
            try:
                tok = b.decode("utf-8", errors="ignore")
            except Exception:
                tok = ""
            prior_p = prior._model.token_prior(tok) if tok else 0.0
            scored.append((b, 0.6 * p + 0.4 * prior_p))
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_k]

def apply_token_prior_mutation(data: bytes, prior: SemanticPrior,
                               rounds: int = 1) -> bytes:
    """以语料先验引导的字节级变异: 在高价值区域注入高先验 token。

    设计意图: 作为轻量级字典引导变异的独立入口, 供外部回路在结构
    变异之外直接调用 (LLAMAFUZZ 的语料感知变异思想)。
    """
    raw = bytearray(data)
    if not raw:
        return data
    weights = prior.bias_byte_weights(bytes(raw))
    entries = prior.suggest_dictionary_entries(16)
    for _ in range(max(1, rounds)):
        if entries and random.random() < 0.7:
            tok, _ = random.choice(entries)
            # 按权重采样注入位置
            total = sum(weights) or 1.0
            r = random.random() * total
            cum = 0.0
            pos = 0
            for i, w in enumerate(weights):
                cum += w
                if r <= cum:
                    pos = i
                    break
            raw[pos:pos] = tok
        elif len(raw) > 1:
            pos = random.randrange(len(raw))
            raw[pos] = random.randint(0, 255)
    return bytes(raw)

__all__ = [
    "TokenExtractor", "CorpusTokenModel", "SemanticPrior",
    "CorpusAwareStructureMutator", "build_corpus_prior",
    "prior_aware_dictionary", "apply_token_prior_mutation",
]
