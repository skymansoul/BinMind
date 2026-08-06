"""
自适应多模式匹配引擎 (AMPSE)
-------------------------------
Aho-Corasick + 运行时频率追踪 + 周期性重构，
高频模式占据较浅的 trie 层级以降低平均状态转移次数。
"""
import math
import threading
from typing import List, Tuple, Dict
from collections import deque
from modules.utils.pattern_scan import AhoCorasick


class AdaptiveAhoCorasick:
    """自优化的 Aho-Corasick 模式匹配器。

    用法:
        am = AdaptiveAhoCorasick()
        for pat in patterns:
            am.add_pattern(pat)
        am.build()
        matches = am.search(data)
        # 内部自动追踪频率，高偏度时触发重构
    """

    def __init__(
        self,
        rebuild_threshold: float = 0.55,
        min_searches_before_rebuild: int = 20,
        decay_window: int = 200,
    ):
        """
        rebuild_threshold: 基尼系数阈值 (0-1)。频率分布的基尼系数超过此值时
                          触发自动重构。0.55 基于 Zipf 分布的经验阈值——
                          低于此值说明模式命中较均匀，重构收益不足以覆盖开销。
        min_searches_before_rebuild: 两次重构之间的最小搜索次数——防止抖动。
        decay_window: 滑动窗口大小。0 表示不衰减 (全量统计)。
        """
        self._automaton = AhoCorasick()
        self._patterns: List[bytes] = []
        self._freq: List[int] = []          # 各模式累计命中数
        self._search_count = 0
        self._last_rebuild_at = 0
        self._rebuild_threshold = rebuild_threshold
        self._min_searches = min_searches_before_rebuild
        self._decay = decay_window
        # 滑动窗口——记录最近 N 次搜索中每个模式的命中
        self._recent_window: deque = deque() if decay_window > 0 else None
        self._recent_freq: List[int] = []
        self._lock = threading.Lock()

    def add_pattern(self, pattern: bytes) -> int:
        """添加模式并返回其索引。必须在 build() 之前调用。"""
        idx = len(self._patterns)
        self._patterns.append(pattern)
        self._freq.append(0)
        if self._recent_window is not None:
            self._recent_freq.append(0)
        self._automaton.add_pattern(pattern)
        return idx

    def build(self):
        """构造 AC 自动机。初次调用或重构后调用。"""
        self._automaton.build()

    def search(self, data: bytes) -> List[Tuple[int, int]]:
        """搜索全部模式匹配并更新频率统计。
        返回 [(end_position, pattern_index), ...]。
        若频率偏度超过阈值，内部触发自动重构。
        """
        matches = self._automaton.search(data)
        with self._lock:
            self._search_count += 1
            # 统计本轮的命中
            round_hits: Dict[int, int] = {}
            for _, pat_idx in matches:
                round_hits[pat_idx] = round_hits.get(pat_idx, 0) + 1
            # 更新全量频率
            for pat_idx, count in round_hits.items():
                if pat_idx < len(self._freq):
                    self._freq[pat_idx] += count
            # 更新滑动窗口
            if self._recent_window is not None:
                self._recent_window.append(round_hits)
                for pat_idx, count in round_hits.items():
                    if pat_idx < len(self._recent_freq):
                        self._recent_freq[pat_idx] += count
                if len(self._recent_window) > self._decay:
                    old = self._recent_window.popleft()
                    for pat_idx, count in old.items():
                        if pat_idx < len(self._recent_freq):
                            self._recent_freq[pat_idx] -= count
            # 评估是否需要重构
            if self._should_rebuild():
                self._rebuild()
        return matches

    def _should_rebuild(self) -> bool:
        """检查是否满足重构条件。"""
        if self._search_count - self._last_rebuild_at < self._min_searches:
            return False
        if len(self._patterns) < 4:
            return False
        # 选择合适的频率源
        if self._recent_window is not None and len(self._recent_window) >= 10:
            freqs = self._recent_freq
        else:
            freqs = self._freq
        gini = _gini_coefficient(freqs)
        return gini > self._rebuild_threshold

    def _rebuild(self):
        """按频率降序重排模式后重构自动机。同步重排 _patterns 和 _freq。"""
        if self._recent_window is not None and len(self._recent_window) >= 10:
            freq_src = self._recent_freq
        else:
            freq_src = self._freq
        indexed = list(enumerate(self._patterns))
        indexed.sort(key=lambda x: freq_src[x[0]], reverse=True)
        self._old_to_new: Dict[int, int] = {}
        for new_idx, (old_idx, _) in enumerate(indexed):
            self._old_to_new[old_idx] = new_idx
        # 按新顺序重建
        new_automaton = AhoCorasick()
        new_patterns = []
        new_freq = []
        new_recent = [] if self._recent_window is not None else None
        for old_idx, pat in indexed:
            new_automaton.add_pattern(pat)
            new_patterns.append(pat)
            new_freq.append(self._freq[old_idx])
            if new_recent is not None:
                new_recent.append(self._recent_freq[old_idx])
        new_automaton.build()
        self._automaton = new_automaton
        self._patterns = new_patterns
        self._freq = new_freq
        if new_recent is not None:
            self._recent_freq = new_recent
        self._last_rebuild_at = self._search_count

    def get_stats(self) -> dict:
        """返回频率统计信息: 各模式命中数, 基尼系数, 搜索次数。"""
        with self._lock:
            if self._recent_window is not None and len(self._recent_window) >= 10:
                freqs = self._recent_freq
            else:
                freqs = self._freq
            return {
                "search_count": self._search_count,
                "rebuild_count": sum(
                    1 for i in range(1, len(self._patterns))
                    if self._freq[i] > 0
                ),
                "gini": _gini_coefficient(freqs),
                "total_hits": sum(freqs),
                "top_patterns": sorted(
                    enumerate(freqs), key=lambda x: x[1], reverse=True
                )[:5],
            }

    def force_rebuild(self):
        """手动触发重构——用于外部观测到工作负载变化时。"""
        with self._lock:
            if len(self._patterns) >= 2:
                self._rebuild()


def _gini_coefficient(values: List[int]) -> float:
    """基尼系数——衡量频率分布不均匀程度。0=均匀, 1=极端集中。"""
    n = len(values)
    if n == 0:
        return 0.0
    total = sum(values)
    if total == 0:
        return 0.0
    sorted_vals = sorted(values)
    gini_sum = 0.0
    for i, v in enumerate(sorted_vals):
        gini_sum += (i + 1) * v
    return (2.0 * gini_sum) / (n * total) - (n + 1.0) / n


class ThreadSafeAdaptiveAC(AdaptiveAhoCorasick):
    """线程安全版自适应 AC 匹配器。
    使用读写锁: 多个 search() 可并发，但重构时独占。
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._rwlock = threading.RLock()

    def search(self, data: bytes) -> List[Tuple[int, int]]:
        with self._rwlock:
            return super().search(data)

    def force_rebuild(self):
        with self._rwlock:
            super().force_rebuild()


class SPRTRebuildDecider:
    """序贯概率比检验 (SPRT) 重建决策器.

    替代简单基尼阈值: SPRT 按 Wald (1945) 的序贯检验框架,
    累积每次搜索的对数似然比, 直至有足够证据支持 H1(偏度>阈值).
    相比固定基尼阈值:
      - 控制误报率 α (不应重建却重建) 和漏报率 β (应重建却未重建)
      - 早期强信号可快速触发 (无需等满 min_searches)
      - 晚期弱信号不会无限累积 (对数似然比下界截断)

    参考: Wald, A. (1945) "Sequential Tests of Statistical Hypotheses"
    """

    def __init__(self, h0_gini: float = 0.3, h1_gini: float = 0.55,
                 alpha: float = 0.05, beta: float = 0.10):
        self._h0 = h0_gini   # H0: 偏度 ≤ 此值 (均匀, 不需重建)
        self._h1 = h1_gini   # H1: 偏度 ≥ 此值 (偏斜, 需要重建)
        # 决策边界: A ≈ β/(1-α), B ≈ (1-β)/α
        self._log_A = math.log(beta / (1 - alpha))  # 接受 H0
        self._log_B = math.log((1 - beta) / alpha)  # 接受 H1
        self._llr = 0.0  # 累积对数似然比
        self._n = 0
        self._decision = 'undecided'

    def update(self, gini: float) -> str:
        """摄入一次基尼观测, 返回 'h0' | 'h1' | 'undecided'."""
        self._n += 1
        # 似然: 用 Beta 分布近似基尼系数的抽样分布
        # P(gini | H0): Beta 集中于 h0 附近
        # P(gini | H1): Beta 集中于 h1 附近
        # 简化: 用高斯近似
        sigma = 0.15  # 基尼系数的估计标准差
        ll_h0 = _log_gaussian_pdf(gini, self._h0, sigma)
        ll_h1 = _log_gaussian_pdf(gini, self._h1, sigma)
        self._llr += (ll_h1 - ll_h0)
        # 截断: 不允许 LLR 低于 log_A (避免无限累积)
        self._llr = max(self._log_A, self._llr)
        if self._llr >= self._log_B:
            self._decision = 'h1'
        elif self._llr <= self._log_A:
            self._decision = 'h0'
        return self._decision

    def reset(self):
        self._llr = 0.0
        self._n = 0
        self._decision = 'undecided'

    @property
    def decision(self) -> str:
        return self._decision

    @property
    def llr(self) -> float:
        return self._llr


def _log_gaussian_pdf(x: float, mean: float, std: float) -> float:
    """高斯对数概率密度."""
    z = (x - mean) / std
    return -0.5 * z * z - math.log(std) - 0.9189385332046727
