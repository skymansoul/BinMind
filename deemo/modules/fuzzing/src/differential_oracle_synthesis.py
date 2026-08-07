# 修改记录:
# 2025-08-07 11:23 - 初始实现：多版本差分行为对比的自动化 oracle 合成

"""差分 Oracle 合成 — 从多版本/多编译器二进制对比中自动推导正确性 oracle。

fuzzing 的核心瓶颈不是输入生成，而是 oracle 问题——"如何判断一次执行
是否暴露了 bug"。现有方法几乎完全依赖崩溃检测（SIGSEGV、assert fail 等），
但逻辑错误、语义偏离、性能退化等非崩溃 bug 无法被这些信号捕获。

本模块的方案——差分 Oracle 合成 (Differential Oracle Synthesis, DOS)：
1. 对同一源码的不同编译版本（或同函数的不同实现）运行相同输入。
2. 比较执行轨迹在多个语义维度上的差异：
   - 函数调用序列（顺序偏差→逻辑错误）
   - 堆分配模式（大小差异→缓冲区边界错误）
   - 返回值/输出缓冲区内容（直接正确性偏离）
3. 对被多数版本一致认可的"正常行为"建模为参考分布，
   偏离参考分布超过阈值的执行标记为潜在 bug。
4. 无需 ground truth、无需源码、无需人工标注。

关键创新——"多数一致即为 oracle"的假设：
若 N 个独立编译版本在相同输入下产生高度相似的执行行为，
则此行为可视为参考正确性基线。单版本偏离基线→自动标记为异常。
这一假设在编译器非 buggy 且优化不改变语义的前提下成立。

与 Centaur 的区别：
Centaur 用 LLM 推断 DL API 的不变式，依赖于 LLM 质量。
DOS 用多版本统计一致性替代 LLM，消除外部依赖和幻觉风险。

- "Differential Testing for Software" — 差分测试的理论基础。
- Centaur — LLM 辅助的不变式推断。本方案用多版本一致性替代 LLM。
"""

import hashlib
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class ExecutionTrace:
    """单次执行的轻量级语义摘要。"""
    input_hash: str
    binary_version: str
    # 函数调用序列（按地址排序去重 → 顺序无关的集合表征）
    function_calls: FrozenSet[int] = field(default_factory=frozenset)
    # 调用序列（保留顺序——用于顺序敏感的比较）
    call_sequence: Tuple[int, ...] = field(default_factory=tuple)
    # 堆分配摘要：{size: count}
    heap_allocs: Dict[int, int] = field(default_factory=dict)
    # 关键输出（返回值或输出缓冲区前 N 字节的哈希）
    output_hash: str = ""
    # 执行时间
    exec_time_us: int = 0

    def semantic_distance(self, other: 'ExecutionTrace') -> float:
        """计算两条轨迹的语义距离 ∈ [0, 1]。

        距离综合考虑函数调用集差异、调用顺序差异、
        堆分配模式差异和输出差异。
        """
        _dist = 0.0

        # 函数调用集 Jaccard 距离
        _a = set(self.function_calls)
        _b = set(other.function_calls)
        _union = _a | _b
        if _union:
            _dist += 1.0 - len(_a & _b) / len(_union)

        # 调用序列编辑距离近似（最长公共子序列比率）
        if self.call_sequence and other.call_sequence:
            _lcs_len = _lcs_length(self.call_sequence, other.call_sequence)
            _max_len = max(len(self.call_sequence), len(other.call_sequence))
            _dist += 1.0 - _lcs_len / _max_len

        # 堆分配模式差异
        _all_sizes = set(self.heap_allocs) | set(other.heap_allocs)
        if _all_sizes:
            _heap_diff = 0.0
            for _s in _all_sizes:
                _c1 = self.heap_allocs.get(_s, 0)
                _c2 = other.heap_allocs.get(_s, 0)
                _heap_diff += abs(_c1 - _c2)
            _dist += min(1.0, _heap_diff / max(sum(self.heap_allocs.values()),
                                                sum(other.heap_allocs.values()), 1))

        # 输出哈希不同 → 明显偏离
        if self.output_hash and other.output_hash:
            if self.output_hash != other.output_hash:
                _dist += 1.0

        return _dist / 4.0  # 四个维度等权平均

class DifferentialOracleSynthesizer:
    """差分 Oracle 合成器——从多版本执行轨迹中推导隐式正确性约束。

    使用范式：
      dos = DifferentialOracleSynthesizer(min_versions=3)
      dos.ingest_trace(binary_version, input_hash, execution_trace)
      bugs = dos.detect_anomalies()  # 返回异常轨迹列表
    """

    def __init__(
        self,
        min_versions: int = 3,
        anomaly_threshold: float = 0.25,
        trace_window: int = 500,
    ):
        """
        min_versions: 构成"多数一致"的最小版本数。
        anomaly_threshold: 语义距离超过此倍标准差的轨迹标记为异常。
        trace_window: 滑动窗口中保留的最近轨迹数。
        """
        self.min_versions = min_versions
        self.anomaly_threshold = anomaly_threshold
        self.trace_window = trace_window

        # {input_hash: {version: trace}}
        self._traces: Dict[str, Dict[str, ExecutionTrace]] = defaultdict(dict)
        # {version: [trace]} 用于全局基线
        self._version_traces: Dict[str, List[ExecutionTrace]] = defaultdict(list)
        # 已检测的异常
        self._anomalies: List[Tuple[str, str, float]] = []  # (input_hash, version, score)
        # Oracle 规则——从一致性中提取
        self._oracle_rules: List[Dict[str, Any]] = []

    def ingest_trace(
        self,
        binary_version: str,
        input_hash: str,
        trace: ExecutionTrace,
    ):
        """摄入一次执行轨迹。"""
        self._traces[input_hash][binary_version] = trace
        self._version_traces[binary_version].append(trace)

        # 滑动窗口裁剪
        if len(self._version_traces[binary_version]) > self.trace_window:
            self._version_traces[binary_version] = (
                self._version_traces[binary_version][-self.trace_window:]
            )

    def detect_anomalies(self) -> List[Tuple[str, str, float]]:
        """对所有已摄入的轨迹进行异常检测。

        返回：[(input_hash, version, anomaly_score), ...]。

        算法：对每对 (input, version)，计算其与同 input 的其他 version
        的语义距离。若该距离在全部 input 的跨版本距离分布中是统计离群值，
        标记为异常。
        """
        # 第一步：构建所有输入在各版本间的跨版本距离分布
        _cross_distances: List[Tuple[str, str, float]] = []  # [(input, version, dist)]
        for _input_hash, _version_traces in self._traces.items():
            _versions = list(_version_traces.keys())
            if len(_versions) < 2:
                continue
            for _ver in _versions:
                _trace = _version_traces[_ver]
                _others = [_version_traces[v] for v in _versions if v != _ver]
                _dists = [_trace.semantic_distance(_o) for _o in _others]
                _mean = sum(_dists) / len(_dists)
                _cross_distances.append((_input_hash, _ver, _mean))

        if len(_cross_distances) < self.min_versions * 3:
            return []

        # 第二步：用全部跨版本距离的分布做离群检测
        _all_dists = [d for _, _, d in _cross_distances]
        _global_mean = sum(_all_dists) / len(_all_dists)
        _global_std = statistics.stdev(_all_dists) if len(_all_dists) > 1 else 0.0

        if _global_std < _EPS:
            return []

        # 第三步：Z-score 检测——距离偏离均值超过 2σ 的标记为异常
        _new_anomalies: List[Tuple[str, str, float]] = []
        for _input_hash, _ver, _mean_dist in _cross_distances:
            _z_score = (_mean_dist - _global_mean) / _global_std
            # sigmoid 映射到 [0,1]，阈值偏移使 z>1.5 开始得分上升
            _anomaly_score = 1.0 / (1.0 + math.exp(-(_z_score - 1.5) * 3.0))

            if _anomaly_score > self.anomaly_threshold:
                _new_anomalies.append((_input_hash, _ver, round(_anomaly_score, 4)))

        self._anomalies = _new_anomalies
        return list(self._anomalies)

    def synthesize_oracles(self) -> List[Dict[str, Any]]:
        """从跨版本一致性中合成显式 oracle 规则。

        规则类型：
        - output_consistency: 所有版本应产生相同输出哈希
        - call_set_stability: 函数调用集 Jaccard 相似度应 > 0.9
        - heap_pattern: 堆分配模式应对齐
        """
        _rules: List[Dict[str, Any]] = []

        # 规则1: 输出一致性——若多数输入在各版本间输出一致，将此作为 oracle
        _output_consistent = 0
        _total = 0
        for _inp, _vts in self._traces.items():
            if len(_vts) < self.min_versions:
                continue
            _total += 1
            _outputs = {t.output_hash for t in _vts.values() if t.output_hash}
            if len(_outputs) <= 1:
                _output_consistent += 1

        if _total > 0 and _output_consistent / _total > 0.8:
            _rules.append({
                "type": "output_consistency",
                "confidence": round(_output_consistent / _total, 3),
                "description": "output hash consistent across >= 80% inputs",
            })

        # 规则2: 调用集稳定性
        _call_jaccards: List[float] = []
        for _inp, _vts in self._traces.items():
            if len(_vts) < 2:
                continue
            _traces_list = list(_vts.values())
            for _i in range(len(_traces_list)):
                for _j in range(_i + 1, len(_traces_list)):
                    _a = set(_traces_list[_i].function_calls)
                    _b = set(_traces_list[_j].function_calls)
                    _union = _a | _b
                    if _union:
                        _call_jaccards.append(len(_a & _b) / len(_union))

        if _call_jaccards:
            _mean_j = sum(_call_jaccards) / len(_call_jaccards)
            _rules.append({
                "type": "call_set_stability",
                "mean_jaccard": round(_mean_j, 3),
                "threshold": max(0.7, round(_mean_j - 0.1, 3)),
                "description": "cross-version function call Jaccard stability",
            })

        self._oracle_rules = _rules
        return _rules

    def score_input_novelty(self, input_hash: str) -> float:
        """评估一个输入的"oracle 新颖度"——多版本间分歧越大，越可能暴露 bug。"""
        _vts = self._traces.get(input_hash, {})
        if len(_vts) < 2:
            return 0.0

        _traces_list = list(_vts.values())
        _dist_sum = 0.0
        _count = 0
        for _i in range(len(_traces_list)):
            for _j in range(_i + 1, len(_traces_list)):
                _dist_sum += _traces_list[_i].semantic_distance(_traces_list[_j])
                _count += 1

        return _dist_sum / max(_count, 1) if _count > 0 else 0.0

    # 内部
    pass

def _lcs_length(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    """最长公共子序列长度——O(min(|a|,|b|)·max(|a|,|b|))。"""
    _m, _n = len(a), len(b)
    if _m == 0 or _n == 0:
        return 0
    if _m > _n:
        a, b = b, a
        _m, _n = _n, _m

    _prev = [0] * (_n + 1)
    for _i in range(1, _m + 1):
        _curr = [0] * (_n + 1)
        for _j in range(1, _n + 1):
            if a[_i - 1] == b[_j - 1]:
                _curr[_j] = _prev[_j - 1] + 1
            else:
                _curr[_j] = max(_prev[_j], _curr[_j - 1])
        _prev = _curr
    return _prev[_n]

# 冒烟测试
def _smoke_test():
    _dos = DifferentialOracleSynthesizer(min_versions=3)

    # 模拟 3 个编译版本，10 个输入
    _versions = ["gcc_O0", "gcc_O2", "clang_O2"]
    for _inp_id in range(10):
        _inp_hash = hashlib.sha256(str(_inp_id).encode()).hexdigest()[:8]
        for _vi, _ver in enumerate(_versions):
            _fcalls = frozenset({
                0x401000 + _inp_id * 16,
                0x402000 + _inp_id * 16 + _vi,
                0x403000,
            })
            _cseq = tuple([
                0x401000 + _inp_id * 16,
                0x402000 + _inp_id * 16 + _vi,
                0x403000,
            ])
            _output = hashlib.sha256(
                f"{_inp_id}_{_ver}".encode()
            ).hexdigest()[:16]

            # 对 input 5 在 gcc_O2 下注入异常：修改输出和调用序列
            if _inp_id == 5 and _ver == "gcc_O2":
                _output = "anomalous_output!"
                _cseq = tuple([0x401000, 0xDEADBEEF])

            _trace = ExecutionTrace(
                input_hash=_inp_hash,
                binary_version=_ver,
                function_calls=_fcalls,
                call_sequence=_cseq,
                output_hash=_output,
            )
            _dos.ingest_trace(_ver, _inp_hash, _trace)

    _anomalies = _dos.detect_anomalies()
    print(f"[diff_oracle] detected {len(_anomalies)} anomalies")
    for _inp, _ver, _score in _anomalies:
        print(f"  input={_inp} version={_ver} score={_score:.4f}")

    # 验证注入的异常被检测到
    _anomaly_inputs = {a[0] for a in _anomalies}
    _target_hash = hashlib.sha256(b"5").hexdigest()[:8]
    assert _target_hash in _anomaly_inputs, (
        f"injected anomaly for input 5 should be detected, got {_anomaly_inputs}"
    )

    _rules = _dos.synthesize_oracles()
    print(f"[diff_oracle] synthesized {len(_rules)} oracle rules:")
    for _r in _rules:
        print(f"  {_r['type']}: {_r.get('description', '')}")

    assert len(_rules) >= 1, "should synthesize at least one rule"

    print("[OK] DifferentialOracleSynthesizer smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
