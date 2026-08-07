#
# 基于时序因果性的协议状态机推断。
#
# 二进制程序的网络协议处理逻辑硬编码在消息派发函数中。
# 传统方法（L*算法/动态污点分析）依赖主动查询或符号执行。
# 本模块采用正交路径：仅从被动抓取的报文时序序列推断状态转移。
#
#   1. 将消息序列按方向切分为client→server / server→client两条
#      时间序列，每元素为 (msg_type, inter_arrival_time)。
#   2. 对时间序列计算转移熵 (transfer entropy)：
#      T_{X→Y}(δ) = I(X_{t-δ}; Y_t | Y_{t-1})，
#      即X的过去在多大程度上减少了Y当前值的不确定性，
#      超出Y自身过去提供的预测能力。
#   3. 转移熵显著>0的 (msg_type_i, msg_type_j, delay_δ) 三元组
#      标记为候选因果转移边。
#   4. 对候选边做置换检验 (permutation test, n=1000)，p<0.01的边
#      保留为最终状态转移边。
#
# 此方法独立于二进制分析：不要求访问源码或符号执行引擎，
# 仅依赖网络层抓包。与protocol_state_inference.py的静态分析方法
# 互补：静态方法推断"可能的状态变量"，本模块推断"实际发生的状态转移"。
#
# Wibral et al. "Measuring information-transfer delays."
#      PLOS ONE 8.2: e55809.
#      — 提出SPO归一化转移熵估计器，消除自预测偏差。
#      本项目将SPO估计器从神经科学领域适配到协议报文序列：
#      使用自适应分箱替代等宽离散化以处理重尾的报文到达间隔分布。
#
# Schreiber, T. "Measuring information transfer."
#      Physical Review Letters 85.2: 461.
#      — 首次定义转移熵。本项目增加置换检验步骤
#      以过滤有限样本引起的虚假因果边。

import math
import random
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict, Counter
from dataclasses import dataclass, field


@dataclass
class CausalTransition:
    """因果状态转移边。"""
    source_type: str        # 源消息类型
    target_type: str        # 目标消息类型
    delay_ms: float         # 最优因果延迟 (ms)
    transfer_entropy: float # SPO归一化转移熵值 [0, 1]
    p_value: float          # 置换检验p值
    significant: bool       # p < 0.01


@dataclass
class ProtocolStateMachine:
    """从时序因果分析推断的协议状态机。"""
    states: List[str] = field(default_factory=list)
    transitions: List[CausalTransition] = field(default_factory=list)
    initial_state: str = ""
    terminal_states: Set[str] = field(default_factory=set)
    # 元数据
    total_messages: int = 0
    unique_msg_types: int = 0
    entropy_significance_threshold: float = 0.01


def _adaptive_binning(values: List[float], target_bins: int = 5) -> List[int]:
    """自适应分箱：按数据分布而非等宽区间划分。

    等宽分箱在重尾分布（报文到达间隔通常为指数/对数正态）上
    会把大部分数据点丢进前1-2个箱，其余箱几乎为空，
    导致互信息估计的离散化偏差。自适应分箱使用分位数边界，
    保证每个箱的样本量大致相等。
    """
    if len(values) < target_bins:
        return list(range(len(values)))
    sorted_vals = sorted(values)
    n = len(sorted_vals)
    bins = []
    for v in values:
        # 二分查找分位：O(log n) per value
        rank = 0
        lo, hi = 0, n - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if sorted_vals[mid] < v:
                lo = mid + 1
            else:
                hi = mid - 1
        rank = lo
        bin_idx = min(target_bins - 1, (rank * target_bins) // n)
        bins.append(bin_idx)
    return bins


def _joint_probability(x_bins: List[int], y_bins: List[int],
                       x_lag_bins: List[int]) -> Dict[Tuple[int, int, int], float]:
    """估计P(X_t, X_{t-1}, Y_t)的联合概率分布。

    三变量联合分布维度为bins³，使用稀疏字典而非稠密数组避免内存爆炸。
    """
    counts: Dict[Tuple[int, int, int], int] = defaultdict(int)
    # 序列从索引1开始，需要X_{t-1}的值
    n = min(len(x_bins), len(y_bins), len(x_lag_bins))
    for t in range(1, n):
        key = (x_bins[t], x_lag_bins[t-1], y_bins[t])
        counts[key] += 1
    total = sum(counts.values()) or 1
    return {k: v / total for k, v in counts.items()}


def _marginalize(joint: Dict[Tuple[int, int, int], float],
                 keep_dims: Tuple[int, ...]) -> Dict[Tuple, float]:
    """从联合分布中边缘化出指定维度的分布。"""
    result: Dict[Tuple, float] = defaultdict(float)
    for key, prob in joint.items():
        sub_key = tuple(key[d] for d in keep_dims)
        result[sub_key] += prob
    return dict(result)


def _mutual_information_conditional(joint_xyz: Dict[Tuple[int, int, int], float]
                                    ) -> float:
    """计算I(X_t; Y_t | X_{t-1})：条件互信息，SPO转移熵的核心。"""
    # 边缘分布
    p_xz = _marginalize(joint_xyz, (0, 2))      # P(x_t, y_t)
    p_xx = _marginalize(joint_xyz, (0, 1))      # P(x_t, x_{t-1})
    p_yx = _marginalize(joint_xyz, (2, 1))      # P(y_t, x_{t-1})
    p_x = _marginalize(joint_xyz, (1,))          # P(x_{t-1})
    p_x_single = _marginalize(joint_xyz, (0,))   # P(x_t)
    p_y_single = _marginalize(joint_xyz, (2,))   # P(y_t)

    mi = 0.0
    for key, prob in joint_xyz.items():
        xt, xlag, yt = key
        if prob < 1e-12:
            continue
        p_cond = prob * p_x.get((xlag,), 1e-12)
        p_indep = p_xz.get((xt, yt), 1e-12) * p_xx.get((xt, xlag), 1e-12)
        if p_indep < 1e-12:
            continue
        ratio = p_cond / p_indep
        if ratio > 1e-12:
            mi += prob * math.log2(ratio)
    # 归一化: MI ∈ [0, min(H(X), H(Y))]，归一化到[0,1]
    h_x = 0.0
    for prob in p_x_single.values():
        if prob > 1e-12:
            h_x -= prob * math.log2(prob)
    if h_x < 1e-12:
        return 0.0
    return max(0.0, min(1.0, mi / h_x))


def _transfer_entropy_spo(source_vals: List[float],
                          target_vals: List[float],
                          delay: int = 1,
                          bins: int = 5) -> float:
    """计算源序列到目标序列的SPO归一化转移熵。

    delay: 滞后步数（每步 = 一条消息的间隔）。
    返回归一化值 ∈ [0, 1]。
    """
    n = min(len(source_vals), len(target_vals))
    if n < delay + 10:
        return 0.0  # 样本量不足以可靠估计

    # 滞后对齐
    x_t = source_vals[delay:]
    x_lag = source_vals[:-delay] if delay > 0 else source_vals
    y_t = target_vals[delay:]

    min_len = min(len(x_t), len(x_lag), len(y_t))
    if min_len < 10:
        return 0.0

    x_t = x_t[:min_len]
    x_lag = x_lag[:min_len]
    y_t = y_t[:min_len]

    x_bins = _adaptive_binning(x_t, bins)
    x_lag_bins = _adaptive_binning(x_lag, bins)
    y_bins = _adaptive_binning(y_t, bins)

    joint = _joint_probability(x_bins, y_bins, x_lag_bins)
    return _mutual_information_conditional(joint)


def _permutation_test(source_vals: List[float],
                      target_vals: List[float],
                      observed_te: float,
                      delay: int = 1,
                      n_permutations: int = 1000) -> float:
    """置换检验：打乱源序列时间顺序，重新计算转移熵。

    H0: 转移熵=0（无因果关联）。
    返回p值 = (TE_perm ≥ TE_observed的次数) / n_permutations。
    """
    if observed_te < 1e-8:
        return 1.0
    count_exceed = 0
    source_copy = list(source_vals)
    for _ in range(n_permutations):
        random.shuffle(source_copy)
        perm_te = _transfer_entropy_spo(source_copy, target_vals, delay)
        if perm_te >= observed_te:
            count_exceed += 1
    return count_exceed / n_permutations


def infer_state_machine_from_timing(
    messages: List[Tuple[str, float, str]],
    # 每元素: (msg_type, arrival_time_ms, direction: "c2s"|"s2c")
    max_delay_steps: int = 10,
    te_threshold: float = 0.03,
    significance_level: float = 0.01,
    n_permutations: int = 1000,
) -> ProtocolStateMachine:
    """从报文时序序列推断协议状态机。

    Args:
        messages: 按时间排序的消息列表。
        max_delay_steps: 最大因果延迟搜索范围。
        te_threshold: 转移熵最小阈值，低于此值的边被丢弃。
        significance_level: 置换检验显著性水平。
        n_permutations: 每次检验的置换次数。

    Returns:
        推断出的ProtocolStateMachine实例。
    """
    if len(messages) < 50:
        return ProtocolStateMachine()

    # 按方向和类型分组消息
    c2s_msgs: Dict[str, List[float]] = defaultdict(list)
    s2c_msgs: Dict[str, List[float]] = defaultdict(list)
    all_types: Set[str] = set()
    prev_time: Optional[float] = None

    for msg_type, arrival, direction in messages:
        all_types.add(msg_type)
        iat = arrival - prev_time if prev_time is not None else 0.0
        prev_time = arrival
        if direction == "c2s":
            c2s_msgs[msg_type].append(iat)
        else:
            s2c_msgs[msg_type].append(iat)

    # 对每对消息类型计算转移熵
    # 搜索方向: c→s和s→c各有因果可能性
    transitions: List[CausalTransition] = []
    msg_types = sorted(all_types)

    for src_type in msg_types:
        for tgt_type in msg_types:
            if src_type == tgt_type:
                continue
            # 自环在状态机推断中单独处理（_detect_self_loops）

            best_te = 0.0
            best_delay = 0

            # 尝试两个方向的序列
            for src_dict, tgt_dict in [
                (c2s_msgs, s2c_msgs),
                (s2c_msgs, c2s_msgs),
            ]:
                src_seq = src_dict.get(src_type, [])
                tgt_seq = tgt_dict.get(tgt_type, [])
                if len(src_seq) < 20 or len(tgt_seq) < 20:
                    continue

                for delay in range(1, min(max_delay_steps, len(src_seq) // 5)):
                    te = _transfer_entropy_spo(src_seq, tgt_seq, delay)
                    if te > best_te:
                        best_te = te
                        best_delay = delay

            if best_te < te_threshold:
                continue

            # 置换检验：过滤虚假因果
            # 选择包含最多消息的方向组合做检验
            src_longest = (c2s_msgs.get(src_type, [])
                          if len(c2s_msgs.get(src_type, [])) >= len(s2c_msgs.get(src_type, []))
                          else s2c_msgs.get(src_type, []))
            tgt_longest = (s2c_msgs.get(tgt_type, [])
                          if len(s2c_msgs.get(tgt_type, [])) >= len(c2s_msgs.get(tgt_type, []))
                          else c2s_msgs.get(tgt_type, []))

            p_val = _permutation_test(
                src_longest, tgt_longest,
                best_te, best_delay, n_permutations,
            )
            significant = p_val < significance_level

            transitions.append(CausalTransition(
                source_type=src_type,
                target_type=tgt_type,
                delay_ms=best_delay,  # 此处是步数而非毫秒，调用方需自行转换
                transfer_entropy=round(best_te, 4),
                p_value=round(p_val, 4),
                significant=significant,
            ))

    # 按转移熵降序排列：最强的因果边排在前面
    transitions.sort(key=lambda t: (-t.transfer_entropy, t.p_value))

    # 识别初始状态和终止状态
    # 初始状态：不作为任何高置信度边目标的源节点
    source_types = {t.source_type for t in transitions if t.significant}
    target_types = {t.target_type for t in transitions if t.significant}
    initial_candidates = source_types - target_types
    terminal_candidates = target_types - source_types

    # 初始状态取在c2s中出现最早的msg_type
    initial_state = ""
    for mt in c2s_msgs:
        if mt in (initial_candidates or source_types):
            initial_state = mt
            break
    if not initial_state and source_types:
        initial_state = sorted(source_types)[0]

    terminal_states = terminal_candidates or set()

    return ProtocolStateMachine(
        states=msg_types,
        transitions=transitions,
        initial_state=initial_state,
        terminal_states=terminal_states,
        total_messages=len(messages),
        unique_msg_types=len(msg_types),
    )
