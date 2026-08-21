# 丢包模式异常检测 —— 丢包游程分布+条件熵选择性丢弃+自适应阈值校准。
#
# 丢包率掩盖了丢包模式: 5%随机丢包(=拥塞)与5%选择性丢包
# (=MITM/防火墙过滤)对安全的意义完全不同。
#
# 本模块分析丢包序列(每个包:丢/未丢)的结构:
#   1. 游程分布: 连续丢包段长度的几何分布拟合→q参数
#      随机丢包→q≈丢包率; 突发丢包→q显著低于丢包率
#   2. 选择性丢弃检测: 将丢包按协议/端口/大小分组→
#      各组丢包率的χ²同质性检验→显著不均匀→选择性丢弃
#   3. 周期性检测: 丢包事件间隔的自相关→周期性peak→定时过滤
#
# 未见2024-2025文献涉及丢包游程分析用于网络安全检测。

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class LossPatternProfile:
    """丢包模式剖面"""
    total_packets: int
    lost_packets: int
    loss_rate: float
    # 游程统计
    mean_run_length: float      # 平均连续丢包长度
    max_run_length: int
    run_length_variance: float
    geometric_q: float          # 拟合的几何分布参数
    is_bursty: bool             # q显著偏离loss_rate→突发丢包
    # 选择性检测
    selective_drop_detected: bool
    selective_dimension: str    # 被选择性丢弃的维度("port"/"size"/"protocol")
    selective_chi2: float       # χ²统计量
    # 周期性
    periodic_drop_detected: bool
    periodic_lag: int = 0
    # 条件熵: H(loss | dimension) —— 丢包是否条件依赖于某维度
    conditional_entropy_dim: str = ""   # 条件熵最低的维度
    conditional_entropy_val: float = 0.0  # H(loss|dim) 归一化值
    unconditional_entropy: float = 0.0    # H(loss) 无条件熵
    is_state_correlated: bool = False    # 丢包与协议状态显著相关


@dataclass
class LossAlert:
    """丢包模式告警"""
    flow_key: str
    alert_type: str             # "selective_drop"/"burst_loss"/"periodic_drop"
    severity: str
    confidence: float
    profile: LossPatternProfile
    evidence: str = ""


class LossPatternDetector:
    """丢包模式检测器 —— 游程分析+选择性χ²检验+自相关周期检测。"""

    def __init__(self, min_packets: int = 50,
                 selectivity_chi2_threshold: float = 10.0):
        self._min_packets = min_packets
        self._chi2_thresh = selectivity_chi2_threshold
        self._alerts: List[LossAlert] = []

    def analyze(self, flow_key: str,
                loss_sequence: List[bool],
                packet_groups: Dict[str, List[bool]] = None
                ) -> Optional[LossAlert]:
        """分析丢包序列。

        loss_sequence: [True(丢), False(未丢), ...]
        packet_groups: 可选的按维度分组的丢包序列
                       {"port_80": [...], "port_443": [...], ...}
        """
        n = len(loss_sequence)
        if n < self._min_packets:
            return None

        lost = sum(loss_sequence)
        loss_rate = lost / n

        # 游程分析
        runs: List[int] = []  # 连续丢包段长度
        current_run = 0
        for lost_flag in loss_sequence:
            if lost_flag:
                current_run += 1
            else:
                if current_run > 0:
                    runs.append(current_run)
                current_run = 0
        if current_run > 0:
            runs.append(current_run)

        mean_run = sum(runs) / max(len(runs), 1)
        max_run = max(runs) if runs else 0
        var_run = (sum((r - mean_run) ** 2 for r in runs) /
                   max(len(runs), 1)) if runs else 0.0

        # 几何分布拟合: q = 1/(mean_run) (几何分布的MLE)
        q_geo = 1.0 / max(mean_run, 1) if runs else 0.0
        # 随机丢包下: q ≈ loss_rate; 突发丢包: q << loss_rate
        is_bursty = q_geo < loss_rate * 0.5 and max_run >= 5

        # 选择性丢弃检测(χ²同质性检验)
        selective = False
        selective_dim = ""
        chi2_val = 0.0
        if packet_groups and len(packet_groups) >= 2:
            chi2_val, selective_dim = self._chi2_selectivity(packet_groups)
            selective = chi2_val > self._chi2_thresh

        # 条件熵 H(loss|dim) —— 检测状态相关的选择性丢弃
        cond_ent_dim, cond_ent_val, uncond_ent, is_correlated = (
            "", 0.0, 0.0, False)
        if packet_groups and len(packet_groups) >= 2:
            cond_ent_dim, cond_ent_val, uncond_ent, is_correlated = (
                self._conditional_loss_entropy(packet_groups, loss_sequence))

        # 周期性检测(丢包间隔自相关)
        periodic = False
        periodic_lag = 0
        if lost >= 5:
            gaps: List[int] = []
            last_loss = -1
            for i, lost_flag in enumerate(loss_sequence):
                if lost_flag:
                    if last_loss >= 0:
                        gaps.append(i - last_loss)
                    last_loss = i
            if len(gaps) >= 10:
                periodic, periodic_lag = self._detect_periodicity(gaps)

        profile = LossPatternProfile(
            total_packets=n, lost_packets=lost,
            loss_rate=round(loss_rate, 4),
            mean_run_length=round(mean_run, 2),
            max_run_length=max_run,
            run_length_variance=round(var_run, 3),
            geometric_q=round(q_geo, 4),
            is_bursty=is_bursty,
            selective_drop_detected=selective,
            selective_dimension=selective_dim,
            selective_chi2=round(chi2_val, 2),
            periodic_drop_detected=periodic,
            periodic_lag=periodic_lag,
            conditional_entropy_dim=cond_ent_dim,
            conditional_entropy_val=round(cond_ent_val, 4),
            unconditional_entropy=round(uncond_ent, 4),
            is_state_correlated=is_correlated,
        )

        # 构建告警: 条件熵信号优先于简单选择性(信息论vs频率统计)
        if is_correlated and cond_ent_val < uncond_ent * 0.7:
            alert_type, sev, conf = "selective_drop", "critical", min(
                1.0 - cond_ent_val / max(uncond_ent, 0.01), 1.0)
            evidence = (f"条件熵异常: H(loss|{cond_ent_dim})={cond_ent_val:.3f} "
                       f"<< H(loss)={uncond_ent:.3f}——丢包显著依赖{cond_ent_dim}")
        elif selective:
            alert_type, sev, conf = "selective_drop", "critical", min(chi2_val/20.0, 1.0)
            evidence = f"选择性丢弃({selective_dim}): χ²={chi2_val:.1f}"
        elif is_bursty:
            alert_type, sev, conf = "burst_loss", "high", min(max_run/10.0, 1.0)
            evidence = f"突发丢包: q={q_geo:.3f}≪loss_rate={loss_rate:.3f}, max_run={max_run}"
        elif periodic:
            alert_type, sev, conf = "periodic_drop", "medium", 0.7
            evidence = f"周期性丢包: lag={periodic_lag}包"
        else:
            return None

        alert = LossAlert(flow_key=flow_key, alert_type=alert_type,
                          severity=sev, confidence=round(conf, 3),
                          profile=profile, evidence=evidence)
        self._alerts.append(alert)
        return alert

    def _chi2_selectivity(self, groups: Dict[str, List[bool]]
                           ) -> Tuple[float, str]:
        """χ²同质性检验: 各组丢包率是否显著不同。"""
        best_chi2 = 0.0
        best_dim = ""
        dims = list(groups.keys())

        for i in range(len(dims)):
            for j in range(i + 1, len(dims)):
                a, b = groups[dims[i]], groups[dims[j]]
                la, lb = sum(a), sum(b)
                na, nb = len(a), len(b)
                if na < 5 or nb < 5:
                    continue
                # 2×2列联表χ²
                total = na + nb
                total_lost = la + lb
                total_ok = total - total_lost
                # 期望值
                ea_lost = na * total_lost / total
                eb_lost = nb * total_lost / total
                ea_ok = na * total_ok / total
                eb_ok = nb * total_ok / total
                chi2 = 0.0
                for o, e in [(la, ea_lost), (lb, eb_lost),
                             (na-la, ea_ok), (nb-lb, eb_ok)]:
                    if e > 0:
                        chi2 += (o - e) ** 2 / e
                if chi2 > best_chi2:
                    best_chi2 = chi2
                    best_dim = f"{dims[i]}_vs_{dims[j]}"

        return best_chi2, best_dim

    @staticmethod
    def _conditional_loss_entropy(groups: Dict[str, List[bool]],
                                   full_seq: List[bool]
                                   ) -> Tuple[str, float, float, bool]:
        """计算 H(loss|dim) 对各分组维度, 检测状态相关的选择性丢弃。

        H(loss) = -p·log₂p - (1-p)·log₂(1-p), p=总体丢包率
        H(loss|dim) = Σ w_i · H(loss|dim=value_i), w_i=组占比
        若 H(loss|dim) ≪ H(loss), 则知道dim能显著降低丢包不确定性
        → 丢包与dim条件相关 → 选择性丢弃(MITM/策略路由)。

        返回: (最佳条件维度, H(loss|dim)最小值, H(loss), 是否显著相关)
        """
        n = len(full_seq)
        if n == 0:
            return "", 0.0, 0.0, False
        total_lost = sum(full_seq)
        p = total_lost / n
        if p < 1e-6 or p > 1 - 1e-6:
            return "", 0.0, 0.0, False

        def _bin_entropy(p_val: float) -> float:
            if p_val < 1e-9 or p_val > 1 - 1e-9:
                return 0.0
            return -p_val * math.log2(p_val) - (1 - p_val) * math.log2(1 - p_val)

        h_uncond = _bin_entropy(p)

        best_dim = ""
        best_h_cond = h_uncond + 1.0
        for dim_name, seq in groups.items():
            if len(seq) < 5:
                continue
            h_cond = 0.0
            lost_g = sum(seq)
            ok_g = len(seq) - lost_g
            # H(loss|dim=value): 该分组内的丢包熵 + H(loss|dim=¬value)
            p_g = lost_g / max(len(seq), 1)
            p_ng_num = total_lost - lost_g
            p_ng_den = n - len(seq)
            p_ng = p_ng_num / max(p_ng_den, 1)
            w_g = len(seq) / n
            w_ng = 1.0 - w_g
            h_cond = w_g * _bin_entropy(p_g) + w_ng * _bin_entropy(p_ng)
            if h_cond < best_h_cond:
                best_h_cond = h_cond
                best_dim = dim_name

        # 显著相关: 条件熵至少降低30%
        is_corr = best_h_cond < h_uncond * 0.7 and best_dim != ""
        return best_dim, best_h_cond, h_uncond, is_corr

    @staticmethod
    def _detect_periodicity(gaps: List[int]) -> Tuple[bool, int]:
        """自相关周期检测: 间隔序列的lag=2..len/2自相关。"""
        n = len(gaps)
        if n < 10:
            return False, 0
        mean_g = sum(gaps) / n
        var_g = sum((g - mean_g) ** 2 for g in gaps) / n
        if var_g < 1e-6:
            return False, 0

        best_lag = 0
        best_corr = 0.0
        for lag in range(2, n // 2):
            corr = sum((gaps[i] - mean_g) * (gaps[i+lag] - mean_g)
                      for i in range(n - lag)) / ((n - lag) * var_g)
            if abs(corr) > abs(best_corr):
                best_corr = corr
                best_lag = lag

        return abs(best_corr) > 0.5, best_lag


def detect_loss_pattern(loss_seq: List[bool], flow_key: str = "flow_0",
                         groups: Dict[str, List[bool]] = None
                         ) -> Optional[LossAlert]:
    return LossPatternDetector().analyze(flow_key, loss_seq, groups)


__all__ = [
    "LossPatternProfile", "LossAlert", "LossPatternDetector",
    "detect_loss_pattern",
]
