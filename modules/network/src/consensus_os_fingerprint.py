# 共识OS指纹识别 —— 多TCP/IP参数加权投票替代单模式匹配。
#
# 现有topology_mapper用p0f风格单签名匹配(TTL+窗口+选项顺序→OS),
# 三个缺陷: (1)签名库覆盖不全→未知OS无法识别 (2)单特征冲突→误判
# (3)无法处理NAT后多OS混合场景。
#
# 本模块对五个独立TCP/IP参数各自打分→加权投票→共识OS推断:
#   1. 初始TTL: 2^n边界值(64/128/255)→OS族(Win=128, Linux=64)
#   2. TCP窗口大小: 不同OS有不同的默认窗口范围和缩放策略
#   3. TCP选项顺序: 各OS有特征选项序列
#   4. IP ID生成模式: 全局递增(Win)/每连接递增(Linux)/随机(BSD)
#   5. TCP时间戳行为: 是否发送TSopt/TS值频率(从clock_skew得来)
#
# 共识投票: 各参数独立→OS候选集, 交集候选投票得分最高者→共识OS。
# 无交集时→按参数置信度加权排序, 输出前3候选+混合OS(NAT)标记。
#
# 与p0f(topology_mapper)互补: p0f做快速单签名匹配, 本模块做多参数
# 共识推断, 对未知/模糊OS的覆盖率更高。

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class OsSignal:
    """单个TCP/IP参数的OS推断信号"""
    parameter: str       # "ttl"/"window"/"options"/"ip_id"/"tcp_ts"
    candidates: List[Tuple[str, float]]  # [(os_name, score)]
    # score ∈ [0,1]: 该参数对该OS的支持度
    raw_value: Any = None
    confidence: float = 0.0  # 该参数自身的区分度


@dataclass
class ConsensusFingerprint:
    """共识OS指纹结果"""
    device_ip: str
    primary_os: str              # 共识推断的OS
    primary_confidence: float    # [0,1]
    alternative_os: List[Tuple[str, float]]  # 替代候选
    signals: List[OsSignal]
    is_nat_gateway: bool         # 多个OS族显著混合→NAT
    nat_os_components: List[str] = field(default_factory=list)


class ConsensusOsFingerprinter:
    """多参数共识OS指纹识别器。

    五个参数各自对OS候选集打分→加权投票→共识推断。
    各参数权重基于区分度和抗伪造性设定。
    """

    # OS族TTL基准值
    _TTL_BASES = {
        64: [("Linux", 0.9), ("Android", 0.8), ("macOS", 0.7),
             ("FreeBSD", 0.7), ("iOS", 0.6)],
        128: [("Windows", 0.9), ("Windows Server", 0.7)],
        255: [("Cisco IOS", 0.8), ("Solaris", 0.6), ("Juniper", 0.5)],
        32: [("Windows 95/98", 0.3)],
    }

    # TCP窗口大小特征(缩放前)
    _WINDOW_PROFILES = {
        "Windows 10/11": (28000, 65535, 0.85),
        "Windows 7/2008": (8000, 18000, 0.7),
        "Linux 4.x+": (28000, 32000, 0.85),
        "Linux 2.6/3.x": (5800, 65535, 0.8),
        "macOS": (65535, 65535, 0.8),
        "Android": (65535, 65535, 0.75),
        "iOS": (65535, 65535, 0.75),
        "Cisco IOS": (2000, 5000, 0.6),
        "FreeBSD": (65535, 65535, 0.7),
    }

    _OPTION_ORDER_PROFILES = {
        "mss,sok,ts,nop,ws": [("Linux 4.x+", 0.95), ("Android", 0.85)],
        "mss,nop,ws,nop,nop,sok": [("Windows 10/11", 0.9)],
        "mss,nop,nop,sok": [("Windows 7/2008", 0.85)],
        "mss,nop,ws,nop,nop,ts,nop,sok,eol": [("macOS", 0.9)],
        "mss,nop,ws,nop,nop,ts,sok,eol": [("iOS", 0.9)],
        "mss": [("Cisco IOS", 0.6)],
        "mss,sok,ts": [("FreeBSD", 0.8)],
    }

    _IP_ID_MODES = {
        "global_increment": [("Windows", 0.8), ("Windows Server", 0.7)],
        "per_conn_increment": [("Linux", 0.85), ("Android", 0.7)],
        "random": [("OpenBSD", 0.7), ("macOS", 0.5)],
        "zero": [("Embedded", 0.5), ("IoT", 0.5)],
    }

    _PARAM_WEIGHTS = {
        "ttl": 0.15, "window": 0.25, "options": 0.30,
        "ip_id": 0.15, "tcp_ts": 0.15,
    }

    def fingerprint(self, device_ip: str,
                    initial_ttl: int = 0,
                    tcp_window: int = 0,
                    tcp_options_order: str = "",
                    ip_id_mode: str = "",
                    tcp_ts_present: bool = False,
                    ) -> ConsensusFingerprint:
        """多参数共识OS指纹识别。"""
        signals: List[OsSignal] = []

        # 1. TTL分析
        ttl_candidates = self._analyze_ttl(initial_ttl)
        signals.append(OsSignal("ttl", ttl_candidates,
                                raw_value=initial_ttl,
                                confidence=0.6 if initial_ttl in (64,128,255) else 0.2))

        # 2. TCP窗口大小
        win_candidates = self._analyze_window(tcp_window)
        signals.append(OsSignal("window", win_candidates,
                                raw_value=tcp_window,
                                confidence=0.7 if tcp_window > 0 else 0.0))

        # 3. TCP选项顺序
        opt_candidates = self._analyze_options(tcp_options_order)
        signals.append(OsSignal("options", opt_candidates,
                                raw_value=tcp_options_order,
                                confidence=0.8 if tcp_options_order else 0.0))

        # 4. IP ID模式
        ipid_candidates = self._analyze_ip_id(ip_id_mode)
        signals.append(OsSignal("ip_id", ipid_candidates,
                                raw_value=ip_id_mode,
                                confidence=0.5 if ip_id_mode else 0.0))

        # 5. TCP时间戳
        ts_candidates = (self._analyze_tcp_ts(tcp_ts_present)
                        if tcp_ts_present is not None else [])
        signals.append(OsSignal("tcp_ts", ts_candidates,
                                raw_value=tcp_ts_present,
                                confidence=0.4))

        # 加权投票
        os_scores: Dict[str, float] = Counter()
        for s in signals:
            w = self._PARAM_WEIGHTS.get(s.parameter, 0.15)
            for os_name, score in s.candidates:
                os_scores[os_name] += w * score * s.confidence

        ranked = sorted(os_scores.items(), key=lambda x: -x[1])
        # 归一化
        max_score = max((s for _, s in ranked), default=1.0)
        ranked_norm = [(n, round(s / max(max_score, 0.01), 3))
                       for n, s in ranked]

        primary = ranked_norm[0] if ranked_norm else ("unknown", 0.0)

        # NAT检测: 多个OS族得分差距<0.3且来自不同OS族
        is_nat = False
        nat_components: List[str] = []
        if len(ranked_norm) >= 2:
            gap = ranked_norm[0][1] - ranked_norm[1][1]
            if gap < 0.3:
                os_families = set()
                for name, _ in ranked_norm[:3]:
                    fam = name.split()[0] if name else ""
                    os_families.add(fam)
                if len(os_families) >= 2:
                    is_nat = True
                    nat_components = [n for n, _ in ranked_norm[:3]]

        return ConsensusFingerprint(
            device_ip=device_ip,
            primary_os=primary[0],
            primary_confidence=primary[1],
            alternative_os=ranked_norm[1:4] if len(ranked_norm) > 1 else [],
            signals=signals,
            is_nat_gateway=is_nat,
            nat_os_components=nat_components,
        )

    def _analyze_ttl(self, ttl: int) -> List[Tuple[str, float]]:
        if ttl in self._TTL_BASES:
            return list(self._TTL_BASES[ttl])
        # 近似匹配: 最近的2^n边界
        for base in [64, 128, 255, 32]:
            if abs(ttl - base) <= 3:
                return [(f"{self._TTL_BASES[base][0][0]} (≈{base})",
                        self._TTL_BASES[base][0][1] * 0.7)]
        return [("unknown", 0.1)]

    def _analyze_window(self, window: int) -> List[Tuple[str, float]]:
        if window <= 0:
            return []
        candidates: List[Tuple[str, float]] = []
        for os_name, (lo, hi, score) in self._WINDOW_PROFILES.items():
            if lo <= window <= hi:
                # 越接近范围中心→得分越高
                mid = (lo + hi) / 2
                dist_penalty = 1.0 - abs(window - mid) / max(hi - lo, 1)
                candidates.append((os_name, round(score * max(dist_penalty, 0.5), 3)))
        candidates.sort(key=lambda x: -x[1])
        return candidates[:3]

    def _analyze_options(self, order: str) -> List[Tuple[str, float]]:
        if not order:
            return []
        order_lower = order.lower()
        for pattern, candidates in self._OPTION_ORDER_PROFILES.items():
            if order_lower == pattern:
                return list(candidates)
        # 模糊匹配: 选项子集
        opts = set(order_lower.split(","))
        best_match = []
        for pattern, candidates in self._OPTION_ORDER_PROFILES.items():
            p_opts = set(pattern.split(","))
            jaccard = len(opts & p_opts) / max(len(opts | p_opts), 1)
            if jaccard > 0.5:
                for name, score in candidates:
                    best_match.append((name, round(score * jaccard, 3)))
        return sorted(best_match, key=lambda x: -x[1])[:3]

    def _analyze_ip_id(self, mode: str) -> List[Tuple[str, float]]:
        return self._IP_ID_MODES.get(mode, [])

    def _analyze_tcp_ts(self, present: bool) -> List[Tuple[str, float]]:
        if present:
            return [("Modern OS", 0.5)]
        return [("Legacy/Embedded", 0.3)]


__all__ = [
    "OsSignal", "ConsensusFingerprint",
    "ConsensusOsFingerprinter",
]
