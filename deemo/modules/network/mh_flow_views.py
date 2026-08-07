"""MH-Flow: 多视图特征抽取器。

从SessionRecord提取四视图定长特征向量：
TLS指纹视图/报文大小序列视图/时序视图/可读明文段视图。

MH-Net视图划分：同一对象从多个互补视角观测，
每视图独立编码后在图层融合，缓解单一统计视图盲区。
"""
from typing import List, Tuple

from .mh_flow_types import (
    SessionRecord, MultiViewFeatures,
    LEN_BINS, IAT_BINS, PLAINTEXT_MARKERS,
    shannon_entropy, quantile, seq_hash,
    extract_readable_segments,
)


class MultiViewExtractor:
    """多视图特征抽取器 —— 从会话提取四视图定长特征向量。"""

    @staticmethod
    def extract(session: SessionRecord) -> MultiViewFeatures:
        feats = MultiViewFeatures()
        feats.tls_view = MultiViewExtractor._tls_view(session)
        feats.size_view = MultiViewExtractor._size_view(session)
        feats.timing_view = MultiViewExtractor._timing_view(session)
        feats.plaintext_view, readable = MultiViewExtractor._plaintext_view(session)
        feats.raw_plaintext = readable
        return feats

    @staticmethod
    def _tls_view(s: SessionRecord) -> List[float]:
        """TLS指纹视图 —— 密码套件/扩展序列的结构统计。

        与tls_analyzer的JA3/JA4互补：此处关注序列结构与复杂度，
        而非精确哈希；用于图分类的连续特征。
        """
        import math
        ciphers = s.tls_ciphers or []
        exts = s.tls_extensions or []
        c_ent = shannon_entropy(ciphers)
        e_ent = shannon_entropy(exts)
        _seq_hash = seq_hash(ciphers, exts)
        return [
            float(len(ciphers)),
            float(len(exts)),
            c_ent,
            e_ent,
            float(bool(ciphers) or bool(exts)),
            float(_seq_hash % 1000000) / 1000000.0,
        ]

    @staticmethod
    def _size_view(s: SessionRecord) -> List[float]:
        """报文大小序列视图 —— 分箱直方图+矩特征。

        分箱对齐MTU边界（ECHO非均匀分箱），捕获大小形态；
        矩特征捕获整体尺度与离散度。
        """
        import math
        lens = s.packet_lens
        n = len(lens)
        if n == 0:
            return [0.0] * (len(LEN_BINS) + 4)
        hist = [0] * len(LEN_BINS)
        for pl in lens:
            for bi, (lo, hi) in enumerate(LEN_BINS):
                if lo <= pl <= hi:
                    hist[bi] += 1
                    break
        total = max(n, 1)
        hist_n = [h / total for h in hist]
        mean_l = sum(lens) / total
        var_l = sum((x - mean_l) ** 2 for x in lens) / total
        std_l = math.sqrt(var_l)
        ent = shannon_entropy(lens)
        return hist_n + [
            min(mean_l / 9000.0, 1.0),
            min(std_l / 9000.0, 1.0),
            min(ent / 12.0, 1.0),
            min(n / 200.0, 1.0),
        ]

    @staticmethod
    def _timing_view(s: SessionRecord) -> List[float]:
        """时序视图 —— 包间隔（IAT）分布统计。

        IAT是加密流量分类高区分度维度：交互式/流媒体/批量传输
        到达模式差异显著。对数分箱+矩特征+分位数。
        """
        import math
        times = s.packet_times
        n = len(times)
        if n < 2:
            return [0.0] * (len(IAT_BINS) + 6)
        iats = [max(times[i + 1] - times[i], 0.0) for i in range(n - 1)]
        hist = [0] * len(IAT_BINS)
        for iat in iats:
            for bi, (lo, hi) in enumerate(IAT_BINS):
                if lo <= iat < hi:
                    hist[bi] += 1
                    break
        total = max(len(iats), 1)
        hist_n = [h / total for h in hist]
        mean_i = sum(iats) / total
        var_i = sum((x - mean_i) ** 2 for x in iats) / total
        std_i = math.sqrt(var_i)
        ent = shannon_entropy([round(x, 4) for x in iats])
        iat_sorted = sorted(iats)
        q = [quantile(iat_sorted, p) for p in (0.25, 0.5, 0.75)]
        return hist_n + [
            min(mean_i, 1.0),
            min(std_i, 1.0),
            min(ent / 8.0, 1.0),
        ] + [min(qq / 2.0, 1.0) for qq in q]

    @staticmethod
    def _plaintext_view(s: SessionRecord) -> Tuple[List[float], List[bytes]]:
        """可读明文段视图 —— 明文比例/词元统计/协议标记得分。

        两阶段策略的明文判据：明文比例高且命中协议标记的会话
        进入明文预筛，无需做密文图建模。
        """
        readable_segs: List[bytes] = []
        for payload in s.payloads:
            readable_segs.extend(extract_readable_segments(payload))
        if not readable_segs:
            return [0.0] * 6, []
        total_bytes = sum(len(x) for x in s.payloads)
        plain_bytes = sum(len(x) for x in readable_segs)
        ratio = plain_bytes / max(total_bytes, 1)
        tokens: List[str] = []
        for seg in readable_segs[:8]:
            try:
                tokens.extend(seg.decode("utf-8", errors="ignore").split())
            except Exception:
                pass
        distinct = len(set(t.lower() for t in tokens))
        marker_score = 0.0
        for markers in PLAINTEXT_MARKERS.values():
            if any(mk in seg for seg in readable_segs[:4] for mk in markers):
                marker_score = 1.0
                break
        seg_ent = shannon_entropy(b"".join(readable_segs[:4]))
        return [
            min(ratio, 1.0),
            min(seg_ent / 8.0, 1.0),
            min(distinct / 50.0, 1.0),
            marker_score,
            min(len(readable_segs) / 20.0, 1.0),
            min(sum(len(x) for x in readable_segs) / 1000.0, 1.0),
        ], readable_segs


__all__ = ["MultiViewExtractor"]
