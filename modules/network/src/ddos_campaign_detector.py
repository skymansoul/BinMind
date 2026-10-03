# DDoS协同活动检测入口 —— 便捷接口。

from typing import Dict, List

from .ddos_cross_vector import CrossVectorCorrelator, CrossVectorReport


def detect_cross_vector_campaigns(
    vector_history: Dict[str, List[int]]
) -> CrossVectorReport:
    """便捷入口: {向量名→计数历史}→跨向量关联分析→协同活动报告。

    vector_history: {"syn": [100,120,...], "udp": [50,60,...], ...}
    每个列表元素=一个时间窗口的包计数。
    """
    correlator = CrossVectorCorrelator()
    max_len = max((len(v) for v in vector_history.values()), default=0)
    for w in range(max_len):
        counts = {}
        for vname, history in vector_history.items():
            if w < len(history):
                counts[vname] = history[w]
        if counts:
            correlator.feed_counts(counts, float(w))
    return correlator.analyze()


__all__ = ["detect_cross_vector_campaigns"]
