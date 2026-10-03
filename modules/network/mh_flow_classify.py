"""MH-Flow: 多视图融合分类器。

每视图独立原型匹配后加权融合。MH-Net视图级融合：
各视图对同一对象给出互补信号，加权求和优于单一视图。
原型法支持无外部ML库增量训练。
"""
from typing import List, Dict, Tuple, Any

from .mh_flow_types import (
    MultiViewFeatures, LEN_BINS, IAT_BINS, VIEW_DIMS,
    cosine_sim,
)


class MhFlowClassifier:
    """多视图融合分类器 —— 每视图独立原型匹配后加权融合。"""

    _VIEW_WEIGHTS = {"tls": 0.20, "size": 0.30, "timing": 0.25, "plaintext": 0.25}
    _CONF_MARGIN = 0.05

    def __init__(self, use_default_prototypes: bool = True):
        self._prototypes: Dict[str, Dict[str, List[float]]] = {}
        self._classes: List[str] = []
        if use_default_prototypes:
            self._prototypes = self._default_prototypes()
            self._classes = list(self._prototypes.keys())

    @staticmethod
    def _default_prototypes() -> Dict[str, Dict[str, List[float]]]:
        """默认类原型 —— 基于公开数据集先验的启发式原型。"""
        nb, ni = len(LEN_BINS), len(IAT_BINS)

        def _mk(size_peak: List[int], iat_peak: List[int], plain: float) -> Dict[str, List[float]]:
            sv = [0.0] * nb
            for i in size_peak:
                sv[i] = 1.0
            ssum = sum(sv) or 1.0
            sv = [x / ssum for x in sv]
            tv = [0.0] * ni
            for i in iat_peak:
                tv[i] = 1.0
            tsum = sum(tv) or 1.0
            tv = [x / tsum for x in tv]
            return {
                "size": sv + [0.5, 0.3, 0.5, 0.3],
                "timing": tv + [0.3, 0.3, 0.5, 0.3, 0.3, 0.3],
                "tls": [0.4, 0.4, 0.5, 0.5, 0.8, 0.5],
                "plaintext": [plain, 0.5, 0.3, 0.0, 0.2, 0.2],
            }

        protos = {
            "video_streaming": _mk([8, 9, 10, 11], [0, 1], 0.05),
            "file_transfer": _mk([10, 11], [0], 0.10),
            "web_browsing": _mk([4, 5, 6, 7, 8], [1, 2, 3], 0.50),
            "voip": _mk([0, 1, 2], [1, 2], 0.0),
            "dns": _mk([0, 1], [3, 4], 0.20),
            "iot_telemetry": _mk([0, 1, 2], [5, 6], 0.0),
        }
        return protos

    def get_classes(self) -> List[str]:
        return list(self._classes)

    def fit(self, samples: List[Tuple[str, MultiViewFeatures]]) -> int:
        """以 (标签, 多视图特征) 样本增量构建类原型。

        每视图取样本均值作为原型；已存在类原型与新均值50/50合并
        （轻量在线更新，避免完全重训）。
        """
        from collections import defaultdict
        agg: Dict[str, Dict[str, List[float]]] = {}
        cnt: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        view_map_names = ("tls", "size", "timing", "plaintext")
        for label, feats in samples:
            view_map = {v: getattr(feats, v + "_view") for v in view_map_names}
            d = agg.setdefault(label, {})
            for vname, vec in view_map.items():
                cur = d.setdefault(vname, [0.0] * len(vec))
                for i, x in enumerate(vec):
                    cur[i] += x
                cnt[label][vname] += 1
        for label, vd in agg.items():
            for vname, vec in vd.items():
                n = max(cnt[label][vname], 1)
                vd[vname] = [x / n for x in vec]
        for label, vd in agg.items():
            if label in self._prototypes:
                old = self._prototypes[label]
                for vname, nv in vd.items():
                    ov = old.get(vname)
                    if ov:
                        self._prototypes[label][vname] = \
                            [(o + x) / 2.0 for o, x in zip(ov, nv)]
                    else:
                        self._prototypes[label][vname] = nv
            else:
                self._prototypes[label] = vd
                self._classes.append(label)
        return len(self._classes)

    def predict(self, feats: MultiViewFeatures) -> Dict[str, Any]:
        """对多视图特征做余弦原型匹配并加权融合。"""
        view_map = {"tls": feats.tls_view, "size": feats.size_view,
                    "timing": feats.timing_view, "plaintext": feats.plaintext_view}
        if not self._prototypes:
            return {"class": "unknown", "confidence": 0.0,
                    "scores": {}}
        scores: Dict[str, float] = {}
        for label, proto_views in self._prototypes.items():
            total = 0.0
            for vname, weight in self._VIEW_WEIGHTS.items():
                sim = cosine_sim(view_map.get(vname, []),
                                proto_views.get(vname, []))
                total += weight * sim
            scores[label] = total
        best = max(scores, key=scores.get)
        vals = sorted(scores.values(), reverse=True)
        runner = vals[1] if len(vals) > 1 else 0.0
        margin = vals[0] - runner if vals else 0.0
        return {
            "class": best if margin > self._CONF_MARGIN else "unknown",
            "confidence": min(max(vals[0], 0.0), 1.0),
            "scores": dict(scores),
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "classes": list(self._classes),
            "prototype_count": len(self._prototypes),
            "view_weights": dict(self._VIEW_WEIGHTS),
        }


def split_view_vector(vec: List[float]) -> MultiViewFeatures:
    """将拼接视图向量拆回四视图 —— 图精化特征回映射。

    维度由 VIEW_DIMS 约束；不足部分补零，保证分类器输入定长。
    """
    f = MultiViewFeatures()
    pos = 0
    for name, dim in VIEW_DIMS.items():
        part = list(vec[pos:pos + dim]) if vec else []
        part += [0.0] * (dim - len(part))
        setattr(f, name + "_view", part)
        pos += dim
    return f


__all__ = ["MhFlowClassifier", "split_view_vector"]
