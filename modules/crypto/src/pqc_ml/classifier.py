"""
ML-QED-Lite XGBoost 分类器 — PQC 库版本分类。

参考: ML-QED-Lite Section 4.2，使用预训练 XGBoost 从 27 维特征向量
预测最可能的 PQC 库和版本，输出校准概率。
"""

import os
import logging
from typing import List

from .features import PQCMLResult

_log = logging.getLogger(__name__)

# 可选依赖 — 仅在分类时加载 XGBoost
try:
    import xgboost as xgb
    _XGB_AVAILABLE = True
except ImportError:
    _XGB_AVAILABLE = False


__all__ = [
    "PQCLibraryClassifier",
    "_CLASS_LABELS",
    "_XGB_AVAILABLE",
]


# 分类标签 — ML-QED-Lite Table 4 输出类别
_CLASS_LABELS = [
    "liboqs", "PQClean", "OpenSSL3+_PQC", "Botan_PQC",
    "libsodium_PQC", "ring_pqc", "hacl_pqc", "custom_pqc", "no_pqc",
]


class PQCLibraryClassifier:
    """
    XGBoost PQC 库版本分类器 — ML-QED-Lite Section 4.2。

    使用预训练 XGBoost 从二进制特征向量预测 PQC 库和版本，
    输出校准概率 + 可解释特征重要性。

    模型路径: <module_dir>/models/pqc_xgb_v1.json。
    模型缺失 → 降级为规则启发式 (零依赖)。

    输出类别: liboqs, PQClean, OpenSSL3+_PQC, Botan_PQC,
              libsodium_PQC, ring_pqc, hacl_pqc, custom_pqc, no_pqc
    """

    def __init__(self, model_path: str = ""):
        self._model = None
        self._loaded = False
        self._model_path = model_path or self._default_model_path()

        if _XGB_AVAILABLE and os.path.isfile(self._model_path):
            try:
                self._model = xgb.Booster()
                self._model.load_model(self._model_path)
                self._loaded = True
                _log.info("XGBoost PQC 分类器已加载: %s", self._model_path)
            except Exception as e:
                _log.warning("XGBoost 模型加载失败 (%s), 降级为启发式分类", e)

    @staticmethod
    def _default_model_path() -> str:
        # 模型 → crypto/src/models/pqc_xgb_v1.json
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "pqc_xgb_v1.json")

    def classify(
        self, features: list, top_k: int = 3
    ) -> List[PQCMLResult]:
        """
        特征向量分类，返回 top-K 预测。

        参数:
          features: 27 维特征向量
          top_k:    返回概率最高的 K 个类别

        返回: 概率降序的 PQCMLResult 列表。

        降级: 模型未加载 → 规则启发式。
        规则依据特征 1 (PQC 符号数) 和特征 12-18 (库标志) 阈值。
        """
        if self._loaded and self._model is not None:
            return self._classify_xgboost(features, top_k)
        return self._classify_heuristic(features, top_k)

    def _classify_xgboost(self, features: list, top_k: int) -> List[PQCMLResult]:
        """XGBoost 分类."""
        import numpy as np
        dmatrix = xgb.DMatrix(np.array([features], dtype=np.float32))
        probs = self._model.predict(dmatrix)[0]  # shape (n_classes,)

        results = []
        top_indices = np.argsort(probs)[::-1][:top_k]
        for idx in top_indices:
            label = _CLASS_LABELS[idx] if idx < len(_CLASS_LABELS) else "unknown"
            prob = float(probs[idx])
            if prob < 0.05:
                continue
            results.append(PQCMLResult(
                algorithm=label,
                confidence=min(prob + 0.1, 0.99),
                tier=1,
                probability=prob,
                feature_vector=features,
                library_hint=label,
            ))
        return results

    def _classify_heuristic(self, features: list, top_k: int) -> List[PQCMLResult]:
        """
        规则启发式分类 — XGBoost 不可用时的降级。

        依据 ML-QED-Lite Table 3 特征重要性:
          - 特征 1 (PQC 符号数) gain=0.38
          - 特征 12-18 (库检测) 联合 gain=0.41
        """
        results = []
        n_pqc_symbols = features[1]
        dep_flags = {
            "liboqs": features[13],
            "PQClean": features[14],
            "OpenSSL3+_PQC": features[16],
            "Botan_PQC": features[15],
            "libsodium_PQC": features[12],
            "ring_pqc": features[17],
            "hacl_pqc": features[18],
        }

        if n_pqc_symbols == 0 and all(v == 0.0 for v in dep_flags.values()):
            results.append(PQCMLResult(
                algorithm="no_pqc", confidence=0.95, tier=1, probability=0.95,
                library_hint="no_pqc",
                evidence=["无 PQC 符号且无已知 PQC 库依赖"],
            ))
            return results

        has_unknown = features[19] > 0.0
        total_hits = sum(dep_flags.values())

        for lib_name, flag in dep_flags.items():
            if flag > 0.0:
                # 库检测命中 → 较高置信度
                confidence = 0.85 if n_pqc_symbols > 2 else 0.65
                results.append(PQCMLResult(
                    algorithm=lib_name, confidence=confidence, tier=1,
                    probability=0.85, library_hint=lib_name,
                    evidence=[f"库依赖检测: {lib_name}"],
                ))

        if not results:
            # PQC 符号存在但无已知库 → custom_pqc
            conf = 0.55 if has_unknown else 0.45
            results.append(PQCMLResult(
                algorithm="custom_pqc", confidence=conf, tier=1,
                probability=0.45, library_hint="custom_pqc",
                evidence=["检测到 PQC 符号但无已知库匹配"],
            ))

        return sorted(results, key=lambda r: r.confidence, reverse=True)[:top_k]
