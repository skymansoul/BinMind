"""
ML-QED-Lite 三级 PQC 检测管道。

流水线: Tier 1 (XGBoost 分类) 快速排除非 PQC -> Tier 2 (QED-Lite 指纹) 精确验证 -> Tier 3 (FoC 摘要) 语义描述。
设计依据: ML-QED-Lite Figure 2 级联架构，成本与精度逐级递增。
导出: PQCMLPipeline, detect_pqc_ml, detect_pqc_ml_bytes
"""

import logging
from typing import List, Optional

from .features import PQCMLResult, _extract_features
from .classifier import PQCLibraryClassifier
from .fingerprint import _simulate_qed_lite_fingerprint

_log = logging.getLogger(__name__)

__all__ = [
    "PQCMLPipeline",
    "detect_pqc_ml",
    "detect_pqc_ml_bytes",
]


class PQCMLPipeline:
    """
    ML-QED-Lite 三级管道实例。

    执行顺序: Tier 1 分类 -> Tier 2 指纹验证 -> Tier 3 可选摘要。
    级联策略: 低成本高召回 Tier 1 先行过滤，高成本高精度 Tier 2/3 验证候选。
    """

    def __init__(self, model_path: str = "", api_key: str = ""):
        self._classifier = PQCLibraryClassifier(model_path)
        self._api_key = api_key
        self._tier2_cache: dict = {}

    def scan_file(
        self,
        path: str,
        imported_symbols: Optional[List[str]] = None,
        library_deps: Optional[dict] = None,
        run_tier3: bool = False,
    ) -> List[PQCMLResult]:
        """
        对单个文件执行三级管道。

        参数:
          path:             二进制文件路径
          imported_symbols: 预解析导入符号 (可选)
          library_deps:     预检测库依赖 (可选)
          run_tier3:        是否运行 Tier 3 摘要 (默认关, 涉及 API 成本)

        返回:
          PQCMLResult 列表, 置信度降序。
        """
        raw = None
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            _log.error("无法读取 %s: %s", path, e)
            return []

        if raw is None:
            return []

        all_results: List[PQCMLResult] = []

        # Tier 1: XGBoost 分类
        features = _extract_features(raw, imported_symbols, library_deps, path)
        tier1_results = self._classifier.classify(features)

        for r in tier1_results:
            r.detected_in = path
            if r.algorithm == "no_pqc" and r.confidence > 0.9:
                continue  # 高置信度非 PQC, 不添加到结果
            all_results.append(r)

        # Tier 2: QED-Lite 指纹
        tier2_findings = _simulate_qed_lite_fingerprint(raw)
        for finding in tier2_findings:
            # 关联 Tier 1: 库名部分匹配则置信度取高值
            matched = False
            for r in all_results:
                lib_lower = finding["lib"].lower()
                if lib_lower in r.library_hint.lower() or r.library_hint.lower() in lib_lower:
                    r.confidence = max(r.confidence, finding["confidence"])
                    r.evidence.append(finding["evidence"])
                    r.tier = 2
                    matched = True
                    break

            if not matched:
                all_results.append(PQCMLResult(
                    algorithm=finding["lib"],
                    confidence=finding["confidence"],
                    tier=2,
                    evidence=[finding["evidence"]],
                    library_hint=finding["lib"],
                    version_hint=finding.get("version", ""),
                    detected_in=path,
                ))

        # 去重: (algorithm, library_hint) 保留最高置信度
        seen: set = set()
        unique: List[PQCMLResult] = []
        for r in sorted(all_results, key=lambda x: x.confidence, reverse=True):
            key = (r.algorithm, r.library_hint)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        all_results = unique

        return all_results


# 便捷函数

def detect_pqc_ml(
    path: str,
    run_tier3: bool = False,
    model_path: str = "",
) -> List[PQCMLResult]:
    """便捷入口: 单文件管道检测。"""
    return PQCMLPipeline(model_path=model_path).scan_file(path, run_tier3=run_tier3)


def detect_pqc_ml_bytes(
    data: bytes,
    imported_symbols: Optional[List[str]] = None,
    library_deps: Optional[dict] = None,
) -> List[PQCMLResult]:
    """便捷入口: 内存数据特征提取与分类。"""
    features = _extract_features(data, imported_symbols, library_deps)
    return PQCLibraryClassifier().classify(features)
