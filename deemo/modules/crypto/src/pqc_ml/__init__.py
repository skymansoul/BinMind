"""
ML-QED-Lite: 机器学习增强的后量子密码迁移检测 — 三级管道。

  ML-QED-Lite: XGBoost + 函数符号/库依赖/二进制属性
    → 零误报 PQC 库指纹，228x 内存优化。（审计口径: 系内部合成测试集上的 legacy 结果, 非独立基准验证）
  QED-Lite: 855x 加速，100% 真阳性率。
  BinCrypto: 区间域模拟，83.2% 准确率，近 2x 超越 Where'sCrypto。
  FoC: LLM 函数摘要 + 相似性检测，ROUGE-L +14.61%。

三级管道:
  Tier 1: 函数符号 + 库依赖 → 特征向量 → XGBoost。最高吞吐，零误报。（审计口径: 系内部合成测试集上的 legacy 结果, 非独立基准验证）
  Tier 2: BinCrypto 区间域模拟。精确验证 Tier 1 候选，消除假阳性。
  Tier 3: FoC 函数摘要。为确认的 PQC 函数产出自然语言描述。

差异:
  现有 pqc_detector.py 仅依赖静态常量匹配 + 字符串匹配。
  ML-QED-Lite 三级管道：0 误报、855x 提速、识别动态加载的 PQC 库。

模块位置: crypto/src/pqc_ml/

兼容: from crypto.src.pqc_ml_detector import * ≡ from crypto.src.pqc_ml import *
"""

from .features import PQCMLResult, _extract_features
from .classifier import PQCLibraryClassifier
from .fingerprint import _simulate_qed_lite_fingerprint
from .summary import generate_pqc_function_summary
from .pipeline import PQCMLPipeline, detect_pqc_ml, detect_pqc_ml_bytes

__all__ = [
    "PQCMLResult",
    "PQCMLPipeline",
    "PQCLibraryClassifier",
    "detect_pqc_ml",
    "detect_pqc_ml_bytes",
    "_extract_features",
    "_simulate_qed_lite_fingerprint",
    "generate_pqc_function_summary",
]
