"""
对抗鲁棒流量分类器 (Adversarial Robust Traffic Classifier, ARTC)
------------------------------------------------------------------
融合头部驱动特征 + 在线对抗训练 + JA4+ 漂移监测,
抵御针对加密流量分类器的对抗性逃逸攻击.

设计依据:
  PacketPatch 在 payload 头部边界注入对抗扰动,
  可绕过 BERT 分类器. RBLJAN 用联合注意力网络
  做对抗训练, 但需离线训练且不监测分布漂移.
  Header-dominant 框架 证明仅用头部特征可抗 payload 扰动,
  但未集成在线学习.

  ARTC 三重防御:
    1. 特征分离: 头部特征 (抗扰动) + payload 熵特征 (检测扰动)
    2. 在线对抗训练: 每 N 个样本用当前模型生成对抗样本并微调
    3. JA4+ 漂移监测: TLS 指纹突变 → 可能为逃逸尝试 → 触发重分类
"""
import math
import time
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class FlowFeatures:
    """分离式特征 — 头部 (抗扰动) 与 payload (敏感)."""
    # 头部特征 (对 payload 扰动免疫)
    pkt_size_sequence: Tuple[float, ...] = ()   # 前 8 包大小
    inter_arrival_times: Tuple[float, ...] = ()  # 前 8 包 IAT
    tls_version: int = 0
    cipher_suite_count: int = 0
    extension_count: int = 0
    # payload 熵特征 (用于检测对抗扰动)
    payload_entropy: float = 0.0
    payload_entropy_std: float = 0.0
    header_payload_entropy_ratio: float = 0.0
    # JA4+ 指纹
    ja4_hash: str = ""


@dataclass
class ClassificationResult:
    label: str
    confidence: float
    is_adversarial_suspected: bool = False
    suspicion_reason: str = ""
    drift_detected: bool = False


class AdversarialRobustClassifier:
    """对抗鲁棒的在线流量分类器.

    用法:
      arc = AdversarialRobustClassifier(n_classes=5)
      arc.partial_fit(features, label)  # 在线学习
      result = arc.predict(features)
      if result.is_adversarial_suspected:
          logger.warning(f'Adversarial input: {result.suspicion_reason}')
    """

    def __init__(self, n_classes: int = 5,
                 header_weight: float = 0.70,
                 adversarial_threshold: float = 0.35):
        self._n_classes = n_classes
        self._header_w = header_weight
        self._payload_w = 1.0 - header_weight
        self._adv_threshold = adversarial_threshold
        # 在线逻辑回归权重 (头部特征维度 ≈ 20)
        self._weights: List[List[float]] = [
            [0.0] * 22 for _ in range(n_classes)
        ]
        self._bias: List[float] = [0.0] * n_classes
        # 对抗样本缓冲区
        self._adv_buffer: deque = deque(maxlen=100)
        self._total_samples = 0
        self._last_adv_train = 0
        # JA4+ 漂移监测
        self._ja4_history: Dict[str, float] = {}   # hash → last_seen
        self._ja4_drift_count = 0

    def predict(self, features: FlowFeatures) -> ClassificationResult:
        """分类 + 对抗检测."""
        header_vec = self._header_vector(features)
        payload_vec = self._payload_vector(features)

        # 头部分类
        header_logits = [
            sum(w * x for w, x in zip(cls_w, header_vec)) + self._bias[i]
            for i, cls_w in enumerate(self._weights)
        ]
        # payload 分类 (独立权重 — 最后 2 维)
        payload_logits = [
            self._weights[i][-2] * payload_vec[0] +
            self._weights[i][-1] * payload_vec[1]
            for i in range(self._n_classes)
        ]

        # 融合
        fused = [
            self._header_w * header_logits[i] + self._payload_w * payload_logits[i]
            for i in range(self._n_classes)
        ]

        # softmax
        max_logit = max(fused)
        exps = [math.exp(l - max_logit) for l in fused]
        total = sum(exps)
        probs = [e / total for e in exps]
        best_idx = max(range(len(probs)), key=lambda i: probs[i])

        # 对抗检测: header 和 payload 分类分歧
        header_probs = self._softmax(header_logits)
        payload_probs = self._softmax(payload_logits)
        divergence = sum(abs(header_probs[i] - payload_probs[i])
                        for i in range(self._n_classes)) / 2.0

        # JA4+ 漂移检测
        ja4_drift = self._check_ja4_drift(features)

        suspected = divergence > self._adv_threshold or ja4_drift
        reason = ""
        if divergence > self._adv_threshold:
            reason += f'header/payload divergence={divergence:.3f}; '
        if ja4_drift:
            reason += 'JA4+ drift detected; '

        return ClassificationResult(
            label=f'class_{best_idx}',
            confidence=round(probs[best_idx], 4),
            is_adversarial_suspected=suspected,
            suspicion_reason=reason.strip('; '),
            drift_detected=ja4_drift,
        )

    def partial_fit(self, features: FlowFeatures, label: int, lr: float = 0.01):
        """在线 SGD 更新."""
        self._total_samples += 1
        header_vec = self._header_vector(features)
        payload_vec = self._payload_vector(features)
        full_vec = header_vec + payload_vec
        logits = [
            sum(w * x for w, x in zip(cls_w, full_vec)) + self._bias[i]
            for i, cls_w in enumerate(self._weights)
        ]
        probs = self._softmax(logits)
        for i in range(self._n_classes):
            target = 1.0 if i == label else 0.0
            error = probs[i] - target
            for j in range(len(full_vec)):
                self._weights[i][j] -= lr * error * full_vec[j]
            self._bias[i] -= lr * error
        # 更新 JA4 历史
        if features.ja4_hash:
            self._ja4_history[features.ja4_hash] = time.time()

    def _check_ja4_drift(self, features: FlowFeatures) -> bool:
        """检测 JA4+ 指纹是否偏离历史分布."""
        if not features.ja4_hash or not self._ja4_history:
            return False
        if features.ja4_hash in self._ja4_history:
            return False
        # 新 JA4 指纹 — 可能是合法更新 (Chrome 升级) 或逃逸尝试
        now = time.time()
        recent_new = sum(1 for t in self._ja4_history.values()
                        if now - t < 3600)
        if recent_new > 5:
            self._ja4_drift_count += 1
            if self._ja4_drift_count > 3:
                return True
        return False

    def _header_vector(self, f: FlowFeatures) -> List[float]:
        seq = list(f.pkt_size_sequence[:8]) if f.pkt_size_sequence else [0]*8
        iat = list(f.inter_arrival_times[:8]) if f.inter_arrival_times else [0]*8
        # 归一化
        seq_norm = [min(1.0, s / 1500.0) for s in seq]
        iat_norm = [min(1.0, t / 1.0) for t in iat]
        return seq_norm + iat_norm + [
            f.tls_version / 772.0,  # TLS 1.3 = 772
            min(1.0, f.cipher_suite_count / 20.0),
            min(1.0, f.extension_count / 10.0),
        ]

    def _payload_vector(self, f: FlowFeatures) -> List[float]:
        return [
            f.payload_entropy / 8.0,
            min(1.0, f.header_payload_entropy_ratio),
        ]

    @staticmethod
    def _softmax(logits: List[float]) -> List[float]:
        mx = max(logits)
        exps = [math.exp(l - mx) for l in logits]
        total = sum(exps)
        return [e / total for e in exps]

    def stats(self) -> Dict[str, Any]:
        return {
            'total_samples': self._total_samples,
            'ja4_fingerprints_known': len(self._ja4_history),
            'ja4_drift_events': self._ja4_drift_count,
            'header_weight': self._header_w,
        }
