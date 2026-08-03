"""
漏洞机器学习 — 漏洞严重度预测。

模型/规则混合预测 + 多子分集成融合 + 阈值校准 + 默认模型管理。
"""

from __future__ import annotations

import json
import logging
import math
import os
import pickle
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# Severity labels
_LABELS_ = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_LABEL_MAP_ = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Base scores for vulnerability types (0-1 scale)
_TYPE_SCORES_: Dict[str, float] = {
    'buffer_overflow': 0.8,
    'heap_overflow': 0.85,
    'stack_overflow': 0.85,
    'use_after_free': 0.9,
    'double_free': 0.85,
    'format_string': 0.75,
    'integer_overflow': 0.65,
    'off_by_one': 0.55,
    'null_dereference': 0.5,
    'race_condition': 0.7,
    'command_injection': 0.95,
    'sql_injection': 0.9,
    'xss': 0.6,
    'path_traversal': 0.7,
    'privilege_escalation': 0.9,
    'info_leak': 0.4,
    'denial_of_service': 0.55,
    'memory_corruption': 0.85,
    'code_execution': 0.95,
    'authentication_bypass': 0.9,
    'crypto_weakness': 0.6,
    'default': 0.5,
}

# 漏洞可利用性预估基准 -- 基于历史CVE数据中各类漏洞被野外利用的比例
_EXPLOITABILITY_PRIORS_: Dict[str, float] = {
    'buffer_overflow': 0.12,
    'heap_overflow': 0.15,
    'stack_overflow': 0.14,
    'use_after_free': 0.18,
    'double_free': 0.13,
    'format_string': 0.10,
    'integer_overflow': 0.06,
    'off_by_one': 0.04,
    'null_dereference': 0.03,
    'race_condition': 0.08,
    'command_injection': 0.22,
    'sql_injection': 0.16,
    'xss': 0.05,
    'path_traversal': 0.09,
    'privilege_escalation': 0.20,
    'info_leak': 0.02,
    'denial_of_service': 0.07,
    'memory_corruption': 0.17,
    'code_execution': 0.25,
    'authentication_bypass': 0.19,
    'crypto_weakness': 0.04,
    'default': 0.05,
}


class VulnSeverityPredictor:
    """Predicts vulnerability severity using a hybrid model/rules approach.

    Combines heuristic rules with optional ML model for severity label
    and score prediction. Supports ensemble blending across multiple
    risk sub-dimensions.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        use_rules: bool = True,
    ) -> None:
        self._model: Any = None
        self._scaler: Any = None
        self._use_rules = use_rules
        self._thresholds: Dict[str, float] = {
            'low_to_medium': 0.25,
            'medium_to_high': 0.5,
            'high_to_critical': 0.75,
        }
        self._feature_weights: Dict[str, float] = {
            'code_surface': 0.35,
            'protection_gap': 0.30,
            'vuln_intrinsic': 0.35,
        }
        # 特征名到向量索引的映射，用于模型可解释性分析
        self._vector_feature_names: Tuple[str, ...] = (
            'vuln_type_score', 'no_stack_canary', 'no_nx', 'no_pie',
            'no_full_relro', 'has_exploit', 'reachable_from_input',
            'dangerous_api_ratio', 'cvss_normalized',
        )

        if model_path:
            self.load_model(model_path)

    def predict(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Predict severity label and score for given vulnerability features.

        Args:
            features: Dict with vuln_type, api_calls, mitigations, etc.

        Returns:
            Dict with severity, confidence, and sub-scores.
        """
        if self._use_rules:
            return self._predict_via_rules(features)

        if self._model is not None:
            return self._predict_via_model(features)

        return self._predict_via_rules(features)

    # 批量预测 -- 一次处理多条漏洞记录，避免重复的Python函数调用开销
    def predict_batch(
        self,
        features_list: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Predict severity for a batch of vulnerability records.

        When an ML model is active, performs a single model inference pass
        for efficiency. Otherwise delegates to per-item rules prediction.

        Args:
            features_list: List of feature dicts, one per vulnerability.

        Returns:
            List of prediction result dicts in the same order.
        """
        if not features_list:
            return []

        # ML路径：一次矩阵变换即可，避免逐个调用
        if not self._use_rules and self._model is not None:
            try:
                vecs = [self._features_to_vector(d) for d in features_list]
                if self._scaler is not None:
                    vecs = self._scaler.transform(vecs)
                all_probs = self._model.predict_proba(vecs)
                results: List[Dict[str, Any]] = []
                for i, probs in enumerate(all_probs):
                    pred_class = int(np.argmax(probs))
                    severity = _LABELS_[min(pred_class, len(_LABELS_) - 1)]
                    confidence = float(probs[pred_class])
                    results.append({
                        'severity': severity,
                        'severity_index': pred_class,
                        'confidence': round(confidence, 4),
                        'score': round(pred_class / len(_LABELS_), 4),
                        'probabilities': {
                            label: round(float(p), 4)
                            for label, p in zip(_LABELS_, probs)
                        },
                        'method': 'ml_model_batch',
                    })
                return results
            except Exception as e:
                logger.warning(f"Batch model prediction failed, falling back: {e}")

        # 规则路径：逐条处理，保持与单条预测完全一致的行为
        return [self._predict_via_rules(f) for f in features_list]

    def _predict_via_rules(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Predict severity using ensemble blending of 3 sub-scores.

        Sub-scores:
          - code_surface: How exposed/reachable the vulnerable code is
          - protection_gap: How well mitigations protect against exploitation
          - vuln_intrinsic: Inherent severity of the vulnerability type
        """
        vuln_type = features.get('vuln_type', 'default').lower()
        api_calls = features.get('api_calls', [])
        mitigations = features.get('mitigations', {})
        has_exploit = features.get('has_exploit', False)
        reachable_from_input = features.get('reachable_from_input', True)
        context = features.get('context', {})

        # 1. Code-surface score: how reachable/exposed
        code_surface = 0.5
        if reachable_from_input:
            code_surface += 0.3
        if features.get('is_exported', False):
            code_surface += 0.1
        if features.get('in_hot_path', False):
            code_surface += 0.1
        if context.get('attacker_controlled_input', False):
            code_surface += 0.2
        code_surface = min(code_surface, 1.0)

        # 2. Protection-gap score: lack of mitigations = higher risk
        protection_gap = 0.0
        if not mitigations.get('stack_canary', True):
            protection_gap += 0.2
        if not mitigations.get('nx', True):
            protection_gap += 0.2
        if not mitigations.get('pie', True):
            protection_gap += 0.15
        if not mitigations.get('full_relro', True):
            protection_gap += 0.1
        if not mitigations.get('safe_seh', True):
            protection_gap += 0.1
        if not mitigations.get('cfi', False):
            protection_gap += 0.15
        if not mitigations.get('asan', False):
            protection_gap += 0.1
        protection_gap = min(protection_gap, 1.0)

        # 3. Vulnerability-intrinsic score
        vuln_intrinsic = _TYPE_SCORES_.get(vuln_type, _TYPE_SCORES_['default'])

        if has_exploit:
            vuln_intrinsic = min(vuln_intrinsic + 0.15, 1.0)
        if features.get('cvss_score'):
            try:
                cvss = float(features['cvss_score'])
                vuln_intrinsic = max(vuln_intrinsic, cvss / 10.0)
            except (ValueError, TypeError):
                pass

        # Check for dangerous API calls
        dangerous_apis = {'system', 'popen', 'exec', 'strcpy', 'gets', 'sprintf'}
        if isinstance(api_calls, list):
            dangerous_hits = [c for c in api_calls if c.lower() in dangerous_apis]
            if dangerous_hits:
                vuln_intrinsic += min(len(dangerous_hits) * 0.05, 0.15)

        vuln_intrinsic = min(vuln_intrinsic, 1.0)

        # Ensemble blending
        weights = self._feature_weights
        blended_score = (
            code_surface * weights['code_surface'] +
            protection_gap * weights['protection_gap'] +
            vuln_intrinsic * weights['vuln_intrinsic']
        )

        severity = self._score_to_label(blended_score)
        confidence = 0.5 + abs(blended_score - 0.5)

        return {
            'severity': severity,
            'severity_index': _LABEL_MAP_.get(severity, 0),
            'confidence': round(min(confidence, 0.99), 4),
            'score': round(blended_score, 4),
            'sub_scores': {
                'code_surface': round(code_surface, 4),
                'protection_gap': round(protection_gap, 4),
                'vuln_intrinsic': round(vuln_intrinsic, 4),
            },
            'method': 'rules_ensemble',
        }

    def _predict_via_model(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Predict severity using trained ML model."""
        if self._model is None:
            return self._predict_via_rules(features)

        try:
            feature_vec = self._features_to_vector(features)
            if self._scaler is not None:
                feature_vec = self._scaler.transform([feature_vec])[0]

            probs = self._model.predict_proba([feature_vec])[0]
            pred_class = int(np.argmax(probs))
            severity = _LABELS_[min(pred_class, len(_LABELS_) - 1)]
            confidence = float(probs[pred_class])

            return {
                'severity': severity,
                'severity_index': pred_class,
                'confidence': round(confidence, 4),
                'score': round(pred_class / len(_LABELS_), 4),
                'probabilities': {
                    label: round(float(p), 4)
                    for label, p in zip(_LABELS_, probs)
                },
                'method': 'ml_model',
            }
        except Exception as e:
            logger.warning(f"Model prediction failed: {e}")
            return self._predict_via_rules(features)

    # 模型可解释性 -- 对于审计和调参非常有价值，尤其是RF模型自带feature_importances_
    def explain_prediction(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return feature contributions for model-based prediction.

        When a trained RandomForest is available, reports Gini-importance
        per feature alongside the raw input values. This aids in
        understanding which signals drive severity decisions.

        Args:
            features: Vulnerability feature dict.

        Returns:
            Dict with prediction result and per-feature importance mapping.
        """
        result = self._predict_via_model(features) if self._model is not None \
            else self._predict_via_rules(features)

        explain: Dict[str, Any] = {
            'prediction': result,
            'feature_values': {},
            'feature_importance': {},
        }

        try:
            vec = self._features_to_vector(features)
            for idx, name in enumerate(self._vector_feature_names):
                if idx < len(vec):
                    explain['feature_values'][name] = round(vec[idx], 4)
        except Exception:
            pass

        # RandomForest 内建的特征重要性，直接复用
        if self._model is not None and hasattr(self._model, 'feature_importances_'):
            try:
                importances = self._model.feature_importances_
                for idx, name in enumerate(self._vector_feature_names):
                    if idx < len(importances):
                        explain['feature_importance'][name] = round(float(importances[idx]), 6)
            except Exception:
                pass

        return explain

    def _features_to_vector(self, features: Dict[str, Any]) -> List[float]:
        """Convert feature dict to model input vector."""
        vec: List[float] = []

        vuln_type = features.get('vuln_type', 'default')
        vec.append(_TYPE_SCORES_.get(vuln_type, 0.5))

        mitigations = features.get('mitigations', {})
        vec.append(0.0 if mitigations.get('stack_canary', True) else 1.0)
        vec.append(0.0 if mitigations.get('nx', True) else 1.0)
        vec.append(0.0 if mitigations.get('pie', True) else 1.0)
        vec.append(0.0 if mitigations.get('full_relro', True) else 1.0)

        vec.append(1.0 if features.get('has_exploit', False) else 0.0)
        vec.append(1.0 if features.get('reachable_from_input', True) else 0.0)

        api_calls = features.get('api_calls', [])
        dangerous = {'system', 'popen', 'exec', 'strcpy', 'gets', 'sprintf'}
        vec.append(float(
            sum(1 for c in api_calls if c.lower() in dangerous) / max(len(api_calls), 1)
        ))

        cvss = features.get('cvss_score', 0)
        try:
            vec.append(float(cvss) / 10.0)
        except (ValueError, TypeError):
            vec.append(0.0)

        return vec

    # EPSS启发式 -- 预估漏洞在30天内被野外利用的概率，用于优先级排序
    def estimate_exploit_probability(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Heuristic exploit-probability estimation (EPSS-inspired).

        Combines vuln-type base rates with exploit availability,
        CVSS severity, and reachability signals into a rough
        probability of exploitation within 30 days.

        Args:
            features: Vulnerability feature dict.

        Returns:
            Dict with probability, contributing factors, and percentile.
        """
        vuln_type = features.get('vuln_type', 'default').lower()
        has_exploit = features.get('has_exploit', False)
        reachable_from_input = features.get('reachable_from_input', True)
        cvss_score = 0.0
        try:
            cvss_score = float(features.get('cvss_score', 0))
        except (ValueError, TypeError):
            pass

        # 基准先验概率
        base_prob = _EXPLOITABILITY_PRIORS_.get(vuln_type, _EXPLOITABILITY_PRIORS_['default'])

        # 各因子的对数几率调整
        log_odds = math.log(max(base_prob, 0.001) / max(1.0 - base_prob, 0.001))

        if has_exploit:
            log_odds += 1.5  # 已有公开PoC/Exploit显著提高概率
        if reachable_from_input:
            log_odds += 0.6
        if cvss_score >= 7.0:
            log_odds += 0.8
        elif cvss_score >= 4.0:
            log_odds += 0.3
        if features.get('in_hot_path', False):
            log_odds += 0.4
        if features.get('is_exported', False):
            log_odds += 0.25

        # APT关注度附加因子 -- 高价值目标漏洞更可能被利用
        if features.get('apt_relevant', False):
            log_odds += 1.2

        # CVE 年龄衰减 -- 越老的漏洞如果还没被利用，概率应下调
        cve_age_days = features.get('cve_age_days', 0)
        if cve_age_days > 365:
            log_odds -= 0.8
        elif cve_age_days > 90:
            log_odds -= 0.3

        exploit_prob = 1.0 / (1.0 + math.exp(-log_odds))
        exploit_prob = round(max(0.001, min(exploit_prob, 0.99)), 6)

        # 粗略的百分位映射
        if exploit_prob >= 0.10:
            percentile = 90
        elif exploit_prob >= 0.05:
            percentile = 75
        elif exploit_prob >= 0.02:
            percentile = 50
        elif exploit_prob >= 0.01:
            percentile = 25
        else:
            percentile = 10

        return {
            'exploit_probability_30d': exploit_prob,
            'percentile': percentile,
            'base_prior': base_prob,
            'factors': {
                'has_exploit': has_exploit,
                'reachable_from_input': reachable_from_input,
                'cvss_score': cvss_score,
            },
            'method': 'epss_heuristic',
        }

    def _score_to_label(self, score: float) -> str:
        """Convert a numeric score to severity label."""
        thresholds = self._thresholds
        if score < thresholds['low_to_medium']:
            return "LOW"
        elif score < thresholds['medium_to_high']:
            return "MEDIUM"
        elif score < thresholds['high_to_critical']:
            return "HIGH"
        else:
            return "CRITICAL"

    def calibrate_thresholds(
        self,
        labeled_data: List[Dict[str, Any]],
        metric: str = "f1",
    ) -> Dict[str, float]:
        """Grid-search threshold tuning using labeled data.

        Args:
            labeled_data: List of dicts with features and 'true_severity'.
            metric: Optimization metric ('f1', 'precision', 'recall', 'accuracy').

        Returns:
            Optimized thresholds dict.
        """
        best_thresholds = dict(self._thresholds)
        best_score = -1.0

        candidates_low = [0.15, 0.20, 0.25, 0.30, 0.35]
        candidates_medium = [0.40, 0.45, 0.50, 0.55, 0.60]
        candidates_high = [0.65, 0.70, 0.75, 0.80, 0.85]

        for t_low in candidates_low:
            for t_med in candidates_medium:
                for t_high in candidates_high:
                    if not (t_low < t_med < t_high):
                        continue

                    self._thresholds = {
                        'low_to_medium': t_low,
                        'medium_to_high': t_med,
                        'high_to_critical': t_high,
                    }

                    y_true = []
                    y_pred = []
                    for item in labeled_data:
                        true_label = item.get('true_severity', 'LOW')
                        result = self._predict_via_rules(item)
                        y_true.append(_LABEL_MAP_.get(true_label, 0))
                        y_pred.append(result['severity_index'])

                    score = self._compute_metric(y_true, y_pred, metric)
                    if score > best_score:
                        best_score = score
                        best_thresholds = dict(self._thresholds)

        self._thresholds = best_thresholds
        logger.info(f"Calibrated thresholds: {best_thresholds} (metric={metric}, score={best_score:.4f})")
        return best_thresholds

    @staticmethod
    def _compute_metric(
        y_true: List[int],
        y_pred: List[int],
        metric: str,
    ) -> float:
        """Compute evaluation metric — supports accuracy, macro-F1, macro-precision, macro-recall.

        多分类场景下，precision/recall 采用宏平均，与 F1 的计算方式保持一致。
        """
        if not y_true:
            return 0.0

        if metric == "accuracy":
            return sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)

        classes = sorted(set(y_true))

        # 宏精确率：对每个类别单独算 精确率，再取平均
        if metric == "precision":
            precisions = []
            for c in classes:
                tp = sum(1 for t, p in zip(y_true, y_pred) if t == c and p == c)
                fp = sum(1 for t, p in zip(y_true, y_pred) if t != c and p == c)
                precisions.append(tp / max(tp + fp, 1))
            return sum(precisions) / max(len(precisions), 1)

        # 宏召回率：对每个类别单独算 召回率，再取平均
        if metric == "recall":
            recalls = []
            for c in classes:
                tp = sum(1 for t, p in zip(y_true, y_pred) if t == c and p == c)
                fn = sum(1 for t, p in zip(y_true, y_pred) if t == c and p != c)
                recalls.append(tp / max(tp + fn, 1))
            return sum(recalls) / max(len(recalls), 1)

        # 默认：宏平均 F1（保持原有行为，兼容未指定metric或metric="f1"）
        f1s = []
        for c in classes:
            tp = sum(1 for t, p in zip(y_true, y_pred) if t == c and p == c)
            fp = sum(1 for t, p in zip(y_true, y_pred) if t != c and p == c)
            fn = sum(1 for t, p in zip(y_true, y_pred) if t == c and p != c)

            if tp + fp + fn == 0:
                f1s.append(1.0)
                continue

            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 0.001)
            f1s.append(f1)

        return sum(f1s) / max(len(f1s), 1)

    def train_model(
        self,
        X: List[List[float]],
        y: List[int],
    ) -> None:
        """Train the ML model with features and labels.

        Args:
            X: Feature vectors.
            y: Label indices (0-3).
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler

            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            self._model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced',
            )
            self._model.fit(X_scaled, y)

            logger.info(f"Model trained on {len(X)} samples")
        except ImportError:
            logger.warning("scikit-learn not available for model training")

    def save_model(self, filepath: str) -> None:
        """Save trained model and scaler to file.

        Args:
            filepath: Output file path.
        """
        if self._model is None:
            logger.warning("No model to save")
            return

        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        data = {
            'model': self._model,
            'scaler': self._scaler,
            'thresholds': self._thresholds,
            'feature_weights': self._feature_weights,
        }
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        logger.info(f"Model saved to {filepath}")

    def load_model(self, filepath: str) -> bool:
        """Load trained model from file.

        Args:
            filepath: Model file path.

        Returns:
            True if loaded successfully.
        """
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            self._model = data.get('model')
            self._scaler = data.get('scaler')
            self._thresholds = data.get('thresholds', self._thresholds)
            self._feature_weights = data.get('feature_weights', self._feature_weights)
            logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


_default_predictor: Optional[VulnSeverityPredictor] = None


def train_default_model(
    training_data: Optional[List[Dict[str, Any]]] = None,
) -> VulnSeverityPredictor:
    """Train and return the default severity predictor.

    Args:
        training_data: Optional training data for ML model.

    Returns:
        Trained VulnSeverityPredictor.
    """
    global _default_predictor

    predictor = VulnSeverityPredictor(use_rules=True)

    if training_data:
        X = [predictor._features_to_vector(d) for d in training_data]
        y_raw = [d.get('severity', 'LOW') for d in training_data]
        y = [_LABEL_MAP_.get(s, 0) for s in y_raw]
        predictor.train_model(X, y)

    _default_predictor = predictor
    return predictor


def create_vuln_severity_predictor(
    model_path: Optional[str] = None,
) -> VulnSeverityPredictor:
    """Factory function for creating a predictor.

    Args:
        model_path: Optional path to pre-trained model.

    Returns:
        Configured VulnSeverityPredictor.
    """
    predictor = VulnSeverityPredictor(model_path=model_path, use_rules=True)
    return predictor


def get_default_predictor() -> VulnSeverityPredictor:
    """Get or create the default severity predictor singleton.

    Returns:
        Default VulnSeverityPredictor instance.
    """
    global _default_predictor
    if _default_predictor is None:
        _default_predictor = create_vuln_severity_predictor()
    return _default_predictor


def _debug_print(*args, **kwargs):  # 调试残余--未删除
    """Print debug info if env var is set. Not currently called."""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
