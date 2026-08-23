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

# 内部标签使用大写，作为新接口预测结果的共同来源
_LABELS_ = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_LABEL_MAP_ = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# 对外暴露的严重度常量 - 标题大小写，旧版接口使用
SEVERITY_LEVELS = ['Low', 'Medium', 'High', 'Critical']
SEVERITY_MAPPING = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}

# 内置合成训练样本 - 覆盖四档严重度的典型特征组合，
# 供无外部训练数据时生成可加载的默认模型。
_SYNTHETIC_TRAINING_DATA: List[Dict[str, Any]] = [
    {'vuln_type': 'buffer_overflow', 'api_calls': ['strcpy'], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': True, 'cvss_score': 9.0,
     'severity': 'CRITICAL'},
    {'vuln_type': 'stack_overflow', 'api_calls': ['strcpy', 'gets'], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': True, 'cvss_score': 8.0,
     'severity': 'CRITICAL'},
    {'vuln_type': 'integer_overflow', 'api_calls': ['memcpy'], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': True, 'cvss_score': 7.0,
     'severity': 'HIGH'},
    {'vuln_type': 'use_after_free', 'api_calls': [], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': True, 'cvss_score': 6.0,
     'severity': 'MEDIUM'},
    {'vuln_type': 'null_dereference', 'api_calls': [], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': False, 'cvss_score': 4.0,
     'severity': 'LOW'},
    {'vuln_type': 'info_leak', 'api_calls': [], 'mitigations': {},
     'has_exploit': False, 'reachable_from_input': False, 'cvss_score': 3.0,
     'severity': 'LOW'},
]

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

# 漏洞可利用性预估基准 - 基于历史CVE数据中各类漏洞被野外利用的比例
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


class _NumpyCentroidClassifier:
    """轻量最近质心分类器 - scikit-learn 不可用时的回退实现。

    训练阶段记录各类别样本质心；预测时按到质心的反距离归一化生成
    类别概率，接口与 sklearn 分类器兼容（predict_proba）。
    """

    def __init__(self, classes: Optional[List[int]] = None):
        self.classes_: List[int] = classes if classes is not None else [0, 1, 2, 3]
        self._centroids: Dict[int, np.ndarray] = {}
        self._fitted = False

    def fit(self, X: List[List[float]], y: List[int]) -> '_NumpyCentroidClassifier':
        X = np.asarray(X, dtype=float)
        self._centroids = {}
        for cls in self.classes_:
            idx = [i for i, v in enumerate(y) if v == cls]
            if idx:
                self._centroids[cls] = X[idx].mean(axis=0)
        self._fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """按质心距离反比归一化输出概率矩阵 (n_samples, n_classes)。"""
        X = np.asarray(X, dtype=float)
        n = X.shape[0]
        probs = np.zeros((n, len(self.classes_)))
        for si in range(n):
            dists = {}
            for cls in self.classes_:
                if cls in self._centroids:
                    dists[cls] = float(np.linalg.norm(X[si] - self._centroids[cls]))
                else:
                    dists[cls] = float('inf')
            total = 0.0
            weights = {}
            for cls, dist in dists.items():
                w = 1.0 / (1.0 + dist) if dist != float('inf') else 0.0
                weights[cls] = w
                total += w
            if total > 0:
                for ci, cls in enumerate(self.classes_):
                    probs[si, ci] = weights[cls] / total
            else:
                # 全部质心缺失：退化为均匀分布
                probs[si, :] = 1.0 / len(self.classes_)
        return probs


class _FallbackModel:
    """sklearn 缺失时的轻量预测器。

    按特征向量均值映射到四级严重度概率，接口对齐
    RandomForestClassifier 的 fit/predict_proba/feature_importances_，
    保证无外部 ML 依赖时模型训练与预测路径仍可用。
    """

    def __init__(self, n_features: int = 9):
        self.n_features = n_features
        self._means_: Optional[np.ndarray] = None
        self._classes_ = [0, 1, 2, 3]

    def fit(self, X, y):
        if X:
            self._means_ = np.mean(np.asarray(X, dtype=float), axis=0)
        else:
            self._means_ = np.zeros(self.n_features)
        return self

    def predict_proba(self, X):
        rows = []
        for vec in X:
            s = float(np.mean(vec))
            if s >= 0.75:
                p = [0.05, 0.05, 0.20, 0.70]
            elif s >= 0.50:
                p = [0.05, 0.10, 0.60, 0.25]
            elif s >= 0.25:
                p = [0.10, 0.60, 0.20, 0.10]
            else:
                p = [0.70, 0.20, 0.05, 0.05]
            rows.append(p)
        return np.asarray(rows, dtype=float)

    def predict(self, X):
        """返回类别索引数组 - 与 sklearn 分类器接口对齐。"""
        probs = self.predict_proba(X)
        return np.argmax(probs, axis=1)

    @property
    def feature_importances_(self):
        if self._means_ is None:
            return np.zeros(self.n_features)
        total = float(np.sum(np.abs(self._means_))) or 1.0
        return np.abs(self._means_) / total


class VulnSeverityPredictor:
    """模型/规则混合预测严重度，支持多子分集成融合。"""

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

        # 旧版兼容属性 — 基于规则的预测入口沿用 model_path/model/scaler 命名
        self.model_path: str = model_path or os.path.join(
            'models', 'severity_model.pkl')
        self.model: Any = None
        self.scaler: Any = None
        self.feature_names: List[str] = self._LEGACY_FEATURE_NAMES[:]

        if model_path:
            self.load_model(model_path)

    def predict(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """兼容新接口（vuln_type/api_calls/mitigations）与旧接口（legacy 特征字典）。"""
        if 'vuln_type' in features or 'api_calls' in features \
                or 'mitigations' in features:
            if self._use_rules:
                return self._predict_via_rules(features)

            if self._model is not None:
                return self._predict_via_model(features)

            return self._predict_via_rules(features)

        # 旧接口输入 — 按 legacy 特征体系预测
        return self._predict_legacy(features)

    # 批量预测 - 一次处理多条漏洞记录，避免重复的Python函数调用开销
    def predict_batch(
        self,
        features_list: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """ML 模型可用时单次矩阵推理，否则逐条走规则路径。"""
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
        results = []
        for f in features_list:
            pred = self._predict_via_rules(f)
            pred = dict(pred)
            pred['ml_prediction'] = dict(pred)
            results.append(pred)
        return results

    def _normalize_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """统一新旧特征命名: type/dangerous_functions/checksec/is_reachable
        兼容 vuln_type/api_calls/mitigations/reachable_from_input。"""
        norm = dict(features)
        if 'vuln_type' not in norm and 'type' in norm:
            norm['vuln_type'] = norm['type']
        if 'api_calls' not in norm and 'dangerous_functions' in norm:
            norm['api_calls'] = norm['dangerous_functions']
        if 'reachable_from_input' not in norm and 'is_reachable' in norm:
            norm['reachable_from_input'] = norm['is_reachable']
        if 'mitigations' not in norm and 'checksec' in norm:
            cs = norm.get('checksec') or {}
            norm['mitigations'] = {
                'stack_canary': bool(cs.get('canary', False)),
                'nx': bool(cs.get('nx', False)),
                'pie': bool(cs.get('pie', False)),
                'full_relro': str(cs.get('relro', '')).lower() == 'full',
            }
        return norm

    def _predict_via_rules(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """类型基准+危险函数+可达性+缓解缺口累加评分，阈值映射四级严重度。"""
        features = self._normalize_features(features)
        vuln_type = features.get('vuln_type', 'default').lower().replace(' ', '_')
        api_calls = features.get('api_calls', [])
        mitigations = features.get('mitigations', {})
        has_exploit = features.get('has_exploit', False)
        reachable_from_input = features.get('reachable_from_input', True)
        context = features.get('context', {})

        base_scores = {
            'buffer_overflow': 0.90, 'stack_overflow': 0.85, 'heap_overflow': 0.85,
            'use_after_free': 0.55, 'double_free': 0.80, 'format_string': 0.75,
            'integer_overflow': 0.60, 'command_injection': 0.95, 'sql_injection': 0.90,
            'code_execution': 0.95, 'privilege_escalation': 0.90,
            'memory_corruption': 0.85, 'denial_of_service': 0.55,
            'info_leak': 0.40, 'null_dereference': 0.45, 'race_condition': 0.70,
        }
        score = base_scores.get(vuln_type, 0.40)

        if isinstance(api_calls, list):
            dangerous = {'system', 'popen', 'exec', 'strcpy', 'gets', 'sprintf'}
            hits = [c for c in api_calls if c.lower() in dangerous]
            score += min(len(hits) * 0.05, 0.15)

        if reachable_from_input:
            score += 0.05

        if not mitigations.get('nx', True):
            score += 0.05
        if not mitigations.get('pie', True):
            score += 0.05
        if not mitigations.get('stack_canary', True):
            score += 0.05

        score = min(score, 1.0)

        if score >= 0.85:
            severity = _LABELS_[3]
        elif score >= 0.70:
            severity = _LABELS_[2]
        elif score >= 0.50:
            severity = _LABELS_[1]
        else:
            severity = _LABELS_[0]

        confidence = min(0.5 + abs(score - 0.5), 0.99)

        return {
            'severity': severity,
            'severity_index': _LABEL_MAP_.get(severity, 0),
            'confidence': round(confidence, 4),
            'score': round(score, 4),
            'sub_scores': {
                'vulnerability_type_factor': round(base_scores.get(vuln_type, 0.40), 4),
                'dangerous_function_count': float(score - base_scores.get(vuln_type, 0.40)),
                'protection_gap': 0.0,
            },
            'method': 'rule_based',
        }

    def _predict_via_model(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        if self._model is None:
            return self._predict_via_rules(features)

        try:
            feature_vec = self._features_to_vector(features)
            if self._scaler is not None:
                feature_vec = self._scaler.transform([feature_vec])[0]

            probs = self._model.predict_proba([feature_vec])[0]
            pred_class = int(np.argmax(probs))
            severity = SEVERITY_LEVELS[min(pred_class, len(SEVERITY_LEVELS) - 1)]
            confidence = float(probs[pred_class])

            return {
                'severity': severity,
                'severity_index': pred_class,
                'confidence': round(confidence, 4),
                'score': round(pred_class / len(SEVERITY_LEVELS), 4),
                'probabilities': {
                    label: round(float(p), 4)
                    for label, p in zip(SEVERITY_LEVELS, probs)
                },
                'method': 'machine_learning',
            }
        except Exception as e:
            logger.warning(f"Model prediction failed: {e}")
            return self._predict_via_rules(features)

    # 模型可解释性 - 对于审计和调参非常有价值，尤其是RF模型自带feature_importances_
    def explain_prediction(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """报告 RandomForest 的 Gini-importance 与原始输入值，辅助理解决策信号。"""
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

    # EPSS启发式 - 预估漏洞在30天内被野外利用的概率，用于优先级排序
    def estimate_exploit_probability(
        self,
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """EPSS启发式：组合漏洞类型基准率+可利用性+CVSS+可达性预估30天野外利用概率。"""
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

        # APT关注度附加因子 - 高价值目标漏洞更可能被利用
        if features.get('apt_relevant', False):
            log_odds += 1.2

        # CVE 年龄衰减 - 越老的漏洞如果还没被利用，概率应下调
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
        thresholds = self._thresholds
        if score < thresholds['low_to_medium']:
            return SEVERITY_LEVELS[0]
        elif score < thresholds['medium_to_high']:
            return SEVERITY_LEVELS[1]
        elif score < thresholds['high_to_critical']:
            return SEVERITY_LEVELS[2]
        else:
            return SEVERITY_LEVELS[3]

    def calibrate_thresholds(
        self,
        labeled_data: List[Dict[str, Any]],
        metric: str = "f1",
    ) -> Dict[str, float]:
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
        """多分类宏平均：accuracy/precision/recall/f1，precision/recall 与 F1 口径一致。"""
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

    # 旧版规则预测 — 兼容 legacy 特征体系（10 维）
    _LEGACY_FEATURE_NAMES: List[str] = [
        'basic_block_count', 'cyclomatic_complexity', 'dangerous_function_count',
        'taint_path_length', 'is_reachable', 'protection_level', 'language_factor',
        'arch_factor', 'confidence', 'vulnerability_type_factor',
    ]

    def _predict_legacy(self, vuln_info: Dict[str, Any]) -> Dict[str, Any]:
        """按旧版特征体系预测严重性。

        输入含 basic_block_count / cyclomatic_complexity / dangerous_functions /
        taint_path_length / is_reachable / checksec / language / arch /
        confidence / type 等键。有已加载模型时走模型预测，否则走规则回退。
        """
        features = self.extract_features(vuln_info)

        if self.model is not None:
            return self._predict_legacy_model(features, vuln_info)
        return self._predict_legacy_rules(features, vuln_info)

    def _predict_legacy_model(
        self,
        features: List[float],
        vuln_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            import numpy as _np
            features_array = _np.array([features])
            if self.scaler is not None:
                features_array = self.scaler.transform(features_array)
            prediction = self.model.predict(features_array)
            probabilities = None
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(features_array)

            pred_class = int(prediction[0])
            severity = SEVERITY_LEVELS[min(pred_class, len(SEVERITY_LEVELS) - 1)]
            confidence = float(probabilities[0][pred_class]) \
                if probabilities is not None else 0.7

            return {
                'severity': severity,
                'confidence': round(min(confidence, 1.0), 4),
                'probabilities': {
                    SEVERITY_LEVELS[i]: float(probabilities[0][i])
                    for i in range(len(SEVERITY_LEVELS))
                } if probabilities is not None else None,
                'method': 'machine_learning',
                'feature_importance': self._compute_feature_importance(features),
            }
        except Exception as exc:
            logger.warning(f"Legacy model prediction failed: {exc}")
            return self._predict_legacy_rules(features, vuln_info)

    def _compute_feature_importance(
        self,
        features: List[float],
    ) -> Optional[Dict[str, float]]:
        if self.model is not None and hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            return {
                name: float(importance)
                for name, importance in zip(self.feature_names, importances)
            }
        return None

    def _predict_legacy_rules(
        self,
        features: List[float],
        vuln_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        score = 0.0

        basic_blocks, complexity, dangerous_count, taint_length, is_reachable, \
            protection, language, arch, confidence, vuln_type = features

        score += min(dangerous_count * 0.2, 0.4)
        score += min(vuln_type, 0.3)
        score += (1.0 - protection) * 0.2
        score += (1.0 if is_reachable > 0.5 else 0.0) * 0.1

        if score >= 0.7:
            severity = 'Critical'
        elif score >= 0.5:
            severity = 'High'
        elif score >= 0.3:
            severity = 'Medium'
        else:
            severity = 'Low'

        return {
            'severity': severity,
            'confidence': min(confidence, 0.7),
            'probabilities': None,
            'method': 'rule_based',
            'feature_importance': None,
        }

    def extract_features(self, vuln_info: Dict[str, Any]) -> List[float]:
        """从漏洞信息中提取 10 维特征向量（旧版特征体系）。"""
        return [
            self._extract_basic_block_count(vuln_info),
            self._extract_cyclomatic_complexity(vuln_info),
            self._extract_dangerous_function_count(vuln_info),
            self._extract_taint_path_length(vuln_info),
            self._extract_is_reachable(vuln_info),
            self._extract_protection_level(vuln_info),
            self._extract_language_factor(vuln_info),
            self._extract_arch_factor(vuln_info),
            self._extract_confidence(vuln_info),
            self._extract_vulnerability_type_factor(vuln_info),
        ]

    def _extract_basic_block_count(self, vuln_info: Dict[str, Any]) -> float:
        return float(vuln_info.get('basic_block_count', 10))

    def _extract_cyclomatic_complexity(self, vuln_info: Dict[str, Any]) -> float:
        return float(vuln_info.get('cyclomatic_complexity', 5))

    def _extract_dangerous_function_count(self, vuln_info: Dict[str, Any]) -> float:
        dangerous_funcs = vuln_info.get('dangerous_functions', [])
        return float(len(dangerous_funcs))

    def _extract_taint_path_length(self, vuln_info: Dict[str, Any]) -> float:
        return float(vuln_info.get('taint_path_length', 5))

    def _extract_is_reachable(self, vuln_info: Dict[str, Any]) -> float:
        return float(vuln_info.get('is_reachable', True))

    def _extract_protection_level(self, vuln_info: Dict[str, Any]) -> float:
        checksec = vuln_info.get('checksec', {})
        level = 0.0
        if checksec.get('nx', False):
            level += 0.25
        if checksec.get('pie', False):
            level += 0.25
        if checksec.get('canary', False):
            level += 0.25
        if checksec.get('relro', False) in ('Full', True):
            level += 0.25
        return level

    def _extract_language_factor(self, vuln_info: Dict[str, Any]) -> float:
        language = vuln_info.get('language', 'c/c++').lower()
        if 'rust' in language:
            return 0.3
        if 'go' in language:
            return 0.2
        return 0.0

    def _extract_arch_factor(self, vuln_info: Dict[str, Any]) -> float:
        arch = vuln_info.get('arch', 'unknown').lower()
        if '64' in arch or 'amd64' in arch or 'x86_64' in arch:
            return 0.3
        if '32' in arch or 'i386' in arch or 'x86' in arch:
            return 0.0
        return 0.15

    def _extract_confidence(self, vuln_info: Dict[str, Any]) -> float:
        return float(vuln_info.get('confidence', 0.5))

    def _extract_vulnerability_type_factor(self, vuln_info: Dict[str, Any]) -> float:
        vuln_type = vuln_info.get('type', 'unknown').lower()
        type_scores = {
            'buffer overflow': 1.0,
            'heap overflow': 1.0,
            'use after free': 0.9,
            'double free': 0.9,
            'format string': 0.85,
            'integer overflow': 0.7,
            'stack overflow': 0.95,
            'command injection': 0.9,
            'sql injection': 0.85,
            'path traversal': 0.6,
            'denial of service': 0.4,
            'information disclosure': 0.3,
        }
        for type_name, score in type_scores.items():
            if type_name in vuln_type:
                return score
        return 0.0

    def get_feature_names(self) -> List[str]:
        """返回旧版特征名称列表（10 维）。"""
        return list(self._LEGACY_FEATURE_NAMES)

    def rank_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """按严重性（降序）与置信度（降序）排序漏洞列表。"""
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        return sorted(
            vulnerabilities,
            key=lambda x: (
                severity_order.get(
                    x.get('ml_prediction', {}).get('severity', 'Low'), 3),
                -x.get('ml_prediction', {}).get('confidence', 0.0),
            ),
        )

    def generate_explanation(self, vuln_info: Dict[str, Any]) -> str:
        """生成旧版预测结果的解释文本。"""
        ml_prediction = vuln_info.get('ml_prediction', {})
        severity = ml_prediction.get('severity', 'Unknown')
        confidence = ml_prediction.get('confidence', 0.0)
        method = ml_prediction.get('method', 'unknown')
        feature_importance = ml_prediction.get('feature_importance', {})

        lines = ["## ML 预测结果解释", ""]
        lines.append(f"- **预测严重性**: {severity}")
        lines.append(f"- **置信度**: {confidence:.2f}")
        lines.append(f"- **预测方法**: {method}")
        lines.append("")
        if feature_importance:
            lines.append("### 特征重要性")
            sorted_importance = sorted(
                feature_importance.items(), key=lambda x: -x[1])
            for name, importance in sorted_importance[:5]:
                lines.append(f"- {name}: {importance:.4f}")
        return '\n'.join(lines)

    def is_model_available(self) -> bool:
        """检查是否已加载可用的模型。"""
        return self.model is not None

    def train_model(
        self,
        X: List[List[float]],
        y: List[int],
    ) -> None:
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
            # 同步公共属性，保证 is_model_available/load_model 路径一致
            self.model = self._model
            self.scaler = self._scaler

            logger.info(f"Model trained on {len(X)} samples")
        except ImportError:
            logger.warning("scikit-learn not available; using numpy fallback model")
            fallback = _FallbackModel(n_features=len(X[0]) if X else 9)
            fallback.fit(X, y)
            self._model = fallback
            self._scaler = None
            self.model = fallback
            self.scaler = None

    def save_model(self, filepath: str) -> None:
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

    def load_model(self, filepath: Optional[str] = None) -> bool:
        filepath = filepath or self.model_path
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
            self._model = data.get('model')
            self._scaler = data.get('scaler')
            self.model = self._model
            self.scaler = self._scaler
            self.feature_names = data.get('feature_names', [])
            self._thresholds = data.get('thresholds', self._thresholds)
            self._feature_weights = data.get('feature_weights', self._feature_weights)
            logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False


_default_predictor: Optional[VulnSeverityPredictor] = None


def train_default_model(
    model_path: Optional[str] = None,
    training_data: Optional[List[Dict[str, Any]]] = None,
):
    """训练并保存默认严重度预测器。"""
    global _default_predictor

    predictor = VulnSeverityPredictor(use_rules=True)

    if training_data:
        X = [predictor._features_to_vector(d) for d in training_data]
        y_raw = [d.get('severity', 'LOW') for d in training_data]
        y = [_LABEL_MAP_.get(s, 0) for s in y_raw]
        predictor.train_model(X, y)
    else:
        # 内置合成训练样本：覆盖四档严重度的典型特征组合
        synthetic = _SYNTHETIC_TRAINING_DATA
        X = [predictor._features_to_vector(d) for d in synthetic]
        y = [_LABEL_MAP_.get(d.get('severity', 'LOW'), 0) for d in synthetic]
        predictor.train_model(X, y)

    if model_path:
        predictor.save_model(model_path)

    _default_predictor = predictor
    return True if model_path else predictor


def create_vuln_severity_predictor(
    model_path: Optional[str] = None,
) -> VulnSeverityPredictor:
    predictor = VulnSeverityPredictor(model_path=model_path, use_rules=True)
    return predictor


def get_default_predictor() -> VulnSeverityPredictor:
    global _default_predictor
    if _default_predictor is None:
        _default_predictor = create_vuln_severity_predictor()
    return _default_predictor
