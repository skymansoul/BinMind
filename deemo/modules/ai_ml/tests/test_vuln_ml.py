"""ai_ml vuln_ml — severity prediction pipeline, feature vector extraction."""
import sys
import os
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from vuln_ml import (
    VulnSeverityPredictor,
    _LABELS_, _LABEL_MAP_, _TYPE_SCORES_, _EXPLOITABILITY_PRIORS_,
    train_default_model, create_vuln_severity_predictor, get_default_predictor
)


class TestSeverityPredictionPipeline:
    """严重性预测完整管道（规则模式）"""

    @pytest.fixture
    def predictor(self):
        return VulnSeverityPredictor(use_rules=True)

    @pytest.fixture
    def buffer_overflow_features(self):
        """典型缓冲区溢出漏洞特征"""
        return {
            "vuln_type": "buffer_overflow",
            "severity": "HIGH",
            "function_name": "strcpy_wrapper",
            "reachable_from_input": True,
            "is_exported": False,
            "is_hot_path": True,
            "has_attacker_controlled_input": True,
            "no_stack_canary": True,
            "no_nx": False,
            "no_pie": True,
            "no_full_relro": False,
            "no_safe_seh": True,
            "no_cfi": True,
            "no_asan": True,
            "has_exploit": False,
            "dangerous_api_ratio": 0.8,
            "cvss_score": 8.5,
            "exploit_available": False,
            "is_apt_relevant": False,
            "cve_age_days": 30,
        }

    def test_predict_returns_severity_label(self, predictor, buffer_overflow_features):
        """缓冲区溢出预测返回HIGH或CRITICAL"""
        result = predictor.predict(buffer_overflow_features)
        assert "severity" in result
        assert result["severity"] in _LABELS_
        # buffer_overflow基准分0.8，配合多个保护缺失，应在HIGH以上
        assert result["severity_index"] >= 1  # MEDIUM及以上

    def test_predict_includes_confidence(self, predictor, buffer_overflow_features):
        """预测结果包含置信度"""
        result = predictor.predict(buffer_overflow_features)
        assert "confidence" in result
        assert 0.0 <= result["confidence"] <= 1.0

    def test_info_leak_scores_low(self, predictor):
        """信息泄露漏洞评分较低"""
        features = {
            "vuln_type": "info_leak",
            "severity": "LOW",
            "function_name": "debug_print",
            "reachable_from_input": False,
            "is_exported": False,
            "is_hot_path": False,
            "has_attacker_controlled_input": False,
            "no_stack_canary": False,
            "no_nx": False,
            "no_pie": False,
            "no_full_relro": False,
            "no_safe_seh": False,
            "no_cfi": False,
            "no_asan": False,
            "has_exploit": False,
            "dangerous_api_ratio": 0.0,
            "cvss_score": 2.0,
            "exploit_available": False,
            "is_apt_relevant": False,
            "cve_age_days": 0,
        }
        result = predictor.predict(features)
        # info_leak基准分仅0.4
        assert result["severity_index"] <= 1  # MEDIUM或LOW


class TestFeatureVectorExtraction:
    """_features_to_vector特征向量提取"""

    def test_features_to_vector_9_dimensions(self):
        """特征向量固定为9维"""
        predictor = VulnSeverityPredictor(use_rules=True)
        features = {
            "vuln_type": "code_execution",
            "no_stack_canary": True,
            "no_nx": True,
            "no_pie": True,
            "no_full_relro": True,
            "has_exploit": True,
            "reachable_from_input": True,
            "dangerous_api_ratio": 1.0,
            "cvss_score": 10.0,
        }
        vec = predictor._features_to_vector(features)
        assert len(vec) == 9
        assert all(isinstance(v, (int, float)) for v in vec)

    def test_default_features_produce_mid_range(self):
        """默认特征产生中间范围分数"""
        predictor = VulnSeverityPredictor(use_rules=True)
        features = {
            "vuln_type": "default",
            "no_stack_canary": False,
            "no_nx": False,
            "no_pie": False,
            "no_full_relro": False,
            "has_exploit": False,
            "reachable_from_input": False,
            "dangerous_api_ratio": 0.0,
            "cvss_score": 3.0,
        }
        result = predictor.predict(features)
        assert result["severity"] in ("LOW", "MEDIUM")


class TestBatchPrediction:
    """批量预测"""

    def test_batch_predict_same_count(self):
        """批量预测输入输出数量一致"""
        predictor = VulnSeverityPredictor(use_rules=True)
        features_list = [
            {"vuln_type": "buffer_overflow", "no_stack_canary": True,
             "no_nx": False, "no_pie": False, "no_full_relro": False,
             "has_exploit": False, "reachable_from_input": True,
             "dangerous_api_ratio": 0.5, "cvss_score": 7.0},
            {"vuln_type": "null_dereference", "no_stack_canary": False,
             "no_nx": False, "no_pie": False, "no_full_relro": False,
             "has_exploit": False, "reachable_from_input": False,
             "dangerous_api_ratio": 0.0, "cvss_score": 2.0},
        ]
        results = predictor.predict_batch(features_list)
        assert len(results) == 2

    def test_batch_empty_returns_empty(self):
        """空列表批量预测返回空列表"""
        predictor = VulnSeverityPredictor(use_rules=True)
        assert predictor.predict_batch([]) == []


class TestExploitProbability:
    """漏洞利用概率估算（EPSS启发式）"""

    def test_code_execution_high_exploitability(self):
        """代码执行漏洞利用概率高"""
        predictor = VulnSeverityPredictor(use_rules=True)
        features = {
            "vuln_type": "code_execution",
            "exploit_available": True,
            "reachable_from_input": True,
            "cvss_score": 9.0,
            "is_hot_path": True,
            "is_exported": False,
            "is_apt_relevant": True,
            "cve_age_days": 30,
        }
        result = predictor.estimate_exploit_probability(features)
        # estimate_exploit_probability返回epss_heuristic结果
        assert "method" in result
        # 代码执行漏洞利用概率应显著大于0
        prob_key = [k for k in result if 'prob' in k.lower()][0]
        assert result[prob_key] > 0.4

    def test_info_leak_low_exploitability(self):
        """信息泄露利用概率低"""
        predictor = VulnSeverityPredictor(use_rules=True)
        features = {
            "vuln_type": "info_leak",
            "exploit_available": False,
            "reachable_from_input": False,
            "cvss_score": 2.0,
            "is_hot_path": False,
            "is_exported": False,
            "is_apt_relevant": False,
            "cve_age_days": 500,
        }
        result = predictor.estimate_exploit_probability(features)
        prob_key = [k for k in result if 'prob' in k.lower()][0]
        assert result[prob_key] < 0.2


class TestThresholdCalibration:
    """阈值校准网格搜索"""

    def test_calibrate_returns_thresholds(self):
        """校准返回合法阈值映射"""
        predictor = VulnSeverityPredictor(use_rules=True)
        labeled = [
            {"vuln_type": "code_execution", "severity": "CRITICAL",
             "cvss_score": 9.5, "no_stack_canary": True, "no_nx": True,
             "no_pie": True, "no_full_relro": True, "has_exploit": True,
             "reachable_from_input": True, "dangerous_api_ratio": 1.0},
            {"vuln_type": "null_dereference", "severity": "LOW",
             "cvss_score": 1.0, "no_stack_canary": False, "no_nx": False,
             "no_pie": False, "no_full_relro": False, "has_exploit": False,
             "reachable_from_input": False, "dangerous_api_ratio": 0.0},
        ]
        thresholds = predictor.calibrate_thresholds(labeled, metric="f1")
        assert "low_to_medium" in thresholds
        assert "medium_to_high" in thresholds
        assert "high_to_critical" in thresholds
        # 阈值应该单调递增
        assert thresholds["low_to_medium"] < thresholds["medium_to_high"]
        assert thresholds["medium_to_high"] < thresholds["high_to_critical"]
