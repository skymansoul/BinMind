# tests/test_integration.py — end-to-end integration across multiple modules
import sys
import os
import json
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


class TestMutationToVectorSearch:
    """变异输出 → 向量搜索管道"""

    def test_mutate_then_search(self):
        """生成变异后搜索相似性"""
        from ai_mutator import AIMutator
        from deep_search import EmbeddingStore

        # Phase 1: 构造 mutations
        mutator = AIMutator()
        mutator.learn_mt([b"AAAA", b"BBBB", b"CCCC", b"DDDD", b"EEEE"])
        result = mutator.run_mt(b"FFFF", count=3)
        assert result.m_ok
        assert len(result.m_muts) >= 1

        # Phase 2: Index and search
        store = EmbeddingStore()
        for i, mut in enumerate(result.m_muts):
            # pseudo-嵌入 from byte histogram
            hist = [0.0] * 256
            for b in mut.m_mut:
                hist[b] += 1.0
            total = max(sum(hist), 1)
            vec = [h / total for h in hist]
            store.add_es(f"mut_{i}", vec)

        query_vec = [0.0] * 256
        for b in b"FFFF":
            query_vec[b] += 1.0
        total = max(sum(query_vec), 1)
        query_vec = [v / total for v in query_vec]

        results = store.search_es(query_vec, top_k=2)
        assert len(results) >= 1


class TestVulnMLThenTrend:
    """漏洞预测 → 趋势记录"""

    def test_predict_then_log_to_trend(self):
        """预测后写入趋势数据"""
        from vuln_ml import VulnSeverityPredictor
        from vuln_trend_forecaster import VulnTrendForecaster, VulnTimePoint

        # Phase 1: Predict severity
        predictor = VulnSeverityPredictor(use_rules=True)
        features = {
            "vuln_type": "code_execution",
            "severity": "HIGH",
            "function_name": "unsafe_exec",
            "reachable_from_input": True,
            "is_exported": True,
            "is_hot_path": True,
            "has_attacker_controlled_input": True,
            "no_stack_canary": True,
            "no_nx": True,
            "no_pie": True,
            "no_full_relro": False,
            "no_safe_seh": True,
            "no_cfi": True,
            "no_asan": True,
            "has_exploit": False,
            "dangerous_api_ratio": 1.0,
            "cvss_score": 9.5,
            "exploit_available": False,
            "is_apt_relevant": True,
            "cve_age_days": 10,
        }
        prediction = predictor.predict(features)
        assert prediction['severity'] in ('HIGH', 'CRITICAL')

        # Phase 2: Log to trend 预测器
        forecaster = VulnTrendForecaster()
        tp = VulnTimePoint(
            timestamp=1000000.0 + 1,
            binary_id='test_bin',
            vuln_type='code_execution',
            severity=prediction['severity'],
            count=1,
        )
        forecaster.record(tp)
        count = forecaster.store.count()
        assert count >= 1


class TestConfigToLogging:
    """配置 → 日志管道"""

    def test_config_feeds_logging_setup(self):
        """从配置加载日志设置"""
        from src.config import load_config, reload_config
        from src.utils.logging_setup import setup_logging
        reload_config()
        cfg = load_config()
        log_cfg = cfg.get('logging', {})
        # Verify setup doesn't crash
        setup_logging(
            level=log_cfg.get('level', 'INFO'),
            log_file=None,
            debug=False
        )
        import logging
        logger = logging.getLogger("ai_ml")
        assert logger.level > 0
