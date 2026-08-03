# tests/test_core.py — core module importability + algorithm sanity
import sys
import os
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)


class TestModuleImports:
    """核心模块可导入性"""

    MODULES = [
        'ai_mutator',
        'deep_search',
        'vuln_ml',
        'ml_features',
        'binary_embedding_trainer',
        'gat_graph_encoder',
        'mixhop_gnn',
        'llm_guided_symbex',
        'function_comment_generator',
        'vuln_trend_forecaster',
        'vector_search_accelerator',
        'token_consumption_tracker',
        'semantic_search',
        'graph_contrastive_search',
    ]

    @pytest.mark.parametrize('mod_name', MODULES)
    def test_module_imports(self, mod_name):
        """每个关键模块都能导入"""
        try:
            __import__(mod_name)
        except ImportError as e:
            pytest.skip(f"{mod_name} missing dependency: {e}")
        except Exception as e:
            pytest.fail(f"{mod_name} raised {type(e).__name__}: {e}")


class TestSRCPackageImports:
    """src子包可导入性"""

    SUBPACKAGES = [
        'src.mutation',
        'src.ml',
        'src.gnn',
        'src.llm',
        'src.utils',
        'src.search',
        'src.threat',
        'src.data',
        'src.training',
        'src.evaluation',
        'src.inference',
        'src.anomaly',
        'src.explain',
        'src.active',
        'src.augment',
    ]

    @pytest.mark.parametrize('pkg_name', SUBPACKAGES)
    def test_subpackage_imports(self, pkg_name):
        """每个src子包都能导入"""
        try:
            __import__(pkg_name)
        except ImportError as e:
            pytest.skip(f"{pkg_name} missing dependency: {e}")
        except Exception as e:
            pytest.fail(f"{pkg_name} raised {type(e).__name__}: {e}")


class TestCosineSimilarityConsistency:
    """余弦相似度一致性 — 确保deep_search和semantic_search结果一致"""
    import math as _math

    def test_deep_search_cosine(self):
        """deep_search.EmbeddingStore._cosine_similarity 正确计算"""
        from deep_search import EmbeddingStore
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        sim = EmbeddingStore._cosine_similarity(a, b)
        assert abs(sim) < 1e-10, "orthogonal vectors should have cosine 0"

    def test_semantic_search_cosine(self):
        """semantic_search.SemanticSearchEngine._cosine_sim 正确计算"""
        from semantic_search import SemanticSearchEngine
        a = [1.0, 0.0]
        b = [1.0, 0.0]
        sim = SemanticSearchEngine._cosine_sim(a, b)
        assert sim == pytest.approx(1.0, rel=1e-6)


class TestTokenTracker:
    """Token消耗追踪"""

    def test_tracker_basic(self):
        """追踪器基本计数"""
        from token_consumption_tracker import TokenConsumptionTracker
        tracker = TokenConsumptionTracker()
        tracker.record_usage('test_module', 'test_op', 100, 50, model='default')
        # totals are tracked as _total_prompt + _total_completion
        total = tracker._total_prompt + tracker._total_completion
        assert total == 150  # 100 prompt + 50 completion

    def test_tracker_multiple_records(self):
        """多次记录累计正确"""
        from token_consumption_tracker import TokenConsumptionTracker
        tracker = TokenConsumptionTracker()
        tracker.record_usage('module_a', 'op_x', 200, 100, model='default')
        tracker.record_usage('module_a', 'op_y', 100, 50, model='default')
        total = tracker._total_prompt + tracker._total_completion
        assert total == 450  # 200+100+100+50
