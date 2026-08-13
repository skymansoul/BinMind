
import pytest
import numpy as np
_MOD_DEBUG = False
import tempfile
import os

# 测试是否安装了 PyTorch
try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestMultiViewGNNEmbedder:
    """多视图GNN函数嵌入器测试"""

    def test_embed_single_function(self):
        """测试单个函数嵌入"""
        from modules.multi_view_gnn import MultiViewGNNEmbedder

        embedder = MultiViewGNNEmbedder()

        # 构造测试函数信息
        function_info = {
            "name": "test_function",
            "address": 0x1000,
            "cfg_nodes": [
                {"id": 0, "instructions": ["mov eax, 1", "add eax, ebx"], "label": "entry"},
                {"id": 1, "instructions": ["cmp eax, 0", "jz end"], "label": "cond"},
                {"id": 2, "instructions": ["ret"], "label": "end"}
            ],
            "cfg_edges": [
                {"source": 0, "target": 1},
                {"source": 1, "target": 2}
            ],
            "variables": [{"name": "eax"}, {"name": "ebx"}],
            "call_graph": [{"callee": "printf"}]
        }

        result = embedder.embed_function(function_info)

        assert result.function_name == "test_function"
        assert result.function_address == 0x1000
        assert result.embedding.shape == (512,)
        assert 0 <= result.confidence <= 1.0
        assert "num_cfg_nodes" in result.metadata

    def test_batch_embed(self):
        """测试批量函数嵌入"""
        from modules.multi_view_gnn import MultiViewGNNEmbedder

        embedder = MultiViewGNNEmbedder()

        functions_info = [
            {
                "name": "func1",
                "address": 0x1000,
                "cfg_nodes": [{"id": 0, "instructions": ["mov eax, 1"]}],
                "cfg_edges": [],
                "variables": [],
                "call_graph": []
            },
            {
                "name": "func2",
                "address": 0x2000,
                "cfg_nodes": [{"id": 0, "instructions": ["add eax, ebx"]}],
                "cfg_edges": [],
                "variables": [],
                "call_graph": []
            }
        ]

        results = embedder.batch_embed(functions_info)

        assert len(results) == 2
        assert results[0].function_name == "func1"
        assert results[1].function_name == "func2"

    def test_compute_similarity(self):
        """测试相似度计算"""
        from modules.multi_view_gnn import MultiViewGNNEmbedder

        embedder = MultiViewGNNEmbedder()

        embedding1 = np.array([1.0, 0.0, 0.0])
        embedding2 = np.array([1.0, 0.0, 0.0])
        embedding3 = np.array([0.0, 1.0, 0.0])

        sim1 = embedder.compute_similarity(embedding1, embedding2)
        sim2 = embedder.compute_similarity(embedding1, embedding3)

        assert sim1 == pytest.approx(1.0)
        assert sim2 == pytest.approx(0.0)

    def test_search_similar(self):
        from modules.multi_view_gnn import MultiViewGNNEmbedder

        embedder = MultiViewGNNEmbedder()

        # 添加一些缓存数据
        embedder.embedding_cache["func1_0x1000"] = np.array([1.0, 0.0, 0.0] * 170 + [1.0, 0.0])[:512]
        embedder.embedding_cache["func2_0x2000"] = np.array([0.9, 0.1, 0.0] * 170 + [0.9, 0.1])[:512]
        embedder.embedding_cache["func3_0x3000"] = np.array([0.0, 1.0, 0.0] * 170 + [0.0, 1.0])[:512]

        query_embedding = np.array([1.0, 0.0, 0.0] * 170 + [1.0, 0.0])[:512]
        result = embedder.search_similar(query_embedding, top_k=2)

        assert result.top_k == 2
        assert len(result.similar_functions) == 2
        assert result.similar_functions[0][0] == "func1_0x1000"
        assert result.similar_functions[0][1] >= result.similar_functions[1][1]

    def test_save_load_embeddings(self):
        """测试保存和加载嵌入缓存"""
        from modules.multi_view_gnn import MultiViewGNNEmbedder

        embedder = MultiViewGNNEmbedder()

        # 添加缓存数据
        embedder.embedding_cache["test_func_0x1000"] = np.random.rand(512)

        # 保存
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            temp_path = f.name

        try:
            success = embedder.save_embeddings(temp_path)
            assert success

            # 创建新嵌入器并加载
            embedder2 = MultiViewGNNEmbedder()
            success = embedder2.load_embeddings(temp_path)
            assert success
            assert "test_func_0x1000" in embedder2.embedding_cache
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestMultiViewGNNEmbedderAnalyzer:
    """多视图GNN分析器包装类测试"""

    def test_analyze_with_functions(self):
        """测试分析器处理函数列表"""
        from modules.multi_view_gnn import MultiViewGNNEmbedderAnalyzer

        analyzer = MultiViewGNNEmbedderAnalyzer()

        functions = [
            {
                "name": "test_func",
                "address": 0x1000,
                "cfg_nodes": [{"id": 0, "instructions": ["mov eax, 1"]}],
                "cfg_edges": [],
                "variables": [],
                "call_graph": []
            }
        ]

        result = analyzer.analyze(functions=functions)

        assert result["success"] is True
        assert len(result["embeddings"]) == 1
        assert result["embeddings"][0]["function_name"] == "test_func"

    def test_analyze_with_search_query(self):
        """测试分析器处理搜索查询"""
        from modules.multi_view_gnn import MultiViewGNNEmbedderAnalyzer

        analyzer = MultiViewGNNEmbedderAnalyzer()

        # 先添加一些函数到缓存
        functions = [
            {
                "name": "func1",
                "address": 0x1000,
                "cfg_nodes": [{"id": 0, "instructions": ["mov eax, 1"]}],
                "cfg_edges": [],
                "variables": [],
                "call_graph": []
            }
        ]

        analyzer.analyze(functions=functions)

        # 搜索
        query_embedding = [1.0] * 512
        result = analyzer.analyze(search_query=query_embedding)

        assert result["success"] is True

    def test_validate_input(self):
        # 人工调校的阈值设定
        """测试输入验证"""
        from modules.multi_view_gnn import MultiViewGNNEmbedderAnalyzer

        analyzer = MultiViewGNNEmbedderAnalyzer()

        # 有效输入
        is_valid, error = analyzer.validate_input(functions=[])
        assert is_valid is True
        assert error is None

        # 无效输入 - functions不是列表
        is_valid, error = analyzer.validate_input(functions="invalid")
        assert is_valid is False
        assert "必须是列表类型" in error

    def test_cleanup(self):
        from modules.multi_view_gnn import MultiViewGNNEmbedderAnalyzer

        analyzer = MultiViewGNNEmbedderAnalyzer()
        analyzer.embedder = object()  # 设置一个模拟对象

        analyzer.cleanup()

        assert analyzer.embedder is None


