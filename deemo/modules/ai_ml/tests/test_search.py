"""ai_ml search — cosine similarity, FAISS index building, embedding normalization."""
import sys
import os
import math
import pytest

_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from semantic_search import (
    SemanticSearchEngine, SearchIndex, FunctionEmbedding,
    TFIDFVectorizer, TokenEmbedder, FunctionEmbedder,
    SearchResult, SemanticSearchResult,
    semantic_search, format_search_report
)


class TestCosineSimilarity:
    """余弦相似度计算"""

    def test_identical_vectors(self):
        """相同向量相似度为1.0"""
        a = [1.0, 0.5, 0.2]
        sim = SemanticSearchEngine._cosine_sim(a, a)
        assert sim == pytest.approx(1.0, rel=1e-6)

    def test_orthogonal_vectors(self):
        """正交向量相似度为0.0"""
        a = [1.0, 0.0, 0.0]
        b = [0.0, 1.0, 0.0]
        sim = SemanticSearchEngine._cosine_sim(a, b)
        assert abs(sim) < 1e-10

    def test_opposite_vectors(self):
        """相反方向向量相似度为-1.0"""
        a = [2.0, 1.0, 0.5]
        b = [-2.0, -1.0, -0.5]
        sim = SemanticSearchEngine._cosine_sim(a, b)
        assert sim == pytest.approx(-1.0, rel=1e-6)

    def test_arbitrary_angle(self):
        """验证已知角度（同向向量除以sqrt(2)）"""
        a = [1.0, 0.0]
        b = [1.0, 1.0]
        # cos = dot(a,b) / (|a|*|b|) = 1/(1*sqrt(2)) = 1/sqrt(2)
        sim = SemanticSearchEngine._cosine_sim(a, b)
        assert sim == pytest.approx(1.0 / math.sqrt(2), rel=1e-6)


class TestSearchEngine:
    """搜索索引构建与查询"""

    @pytest.fixture
    def engine(self):
        return SemanticSearchEngine(dimension=4)

    @pytest.fixture
    def populated_engine(self, engine):
        """添加3个已知嵌入向量"""
        engine.index_function("func_a", 0x1000, [1.0, 0.0, 0.0, 0.0])
        engine.index_function("func_b", 0x2000, [0.0, 1.0, 0.0, 0.0])
        engine.index_function("func_c", 0x3000, [0.5, 0.5, 0.0, 0.0])
        return engine

    def test_index_function_adds_embedding(self, engine):
        """index_function添加嵌入向量"""
        engine.index_function("test", 0x4000, [1.0, 2.0, 3.0, 4.0])
        assert len(engine) == 1

    def test_search_returns_sorted_results(self, populated_engine):
        """搜索返回按相似度排序的结果"""
        query = [0.9, 0.1, 0.0, 0.0]
        results = populated_engine.search(query, top_k=3)
        assert len(results) == 3
        # 最相似的应该是func_a（与query方向一致）
        top = results[0]
        assert top[0].name == "func_a"
        # 相似度递减
        assert results[0][1] >= results[1][1] >= results[2][1]

    def test_search_by_name_excludes_self(self, populated_engine):
        """按名称搜索排除自身"""
        results = populated_engine.search_by_name("func_a", top_k=5)
        names = [r[0].name for r in results]
        assert "func_a" not in names

    def test_clear_resets_engine(self, populated_engine):
        """clear后引擎为空"""
        populated_engine.clear()
        assert len(populated_engine) == 0

    def test_brute_force_fallback(self):
        """无FAISS时回退到余弦相似度暴力搜索"""
        engine = SemanticSearchEngine(dimension=2)
        # 强制不使用FAISS
        engine._use_faiss = False
        engine.index_function("f1", 0x1000, [1.0, 0.0])
        engine.index_function("f2", 0x2000, [0.0, 1.0])
        results = engine.search([0.99, 0.01], top_k=2)
        assert len(results) == 2
        assert results[0][0].name == "f1"


class TestTFIDFVectorizer:
    """TF-IDF向量化"""

    def test_fit_transform_returns_vectors(self):
        """fit_transform返回正确维度向量"""
        docs = ["hello world foo", "hello bar baz", "world foo qux"]
        vec = TFIDFVectorizer()
        vectors = vec.fit_transform(docs)
        assert len(vectors) == 3
        # 词汇表大小等于所有文档的唯一token数
        assert len(vectors[0]) == len(vec.vocabulary_)

    def test_same_docs_equal_vectors(self):
        """相同文档产生相同向量"""
        docs = ["mov eax ebx", "push ebp", "mov eax ebx"]
        vec = TFIDFVectorizer()
        vectors = vec.fit_transform(docs)
        assert vectors[0] == pytest.approx(vectors[2], rel=1e-6)

    def test_tokenize_extracts_identifiers(self):
        """_tokenize提取C风格标识符"""
        tokens = TFIDFVectorizer._tokenize("mov rax, [rbp-0x10]")
        assert "mov" in tokens
        assert "rax" in tokens
        assert "rbp" in tokens
        # 标点符号被过滤
        assert "[" not in tokens


class TestTokenEmbedder:
    """Token嵌入与L2归一化"""

    def test_embed_returns_normalized_vector(self):
        """嵌入向量L2范数为1.0"""
        embedder = TokenEmbedder()
        vec = embedder.embed("mov rax rbx push pop ret")
        norm = math.sqrt(sum(v * v for v in vec))
        assert norm == pytest.approx(1.0, rel=1e-6) or norm == 0.0

    def test_same_text_same_embedding(self):
        """相同文本产生相同嵌入"""
        embedder = TokenEmbedder()
        text = "pop rdi ret syscall"
        v1 = embedder.embed(text)
        v2 = embedder.embed(text)
        assert v1 == pytest.approx(v2, rel=1e-6)


class TestFunctionEmbedder:
    """函数嵌入封装"""

    def test_embed_extracts_pseudocode(self):
        """函数嵌入优先使用pseudocode字段"""
        embedder = FunctionEmbedder()
        func = {"pseudocode": "mov rax 0 mov rdi 0 syscall", "name": "exec"}
        vec = embedder.embed(func)
        assert len(vec) == 128  # TokenEmbedder维度

    def test_embed_falls_back_to_name(self):
        """无pseudocode时使用函数名"""
        embedder = FunctionEmbedder()
        func = {"name": "memcpy"}
        vec = embedder.embed(func)
        assert len(vec) == 128
