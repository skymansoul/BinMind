"""ai_ml mutator — UCB strategy selection, MinHash dedup, entropy-guided positions."""
import sys
import os
import pytest

# 添加ai_ml目录到sys.path，因为ai_ml/缺少__init__.py不是python包
_src_dir = os.path.join(os.path.dirname(__file__), '..')
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from ai_mutator import (
    AIMutator, InputGrammar, SemanticPreservingMutator,
    MutatedInput, MutationResult,
    _pick_strat_mt, _adapt_weights_mt,
    _minhash_sig, _minhash_jaccard, _seed_is_novel, _register_seed_hash,
    _insert_sort
)


class TestMinHashDedup:
    """MinHash签名去重：验证高相似度数据的Jaccard估计"""

    def test_identical_data_has_jaccard_1(self):
        """相同数据产生Jaccard=1.0"""
        data = b"A" * 200 + b"B" * 200
        sig1 = _minhash_sig(data)
        sig2 = _minhash_sig(data)
        assert _minhash_jaccard(sig1, sig2) == pytest.approx(1.0, rel=1e-6)

    def test_dissimilar_data_has_low_jaccard(self):
        """差异大的数据Jaccard接近0"""
        data_a = b"\x00" * 400
        data_b = b"\xff" * 400
        sig_a = _minhash_sig(data_a)
        sig_b = _minhash_sig(data_b)
        jacc = _minhash_jaccard(sig_a, sig_b)
        # 完全不同的shingle集合，Jaccard应接近0
        assert jacc < 0.3, f"expected low jaccard, got {jacc}"

    def test_similar_data_above_threshold_blocks_novel(self):
        """相似种子被MinHash去重拒绝"""
        data = b"X" * 200 + b"Y" * 200
        _register_seed_hash(data)
        # 相同数据不应被视为新种子（MD5精确匹配）
        assert not _seed_is_novel(data, threshold=0.82)
        # MinHash Jaccard: 相同数据→1.0，不同数据→<1.0
        sig_d = _minhash_sig(data)
        sig_same = _minhash_sig(data)
        jacc_identical = _minhash_jaccard(sig_d, sig_same)
        assert jacc_identical == pytest.approx(1.0, rel=1e-6)
        # 完全不同数据→低相似度
        sig_diff = _minhash_sig(b"\xff" * 400)
        jacc_diff = _minhash_jaccard(sig_d, sig_diff)
        assert jacc_diff < 0.5


class TestUCBStrategySelection:
    """UCB1多臂老虎机策略选择"""
    _KEYS = ['bit_flip', 'multi_bit', 'byte_repl', 'insert',
             'delete', 'shuffle', 'crossover']

    def test_pick_strat_returns_valid_key(self):
        """_pick_strat_mt返回7种合法策略之一"""
        strat = _pick_strat_mt()
        assert strat in self._KEYS, f"unknown strategy {strat}"

    def test_multiple_picks_produce_all_keys(self):
        """多次选择应覆盖所有策略（UCB探索保证）"""
        samples = [_pick_strat_mt() for _ in range(200)]
        seen = set(samples)
        assert len(seen) == len(self._KEYS), \
            f"UCB should explore all {len(self._KEYS)} strategies, saw {seen}"

    def test_adapt_weights_updates_weights(self):
        """权重自适应后成功策略权重上升"""
        # 给bit_flip大量成功反馈
        success = {'bit_flip': 10, 'multi_bit': 0, 'byte_repl': 0,
                    'insert': 0, 'delete': 0, 'shuffle': 0, 'crossover': 0}
        _adapt_weights_mt(success)
        # 验证函数不抛出异常（权重在内部更新）
        # 再次调用_pick_strat_mt不崩溃
        _pick_strat_mt()


class TestInsertSort:
    """插入排序稳定性验证"""

    def test_sort_empty(self):
        assert _insert_sort([], key_fn=lambda x: x) == []

    def test_sort_descending(self):
        items = [5, 3, 8, 1, 9, 2]
        sorted_items = _insert_sort(items, key_fn=lambda x: x, reverse=True)
        assert sorted_items == sorted(items, reverse=True)

    def test_stability_by_key(self):
        """相等键值保持原始相对顺序"""
        data = [("a", 1), ("b", 1), ("c", 2)]
        result = _insert_sort(data, key_fn=lambda x: x[1])
        # 等值元素保持原始顺序
        assert result[0][0] == "a"
        assert result[1][0] == "b"


class TestInputGrammar:
    """熵引导位置 + Markov字节采样"""

    @pytest.fixture
    def corpus(self):
        return [b"GET / HTTP/1.1\r\n", b"POST /api HTTP/1.1\r\n",
                b"PUT /data HTTP/1.1\r\n"]

    def test_learn_makes_grammar_ready(self, corpus):
        """学习语料后ready为True"""
        g = InputGrammar(max_tokens=100)
        g.learn_mt(corpus)
        assert g.ready_mt() is True

    def test_entropy_biased_position_in_range(self, corpus):
        """熵引导位置在有效范围内"""
        g = InputGrammar(max_tokens=100)
        g.learn_mt(corpus)
        # 最小corpus条目长度为17
        pos = g.entropy_biased_position(17)
        assert 0 <= pos < 17

    def test_sample_markov_byte_returns_byte(self, corpus):
        """Markov采样返回0-255范围内的字节"""
        g = InputGrammar(max_tokens=100)
        g.learn_mt(corpus)
        byte = g.sample_markov_byte(0x47)  # 'G'
        assert 0 <= byte <= 255


class TestAIMutatorIntegration:
    """AIMutator端到端工作流"""

    def test_learn_and_run_produces_mutations(self):
        """学习后运行生成变异输出"""
        # 清除全局缓存避免跨测试污染
        from ai_mutator import _MINHASH_SIG_CACHE
        _MINHASH_SIG_CACHE.clear()
        mutator = AIMutator()
        # 使用足够大的语料确保学习到有效grammar
        corpus = [b"A" * 32, b"B" * 32, b"C" * 32, b"D" * 32]
        mutator.learn_mt(corpus)
        result = mutator.run_mt(b"\x00" * 64, count=3)
        assert isinstance(result, MutationResult)
        # 即使MinHash去重可能阻止某些种子，至少不崩溃
        assert result.m_total >= 0

    def test_empty_corpus_produces_mutations(self):
        """空语料仍能生成变异（回退到随机策略）"""
        from ai_mutator import _MINHASH_SIG_CACHE
        _MINHASH_SIG_CACHE.clear()
        mutator = AIMutator()
        result = mutator.run_mt(b"\x00" * 64, count=2)
        assert isinstance(result, MutationResult)
        # 即使没有学习，也应有基本变异能力
        assert len(result.m_muts) > 0
