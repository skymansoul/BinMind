"""
AI驱动的模糊测试智能变异模块测试
"""

import pytest
import random
from modules.ai_mutator import AIMutator, NgramMutator, GrammarBasedMutator, HybridMutator


class TestAIMutator:
    """AI变异器测试类"""
    
    def test_ai_mutator_train(self):
        """测试训练功能"""
        mutator = AIMutator()
        seeds = [b"GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n",
                 b"POST /api/login HTTP/1.1\r\nContent-Length: 20\r\n\r\n"]
        
        result = mutator.analyze(mode='train', seeds=seeds, strategy='hybrid')
        
        assert result['success'] is True
        assert result['strategy'] == 'hybrid'
        assert result['seed_count'] == 2
    
    def test_ai_mutator_mutate(self):
        """测试变异功能"""
        mutator = AIMutator()
        seed = b"GET /test HTTP/1.1\r\n"
        
        result = mutator.analyze(mode='mutate', seed=seed)
        
        assert result['success'] is True
        assert 'mutated_data' in result
        assert result['original_length'] == len(seed)
    
    def test_ai_mutator_get_mutated_seed(self):
        """测试获取变异种子"""
        mutator = AIMutator()
        seed = b"test"
        
        mutated = mutator.get_mutated_seed(seed)
        
        assert isinstance(mutated, bytes)
        assert len(mutated) == len(seed)
    
    def test_ai_mutator_metadata(self):
        """测试元数据获取"""
        metadata = AIMutator.get_metadata()
        
        assert metadata.name == "AIMutator"
        assert metadata.type.value == "vulnerability_detector"
        assert metadata.version == "1.0.0"


class TestNgramMutator:
    """N-gram变异器测试类"""
    
    def test_ngram_train(self):
        """测试训练n-gram模型"""
        mutator = NgramMutator(n=3)
        seeds = [b"hello world", b"hello there"]
        
        mutator.train(seeds)
        
        assert len(mutator.model.vocabulary) > 0
    
    def test_ngram_mutate(self):
        """测试n-gram变异"""
        mutator = NgramMutator(n=3)
        mutator.train([b"test string"])
        
        result = mutator.mutate(b"test", 0)
        
        assert isinstance(result, bytes)
        assert len(result) == 4


class TestGrammarBasedMutator:
    """语法规则变异器测试类"""
    
    def test_grammar_train(self):
        """测试学习语法规则"""
        mutator = GrammarBasedMutator()
        seeds = [b"GET /path HTTP/1.1\r\nHost: localhost\r\n\r\n"]
        
        mutator.train(seeds)
    
    def test_grammar_mutate(self):
        """测试语法规则变异"""
        mutator = GrammarBasedMutator()
        seed = b"GET /test HTTP/1.0"
        
        result = mutator.mutate(seed, 0)
        
        assert isinstance(result, bytes)


class TestHybridMutator:
    """混合变异器测试类"""
    
    def test_hybrid_train(self):
        """测试训练混合模型"""
        mutator = HybridMutator()
        seeds = [b"test data"]
        
        mutator.train(seeds)
    
    def test_hybrid_mutate(self):
        """测试混合变异"""
        mutator = HybridMutator()
        seed = b"hello"
        
        result = mutator.mutate(seed, 0)
        
        assert isinstance(result, bytes)
        assert len(result) == len(seed)