
import pytest
import random
_MOD_DEBUG = False
from modules.ai_mutator import (
    AIMutator, SemanticPreservingMutator, create_ai_mutator,
    InputGrammar, MutatedInput, MutationResult,
)


class TestAIMutator:
    """AI变异器测试类"""

    def test_ai_mutator_learn(self):
        """测试训练功能"""
        mutator = AIMutator()
        seeds = [b"GET /api/user HTTP/1.1\r\nHost: example.com\r\n\r\n",
                 b"POST /api/login HTTP/1.1\r\nContent-Length: 20\r\n\r\n"]

        mutator.learn(seeds)

        assert len(mutator.grammar.tokens) > 0

    def test_ai_mutator_run(self):
        mutator = AIMutator()
        seed = b"GET /test HTTP/1.1\r\n"

        result = mutator.run(seed, count=3)

        assert result.success is True
        assert len(result.mutations) == 3
        assert result.total == 3
        for m in result.mutations:
            assert isinstance(m, MutatedInput)
            assert m.original == seed
            assert isinstance(m.mutated, bytes)

    def test_create_ai_mutator(self):
        """测试工厂函数"""
        mutator = create_ai_mutator()
        assert isinstance(mutator, AIMutator)


class TestInputGrammar:
    """语法学习器测试类"""

    def test_learn_from_corpus(self):
        grammar = InputGrammar()
        corpus = [b"hello world", b"hello there", b"foo bar"]

        grammar.learn_from_corpus(corpus)

        assert len(grammar.tokens) > 0
        assert isinstance(grammar.tokens, list)


class TestSemanticPreservingMutator:
    """语义保持变异器测试类"""

    def test_mutate(self):
        """测试变异生成"""
        grammar = InputGrammar()
        grammar.tokens = ["hello", "world"]
        mutator = SemanticPreservingMutator(grammar)
        seed = b"test input data"

        results = mutator.mutate(seed, count=3)

        assert len(results) == 3
        for m in results:
            assert isinstance(m, MutatedInput)
            assert m.original == seed
            assert isinstance(m.mutated, bytes)


# Removed tests for classes that no longer exist
# NgramMutator, GrammarBasedMutator, HybridMutator were removed
# from the module. Their tests have been deleted.
# The removed functionality was consolidated into:
#   - AIMutator (main entry point)
#   - InputGrammar (grammar learning)
#   - SemanticPreservingMutator (mutation logic)
#   - create_ai_mutator (factory function)
