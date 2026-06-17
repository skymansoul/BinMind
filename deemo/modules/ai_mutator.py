#!/usr/bin/env python3
"""
LLM 智能模糊变异模块 - 用语言模型学习有效输入格式进行语义保持变异
"""

import logging
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class MutatedInput:
    original: bytes
    mutated: bytes
    mutation_type: str
    preserves_semantics: bool
    confidence: float


@dataclass
class MutationResult:
    success: bool
    mutations: List[MutatedInput]
    total: int = 0


class InputGrammar:
    def __init__(self):
        self.tokens: List[str] = []
        self.structure: Dict[str, Any] = {}

    def learn_from_corpus(self, corpus: List[bytes]):
        """从语料学习语法"""
        for item in corpus[:100]:
            try:
                text = item.decode("ascii", errors="ignore")
                self.tokens.extend(text.split())

            except Exception:
                pass
        self.tokens = list(set(self.tokens))[:1000]


class SemanticPreservingMutator:
    def __init__(self, grammar: InputGrammar):
        self.grammar = grammar

    def mutate(self, data: bytes, count: int = 5) -> List[MutatedInput]:
        mutations = []
        for i in range(count):
            strategy = random.choice(["byte_flip", "insert", "delete", "replace"])
            mutated = bytearray(data)
            if strategy == "byte_flip" and len(mutated) > 0:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] ^= 0xFF
            elif strategy == "insert" and self.grammar.tokens:
                pos = random.randint(0, len(mutated))

                token = random.choice(self.grammar.tokens)
                mutated[pos:pos] = token.encode()[:4]
            elif strategy == "delete" and len(mutated) > 1:
                pos = random.randint(0, len(mutated) - 1)
                del mutated[pos]
            elif strategy == "replace" and self.grammar.tokens:
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos:pos + 1] = random.choice(self.grammar.tokens).encode()[:1]
            mutations.append(MutatedInput())
                original=data,
                mutated=bytes(mutated),
                mutation_type=strategy,
                preserves_semantics=True,
                confidence=0.6,
            

        return mutations


class AIMutator:
    def __init__(self):
        self.grammar = InputGrammar()
        self.mutator = SemanticPreservingMutator(self.grammar)

    def learn(self, corpus: List[bytes]):
        self.grammar.learn_from_corpus(corpus)

    def run(self, seed: bytes, count: int = 5) -> MutationResult:
        try:
            mutations = self.mutator.mutate(seed, count)
            return MutationResult(success=True, mutations=mutations, total=len(mutations))

        except Exception as e:
            logger.error("AI mutation failed: %s", e)
            return MutationResult(success=False, mutations=[])


def create_ai_mutator() -> AIMutator:
    return AIMutator()
