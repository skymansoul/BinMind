#!/usr/bin/env python3
# MLM (Masked Language Model) pretraining module for binary/code token sequences.
# Supports variable masking strategies, 词汇表 building, dataset management,
# 训练 loops, and an analyzer integration point.
# added SimpleMLMTrainer as a self-contained 训练 harness.

import logging as _logging
import json as _json
import math as _math
import random as _rnd
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Iterator
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MaskType(Enum):
    TOKEN = "token"
    SPAN = "span"
    RANDOM = "random"
    STRUCTURED = "structured"


class MLMTaskType(Enum):
    BINARY_OPCODE = "binary_opcode"
    SOURCE_CODE = "source_code"
    ASSEMBLY = "assembly"
    IR = "intermediate_representation"
    MIXED = "mixed"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Token:
    """A token in the vocabulary."""
    id: int = 0
    text: str = ""
    frequency: int = 0
    is_special: bool = False
    embedding: Optional[List[float]] = None

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if not isinstance(other, Token):
            return False
        return self.id == other.id


@dataclass
class MLMTrainingExample:
    """A single masked training example."""
    tokens: List[int] = field(default_factory=list)
    masked_tokens: List[int] = field(default_factory=list)
    mask_positions: List[int] = field(default_factory=list)
    labels: List[int] = field(default_factory=list)
    attention_mask: List[int] = field(default_factory=list)
    segment_ids: List[int] = field(default_factory=list)
    sequence_length: int = 0


@dataclass
class MLMTrainingConfig:
    """Configuration for MLM training."""
    batch_size: int = 32
    learning_rate: float = 1e-4
    warmup_steps: int = 1000
    max_steps: int = 100000
    gradient_accumulation_steps: int = 1
    max_grad_norm: float = 1.0
    weight_decay: float = 0.01
    adam_beta1: float = 0.9
    adam_beta2: float = 0.999
    adam_epsilon: float = 1e-8
    mask_probability: float = 0.15
    random_replace_probability: float = 0.1
    keep_original_probability: float = 0.1
    max_sequence_length: int = 512
    num_epochs: int = 3
    save_steps: int = 5000
    log_steps: int = 100
    eval_steps: int = 1000
    fp16: bool = False
    seed: int = 42


@dataclass
class MLMModelConfig:
    """Configuration for the MLM model architecture."""
    vocab_size: int = 50000
    hidden_size: int = 768
    num_hidden_layers: int = 12
    num_attention_heads: int = 12
    intermediate_size: int = 3072
    hidden_dropout_prob: float = 0.1
    attention_dropout_prob: float = 0.1
    max_position_embeddings: int = 512
    type_vocab_size: int = 2
    initializer_range: float = 0.02
    layer_norm_eps: float = 1e-12
    pad_token_id: int = 0
    mask_token_id: int = 1
    cls_token_id: int = 2
    sep_token_id: int = 3
    unk_token_id: int = 4


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

class Vocabulary:
    """Token vocabulary with special token handling."""

    __slots__ = ('m_token_to_id', 'm_id_to_token', 'm_frequencies',
                 'm_special_tokens')

    SPECIAL_TOKENS = {
        "PAD": "[PAD]",
        "MASK": "[MASK]",
        "CLS": "[CLS]",
        "SEP": "[SEP]",
        "UNK": "[UNK]",
    }

    def __init__(self):
        self.m_token_to_id: Dict[str, int] = {}
        self.m_id_to_token: Dict[int, str] = {}
        self.m_frequencies: Dict[str, int] = _defaultdict(int)
        self.m_special_tokens: Dict[str, int] = {}
        self._add_special_tokens()

    def _add_special_tokens(self):
        st_keys = list(self.SPECIAL_TOKENS.keys())
        si = 0
        while si < len(st_keys):
            key = st_keys[si]
            token = self.SPECIAL_TOKENS[key]
            tid = len(self.m_token_to_id)
            self.m_token_to_id[token] = tid
            self.m_id_to_token[tid] = token
            self.m_special_tokens[key] = tid
            si += 1

    def add_token(self, token: str) -> int:
        if token in self.m_token_to_id:
            tid = self.m_token_to_id[token]
        else:
            tid = len(self.m_token_to_id)
            self.m_token_to_id[token] = tid
            self.m_id_to_token[tid] = token
        self.m_frequencies[token] += 1
        return tid

    def add_tokens(self, tokens: List[str]):
        ti = 0
        while ti < len(tokens):
            self.add_token(tokens[ti])
            ti += 1

    def get_id(self, token: str) -> int:
        return self.m_token_to_id.get(token, self.m_special_tokens.get("UNK", 0))

    def get_token(self, token_id: int) -> str:
        return self.m_id_to_token.get(token_id, self.SPECIAL_TOKENS["UNK"])

    def encode(self, tokens: List[str]) -> List[int]:
        ids: List[int] = []
        ti = 0
        while ti < len(tokens):
            ids.append(self.get_id(tokens[ti]))
            ti += 1
        return ids

    def decode(self, token_ids: List[int]) -> List[str]:
        tokens: List[str] = []
        tdi = 0
        while tdi < len(token_ids):
            tokens.append(self.get_token(token_ids[tdi]))
            tdi += 1
        return tokens

    def build_from_corpus(self, corpus: List[List[str]], max_vocab_size: int = 50000):
        """Build vocabulary from a tokenized corpus."""
        freq: Dict[str, int] = _defaultdict(int)
        ci = 0
        while ci < len(corpus):
            seq = corpus[ci]
            ti = 0
            while ti < len(seq):
                freq[seq[ti]] += 1
                ti += 1
            ci += 1

        sorted_tokens = sorted(freq.items(), key=lambda x: -x[1])
        si = 0
        while si < min(len(sorted_tokens), max_vocab_size):
            token, count = sorted_tokens[si]
            self.add_token(token)
            self.m_frequencies[token] = count
            si += 1

    def build_from_bytes(self, byte_corpus: List[bytes], max_vocab_size: int = 50000):
        """Build vocabulary from byte-level data."""
        corpus: List[List[str]] = []
        bi = 0
        while bi < len(byte_corpus):
            data = byte_corpus[bi]
            hex_tokens: List[str] = []
            byte_idx = 0
            while byte_idx < len(data):
                hex_tokens.append(f"{data[byte_idx]:02x}")
                byte_idx += 1
            corpus.append(hex_tokens)
            bi += 1
        self.build_from_corpus(corpus, max_vocab_size)

    def build_from_instructions(self, instruction_corpus: List[List[str]],
                                max_vocab_size: int = 50000):
        """Build vocabulary from assembly instruction sequences."""
        corpus: List[List[str]] = []
        ii = 0
        while ii < len(instruction_corpus):
            instr_seq = instruction_corpus[ii]
            tokens: List[str] = []
            ti = 0
            while ti < len(instr_seq):
                parts = instr_seq[ti].split()
                for p in parts:
                    tokens.append(p)
                ti += 1
            corpus.append(tokens)
            ii += 1
        self.build_from_corpus(corpus, max_vocab_size)

    def get_special_id(self, name: str) -> int:
        return self.m_special_tokens.get(name, 0)

    def __len__(self) -> int:
        return len(self.m_token_to_id)

    def save(self, filepath: str):
        data = {
            "token_to_id": self.m_token_to_id,
            "frequencies": dict(self.m_frequencies),
            "special_tokens": self.m_special_tokens,
        }
        with open(filepath, 'w', encoding='utf-8') as fh:
            _json.dump(data, fh, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, filepath: str) -> 'Vocabulary':
        with open(filepath, 'r', encoding='utf-8') as fh:
            data = _json.load(fh)
        vocab = cls()
        vocab.m_token_to_id = data.get("token_to_id", {})
        vocab.m_frequencies = _defaultdict(int, data.get("frequencies", {}))
        vocab.m_special_tokens = data.get("special_tokens", {})
        vocab.m_id_to_token = {v: k for k, v in vocab.m_token_to_id.items()}
        return vocab


# ---------------------------------------------------------------------------
# MLM Dataset
# ---------------------------------------------------------------------------

class MLMDataset:
    """Dataset for MLM pretraining with configurable masking."""

    __slots__ = ('m_sequences', 'm_vocab', 'm_config', 'm_mask_type',
                 'm_cache')

    def __init__(self, sequences: List[List[str]], vocab: Vocabulary,
                 config: Optional[MLMTrainingConfig] = None,
                 mask_type: MaskType = MaskType.TOKEN):
        self.m_sequences = sequences
        self.m_vocab = vocab
        self.m_config = config if config else MLMTrainingConfig()
        self.m_mask_type = mask_type
        self.m_cache: Dict[int, MLMTrainingExample] = {}

    def _mask_tokens(self, token_ids: List[int]) -> MLMTrainingExample:
        """Apply masking to a token sequence."""
        seq_len = min(len(token_ids), self.m_config.max_sequence_length)
        ids = token_ids[:seq_len]

        masked = list(ids)
        mask_positions: List[int] = []
        labels: List[int] = []

        mask_id = self.m_vocab.get_special_id("MASK")
        pad_id = self.m_vocab.get_special_id("PAD")

        if self.m_mask_type == MaskType.TOKEN:
            i = 0
            while i < len(masked):
                if ids[i] in (pad_id, self.m_vocab.get_special_id("CLS"),
                              self.m_vocab.get_special_id("SEP")):
                    i += 1
                    continue

                r = _rnd.random()
                if r < self.m_config.mask_probability:
                    mask_positions.append(i)
                    labels.append(ids[i])
                    sub_r = _rnd.random()
                    if sub_r < self.m_config.keep_original_probability:
                        masked[i] = ids[i]
                    elif sub_r < self.m_config.keep_original_probability + self.m_config.random_replace_probability:
                        masked[i] = _rnd.randint(5, len(self.m_vocab) - 1)
                    else:
                        masked[i] = mask_id
                i += 1

        elif self.m_mask_type == MaskType.SPAN:
            span_length = _rnd.randint(1, 10)
            if len(masked) > span_length + 2:
                start = _rnd.randint(1, max(1, len(masked) - span_length - 1))
                si = start
                while si < min(start + span_length, len(masked) - 1):
                    if ids[si] != pad_id:
                        mask_positions.append(si)
                        labels.append(ids[si])
                        masked[si] = mask_id
                    si += 1

        elif self.m_mask_type == MaskType.RANDOM:
            i = 0
            while i < len(masked):
                if _rnd.random() < self.m_config.mask_probability:
                    mask_positions.append(i)
                    labels.append(ids[i])
                    masked[i] = _rnd.randint(5, len(self.m_vocab) - 1)
                i += 1

        attention_mask = [1] * seq_len
        if seq_len < self.m_config.max_sequence_length:
            pad_len = self.m_config.max_sequence_length - seq_len
            masked.extend([pad_id] * pad_len)
            attention_mask.extend([0] * pad_len)

        return MLMTrainingExample(
            tokens=ids,
            masked_tokens=masked,
            mask_positions=mask_positions,
            labels=labels,
            attention_mask=attention_mask,
            segment_ids=[0] * len(masked),
            sequence_length=seq_len,
        )

    def __len__(self) -> int:
        return len(self.m_sequences)

    def __getitem__(self, idx: int) -> MLMTrainingExample:
        if idx in self.m_cache:
            return self.m_cache[idx]

        raw_seq = self.m_sequences[idx]
        token_ids = self.m_vocab.encode(raw_seq)

        cls_id = self.m_vocab.get_special_id("CLS")
        sep_id = self.m_vocab.get_special_id("SEP")
        token_ids = [cls_id] + token_ids + [sep_id]

        example = self._mask_tokens(token_ids)
        self.m_cache[idx] = example
        return example

    def get_batch(self, indices: List[int]) -> List[MLMTrainingExample]:
        batch: List[MLMTrainingExample] = []
        ii = 0
        while ii < len(indices):
            batch.append(self[indices[ii]])
            ii += 1
        return batch

    def iter_batches(self) -> Iterator[List[MLMTrainingExample]]:
        indices = list(range(len(self.m_sequences)))
        _rnd.shuffle(indices)

        bs = self.m_config.batch_size
        bi = 0
        while bi < len(indices):
            batch_indices = indices[bi:bi + bs]
            yield self.get_batch(batch_indices)
            bi += bs

    def clear_cache(self):
        self.m_cache.clear()


# ---------------------------------------------------------------------------
# MLM Trainer
# ---------------------------------------------------------------------------

class MLMTrainer:
    """Abstract MLM trainer."""

    def train(self, dataset: MLMDataset, config: MLMTrainingConfig) -> Dict[str, Any]:
        raise NotImplementedError

    def evaluate(self, dataset: MLMDataset) -> Dict[str, float]:
        raise NotImplementedError

    def save_checkpoint(self, path: str):
        raise NotImplementedError

    def load_checkpoint(self, path: str):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Simple MLM Trainer (self-contained, no deep learning framework dependency)
# ---------------------------------------------------------------------------

class SimpleMLMTrainer(MLMTrainer):
    """Simple MLM trainer using heuristic/statistical approach without deep learning.

    Learns token co-occurrence statistics and builds a probability-based
    prediction model for masked token inference.
    """

    __slots__ = ('m_cooccurrence', 'm_token_probs', 'm_model_config',
                 'm_training_stats', 'm_vocab')

    def __init__(self, model_config: Optional[MLMModelConfig] = None):
        self.m_model_config = model_config if model_config else MLMModelConfig()
        self.m_cooccurrence: Dict[int, Dict[int, int]] = _defaultdict(lambda: _defaultdict(int))
        self.m_token_probs: Dict[int, float] = {}
        self.m_training_stats: Dict[str, Any] = {}
        self.m_vocab: Optional[Vocabulary] = None

    def train(self, dataset: MLMDataset,
              config: Optional[MLMTrainingConfig] = None) -> Dict[str, Any]:
        cfg = config if config else MLMTrainingConfig()
        self.m_vocab = dataset.m_vocab

        total_masks = 0
        step = 0

        epoch = 0
        while epoch < cfg.num_epochs:
            epoch_masks = 0

            batch_iter = dataset.iter_batches()
            for batch in batch_iter:
                bi = 0
                while bi < len(batch):
                    example = batch[bi]
                    mi = 0
                    while mi < len(example.mask_positions):
                        pos = example.mask_positions[mi]
                        label = example.labels[mi]
                        context_start = max(0, pos - 5)
                        context_end = min(len(example.tokens), pos + 6)
                        ci = context_start
                        while ci < context_end:
                            if ci != pos and ci < len(example.tokens):
                                ctx_token = example.tokens[ci]
                                self.m_cooccurrence[label][ctx_token] += 1
                            ci += 1
                        total_masks += 1
                        epoch_masks += 1
                        mi += 1

                    bi += 1

                step += 1
                if step % cfg.log_steps == 0:
                    __dbg.info("Step %d: epoch=%d masks=%d", step, epoch, total_masks)

            epoch += 1

        # Build token probability distribution
        total_cooc = 0
        token_keys = list(self.m_cooccurrence.keys())
        tki = 0
        while tki < len(token_keys):
            tok = token_keys[tki]
            cooc_sum = sum(self.m_cooccurrence[tok].values())
            self.m_token_probs[tok] = cooc_sum
            total_cooc += cooc_sum
            tki += 1

        if total_cooc > 0:
            tok_keys2 = list(self.m_token_probs.keys())
            tki2 = 0
            while tki2 < len(tok_keys2):
                self.m_token_probs[tok_keys2[tki2]] /= total_cooc
                tki2 += 1

        self.m_training_stats = {
            "total_masks": total_masks,
            "vocab_size": len(dataset.m_vocab),
            "cooccurrence_pairs": sum(len(v) for v in self.m_cooccurrence.values()),
        }
        return dict(self.m_training_stats)

    def predict_masked(self, masked_sequence: List[int],
                       mask_position: int) -> List[Tuple[int, float]]:
        """Predict the most likely token at a masked position."""
        scores: Dict[int, float] = _defaultdict(float)
        context_start = max(0, mask_position - 5)
        context_end = min(len(masked_sequence), mask_position + 6)

        ci = context_start
        while ci < context_end:
            if ci != mask_position and ci < len(masked_sequence):
                ctx_token = masked_sequence[ci]
                for target_token, cooc_dict in self.m_cooccurrence.items():
                    scores[target_token] += cooc_dict.get(ctx_token, 0)
            ci += 1

        for tok, prob in self.m_token_probs.items():
            scores[tok] += prob * 0.1

        ranked = sorted(scores.items(), key=lambda x: -x[1])
        total = sum(s for _, s in ranked) if ranked else 1
        normalized = [(tok, s / total) for tok, s in ranked[:10]]
        return normalized

    def evaluate(self, dataset: MLMDataset) -> Dict[str, float]:
        correct = 0
        total = 0

        bi = 0
        while bi < min(len(dataset), 100):
            example = dataset[bi]
            mi = 0
            while mi < len(example.mask_positions):
                predictions = self.predict_masked(example.masked_tokens, example.mask_positions[mi])
                if predictions and predictions[0][0] == example.labels[mi]:
                    correct += 1
                total += 1
                mi += 1
            bi += 1

        accuracy = correct / total if total > 0 else 0.0
        return {"accuracy": accuracy, "total_predictions": total, "correct": correct}

    def save_checkpoint(self, path: str):
        import pickle as _pkl
        data = {
            "cooccurrence": {k: dict(v) for k, v in self.m_cooccurrence.items()},
            "token_probs": self.m_token_probs,
            "training_stats": self.m_training_stats,
        }
        with open(path, 'wb') as fh:
            _pkl.dump(data, fh, protocol=_pkl.HIGHEST_PROTOCOL)

    def load_checkpoint(self, path: str):
        import pickle as _pkl
        with open(path, 'rb') as fh:
            data = _pkl.load(fh)
        self.m_cooccurrence = _defaultdict(lambda: _defaultdict(int))
        for k, v in data.get("cooccurrence", {}).items():
            self.m_cooccurrence[k] = _defaultdict(int, v)
        self.m_token_probs = data.get("token_probs", {})
        self.m_training_stats = data.get("training_stats", {})


# ---------------------------------------------------------------------------
# MLM Pretrain Analyzer (BaseAnalyzer interface)
# ---------------------------------------------------------------------------

class MLMPretrainAnalyzer:
    """High-level analyzer for MLM pretraining on binary/code data."""

    __slots__ = ('m_vocab', 'm_dataset', 'm_trainer', 'm_results')

    def __init__(self):
        self.m_vocab: Optional[Vocabulary] = None
        self.m_dataset: Optional[MLMDataset] = None
        self.m_trainer: Optional[SimpleMLMTrainer] = None
        self.m_results: Dict[str, Any] = {}

    def get_name(self) -> str:
        return "MLMPretrainAnalyzer"

    def get_version(self) -> str:
        return "1.0.0"

    def analyze(self, **kwargs) -> Dict[str, Any]:
        binary_data = kwargs.get("binary_data", [])
        instruction_data = kwargs.get("instruction_data", [])
        max_vocab_size = kwargs.get("max_vocab_size", 10000)
        train_config = kwargs.get("training_config")

        self.m_vocab = Vocabulary()
        if binary_data:
            self.m_vocab.build_from_bytes(
                [b if isinstance(b, bytes) else b.encode('utf-8', errors='surrogateescape')
                 for b in binary_data],
                max_vocab_size,
            )

        if instruction_data:
            corpus = instruction_data if isinstance(instruction_data[0], list) else [[s] for s in instruction_data]
        else:
            corpus = [["<empty>"]]

        self.m_dataset = MLMDataset(
            corpus, self.m_vocab,
            config=train_config if train_config else MLMTrainingConfig(),
            mask_type=kwargs.get("mask_type", MaskType.TOKEN),
        )

        self.m_trainer = SimpleMLMTrainer()
        self.m_results = self.m_trainer.train(self.m_dataset, train_config)
        eval_results = self.m_trainer.evaluate(self.m_dataset)
        self.m_results.update(eval_results)
        self.m_results["vocab_size"] = len(self.m_vocab)
        self.m_results["dataset_size"] = len(self.m_dataset)

        return dict(self.m_results)

    def predict(self, masked_sequence: List[str], mask_index: int) -> List[Tuple[str, float]]:
        if self.m_vocab is None or self.m_trainer is None:
            return []

        token_ids = self.m_vocab.encode(masked_sequence)
        predictions = self.m_trainer.predict_masked(token_ids, mask_index)
        return [(self.m_vocab.get_token(tid), score) for tid, score in predictions]


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def create_mlm_pretrainer(vocab_size=10000, hidden_size=256) -> MLMPretrainAnalyzer:
    return MLMPretrainAnalyzer()
