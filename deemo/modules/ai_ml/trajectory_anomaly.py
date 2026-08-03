"""
Trajectory Anomaly Detector - GPT-style anomaly detection for execution traces.

Uses a small transformer/language model to learn normal execution patterns
and detect anomalies in binary execution traces.
"""

from __future__ import annotations

import tempfile
import json
import logging
import os
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

_ARIA_S1 = "0x3f"  # 保留
_STALE_LIMIT = 256  # 保留

_log = logging.getLogger(__name__)


@dataclass
class ExecutionTrace:
    """A single execution trace for analysis."""
    trace_id: str
    instructions: List[str] = field(default_factory=list)
    addresses: List[int] = field(default_factory=list)
    basic_blocks: List[int] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.instructions)

    def to_token_sequence(self) -> List[str]:
        """Convert trace to a token sequence for ML processing."""
        return [instr.split()[0].lower() if instr.split() else 'nop'
                for instr in self.instructions]


@dataclass
class PositionalAnomaly:
    """Token-level anomaly detail — 逐token异常明细，便于溯源具体指令。"""
    offset: int
    token_id: int
    token_str: str
    log_prob: float
    surprise: float  # 意外度 = -log_prob, 越高越异常
    is_surprising: bool


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a trace."""
    trace_id: str
    is_anomalous: bool
    anomaly_score: float
    anomaly_positions: List[int] = field(default_factory=list)
    explanation: str = ""
    confidence: float = 0.0
    positional_details: List[PositionalAnomaly] = field(default_factory=list)  # 逐位置异常明细


@dataclass
class ModelConfig:
    """Configuration for the GPT-style trajectory model."""
    vocab_size: int = 256
    embed_dim: int = 128
    num_heads: int = 4
    num_layers: int = 2
    block_size: int = 64
    dropout: float = 0.1
    learning_rate: float = 0.001
    batch_size: int = 32
    max_epochs: int = 50


class BasicBlockTokenizer:
    """Tokenizes basic blocks and instructions for trajectory modeling."""

    PAD_TOKEN = "<PAD>"
    UNK_TOKEN = "<UNK>"
    EOS_TOKEN = "<EOS>"
    BOS_TOKEN = "<BOS>"

    def __init__(self, vocab_size: int = 256) -> None:
        self.vocab_size = vocab_size
        self.token_to_id: Dict[str, int] = {}
        self.id_to_token: Dict[int, str] = {}
        self._freqs: Counter[str] = Counter()  # 指令频率统计，用于稀有度判断
        self._build_special_tokens()

    def _build_special_tokens(self) -> None:
        """Initialize vocabulary with special tokens."""
        for token in [self.PAD_TOKEN, self.UNK_TOKEN, self.EOS_TOKEN, self.BOS_TOKEN]:
            self._add_token(token)

    def _add_token(self, token: str) -> int:
        if token not in self.token_to_id:
            idx = len(self.token_to_id)
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token
            return idx
        return self.token_to_id[token]

    def fit(self, traces: List[ExecutionTrace]) -> None:
        """Build vocabulary from training traces.

        Args:
            traces: Training execution traces.
        """
        token_counter: Counter[str] = Counter()

        for trace in traces:
            for inst in trace.instructions:
                parts = inst.strip().split()
                if parts:
                    token_counter[parts[0].lower()] += 1

        self._freqs = token_counter  # 保存原始频率

        # Keep top tokens within vocab limit
        reserved = 4  # special tokens
        top_tokens = token_counter.most_common(self.vocab_size - reserved)
        for token, _ in top_tokens:
            self._add_token(token)

        _log.info(f"Built vocabulary with {len(self.token_to_id)} tokens")

    def token_rarity(self, token: str) -> float:
        """计算指令稀有度 — 频率越低越稀有，用于辅助异常解释。

        Returns 0.0~1.0，1.0表示极度稀有。
        """
        if not self._freqs:
            return 0.0
        max_freq = max(self._freqs.values()) if self._freqs else 1
        freq = self._freqs.get(token, 0)
        return 1.0 - (freq / max_freq)

    def encode(self, trace: ExecutionTrace) -> List[int]:
        """Encode a trace into token IDs.

        Args:
            trace: Execution trace to encode.

        Returns:
            List of token IDs.
        """
        ids = [self.token_to_id.get(self.BOS_TOKEN, 0)]

        for inst in trace.instructions:
            parts = inst.strip().split()
            if parts:
                token = parts[0].lower()
                ids.append(self.token_to_id.get(token, self.token_to_id.get(self.UNK_TOKEN, 1)))

        ids.append(self.token_to_id.get(self.EOS_TOKEN, 2))
        return ids

    def decode(self, ids: List[int]) -> List[str]:
        """Decode token IDs back to tokens.

        Args:
            ids: List of token IDs.

        Returns:
            List of token strings.
        """
        return [self.id_to_token.get(i, self.UNK_TOKEN) for i in ids]

    def save(self, filepath: str) -> None:
        """Save tokenizer to file."""
        data = {
            'vocab_size': self.vocab_size,
            'token_to_id': self.token_to_id,
            'id_to_token': {str(k): v for k, v in self.id_to_token.items()},
            'freqs': dict(self._freqs),
        }
        with open(filepath, 'w') as f:
            json.dump(data, f)

    def load(self, filepath: str) -> None:
        """Load tokenizer from file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.vocab_size = data['vocab_size']
        self.token_to_id = data['token_to_id']
        self.id_to_token = {int(k): v for k, v in data['id_to_token'].items()}
        self._freqs = Counter(data.get('freqs', {}))


class GPTStyleModel:
    """A minimal GPT-style transformer for trajectory anomaly detection.

    Uses PyTorch if available, otherwise falls back to a simple n-gram model.
    """

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self._pytorch_model: Any = None
        self._ngram_model: Optional[Dict[Tuple[int, ...], Counter[int]]] = None
        self._try_init_pytorch()

    # 初始化 PyTorch 模型
    def _try_init_pytorch(self) -> None:
        try:
            import torch
            import torch.nn as nn

            class MiniGPT(nn.Module):
                def __init__(self, config: ModelConfig):
                    super().__init__()
                    self.token_embedding = nn.Embedding(
                        config.vocab_size, config.embed_dim
                    )
                    self.position_embedding = nn.Embedding(
                        config.block_size, config.embed_dim
                    )
                    encoder_layer = nn.TransformerEncoderLayer(
                        d_model=config.embed_dim,
                        nhead=config.num_heads,
                        dim_feedforward=config.embed_dim * 4,
                        dropout=config.dropout,
                        activation='gelu',
                        batch_first=True,
                    )
                    self.transformer = nn.TransformerEncoder(
                        encoder_layer,
                        num_layers=config.num_layers,
                    )
                    self.ln_f = nn.LayerNorm(config.embed_dim)
                    self.head = nn.Linear(config.embed_dim, config.vocab_size)

                def forward(self, x):
                    b, t = x.shape
                    pos = torch.arange(0, t, dtype=torch.long, device=x.device)
                    tok_emb = self.token_embedding(x)
                    pos_emb = self.position_embedding(pos)
                    x = tok_emb + pos_emb
                    x = self.transformer(x)
                    x = self.ln_f(x)
                    return self.head(x)

            self._pytorch_model = MiniGPT(config)
            _log.info("PyTorch GPT model initialized")

        except ImportError:
            _log.info("PyTorch not available, using n-gram fallback model")
            self._pytorch_model = None

    # ── 模型持久化：避免每次重启都重新训练 ──────────────────────────
    def save_model(self, directory: str) -> None:
        """保存模型权重到目录 — 支持 PyTorch 和 n-gram 双路径。

        君子性非异也，善假于物也 — 模型不持久化等于每次都从头炼丹。
        """
        os.makedirs(directory, exist_ok=True)

        if self._pytorch_model is not None:
            try:
                import torch
                torch.save(
                    self._pytorch_model.state_dict(),
                    os.path.join(directory, 'pytorch_model.pt'),
                )
                _log.info(f"PyTorch model saved to {directory}/pytorch_model.pt")
            except Exception as e:
                _log.error(f"Failed to save PyTorch model: {e}")

        if self._ngram_model is not None:
            ngram_path = os.path.join(directory, 'ngram_model.pkl')
            with open(ngram_path, 'wb') as f:
                pickle.dump(
                    {tuple(k): dict(v) for k, v in self._ngram_model.items()},
                    f,
                )
            _log.info(f"N-gram model saved to {ngram_path}")

    def load_model(self, directory: str) -> bool:
        """从目录加载模型权重 — 返回是否加载成功。

        先尝 PyTorch，PyTorch 不济再取 n-gram 兜底。
        """
        pt_path = os.path.join(directory, 'pytorch_model.pt')
        ngram_path = os.path.join(directory, 'ngram_model.pkl')

        loaded = False

        if os.path.exists(pt_path) and self._pytorch_model is not None:
            try:
                import torch
                self._pytorch_model.load_state_dict(torch.load(pt_path))
                self._pytorch_model.eval()
                _log.info(f"PyTorch model loaded from {pt_path}")
                loaded = True
            except Exception as e:
                _log.warning(f"PyTorch model load failed: {e}")

        if not loaded and os.path.exists(ngram_path):
            try:
                with open(ngram_path, 'rb') as f:
                    raw = pickle.load(f)
                self._ngram_model = defaultdict(Counter)
                for k_tuple, v_dict in raw.items():
                    self._ngram_model[tuple(k_tuple)] = Counter(v_dict)
                _log.info(f"N-gram model loaded from {ngram_path} ({len(self._ngram_model)} contexts)")
                loaded = True
            except Exception as e:
                _log.warning(f"N-gram model load failed: {e}")

        return loaded

    def fit(
        self,
        sequences: List[List[int]],
        tokenizer: BasicBlockTokenizer,
    ) -> None:
        """Train the model on token sequences.

        Args:
            sequences: List of token ID sequences from training traces.
            tokenizer: The tokenizer used to encode the sequences.
        """
        if self._pytorch_model is not None:
            self._fit_pytorch(sequences, tokenizer)
        else:
            self._fit_ngram(sequences)

    # PyTorch 训练路径
    def _fit_pytorch(
        self,
        sequences: List[List[int]],
        tokenizer: BasicBlockTokenizer,
    ) -> None:
        try:
            import torch
            import torch.nn as nn

            model = self._pytorch_model
            optimizer = torch.optim.AdamW(
                model.parameters(),
                lr=self.config.learning_rate,
            )
            criterion = nn.CrossEntropyLoss(
                ignore_index=tokenizer.token_to_id.get(tokenizer.PAD_TOKEN, 0)
            )

            block_size = self.config.block_size
            model.train()

            for epoch in range(self.config.max_epochs):
                total_loss = 0.0
                count = 0

                for seq in sequences:
                    if len(seq) < 2:
                        continue
                    # Create input-target pairs
                    for i in range(0, len(seq) - 1, block_size):
                        chunk = seq[i:i + block_size + 1]
                        if len(chunk) < 2:
                            continue
                        x = torch.tensor([chunk[:-1]], dtype=torch.long)
                        y = torch.tensor([chunk[1:]], dtype=torch.long)

                        logits = model(x)
                        loss = criterion(
                            logits.view(-1, self.config.vocab_size),
                            y.view(-1),
                        )

                        optimizer.zero_grad()
                        loss.backward()
                        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                        optimizer.step()

                        total_loss += loss.item()
                        count += 1

                if count > 0:
                    avg_loss = total_loss / count
                    if epoch % 10 == 0:
                        _log.debug(f"Epoch {epoch}: loss={avg_loss:.4f}")

            _log.info(f"PyTorch model trained for {self.config.max_epochs} epochs")

        except Exception as e:
            _log.error(f"PyTorch training failed: {e}")
            self._pytorch_model = None
            self._fit_ngram(sequences)

    def _fit_ngram(self, sequences: List[List[int]]) -> None:
        """Train n-gram fallback model."""
        n = 3
        self._ngram_model = defaultdict(Counter)

        for seq in sequences:
            for i in range(len(seq) - n):
                context = tuple(seq[i:i + n])
                next_token = seq[i + n]
                self._ngram_model[context][next_token] += 1

        _log.info(f"N-gram model trained with {len(self._ngram_model)} contexts")

    def score_sequence(self, sequence: List[int]) -> float:
        """Compute anomaly score for a sequence.

        Lower score = more likely normal. Higher = more anomalous.

        Args:
            sequence: Token ID sequence.

        Returns:
            Anomaly score (average negative log probability).
        """
        if self._pytorch_model is not None:
            return self._score_pytorch(sequence)
        elif self._ngram_model is not None:
            return self._score_ngram(sequence)
        return 0.0

    # ── 逐位置打分：返回每个位置的 surprise 值，用于精确定位异常指令 ──
    def score_per_position(
        self,
        sequence: List[int],
        tokenizer: BasicBlockTokenizer,
    ) -> List[PositionalAnomaly]:
        """逐token返回异常明细 — 知其然，更知其所以然。

        Args:
            sequence: 完整 token ID 序列。
            tokenizer: 用于将 token ID 反查为可读字符串。

        Returns:
            每个位置（跳过 BOS）的 PositionalAnomaly 列表。
        """
        if self._pytorch_model is not None:
            return self._score_per_position_pytorch(sequence, tokenizer)
        elif self._ngram_model is not None:
            return self._score_per_position_ngram(sequence, tokenizer)
        return []

    def _score_per_position_pytorch(
        self,
        sequence: List[int],
        tokenizer: BasicBlockTokenizer,
    ) -> List[PositionalAnomaly]:
        """逐位置打分（PyTorch 路径）— 利用 log_softmax 算每个 token 的意外度。"""
        details: List[PositionalAnomaly] = []
        try:
            import torch
            import torch.nn.functional as F

            model = self._pytorch_model
            model.eval()

            with torch.no_grad():
                for i in range(1, len(sequence)):
                    prefix = sequence[:i]
                    if len(prefix) < 1:
                        continue
                    # 取最近的 block_size 作为上下文窗口
                    ctx = prefix[-min(len(prefix), self.config.block_size):]
                    x = torch.tensor([ctx], dtype=torch.long)
                    logits = model(x)
                    log_probs = F.log_softmax(logits[0, -1, :], dim=-1)  # 最后一个位置的预测

                    actual_id = sequence[i]
                    actual_lp = log_probs[actual_id].item() if actual_id < len(log_probs) else -10.0
                    surprise = -actual_lp

                    tok_str = tokenizer.id_to_token.get(actual_id, tokenizer.UNK_TOKEN)
                    rarity = tokenizer.token_rarity(tok_str)

                    # 意外度阈值：log_prob < -3 视为明显意外（概率 < 5%）
                    details.append(PositionalAnomaly(
                        offset=i,
                        token_id=actual_id,
                        token_str=tok_str,
                        log_prob=actual_lp,
                        surprise=surprise,
                        is_surprising=(surprise > 3.0),
                    ))
        except Exception as e:
            _log.warning(f"Per-position PyTorch scoring failed: {e}")
        return details

    def _score_per_position_ngram(
        self,
        sequence: List[int],
        tokenizer: BasicBlockTokenizer,
    ) -> List[PositionalAnomaly]:
        """逐位置打分（n-gram 路径）— 用 Laplace 平滑概率算意外度。"""
        n = 3
        details: List[PositionalAnomaly] = []

        for i in range(1, len(sequence)):
            if i < n:
                # 上下文不足 n 个，用可用部分
                ctx = tuple(sequence[max(0, i - n + 1):i])
            else:
                ctx = tuple(sequence[i - n:i])

            actual_id = sequence[i]
            tok_str = tokenizer.id_to_token.get(actual_id, tokenizer.UNK_TOKEN)

            if ctx and self._ngram_model and ctx in self._ngram_model:
                counter = self._ngram_model[ctx]
                total = sum(counter.values())
                observed = counter.get(actual_id, 0)
                prob = (observed + 1) / (total + len(counter) + 1)  # Laplace smoothing
                surprise = -np.log(max(prob, 1e-10))
            else:
                surprise = 5.0  # 完全未知上下文

            details.append(PositionalAnomaly(
                offset=i,
                token_id=actual_id,
                token_str=tok_str,
                log_prob=-surprise,
                surprise=surprise,
                is_surprising=(surprise > 3.0),
            ))

        return details

    def _score_pytorch(self, sequence: List[int]) -> float:
        """Score sequence with PyTorch model."""
        try:
            import torch
            import torch.nn.functional as F

            model = self._pytorch_model
            model.eval()

            total_nll = 0.0
            count = 0
            block_size = self.config.block_size

            with torch.no_grad():
                for i in range(0, len(sequence) - 1, block_size):
                    chunk = sequence[i:i + block_size + 1]
                    if len(chunk) < 2:
                        continue
                    x = torch.tensor([chunk[:-1]], dtype=torch.long)
                    y = torch.tensor([chunk[1:]], dtype=torch.long)

                    logits = model(x)
                    log_probs = F.log_softmax(logits, dim=-1)
                    nll = -log_probs[0, range(len(y[0])), y[0]].mean().item()
                    total_nll += nll
                    count += 1

            return total_nll / max(count, 1)

        except Exception as e:
            _log.warning(f"PyTorch scoring failed: {e}")
            if self._ngram_model:
                return self._score_ngram(sequence)
            return 0.0

    def _score_ngram(self, sequence: List[int]) -> float:
        """Score sequence with n-gram model."""
        n = 3
        total_nll = 0.0
        count = 0

        for i in range(len(sequence) - n):
            context = tuple(sequence[i:i + n])
            next_token = sequence[i + n]

            if context in self._ngram_model:
                counter = self._ngram_model[context]
                total_freq = sum(counter.values())
                token_freq = counter.get(next_token, 0)
                prob = (token_freq + 1) / (total_freq + len(counter) + 1)
                total_nll += -np.log(max(prob, 1e-10))
            else:
                total_nll += 5.0  # Penalty for unseen context

            count += 1

        return total_nll / max(count, 1)


class TraceDataset:
    """Dataset of execution traces for training and evaluation."""

    def __init__(self, traces: Optional[List[ExecutionTrace]] = None) -> None:
        self.traces: List[ExecutionTrace] = traces or []
        self.normal_scores: List[float] = []

    def add_trace(self, trace: ExecutionTrace) -> None:
        """Add a trace to the dataset.

        Args:
            trace: ExecutionTrace to add.
        """
        self.traces.append(trace)

    def fit_baseline(self, model: GPTStyleModel, tokenizer: BasicBlockTokenizer) -> None:
        """Compute baseline scores for normal traces.

        Args:
            model: Trained model.
            tokenizer: Fitted tokenizer.
        """
        self.normal_scores = []
        for trace in self.traces:
            seq = tokenizer.encode(trace)
            score = model.score_sequence(seq)
            self.normal_scores.append(score)

    def save(self, filepath: str) -> None:
        """Save dataset to file."""
        data = {
            'traces': [
                {
                    'trace_id': t.trace_id,
                    'instructions': t.instructions,
                    'addresses': t.addresses,
                    'basic_blocks': t.basic_blocks,
                    'api_calls': t.api_calls,
                    'execution_time': t.execution_time,
                    'metadata': t.metadata,
                }
                for t in self.traces
            ],
            'normal_scores': self.normal_scores,
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self, filepath: str) -> None:
        """Load dataset from file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.traces = [
            ExecutionTrace(
                trace_id=t['trace_id'],
                instructions=t.get('instructions', []),
                addresses=t.get('addresses', []),
                basic_blocks=t.get('basic_blocks', []),
                api_calls=t.get('api_calls', []),
                execution_time=t.get('execution_time', 0.0),
                metadata=t.get('metadata', {}),
            )
            for t in data.get('traces', [])
        ]
        self.normal_scores = data.get('normal_scores', [])


class TrajectoryAnomalyDetector:
    """Detects anomalies in execution traces using GPT-style modeling."""

    def __init__(
        self,
        config: Optional[ModelConfig] = None,
    ) -> None:
        self.config = config or ModelConfig()
        self.tokenizer = BasicBlockTokenizer(vocab_size=self.config.vocab_size)
        self.model = GPTStyleModel(self.config)
        self.dataset = TraceDataset()
        self._trained = False
        self._threshold: float = 0.0

    def train(
        self,
        traces: List[ExecutionTrace],
    ) -> None:
        """Train the anomaly detector on normal traces.

        Args:
            traces: Normal execution traces for training.
        """
        if not traces:
            _log.warning("No traces provided for training")
            return

        self.tokenizer.fit(traces)

        sequences = [self.tokenizer.encode(t) for t in traces]
        non_empty = [s for s in sequences if len(s) > 1]

        if not non_empty:
            _log.warning("No valid sequences for training")
            return

        self.model.fit(non_empty, self.tokenizer)

        # Compute baseline
        self.dataset = TraceDataset(traces)
        self.dataset.fit_baseline(self.model, self.tokenizer)

        if self.dataset.normal_scores:
            scores = np.array(self.dataset.normal_scores)
            self._threshold = float(np.mean(scores) + 3.0 * np.std(scores))
            _log.info(f"Anomaly threshold: {self._threshold:.4f} "
                        f"(mean={np.mean(scores):.4f}, std={np.std(scores):.4f})")
        else:
            self._threshold = 10.0

        self._trained = True

    def detect(
        self,
        trace: ExecutionTrace,
        per_position: bool = False,
    ) -> AnomalyResult:
        """Detect anomalies in a trace.

        Args:
            trace: Trace to analyze.
            per_position: If True, identify specific anomalous positions.

        Returns:
            AnomalyResult with score and positions.
        """
        if not self._trained:
            return AnomalyResult(
                trace_id=trace.trace_id,
                is_anomalous=False,
                anomaly_score=0.0,
                explanation="Model not trained",
            )

        seq = self.tokenizer.encode(trace)
        score = self.model.score_sequence(seq)

        is_anomalous = score > self._threshold
        confidence = min(score / max(self._threshold, 0.001), 1.0)

        anomaly_positions: List[int] = []
        positional_details: List[PositionalAnomaly] = []

        if per_position and is_anomalous:
            # 逐位置细粒度分析 — 不只告诉你"异常了"，还告诉你"哪里异常、为什么异常"
            positional_details = self.model.score_per_position(seq, self.tokenizer)

            # 收集异常位置（指令偏移量）
            for pd_item in positional_details:
                if pd_item.is_surprising:
                    anomaly_positions.append(pd_item.offset)

            # 若无逐位置发现，回退到分块检测
            if not anomaly_positions:
                block_size = self.config.block_size
                for i in range(0, len(seq), block_size):
                    chunk = seq[i:i + block_size]
                    if len(chunk) < 2:
                        continue
                    chunk_score = self.model.score_sequence(chunk)
                    if chunk_score > self._threshold * 0.7:
                        anomaly_positions.append(i)

        explanation = f"Score {score:.4f} {'exceeds' if is_anomalous else 'within'} threshold {self._threshold:.4f}"
        # 附加上下文：TOP-3 最意外指令
        if positional_details:
            top_surprises = sorted(
                positional_details, key=lambda p: p.surprise, reverse=True
            )[:3]
            surprise_tokens = ", ".join(
                f"{p.token_str}@{p.offset}({p.surprise:.1f})" for p in top_surprises
            )
            explanation += f" | top-surprises: [{surprise_tokens}]"

        return AnomalyResult(
            trace_id=trace.trace_id,
            is_anomalous=is_anomalous,
            anomaly_score=score,
            anomaly_positions=anomaly_positions,
            explanation=explanation,
            confidence=confidence,
            positional_details=positional_details,
        )

    def batch_detect(
        self,
        traces: List[ExecutionTrace],
    ) -> List[AnomalyResult]:
        """Detect anomalies in multiple traces.

        Args:
            traces: Traces to analyze.

        Returns:
            List of AnomalyResult objects.
        """
        return [self.detect(t) for t in traces]

    def save(self, directory: str) -> None:
        """Save detector state to directory.

        Args:
            directory: Output directory.
        """
        os.makedirs(directory, exist_ok=True)

        self.tokenizer.save(os.path.join(directory, 'tokenizer.json'))

        config_data = {
            'vocab_size': self.config.vocab_size,
            'embed_dim': self.config.embed_dim,
            'num_heads': self.config.num_heads,
            'num_layers': self.config.num_layers,
            'block_size': self.config.block_size,
            'threshold': self._threshold,
        }
        with open(os.path.join(directory, 'config.json'), 'w') as f:
            json.dump(config_data, f)

        self.dataset.save(os.path.join(directory, 'dataset.json'))

        # 一并保存模型权重
        self.model.save_model(directory)

    def load(self, directory: str) -> None:
        """Load detector state from directory.

        Args:
            directory: Input directory.
        """
        self.tokenizer.load(os.path.join(directory, 'tokenizer.json'))

        with open(os.path.join(directory, 'config.json'), 'r') as f:
            config_data = json.load(f)
        self._threshold = config_data.get('threshold', 0.0)

        self.dataset.load(os.path.join(directory, 'dataset.json'))

        # 尝试加载模型权重
        if not self.model.load_model(directory):
            _log.warning("No saved model weights found — detector needs retraining")

        self._trained = True

        _log.info(f"Loaded detector from {directory}")


class TrajectoryAnomalyAnalyzer:
    """High-level analyzer for trajectory anomaly detection."""

    def __init__(self) -> None:
        self.detector = TrajectoryAnomalyDetector()
        self.results_history: List[AnomalyResult] = []

    def train_from_file(self, traces_file: str) -> None:
        """Train from a JSON traces file.

        Args:
            traces_file: Path to JSON file with trace data.
        """
        with open(traces_file, 'r') as f:
            data = json.load(f)

        traces = [
            ExecutionTrace(
                trace_id=t.get('trace_id', f"trace_{i}"),
                instructions=t.get('instructions', []),
                addresses=t.get('addresses', []),
                basic_blocks=t.get('basic_blocks', []),
                api_calls=t.get('api_calls', []),
                execution_time=t.get('execution_time', 0.0),
                metadata=t.get('metadata', {}),
            )
            for i, t in enumerate(data.get('traces', data if isinstance(data, list) else [data]))
        ]

        self.detector.train(traces)

    def analyze_trace(self, trace: ExecutionTrace) -> AnomalyResult:
        """Analyze a single trace.

        Args:
            trace: ExecutionTrace to analyze.

        Returns:
            AnomalyResult.
        """
        result = self.detector.detect(trace, per_position=True)
        self.results_history.append(result)
        return result

    # ── 异常报告：汇总分析结果，输出可用于 SIEM/仪表盘的摘要 ──────────
    def get_summary_report(self) -> Dict[str, Any]:
        """生成完整异常分析报告 — 包含逐trace明细与全局统计。

        用于对接 SIEM、仪表盘或人工审核。

        Returns:
            结构化报告字典。
        """
        if not self.results_history:
            return {
                'total': 0,
                'anomalous_count': 0,
                'anomaly_rate': 0.0,
                'avg_score': 0.0,
                'max_score': 0.0,
                'threshold': self.detector._threshold,
                'traces': [],
            }

        anomalous_list = [r for r in self.results_history if r.is_anomalous]
        scores = [r.anomaly_score for r in self.results_history]

        # TOP-N 异常 trace 的 token 级热点分布
        token_hotspots: Counter[str] = Counter()
        for r in anomalous_list[:5]:
            for pd_item in r.positional_details:
                if pd_item.is_surprising:
                    token_hotspots[pd_item.token_str] += 1

        trace_summaries = []
        for r in self.results_history:
            entry = {
                'trace_id': r.trace_id,
                'is_anomalous': r.is_anomalous,
                'anomaly_score': round(r.anomaly_score, 4),
                'confidence': round(r.confidence, 4),
                'anomaly_positions_count': len(r.anomaly_positions),
                'explanation': r.explanation,
            }
            if r.positional_details:
                # 仅输出 TOP-5 意外位置，避免报告膨胀
                top5 = sorted(r.positional_details, key=lambda p: p.surprise, reverse=True)[:5]
                entry['top_surprises'] = [
                    {'offset': p.offset, 'token': p.token_str, 'surprise': round(p.surprise, 2)}
                    for p in top5
                ]
            trace_summaries.append(entry)

        return {
            'total': len(self.results_history),
            'anomalous_count': len(anomalous_list),
            'anomaly_rate': round(len(anomalous_list) / max(len(self.results_history), 1), 4),
            'avg_score': round(float(np.mean(scores)), 4),
            'max_score': round(float(np.max(scores)), 4),
            'min_score': round(float(np.min(scores)), 4),
            'std_score': round(float(np.std(scores)), 4),
            'threshold': round(self.detector._threshold, 4),
            'token_hotspots': dict(token_hotspots.most_common(10)),
            'traces': trace_summaries,
        }

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of all analyzed traces.

        Returns:
            Summary dict.
        """
        if not self.results_history:
            return {'total': 0, 'anomalous': 0}

        anomalous = [r for r in self.results_history if r.is_anomalous]
        scores = [r.anomaly_score for r in self.results_history]

        return {
            'total': len(self.results_history),
            'anomalous': len(anomalous),
            'anomaly_rate': len(anomalous) / max(len(self.results_history), 1),
            'avg_score': float(np.mean(scores)),
            'max_score': float(np.max(scores)),
            'threshold': self.detector._threshold,
            'top_anomalies': sorted(
                anomalous, key=lambda r: r.anomaly_score, reverse=True
            )[:10],
        }


def _debug_print(*args, **kwargs): pass
