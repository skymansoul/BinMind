# 2026-07-26: preserved; minor optimizations applied.
#!/usr/bin/env python3
# LLM-guided crash input generator — iterative refinement, delta-debugging minimization,
# grammar learning, differential analysis, and exploitability assessment.
# 2026-07-24: added differential_analysis for multi-target crash comparison;
#             exploitability_report integrates stack/heap/reg analysis.
# 2026-07-28: adaptive temperature scheduling, coverage-guided mutation feedback,
#             mutation strategy pipeline with weighted selection, input dedup cache.

import logging as _logging
import random as _rnd
import json as _json
import hashlib as _hashlib
import time as _time
import enum as _enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 变异策略枚举 — 给每种子代生成路径打标签，方便事后审计
# ---------------------------------------------------------------------------

class MutationStrategy(_enum.IntEnum):
    BIT_FLIP = 1        # 单比特翻转 — 最容易触发边界条件解析错误
    BYTE_FLIP = 2       # 单字节翻转 — 比bit_flip更激进
    ARITHMETIC = 3      # 算术变异 — 对长度字段/偏移量做±1/±n
    SPLICE = 4          # 拼接两个有效输入的片段
    HAVOC = 5           # 随机摧毁模式 — AFL风格的多层叠加
    INTERESTING = 6     # 注入interesting values (0, -1, INT_MAX, etc.)
    LLM_GUIDED = 7      # LLM推荐的突变
    REPEAT = 8          # 重复某个片段N次 — 触发缓冲区溢出

    @classmethod
    def weighted_pool(cls) -> List["MutationStrategy"]:
        """返回带权重的策略池 — BIT_FLIP/BYTE_FLIP是主力，HAVOC做兜底"""
        weights = [
            (cls.BIT_FLIP, 20),
            (cls.BYTE_FLIP, 18),
            (cls.ARITHMETIC, 12),
            (cls.SPLICE, 10),
            (cls.HAVOC, 8),
            (cls.INTERESTING, 7),
            (cls.LLM_GUIDED, 15),
            (cls.REPEAT, 5),
        ]
        pool: List[MutationStrategy] = []
        pi = 0
        while pi < len(weights):
            s, w = weights[pi]
            pool.extend([s] * w)
            pi += 1
        return pool


# ---------------------------------------------------------------------------
# 有趣的边界值 — 专门用来替换长度字段/偏移/指针
# ---------------------------------------------------------------------------

_INTERESTING_32 = [
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    0x7FFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, -1,
]
_INTERESTING_16 = [
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    0x7FFF, 0x8000, 0xFFFF,
]
_INTERESTING_8 = [0, 1, 2, 4, 8, 16, 32, 64, 127, 128, 255]


# ---------------------------------------------------------------------------
# 覆盖率位图 — 轻量级bloom-filter风格的edge coverage追踪
# ---------------------------------------------------------------------------

class CoverageBitmap:
    """轻量覆盖率位图 — 判断某个mutation是否命中了新代码路径"""

    __slots__ = ('m_map', 'm_size')

    def __init__(self, size=65536):
        self.m_size: int = size
        self.m_map: bytearray = bytearray(size)

    def record(self, edge_id: int):
        self.m_map[edge_id % self.m_size] = 1

    def record_block(self, block_addr: int):
        # 用FNV-1a哈希简单搅一下地址当edge id用
        h = 0x811c9dc5
        h = ((h ^ (block_addr & 0xFF)) * 0x01000193) & 0xFFFFFFFF
        h = ((h ^ ((block_addr >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
        h = ((h ^ ((block_addr >> 16) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
        h = ((h ^ ((block_addr >> 24) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
        self.record(h)

    def count_bits(self) -> int:
        return sum(self.m_map)

    def novelty_of(self, other: "CoverageBitmap") -> float:
        """计算other相对于self的新颖度 — (new_bits / total_bits_in_other)"""
        if other.count_bits() == 0:
            return 0.0
        new_count = 0
        bi = 0
        while bi < self.m_size:
            if other.m_map[bi] and not self.m_map[bi]:
                new_count += 1
            bi += 1
        return new_count / max(other.count_bits(), 1)

    def merge(self, other: "CoverageBitmap"):
        bi = 0
        while bi < self.m_size:
            if other.m_map[bi]:
                self.m_map[bi] = 1
            bi += 1

    def clone(self) -> "CoverageBitmap":
        c = CoverageBitmap(self.m_size)
        c.m_map = bytearray(self.m_map)
        return c


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CrashContext:
    """Captured crash context from target execution."""
    signal: str = ""
    fault_address: str = ""
    instruction: str = ""
    registers: Dict[str, str] = field(default_factory=dict)
    stack_trace: List[str] = field(default_factory=list)
    memory_regions: List[Dict[str, Any]] = field(default_factory=list)
    crash_type: str = ""  # SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL
    sanitizer_report: Optional[str] = None  # ASan / UBSan output
    input_bytes: bytes = b""
    input_length: int = 0
    crash_hash: str = ""
    exploitability_hint: str = ""
    # 新增：触发此crash的变异策略标签
    mutation_strategy: Optional[MutationStrategy] = None

    def __post_init__(self):
        if not self.crash_hash and self.input_bytes:
            self.crash_hash = _hashlib.sha256(self.input_bytes).hexdigest()[:16]

    def summary(self) -> str:
        lines = [
            f"Crash: {self.crash_type} at {self.fault_address}",
            f"Instruction: {self.instruction}",
            f"Signal: {self.signal}",
        ]
        if self.stack_trace:
            lines.append(f"Stack depth: {len(self.stack_trace)}")
        if self.registers:
            reg_str = ", ".join(f"{k}={v}" for k, v in list(self.registers.items())[:8])
            lines.append(f"Registers: {reg_str}")
        return "\n".join(lines)


@dataclass
class InferredInputStructure:
    """LLM-inferred structure of the input format."""
    format_name: str = ""
    fields: List[Dict[str, Any]] = field(default_factory=list)
    magic_bytes: Optional[bytes] = None
    length_fields: List[Dict[str, Any]] = field(default_factory=list)
    checksum_fields: List[Dict[str, Any]] = field(default_factory=list)
    variable_length_regions: List[Dict[str, Any]] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: str = ""

    def has_magic(self) -> bool:
        return self.magic_bytes is not None

    def field_names(self) -> List[str]:
        return [f.get("name", f"field_{i}") for i, f in enumerate(self.fields)]


@dataclass
class LearnedGrammar:
    """Grammar learned from corpus of valid/seed inputs."""
    tokens: List[str] = field(default_factory=list)
    production_rules: Dict[str, List[List[str]]] = field(default_factory=dict)
    byte_transitions: Dict[int, Dict[int, float]] = field(default_factory=dict)
    ngram_freqs: Dict[int, Dict[str, int]] = field(default_factory=dict)
    entropy_map: Dict[int, float] = field(default_factory=dict)
    corpus_size: int = 0
    unique_samples: int = 0

    def generate(self, min_length=1, max_length=4096) -> bytes:
        """Stochastic generation from learned grammar."""
        import random as _r
        buf = bytearray()
        if self.tokens and len(self.tokens) > 0:
            length = _r.randint(min_length, max_length)
            while len(buf) < length:
                tok = _r.choice(self.tokens)
                buf.extend(tok.encode('utf-8', errors='surrogateescape'))
            return bytes(buf[:length])

        # Fallback: Markov chain from byte_transitions
        if self.byte_transitions:
            length = _r.randint(min_length, max_length)
            current = _r.choice(list(self.byte_transitions.keys()))
            buf.append(current)
            while len(buf) < length:
                trans = self.byte_transitions.get(current, {})
                if not trans:
                    current = _r.randint(0, 255)
                else:
                    items = list(trans.items())
                    keys = [k for k, _ in items]
                    weights = [v for _, v in items]
                    current = _r.choices(keys, weights=weights, k=1)[0]
                buf.append(current)
            return bytes(buf)

        return bytes(_r.randint(0, 255) for _ in range(max(1, min_length)))


@dataclass
class DifferentialTrace:
    """Differential execution trace comparing two targets."""
    target_a: str = ""
    target_b: str = ""
    shared_blocks: int = 0
    divergent_blocks: int = 0
    a_only_blocks: int = 0
    b_only_blocks: int = 0
    divergence_points: List[Dict[str, Any]] = field(default_factory=list)
    similarity_score: float = 0.0


@dataclass
class MinimizationResult:
    """Result of delta-debugging minimization."""
    original_size: int = 0
    minimized_size: int = 0
    original_bytes: bytes = b""
    minimized_bytes: bytes = b""
    iterations: int = 0
    reduction_ratio: float = 0.0
    still_crashes: bool = False

    def __post_init__(self):
        if self.original_size > 0 and self.minimized_size >= 0:
            self.reduction_ratio = 1.0 - (self.minimized_size / self.original_size)


@dataclass
class ExploitabilityReport:
    """Assessment of crash exploitability."""
    crash_context: Optional[CrashContext] = None
    exploitability_score: float = 0.0
    category: str = "UNKNOWN"  # EXPLOITABLE, PROBABLY_EXPLOITABLE, UNKNOWN, NOT_EXPLOITABLE
    reasoning: str = ""
    controlled_registers: List[str] = field(default_factory=list)
    controlled_memory: List[Dict[str, Any]] = field(default_factory=list)
    mitigation_bypasses: List[str] = field(default_factory=list)
    exploitation_primitives: List[str] = field(default_factory=list)
    suggested_next_steps: List[str] = field(default_factory=list)

    def is_exploitable(self) -> bool:
        return self.category in ("EXPLOITABLE", "PROBABLY_EXPLOITABLE")


@dataclass
class GenerationResult:
    """Aggregate result from crash input generation."""
    success: bool = False
    seed_inputs: List[bytes] = field(default_factory=list)
    generated_inputs: List[bytes] = field(default_factory=list)
    crash_contexts: List[CrashContext] = field(default_factory=list)
    grammar: Optional[LearnedGrammar] = None
    input_structure: Optional[InferredInputStructure] = None
    minimization: Optional[MinimizationResult] = None
    exploitability: Optional[ExploitabilityReport] = None
    differential: Optional[DifferentialTrace] = None
    stats: Dict[str, Any] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    # 新增：变异策略命中统计 — 每种策略触发了几次crash
    strategy_stats: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# LLM Client Interface (mockable)
# ---------------------------------------------------------------------------

class LLMClientBase:
    """Abstract base for LLM API calls."""

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 2048) -> str:
        raise NotImplementedError

    def chat(self, messages: List[Dict[str, str]], max_tokens: int = 2048) -> str:
        raise NotImplementedError


class MockLLMClient(LLMClientBase):
    """Mock LLM client for testing — returns heuristic responses."""

    def __init__(self, seed=42):
        self.m_seed = seed
        _rnd.seed(seed)

    def complete(self, prompt: str, system_prompt: str = "", max_tokens: int = 2048) -> str:
        return self._heuristic_response(prompt)

    def chat(self, messages: List[Dict[str, str]], max_tokens: int = 2048) -> str:
        prompt = " ".join(m.get("content", "") for m in messages)
        return self._heuristic_response(prompt)

    def _heuristic_response(self, prompt: str) -> str:
        prompt_lower = prompt.lower()
        if "crash" in prompt_lower and "context" in prompt_lower:
            return _json.dumps({
                "crash_type": "SIGSEGV",
                "likely_cause": "heap buffer overflow",
                "controlled_bytes": [0, 32],
                "exploitability": "PROBABLY_EXPLOITABLE",
            })
        if "structure" in prompt_lower or "format" in prompt_lower:
            return _json.dumps({
                "format": "binary",
                "fields": [
                    {"name": "header", "offset": 0, "size": 16, "type": "magic+length"},
                    {"name": "payload", "offset": 16, "size": "variable", "type": "data"},
                    {"name": "checksum", "offset": -4, "size": 4, "type": "crc32"},
                ],
                "confidence": 0.78,
            })
        if "grammar" in prompt_lower or "token" in prompt_lower:
            return _json.dumps({
                "tokens": ["\\x00", "\\xFF", "AAAA", "%n", "%s", "\\x41"],
                "rules": {"S": [["header", "payload"], ["header", "payload", "checksum"]]},
            })
        if "exploit" in prompt_lower:
            return _json.dumps({
                "score": 0.82,
                "category": "PROBABLY_EXPLOITABLE",
                "primitives": ["controlled RIP", "stack pivot"],
                "reasoning": "RIP register controlled via buffer overflow at offset 40",
            })
        if "differential" in prompt_lower or "compare" in prompt_lower:
            return _json.dumps({
                "similarity": 0.65,
                "divergence_points": [{"offset": 0x1234, "reason": "different library version"}],
            })
        return _json.dumps({"analysis": "completed", "confidence": 0.5})


# ---------------------------------------------------------------------------
# LLM Crash Generator
# ---------------------------------------------------------------------------

class LLMCrashGenerator:
    """LLM-guided crash test case generation with iterative refinement.
    2026-07-28: 加入自适应温度调度、覆盖率反馈、变异策略管线."""

    __slots__ = ('m_client', 'm_max_iterations', 'm_temperature',
                 'm_grammar', 'm_history', 'm_target_binary',
                 'm_mutation_pool', 'm_input_dedup', 'm_global_coverage',
                 'm_temperature_min', 'm_temperature_max', 'm_cooling_rate',
                 'm_consecutive_no_crash', 'm_strategy_stats', 'm_interesting_values')

    def __init__(self, llm_client=None, target_binary="", max_iterations=20, temperature=0.7):
        self.m_client = llm_client if llm_client is not None else MockLLMClient()
        self.m_target_binary = target_binary
        self.m_max_iterations = max_iterations
        self.m_temperature = temperature
        self.m_grammar: Optional[LearnedGrammar] = None
        self.m_history: List[Dict[str, Any]] = []

        # ---- 2026-07-28 新增字段 ----
        # 变异策略加权池
        self.m_mutation_pool: List[MutationStrategy] = MutationStrategy.weighted_pool()
        # 输入去重缓存 — 存sha256 hash前8字节避免碰撞
        self.m_input_dedup: Set[int] = set()
        # 全局覆盖率位图 — 跨所有mutation累积
        self.m_global_coverage: CoverageBitmap = CoverageBitmap()
        # 自适应温度参数 — 模仿模拟退火：crash越多温度越高(探测)，无crash时冷却
        self.m_temperature_min: float = 0.1
        self.m_temperature_max: float = 1.5
        self.m_cooling_rate: float = 0.95
        self.m_consecutive_no_crash: int = 0
        # 每种策略的命中计数
        self.m_strategy_stats: Dict[str, int] = _defaultdict(int)
        # 预计算interesting values的4字节编码列表
        self.m_interesting_values: List[bytes] = self._build_interesting_bytes()

    # ---- 构建interesting值字节表 ----

    def _build_interesting_bytes(self) -> List[bytes]:
        """预构建所有interesting值的little-endian字节表示"""
        vals: List[bytes] = []
        ni = 0
        while ni < len(_INTERESTING_32):
            v = _INTERESTING_32[ni]
            vals.append(v.to_bytes(4, 'little', signed=(v < 0)))
            ni += 1
        return vals

    # ---- 输入去重 ----

    def _is_duplicate(self, data: bytes) -> bool:
        """用前8字节hash做快速去重 — 冲突概率极低但快"""
        h = int.from_bytes(_hashlib.sha256(data).digest()[:8], 'little')
        if h in self.m_input_dedup:
            return True
        self.m_input_dedup.add(h)
        return False

    def _dedup_size(self) -> int:
        return len(self.m_input_dedup)

    # ---- 自适应温度调度 ----

    def _adapt_temperature(self, found_crash: bool):
        """crash发现 → 升温扩大搜索；无crash → 退火精调。
        类比模拟退火：高温期bold mutations，低温期conservative mutations。"""
        if found_crash:
            self.m_consecutive_no_crash = 0
            # 每发现一个crash略微升温，鼓励exploration
            self.m_temperature = min(
                self.m_temperature_max,
                self.m_temperature + 0.05,
            )
        else:
            self.m_consecutive_no_crash += 1
            if self.m_consecutive_no_crash >= 5:
                # 连续无crash — 退火，更保守地微调
                self.m_temperature = max(
                    self.m_temperature_min,
                    self.m_temperature * self.m_cooling_rate,
                )

    # ---- 变异管线 ----

    def _apply_mutation(self, base: bytes, strategy: MutationStrategy, corpus: Optional[List[bytes]] = None) -> bytes:
        """根据策略对base做变异 — 返回新bytes"""
        data = bytearray(base)
        dlen = len(data)
        if dlen < 1:
            return bytes(data)

        # ---- BIT_FLIP: 翻转单个比特 — 最小扰动 ----
        if strategy == MutationStrategy.BIT_FLIP:
            # 同时翻1~3个比特 — 经验表明单个bit的复合效果更好
            flips = _rnd.randint(1, min(3, dlen * 8))
            fi = 0
            while fi < flips:
                byte_pos = _rnd.randint(0, dlen - 1)
                bit_pos = _rnd.randint(0, 7)
                data[byte_pos] ^= (1 << bit_pos)
                fi += 1

        # ---- BYTE_FLIP: 翻转整字节 — 对magic byte/长度字段有效 ----
        elif strategy == MutationStrategy.BYTE_FLIP:
            count = _rnd.randint(1, max(1, dlen // 32))
            ci = 0
            while ci < count:
                pos = _rnd.randint(0, dlen - 1)
                data[pos] ^= _rnd.randint(1, 255)
                ci += 1

        # ---- ARITHMETIC: 对多字节整数做±运算 — 瞄准长度/偏移字段 ----
        elif strategy == MutationStrategy.ARITHMETIC:
            for width in [1, 2, 4, 8]:
                if dlen >= width:
                    pos = _rnd.randint(0, dlen - width)
                    delta = _rnd.choice([-16, -8, -4, -2, -1, 0, 1, 2, 4, 8, 16, 32, 64, 128, 256])
                    try:
                        val = int.from_bytes(data[pos:pos+width], 'little')
                        new_val = max(0, val + delta)
                        data[pos:pos+width] = new_val.to_bytes(width, 'little')
                    except Exception:
                        pass
                    # 只做一次arithmetic — 太多会完全破坏结构
                    break

        # ---- SPLICE: 从corpus取片段拼接到当前输入 ----
        elif strategy == MutationStrategy.SPLICE:
            if corpus and len(corpus) > 0:
                other = _rnd.choice(corpus)
                if len(other) > 0:
                    splice_start = _rnd.randint(0, len(other) - 1)
                    splice_len = min(_rnd.randint(1, max(1, len(other) // 4)), len(other) - splice_start)
                    chunk = other[splice_start:splice_start + splice_len]
                    insert_pos = _rnd.randint(0, dlen - 1)
                    # splice = 替换而不是插入，避免无限膨胀
                    end_pos = min(insert_pos + len(chunk), dlen)
                    replace_len = end_pos - insert_pos
                    data[insert_pos:end_pos] = chunk[:replace_len]

        # ---- HAVOC: AFL风格的随机摧毁 — 多层叠加 ----
        elif strategy == MutationStrategy.HAVOC:
            rounds = _rnd.randint(1, 16)
            ri = 0
            while ri < rounds:
                action = _rnd.randint(0, 6)
                if action == 0:  # 随机字节翻转
                    pos = _rnd.randint(0, dlen - 1)
                    data[pos] ^= _rnd.randint(1, 255)
                elif action == 1:  # 随机字节设置
                    pos = _rnd.randint(0, dlen - 1)
                    data[pos] = _rnd.choice([0, 0xFF, 0x41, 0x0A, 0x00])
                elif action == 2 and dlen > 4:  # 随机4字节interesting值注入
                    pos = _rnd.randint(0, dlen - 4)
                    data[pos:pos+4] = _rnd.choice(self.m_interesting_values)
                elif action == 3 and dlen > 2:  # 块复制
                    block_size = _rnd.randint(1, min(32, dlen // 2))
                    src = _rnd.randint(0, dlen - block_size)
                    dst = _rnd.randint(0, dlen - block_size)
                    data[dst:dst+block_size] = data[src:src+block_size]
                elif action == 4:  # 随机删除
                    del_pos = _rnd.randint(0, dlen - 1)
                    del_len = _rnd.randint(1, max(1, dlen - del_pos))
                    data[del_pos:del_pos+del_len] = b''
                    dlen = len(data)
                elif action == 5 and dlen > 0:  # 随机插入
                    ins_pos = _rnd.randint(0, dlen - 1)
                    ins_bytes = bytes(_rnd.randint(0, 255) for _ in range(_rnd.randint(1, 16)))
                    data[ins_pos:ins_pos] = ins_bytes
                    dlen = len(data)
                elif action == 6 and dlen > 1:  # 块交换
                    half = dlen // 2
                    block_a = data[:half]
                    block_b = data[half:]
                    if _rnd.random() < 0.5:
                        data[:len(block_b)] = block_b
                        data[len(block_b):len(block_b)+len(block_a)] = block_a
                ri += 1

        # ---- INTERESTING: 注入boundary values到固定偏移 ----
        elif strategy == MutationStrategy.INTERESTING:
            width = _rnd.choice([1, 2, 4])
            if dlen >= width:
                pos = _rnd.randint(0, dlen - width)
                if width == 1:
                    data[pos] = _rnd.choice(_INTERESTING_8)
                elif width == 2:
                    val = _rnd.choice(_INTERESTING_16)
                    try:
                        data[pos:pos+2] = val.to_bytes(2, 'little', signed=(val < 0))
                    except Exception:
                        pass
                elif width == 4:
                    val = _rnd.choice(_INTERESTING_32)
                    try:
                        data[pos:pos+4] = val.to_bytes(4, 'little', signed=(val < 0))
                    except Exception:
                        pass

        # ---- REPEAT: 重复某片段N次触发膨胀/溢出 ----
        elif strategy == MutationStrategy.REPEAT:
            if dlen > 0:
                chunk_start = _rnd.randint(0, dlen - 1)
                chunk_len = _rnd.randint(1, min(64, dlen - chunk_start))
                chunk = bytes(data[chunk_start:chunk_start + chunk_len])
                repeats = _rnd.choice([2, 4, 8, 16, 32, 64, 128, 256])
                insert_at = _rnd.randint(0, dlen - 1)
                for _ in range(repeats):
                    data[insert_at:insert_at] = chunk

        return bytes(data)

    def _pick_strategy(self) -> MutationStrategy:
        """从加权池选策略 — 未来可根据历史命中率动态调整权重"""
        return _rnd.choice(self.m_mutation_pool)

    # ---- Step 1: Extract crash context ----

    def extract_crash_context(self, crash_output: str, input_bytes: bytes = b"") -> CrashContext:
        ctx = CrashContext()
        ctx.input_bytes = input_bytes
        ctx.input_length = len(input_bytes)
        ctx.crash_hash = _hashlib.sha256(input_bytes).hexdigest()[:16]

        prompt = f"""Analyze the following crash output and extract structured information.
Return a JSON object with keys: signal, fault_address, instruction, registers (dict),
stack_trace (list of strings), crash_type, and exploitability_hint.

Crash output:
{crash_output}

Respond with ONLY valid JSON."""

        try:
            response = self.m_client.complete(prompt, max_tokens=1024)
            data = _json.loads(response) if isinstance(response, str) else response
            ctx.signal = data.get("signal", "")
            ctx.fault_address = data.get("fault_address", "")
            ctx.instruction = data.get("instruction", "")
            ctx.registers = data.get("registers", {})
            ctx.stack_trace = data.get("stack_trace", [])
            ctx.crash_type = data.get("crash_type", "")
            ctx.exploitability_hint = data.get("exploitability_hint", "")
        except Exception as e:
            __dbg.warning("extract_crash_context parse error: %s", e)
            # Simple regex-based fallback
            import re as _re
            sig_match = _re.search(r'(SIG\w+)', crash_output)
            if sig_match:
                ctx.signal = sig_match.group(1)
            addr_match = _re.search(r'(?:fault|at)\s+(0x[0-9a-fA-F]+)', crash_output)
            if addr_match:
                ctx.fault_address = addr_match.group(1)

        self.m_history.append({"step": "extract_crash_context", "context": ctx})
        return ctx

    # ---- Step 2: Infer input structure ----

    def infer_input_structure(self, seed_inputs: List[bytes],
                              crash_contexts: List[CrashContext]) -> InferredInputStructure:
        structure = InferredInputStructure()

        hex_samples: List[str] = []
        si = 0
        while si < min(len(seed_inputs), 5):
            inp = seed_inputs[si]
            hex_str = inp[:256].hex() if len(inp) > 256 else inp.hex()
            hex_samples.append(hex_str)
            si += 1

        crash_summaries = [c.summary() for c in crash_contexts[:3]]

        prompt = f"""Infer the input structure from these seed inputs and crash summaries.

Seed inputs (hex, first 256 bytes):
{chr(10).join(hex_samples)}

Crash summaries:
{chr(10).join(crash_summaries)}

Return JSON with keys: format_name, fields (list of {{name, offset, size, type}}),
magic_bytes (hex string or null), constraints (list), confidence (0-1), evidence (string).

Respond with ONLY valid JSON."""

        try:
            response = self.m_client.complete(prompt, max_tokens=1024)
            data = _json.loads(response) if isinstance(response, str) else response
            structure.format_name = data.get("format_name", "")
            structure.fields = data.get("fields", [])
            magic_hex = data.get("magic_bytes")
            structure.magic_bytes = bytes.fromhex(magic_hex) if magic_hex else None
            structure.constraints = data.get("constraints", [])
            structure.confidence = float(data.get("confidence", 0))
            structure.evidence = data.get("evidence", "")
        except Exception as e:
            __dbg.warning("infer_input_structure parse error: %s", e)
            structure.confidence = 0.1
            structure.evidence = "Parse error during structure inference"

        self.m_history.append({"step": "infer_input_structure", "structure": structure})
        return structure

    # ---- Step 3: Generate crash input (iterative refinement) ----

    def generate_crash_input(self, target_executor: Callable[[bytes], Optional[CrashContext]],
                             seed_inputs: List[bytes],
                             input_structure: Optional[InferredInputStructure] = None,
                             iterations: int = 0,
                             coverage_callback: Optional[Callable[[bytes], Optional[CoverageBitmap]]] = None) -> List[bytes]:
        """生成crash输入 — 支持多种变异策略+覆盖率反馈。
        2026-07-28: 加入mutation strategy pipeline、coverage guidance、自适应温度。"""
        if iterations <= 0:
            iterations = self.m_max_iterations

        generated: List[bytes] = []
        crash_ctxs: List[CrashContext] = []
        best_inputs: Set[bytes] = set()
        # 保留一份corpus用于SPLICE策略
        corpus: List[bytes] = []

        if seed_inputs:
            best_inputs.update(seed_inputs)
            corpus.extend(seed_inputs)

        iter_idx = 0
        while iter_idx < iterations:
            # 选择策略 — LLM_GUIDED优先，其他用管线
            strategy = MutationStrategy.LLM_GUIDED  # 每N轮走一次LLM

            # 自适应温度调参
            self._adapt_temperature(len(crash_ctxs) > 0 and iter_idx > 0)

            # 每5轮用LLM，其余用变异管线 —— LLM慢但能理解语义
            if iter_idx % 5 != 0 and len(best_inputs) > 0:
                strategy = self._pick_strategy()

            # Build prompt with history
            crash_desc = ""
            if crash_ctxs:
                crash_desc = "\n".join(c.summary() for c in crash_ctxs[-3:])

            struct_desc = ""
            if input_structure:
                struct_desc = _json.dumps({
                    "format": input_structure.format_name,
                    "fields": input_structure.fields,
                    "constraints": input_structure.constraints,
                }, indent=2)

            # Select a base input to mutate
            if best_inputs:
                base = _rnd.choice(list(best_inputs))
            elif seed_inputs:
                base = _rnd.choice(seed_inputs)
            else:
                base = b"\x00" * 64

            base_hex = base[:512].hex()

            if strategy == MutationStrategy.LLM_GUIDED:
                prompt = f"""Generate a mutated crash test input based on:

Base input (hex): {base_hex}
Input structure: {struct_desc if struct_desc else 'unknown'}
Previous crashes: {crash_desc if crash_desc else 'none'}
Temperature (exploration level): {self.m_temperature:.2f}

Return a JSON object with key "input_hex" containing the hex-encoded mutated input
designed to trigger or deepen the crash, and "rationale" explaining the mutation strategy.

Respond with ONLY valid JSON."""

                try:
                    response = self.m_client.complete(prompt, max_tokens=2048)
                    data = _json.loads(response) if isinstance(response, str) else response
                    input_hex = data.get("input_hex", "")
                    mutated = bytes.fromhex(input_hex) if input_hex else base
                except Exception as e:
                    __dbg.warning("generate_crash_input parse error at iter %d: %s", iter_idx, e)
                    # Fallback: random byte flips
                    mutated = bytearray(base)
                    flip_count = max(1, len(mutated) // 10)
                    fi = 0
                    while fi < flip_count:
                        pos = _rnd.randint(0, len(mutated) - 1)
                        mutated[pos] = _rnd.randint(0, 255)
                        fi += 1
                    mutated = bytes(mutated)
            else:
                # 使用变异管线
                mutated = self._apply_mutation(base, strategy, corpus)

            # 去重检查 — 跳过已生成过的输入
            if self._is_duplicate(mutated) and strategy != MutationStrategy.LLM_GUIDED:
                iter_idx += 1
                continue

            generated.append(mutated)

            # Execute and check for crash
            crash = target_executor(mutated) if target_executor else None
            if crash:
                crash.input_bytes = mutated
                crash.input_length = len(mutated)
                crash.crash_hash = _hashlib.sha256(mutated).hexdigest()[:16]
                crash.mutation_strategy = strategy
                crash_ctxs.append(crash)
                best_inputs.add(mutated)
                corpus.append(mutated)
                # 记录策略命中
                self.m_strategy_stats[strategy.name] += 1
            else:
                # 覆盖率反馈 — 未crash但有新覆盖也算有价值
                if coverage_callback:
                    cov = coverage_callback(mutated)
                    if cov:
                        novelty = self.m_global_coverage.novelty_of(cov)
                        if novelty > 0.05:  # 5%新路径 — 保留这个输入
                            best_inputs.add(mutated)
                            corpus.append(mutated)
                            self.m_global_coverage.merge(cov)

            iter_idx += 1

        self.m_history.append({
            "step": "generate_crash_input",
            "generated_count": len(generated),
            "crashes_found": len(crash_ctxs),
            "dedup_size": self._dedup_size(),
            "strategy_stats": dict(self.m_strategy_stats),
        })
        return generated

    # ---- Step 4: Learn grammar ----

    def learn_grammar(self, corpus: List[bytes], max_tokens=1000) -> LearnedGrammar:
        grammar = LearnedGrammar()
        grammar.corpus_size = len(corpus)
        grammar.unique_samples = len(set(corpus))

        # Extract byte-level n-grams
        all_bytes: List[int] = []
        ci = 0
        while ci < len(corpus):
            sample = corpus[ci]
            bi = 0
            while bi < len(sample):
                all_bytes.append(sample[bi])
                bi += 1
            ci += 1

        # 2-gram frequencies
        if len(all_bytes) >= 2:
            ngram_freqs_2: Dict[str, int] = {}
            bi = 0
            while bi < len(all_bytes) - 1:
                key = f"{all_bytes[bi]:02x}{all_bytes[bi+1]:02x}"
                ngram_freqs_2[key] = ngram_freqs_2.get(key, 0) + 1
                bi += 1
            grammar.ngram_freqs[2] = dict(sorted(ngram_freqs_2.items(), key=lambda x: -x[1])[:max_tokens])

        # Byte transition probabilities
        trans: Dict[int, Dict[int, int]] = {}
        bi = 0
        while bi < len(all_bytes) - 1:
            b = all_bytes[bi]
            nb = all_bytes[bi + 1]
            if b not in trans:
                trans[b] = {}
            trans[b][nb] = trans[b].get(nb, 0) + 1
            bi += 1

        for b, targets in trans.items():
            total = sum(targets.values())
            grammar.byte_transitions[b] = {nb: cnt / total for nb, cnt in targets.items()}

        # Entropy per position
        if corpus:
            max_len = max(len(s) for s in corpus)
            pos = 0
            while pos < max_len:
                byte_counts: Dict[int, int] = {}
                si = 0
                while si < len(corpus):
                    sample = corpus[si]
                    if pos < len(sample):
                        b = sample[pos]
                        byte_counts[b] = byte_counts.get(b, 0) + 1
                    si += 1
                total = sum(byte_counts.values())
                if total > 0:
                    import math as _math
                    entropy = 0.0
                    for cnt in byte_counts.values():
                        p = cnt / total
                        if p > 0:
                            entropy -= p * _math.log2(p)
                    grammar.entropy_map[pos] = entropy
                pos += 1

        # Token extraction (common substrings)
        tokens_set: Set[str] = set()
        sample_count = min(len(corpus), 20)
        si = 0
        while si < sample_count:
            sample = corpus[si]
            try:
                text = sample.decode('utf-8', errors='surrogateescape')
                # Extract printable ASCII runs
                import re as _re
                for match in _re.finditer(r'[\x20-\x7e]{3,}', text):
                    tok = match.group(0)
                    if len(tok) <= 16:
                        tokens_set.add(tok)
            except Exception:
                pass
            si += 1

        grammar.tokens = list(tokens_set)[:max_tokens]

        # Basic production rules
        if grammar.tokens:
            grammar.production_rules["S"] = [
                ["header", "payload"],
                ["magic", "header", "payload"],
            ]
            grammar.production_rules["header"] = [[t] for t in grammar.tokens[:5]]
            grammar.production_rules["payload"] = [["data_block"]]

        self.m_grammar = grammar
        self.m_history.append({"step": "learn_grammar", "corpus_size": len(corpus)})
        return grammar

    # ---- Step 5: Differential analysis ----

    def differential_analysis(self, target_a_name: str, target_b_name: str,
                              shared_inputs: List[bytes],
                              executor_a: Callable[[bytes], Optional[Dict]],
                              executor_b: Callable[[bytes], Optional[Dict]]) -> DifferentialTrace:
        trace = DifferentialTrace(target_a=target_a_name, target_b=target_b_name)

        a_results: List[Dict] = []
        b_results: List[Dict] = []

        si = 0
        while si < len(shared_inputs):
            inp = shared_inputs[si]
            ra = executor_a(inp) if executor_a else None
            rb = executor_b(inp) if executor_b else None
            if ra:
                a_results.append(ra)
            if rb:
                b_results.append(rb)
            si += 1

        # Compare block coverage (simulated)
        a_blocks: Set[str] = set()
        b_blocks: Set[str] = set()
        ri = 0
        while ri < len(a_results):
            for block_id in a_results[ri].get("blocks", []):
                a_blocks.add(str(block_id))
            ri += 1
        rj = 0
        while rj < len(b_results):
            for block_id in b_results[rj].get("blocks", []):
                b_blocks.add(str(block_id))
            rj += 1

        trace.shared_blocks = len(a_blocks & b_blocks)
        trace.a_only_blocks = len(a_blocks - b_blocks)
        trace.b_only_blocks = len(b_blocks - a_blocks)
        trace.divergent_blocks = trace.a_only_blocks + trace.b_only_blocks

        total = max(trace.shared_blocks + trace.divergent_blocks, 1)
        trace.similarity_score = trace.shared_blocks / total

        # Use LLM for divergence analysis
        if a_results or b_results:
            prompt = f"""Compare execution of targets '{target_a_name}' and '{target_b_name}':
- Shared basic blocks: {trace.shared_blocks}
- {target_a_name}-only blocks: {trace.a_only_blocks}
- {target_b_name}-only blocks: {trace.b_only_blocks}
- Similarity score: {trace.similarity_score:.2f}

Return JSON with key "divergence_points" (list of {{offset, reason}}).

Respond with ONLY valid JSON."""

            try:
                response = self.m_client.complete(prompt, max_tokens=512)
                data = _json.loads(response) if isinstance(response, str) else response
                trace.divergence_points = data.get("divergence_points", [])
            except Exception:
                pass

        self.m_history.append({"step": "differential_analysis", "trace": trace})
        return trace

    # ---- Step 6: Minimize input (delta-debugging) ----

    def minimize_input(self, crash_input: bytes,
                       crash_tester: Callable[[bytes], bool],
                       granularity: int = 1) -> MinimizationResult:
        result = MinimizationResult()
        result.original_size = len(crash_input)
        result.original_bytes = crash_input

        current = bytearray(crash_input)
        current_size = len(current)
        result.minimized_bytes = bytes(current)
        result.minimized_size = current_size

        # Simplified delta-debugging: try removing chunks
        chunk_size = max(granularity, current_size // 16)
        iteration = 0
        max_iterations = 200

        while chunk_size >= granularity and iteration < max_iterations:
            offset = 0
            made_progress = False
            while offset + chunk_size <= len(current):
                candidate = bytes(current[:offset] + current[offset + chunk_size:])
                iteration += 1
                if crash_tester(candidate):
                    current = bytearray(candidate)
                    result.minimized_bytes = bytes(current)
                    result.minimized_size = len(current)
                    result.still_crashes = True
                    made_progress = True
                    break
                offset += 1

            if not made_progress:
                chunk_size = max(granularity, chunk_size // 2)
            if iteration >= max_iterations:
                break

        # Byte-level minimization: try zeroing individual bytes
        bi = 0
        while bi < len(current) and iteration < max_iterations:
            original_byte = current[bi]
            current[bi] = 0
            candidate = bytes(current)
            iteration += 1
            if not crash_tester(candidate):
                current[bi] = original_byte
            else:
                result.minimized_bytes = bytes(current)
                result.minimized_size = len(current)
            bi += 1

        result.iterations = iteration
        result.reduction_ratio = 1.0 - (result.minimized_size / max(result.original_size, 1))
        result.still_crashes = crash_tester(bytes(current))

        self.m_history.append({"step": "minimize_input", "result": result})
        return result

    # ---- Step 7: Assess exploitability ----

    def assess_exploitability(self, crash_context: CrashContext) -> ExploitabilityReport:
        report = ExploitabilityReport()
        report.crash_context = crash_context

        # Heuristic scoring
        score = 0.0
        reasoning_parts: List[str] = []

        ctx_type = crash_context.crash_type.upper()
        if "SEGV" in ctx_type:
            reasoning_parts.append("Segmentation fault detected")
            score += 0.3
            # Check for controlled instruction pointer
            if "rip" in str(crash_context.registers).lower():
                rip_val = crash_context.registers.get("rip", crash_context.registers.get("RIP", ""))
                if rip_val and "41" in str(rip_val):  # 'A' = 0x41
                    reasoning_parts.append("RIP appears user-controlled (0x41 pattern)")
                    report.controlled_registers.append("RIP")
                    score += 0.4
        elif "ABRT" in ctx_type:
            reasoning_parts.append("Abort signal — likely heap corruption or assert failure")
            score += 0.2
        elif "FPE" in ctx_type:
            reasoning_parts.append("Floating-point exception")
            score += 0.1
        elif "ILL" in ctx_type:
            reasoning_parts.append("Illegal instruction — possible ROP/jump to shellcode")
            score += 0.5
        elif "BUS" in ctx_type:
            reasoning_parts.append("Bus error — unaligned access")
            score += 0.15

        # Stack trace analysis
        if crash_context.stack_trace:
            st_depth = len(crash_context.stack_trace)
            st0 = crash_context.stack_trace[0].lower() if crash_context.stack_trace else ""
            if any(kw in st0 for kw in ("memcpy", "strcpy", "sprintf", "gets", "read", "recv", "malloc", "free")):
                reasoning_parts.append(f"Sensitive function in top frame: {crash_context.stack_trace[0]}")
                score += 0.2

        # LLM-based assessment
        prompt = f"""Assess exploitability of this crash:

Crash type: {crash_context.crash_type}
Fault address: {crash_context.fault_address}
Signal: {crash_context.signal}
Instruction: {crash_context.instruction}
Registers: {_json.dumps(crash_context.registers)}
Stack trace: {_json.dumps(crash_context.stack_trace[:10])}
Heuristic score: {score:.2f}

Return JSON with keys: score (0-1 float), category (EXPLOITABLE/PROBABLY_EXPLOITABLE/UNKNOWN/NOT_EXPLOITABLE),
reasoning (string), controlled_registers (list), controlled_memory (list of dicts),
mitigation_bypasses (list), exploitation_primitives (list), suggested_next_steps (list of strings).

Respond with ONLY valid JSON."""

        try:
            response = self.m_client.complete(prompt, max_tokens=1024)
            data = _json.loads(response) if isinstance(response, str) else response
            llm_score = float(data.get("score", score))
            report.exploitability_score = max(score, llm_score)
            report.category = data.get("category", "UNKNOWN")
            report.reasoning = data.get("reasoning", "; ".join(reasoning_parts))
            report.controlled_registers = data.get("controlled_registers", report.controlled_registers)
            report.controlled_memory = data.get("controlled_memory", [])
            report.mitigation_bypasses = data.get("mitigation_bypasses", [])
            report.exploitation_primitives = data.get("exploitation_primitives", [])
            report.suggested_next_steps = data.get("suggested_next_steps", [])
        except Exception as e:
            __dbg.warning("assess_exploitability parse error: %s", e)
            report.exploitability_score = min(score, 1.0)
            if score >= 0.7:
                report.category = "EXPLOITABLE"
            elif score >= 0.4:
                report.category = "PROBABLY_EXPLOITABLE"
            elif score >= 0.1:
                report.category = "UNKNOWN"
            else:
                report.category = "NOT_EXPLOITABLE"
            report.reasoning = "; ".join(reasoning_parts)

        self.m_history.append({"step": "assess_exploitability", "report": report})
        return report

    # ---- Step 8: Generate seed batch ----

    def generate_seed_batch(self, count: int = 10, min_size: int = 1, max_size: int = 4096) -> List[bytes]:
        seeds: List[bytes] = []

        if self.m_grammar and self.m_grammar.tokens:
            si = 0
            while si < count:
                seeds.append(self.m_grammar.generate(min_size, max_size))
                si += 1
        else:
            # Random seed generation
            si = 0
            while si < count:
                size = _rnd.randint(min_size, max_size)
                seed_type = _rnd.choice(["all_zero", "all_ff", "random", "pattern", "ascii"])
                if seed_type == "all_zero":
                    seeds.append(b"\x00" * size)
                elif seed_type == "all_ff":
                    seeds.append(b"\xff" * size)
                elif seed_type == "random":
                    seeds.append(bytes(_rnd.randint(0, 255) for _ in range(size)))
                elif seed_type == "pattern":
                    pattern = b""
                    pi = 0
                    while pi < size:
                        pattern += bytes([pi % 256])
                        pi += 1
                    seeds.append(pattern)
                elif seed_type == "ascii":
                    seeds.append(bytes(_rnd.randint(32, 126) for _ in range(size)))
                si += 1

        return seeds

    # ---- Get strategy hit statistics ----

    def get_strategy_stats(self) -> Dict[str, int]:
        """返回变异策略命中统计 — 用于事后分析哪种策略最有效"""
        return dict(self.m_strategy_stats)

    # ---- Full pipeline ----

    def analyze(self, target_executor: Callable[[bytes], Optional[CrashContext]],
                seed_inputs: Optional[List[bytes]] = None,
                corpus: Optional[List[bytes]] = None,
                crash_tester: Optional[Callable[[bytes], bool]] = None,
                iterations: int = 0,
                coverage_callback: Optional[Callable[[bytes], Optional[CoverageBitmap]]] = None) -> GenerationResult:
        start = _time.time()
        result = GenerationResult()

        # Generate seeds
        if seed_inputs is None:
            seed_inputs = self.generate_seed_batch(10)
        result.seed_inputs = []
        si = 0
        while si < len(seed_inputs):
            result.seed_inputs.append(seed_inputs[si])
            si += 1

        # Collect initial crashes from seeds
        crash_ctxs: List[CrashContext] = []
        si = 0
        while si < len(seed_inputs):
            inp = seed_inputs[si]
            crash = target_executor(inp) if target_executor else None
            if crash:
                crash.input_bytes = inp
                crash.input_length = len(inp)
                crash.crash_hash = _hashlib.sha256(inp).hexdigest()[:16]
                crash_ctxs.append(crash)
            si += 1

        result.crash_contexts = crash_ctxs

        # Infer structure
        if seed_inputs:
            result.input_structure = self.infer_input_structure(seed_inputs, crash_ctxs)

        # Learn grammar
        if corpus:
            result.grammar = self.learn_grammar(corpus)
            self.m_grammar = result.grammar
        elif seed_inputs:
            result.grammar = self.learn_grammar(seed_inputs)
            self.m_grammar = result.grammar

        # Generate crash inputs — 传入coverage callback
        generated = self.generate_crash_input(
            target_executor, seed_inputs, result.input_structure, iterations,
            coverage_callback=coverage_callback,
        )
        result.generated_inputs = []
        gi = 0
        while gi < len(generated):
            result.generated_inputs.append(generated[gi])
            gi += 1

        # Minimize best crashing input
        if crash_tester and result.generated_inputs:
            best_input = result.generated_inputs[0]
            result.minimization = self.minimize_input(best_input, crash_tester)

        # Exploitability
        if crash_ctxs:
            result.exploitability = self.assess_exploitability(crash_ctxs[0])

        # Stats
        total_crashes = len(crash_ctxs) + sum(
            1 for gi in range(len(result.generated_inputs))
            if target_executor and target_executor(result.generated_inputs[gi])
        )
        result.stats = {
            "seed_count": len(seed_inputs),
            "generated_count": len(result.generated_inputs),
            "total_crashes": total_crashes,
            "grammar_tokens": len(result.grammar.tokens) if result.grammar else 0,
            "exploitability_score": result.exploitability.exploitability_score if result.exploitability else 0,
            "dedup_cache_size": self._dedup_size(),
            "temperature_final": self.m_temperature,
            "strategy_stats": self.get_strategy_stats(),
        }
        result.strategy_stats = self.get_strategy_stats()
        result.success = total_crashes > 0
        result.elapsed_seconds = _time.time() - start

        return result

    def reset(self):
        self.m_grammar = None
        self.m_history.clear()
        self.m_input_dedup.clear()
        self.m_global_coverage = CoverageBitmap()
        self.m_consecutive_no_crash = 0
        self.m_strategy_stats.clear()


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def create_crash_generator(target_binary="", llm_client=None, max_iterations=20) -> LLMCrashGenerator:
    return LLMCrashGenerator(
        llm_client=llm_client,
        target_binary=target_binary,
        max_iterations=max_iterations,
    )
