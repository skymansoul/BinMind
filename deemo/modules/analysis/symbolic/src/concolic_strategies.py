#!/usr/bin/env python3
# (c) 2024-2025 h1016 — Constraint-solving 优化 strategies for concolic execution

"""Constraint-solving 优化 strategies for concolic execution

Extracted concolic_execution.py — self-contained strategy components
composed independently main executor:

CrashCategory / CrashTriage分类器
Constraint-签名 崩溃分类 — classifies crashes fusing
address, error message, symbolic constraint pattern signals

FuzzDictEntry / FuzzDictGenerator
High-entropy seed → AFL/lib模糊测试器 dictionary 流水线. 排序
composite effectiveness score (覆盖率 gain ∨ entropy)

StructuredMetrics
Per-舍入 metric accumulator — replaces scattered 记录 statements
a single 快照 per concolic loop iteration

Seed变异流水线
Three-operator lightweight 变异 (byte flip, arithmetic tweak
block swap) applied seeds symbolic injection

_entropy_of
Shannon entropy over byte sequences — 代理 for seed diversity
"""

from __future__ import annotations

import logging
import math
import os
import random
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover — avoids circular import at runtime
    from ..concolic_execution import ConcolicSeed

logger = logging.getLogger(__name__)

__all__ = [
    "CrashCategory",
    "CrashTriageClassifier",
    "FuzzDictEntry",
    "FuzzDictGenerator",
    "StructuredMetrics",
    "SeedMutationPipeline",
    "_entropy_of",
]


# =============================================================================
# CrashCategory — crash taxonomy for triage 分类
# =============================================================================
class CrashCategory(Enum):
    """Crash taxonomy for triage 分类"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_CORRUPTION = "heap_corruption"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_deref"
    UNKNOWN = "unknown"


# =============================================================================
# FuzzDictEntry — one dictionary token for AFL/lib模糊测试器 corpus
# =============================================================================
@dataclass
class FuzzDictEntry:
    """One dictionary token for AFL/lib模糊测试器 corpus"""
    key: str            # "SEED_xxx" label
    payload: bytes
    source_name: str
    entropy: float
    hit_round: int      # iteration first collected
    coverage_gain: float


# =============================================================================
# CrashTriage分类器
#   基于崩溃地址+错误信息+约束模式的分类器
#   匹配优先级从具体到抽象 — 先检查特定函数偏移，再检查通用错误文本
#   约束模式匹配作为兜底，当崩溃地址无法解析时被激活
# =============================================================================
class CrashTriageClassifier:
    """Classify crashes one {栈_overflow, 堆_corruption
    format_string, integer_overflow, null_deref, unknown}
    
    Three-phase analysis 流水线:
    1. crash address canonicalization (strip paging bits, 标准化)
    2. error message pattern matching (canary, 堆 guard, fmt specifier)
    3. constraint 签名 analysis (overflow bounds, deref guards)
    
    设计取舍 — 不依赖符号解析作为必要条件，地址信息缺失时仍可通过错误文本
    和约束模式完成分类，确保在 stripped binary 场景下也能输出有意义的标签
    """

    # 栈溢出特征：低地址段（< 0x1000）的违规写入，或 __stack_chk 错误
    _STACK_OVERFLOW_PATTERNS = [
        re.compile(r"stack.*(?:smash|overflow|canary|buffer)", re.IGNORECASE),
        re.compile(r"__stack_chk|__stack_smash|SSP", re.IGNORECASE),
        re.compile(r"stack.*guard.*(?:fail|violat)", re.IGNORECASE),
        re.compile(r"RET\s.*addr.*overwrit", re.IGNORECASE),
    ]

    # 堆破坏特征：malloc/free 内部断言，或堆元数据区域违规
    _HEAP_CORRUPTION_PATTERNS = [
        re.compile(r"heap.*(?:corrupt|overflow|guard)", re.IGNORECASE),
        re.compile(r"(?:double\s+free|free.*invalid|malloc.*assert)", re.IGNORECASE),
        re.compile(r"munmap_chunk.*invalid", re.IGNORECASE),
        re.compile(r"(?:top|last|first)\s*chunk", re.IGNORECASE),
        re.compile(r"corrupted double-linked list", re.IGNORECASE),
    ]

    # 格式化字符串特征：%n 写入检测或格式参数异常
    _FORMAT_STRING_PATTERNS = [
        re.compile(r"format.*(?:string|specifier|overflow)", re.IGNORECASE),
        re.compile(r"%n\s*(?:write|deref|access)", re.IGNORECASE),
        re.compile(r"(?:printf|fprintf|sprintf|snprintf|vprintf|vfprintf).*fmt", re.IGNORECASE),
    ]

    # 整数溢出特征：回绕检测或长度校验失败后的大值
    _INTEGER_OVERFLOW_PATTERNS = [
        re.compile(r"integer\s*(?:overflow|wraparound|underflow)", re.IGNORECASE),
        re.compile(r"(?:size_t|uint\d+|int\d+)\s*(?:overflow|wrap)", re.IGNORECASE),
        re.compile(r"len\s*[><=]+\s*0[fF]{8,}", re.IGNORECASE),
        re.compile(r"malloc\(\s*-\d+|\balloc\(\s*-\d+", re.IGNORECASE),
    ]

    # 空指针解引用特征：0x0 或 NULL page 附近地址违规
    _NULL_DEREF_PATTERNS = [
        re.compile(r"null\s*(?:pointer\s*)?(?:deref|access|read|write)", re.IGNORECASE),
        re.compile(r"segfault.*at\s+0+\s", re.IGNORECASE),
        re.compile(r"[Aa]ccess\s+violation.*address\s+0[xX]0+", re.IGNORECASE),
        re.compile(r"cannot\s+access\s+memory\s+at\s+0[xX]0+", re.IGNORECASE),
    ]

    # 约束级特征 — 当崩溃地址无法分类时，用符号约束内容推断
    _CONSTRAINT_SIGNATURES = {
        CrashCategory.STACK_OVERFLOW: [
            re.compile(r"\(<=?\s*(?:stack|sp|esp|rbp|rsp)\w*\s", re.IGNORECASE),
            re.compile(r"\(>=?\s*(?:stack_top|stack_end)", re.IGNORECASE),
        ],
        CrashCategory.HEAP_CORRUPTION: [
            re.compile(r"\(=?\s*(?:malloc|free|heap|alloc)\w*\s", re.IGNORECASE),
        ],
        CrashCategory.INTEGER_OVERFLOW: [
            re.compile(r"b[vu](?:add|mul|sub).*overflow", re.IGNORECASE),
            re.compile(r"check.*wrap.*around", re.IGNORECASE),
        ],
        CrashCategory.NULL_DEREF: [
            re.compile(r"\(=\s*0x0+\s*\)", re.IGNORECASE),
            re.compile(r"\(not\s*\(=\s*\w+\s*0x0+", re.IGNORECASE),
        ],
    }

    # 地址归一化掩码：x86-64 用户态地址高 16 位置零，ARM64 保留 48 位
    # 避免 ASLR 引起的地址抖动破坏模式匹配
    ADDRESS_NORMALIZE_MASK = 0x0000FFFFFFFFFFFF

    def __init__(self) -> None:
        self._classification_cache: Dict[str, CrashCategory] = {}

    # ------------------------------------------------------------------
    # triage_stage_address: 地址优先匹配 — 低地址段优先判断栈/空指针
    # 堆地址典型范围在 0x7f. 附近（libc 分配的 mmap 区域）
    # ------------------------------------------------------------------
    def _triage_by_address(self, crash_addr: int) -> Optional[CrashCategory]:
        normalized = crash_addr & self.ADDRESS_NORMALIZE_MASK
        if normalized == 0:
            return CrashCategory.NULL_DEREF
        if normalized < 0x1000:
            return CrashCategory.NULL_DEREF
        if normalized < 0x10000:
            return CrashCategory.STACK_OVERFLOW
        return None

    def _triage_by_message(self, error_msg: str) -> Optional[CrashCategory]:
        if not error_msg:
            return None

        matchers = [
            (CrashCategory.STACK_OVERFLOW, self._STACK_OVERFLOW_PATTERNS),
            (CrashCategory.HEAP_CORRUPTION, self._HEAP_CORRUPTION_PATTERNS),
            (CrashCategory.FORMAT_STRING, self._FORMAT_STRING_PATTERNS),
            (CrashCategory.INTEGER_OVERFLOW, self._INTEGER_OVERFLOW_PATTERNS),
            (CrashCategory.NULL_DEREF, self._NULL_DEREF_PATTERNS),
        ]

        best_cat: Optional[CrashCategory] = None
        best_score = 0
        for cat, regexes in matchers:
            score = sum(1 for r in regexes if r.search(error_msg))
            if score > best_score:
                best_score = score
                best_cat = cat

        return best_cat if best_score > 0 else None

    def _triage_by_constraints(self, constraint_texts: List[str]) -> Optional[CrashCategory]:
        if not constraint_texts:
            return None

        cat_scores: Dict[CrashCategory, int] = {}
        for category, regexes in self._CONSTRAINT_SIGNATURES.items():
            score = 0
            for cst in constraint_texts:
                if cst is None:
                    continue
                hits = sum(1 for r in regexes if r.search(cst))
                score += hits
            if score > 0:
                cat_scores[category] = score

        if not cat_scores:
            return None
        return max(cat_scores, key=cat_scores.get)

    def classify(
        self,
        crash_address: int = 0,
        error_message: str = "",
        constraint_texts: Optional[List[str]] = None,
    ) -> CrashCategory:
        """Classify a crash fusing address, message, constraint signals
        
        Priority: address > message > constraints. stage defers
        next signal absent or inconclusive
        
        Args:
        crash_address: Faulting instruction or data address (raw)
        error_message: OS/signal/runtime error text (e.g. SIGSEGV detail)
        constraint_texts: Symbolic constraint expressions active crash
        
        返回:
        Best-fit CrashCategory enum
        """
        # 地址优先 — 确定性最强
        if crash_address != 0:
            addr_cat = self._triage_by_address(crash_address)
            if addr_cat is not None:
                return addr_cat

        # 错误文本次优先 — 语义最丰富
        if error_message:
            msg_cat = self._triage_by_message(error_message)
            if msg_cat is not None:
                return msg_cat

        # 约束兜底 — 符号执行独有的信息源
        if constraint_texts:
            cst_cat = self._triage_by_constraints(constraint_texts)
            if cst_cat is not None:
                return cst_cat

        return CrashCategory.UNKNOWN

    def classify_with_confidence(
        self,
        crash_address: int = 0,
        error_message: str = "",
        constraint_texts: Optional[List[str]] = None,
        path_constraints: Optional[List[str]] = None,
    ) -> Tuple[CrashCategory, float]:
        """Classify 返回 a confidence 估算 [0, 1]
        
        Confidence heuristics:
        - address-based: 0.95 (near-certain)
        - error-message >= 2 pattern hits: 0.85
        - error-message 1 pattern hit: 0.70
        - constraint-based >= 2 hits across constraints: 0.55
        - constraint-based 1 hit: 0.35
        - unknown: 0.0
        """
        category = self.classify(crash_address, error_message, constraint_texts)

        if category == CrashCategory.UNKNOWN:
            return category, 0.0

        if crash_address != 0:
            addr_cat = self._triage_by_address(crash_address)
            if addr_cat is not None:
                return addr_cat, 0.95

        if error_message:
            msg_cat = self._triage_by_message(error_message)
            if msg_cat is not None:
                return msg_cat, 0.85

        if constraint_texts:
            cst_cat = self._triage_by_constraints(constraint_texts)
            if cst_cat is not None:
                return cst_cat, 0.55

        return category, 0.35


# =============================================================================
# FuzzDictGenerator: 从高熵种子生成 AFL/lib模糊测试器 字典
# 格式：每行 "SEED_xxx"="<hex bytes>" 或 "SEED_xxx"="<escaped ascii>"
# 按种子有效性排序：coverage_gain 降序 → entropy 降序 → 收集轮次升序
# =============================================================================
class FuzzDictGenerator:
    """Produce an AFL/lib模糊测试器-compatible dictionary high-entropy seeds
    
    Dictionary entries ``SEED_xxx`` sorted a composite
    effectiveness score: higher 覆盖率 gain + higher entropy + earlier
    collection 舍入 yields a higher rank
    
    输出 格式化 follows AFL/lib模糊测试器 convention:
    SEED_001="\\x48\\x65\\x6c\\x6c\\x6f" (hex-escaped)
    SEED_002="readable_ascii" (printable -)
    
    设计意图 — 高熵种子更可能携带魔术字节、结构签名或边界值
    作为 fuzzer 字典条目可以加速路径发现，是对文件格式解析器
    """

    # 最小熵阈值：低于此值的种子过于均匀（全 A / 全 NUL），不值得加入字典
    MIN_ENTROPY_THRESHOLD = 2.0

    # 种子 payload 最小/最大长度：太短无区分度，太长超出字典 token 合理范围
    MIN_PAYLOAD_BYTES = 1
    MAX_PAYLOAD_BYTES = 32

    def __init__(self, max_entries: int = 200) -> None:
        self.max_entries = max_entries
        self._entries: List[FuzzDictEntry] = []

    def _escape_hex(self, raw: bytes) -> str:
        """转换 bytes \\xHH escaped literal for AFL dictionary 格式化"""
        return "".join(f"\\x{b:02x}" for b in raw)

    def _is_printable_ascii(self, raw: bytes) -> bool:
        """True bytes printable ASCII (0x20–0x7E) excluding backslash"""
        for byte in raw:
            if byte < 0x20 or byte > 0x7E or byte == 0x5C:
                return False
        return len(raw) > 0

    def _is_bmp_header(self, raw: bytes) -> bool:
        """BMP magic 'BM' — heuristic 包含 dictionary entry"""
        return len(raw) >= 2 and raw[:2] == b'\x42\x4d'

    def ingest_seed(
        self,
        key: str,
        payload: bytes,
        source_name: str = "",
        entropy: float = 0.0,
        hit_round: int = 0,
        coverage_gain: float = 0.0,
    ) -> bool:
        """Accept a seed passes entropy length gates
        
        返回 True seed added entry set
        """
        if entropy < self.MIN_ENTROPY_THRESHOLD and not self._is_bmp_header(payload):
            return False
        p_len = len(payload) if payload else 0
        if p_len < self.MIN_PAYLOAD_BYTES or p_len > self.MAX_PAYLOAD_BYTES:
            return False

        entry = FuzzDictEntry(
            key=key,
            payload=payload,
            source_name=source_name,
            entropy=entropy,
            hit_round=hit_round,
            coverage_gain=coverage_gain,
        )
        self._entries.append(entry)
        return True

    def ingest_from_seeds(
        self,
        seeds: List[ConcolicSeed],
        coverage_gains: Optional[Dict[int, float]] = None,
    ) -> int:
        """Batch ingestion a list ConcolicSeed objects
        
        Seeds keyed source_name round_collected; 覆盖率
        gains map seed index a gain delta
        """
        admitted = 0
        if coverage_gains is None:
            coverage_gains = {}
        for idx, seed in enumerate(seeds):
            key_base = seed.source_name or "anonymous"
            seed_key = f"seed_{key_base}_{idx:04d}"
            gain = coverage_gains.get(idx, 0.0)
            if self.ingest_seed(
                key=seed_key,
                payload=seed.value,
                source_name=seed.source_name,
                entropy=seed.entropy,
                hit_round=seed.round_collected,
                coverage_gain=gain,
            ):
                admitted += 1
        logger.debug("FuzzDict ingested %d/%d seeds", admitted, len(seeds))
        return admitted

    def _effectiveness_score(self, entry: FuzzDictEntry) -> float:
        """Composite score: 覆盖率 gain primary, entropy tiebreaker"""
        return entry.coverage_gain * 10.0 + entry.entropy * 0.5 - entry.hit_round * 0.1

    def generate_dict(self) -> str:
        """Produce dictionary text, sorted effectiveness score descending
        
        截断 ``max_entries`` formatting
        """
        if not self._entries:
            return "# AFL/libFuzzer dictionary — no entries\n"

        sorted_entries = sorted(
            self._entries,
            key=lambda e: self._effectiveness_score(e),
            reverse=True,
        )[: self.max_entries]

        lines = ["# AFL/libFuzzer dictionary — auto-generated by concolic engine"]
        lines.append(f"# {len(sorted_entries)} entries (max={self.max_entries})")
        lines.append("")

        for idx, entry in enumerate(sorted_entries):
            seg_label = f"SEED_{idx + 1:03d}"
            if self._is_printable_ascii(entry.payload):
                lines.append(f'{seg_label}="{entry.payload.decode("ascii")}"')
            else:
                hex_body = self._escape_hex(entry.payload)
                lines.append(f'{seg_label}="{hex_body}"')

        return "\n".join(lines)

    def export_to_file(self, filepath: str) -> int:
        """写入 dictionary *filepath*. 返回 entry count written"""
        content = self.generate_dict()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
            f.write("\n")
        count = len([l for l in content.splitlines() if l.startswith("SEED_")])
        logger.info("FuzzDict exported %d entries → %s", count, filepath)
        return count

    def entry_count(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        self._entries.clear()


# =============================================================================
# StructuredMetrics — 结构化指标收集器
# 替代分散的 logger.info/warning 调用
# 每轮结束时调用 _snapshot_metrics() 一次性输出，避免日志碎片化
# 下游解析工具可直接读取此结构体而非 grep 日志行
# =============================================================================
@dataclass
class StructuredMetrics:
    """Per-舍入 metrics — replaces scattered inline 日志器 calls
    
    字段说明：
    seeds_collected 本轮/累计收集的种子数
    paths_validated 成功验证（动态重放通过）的路径数
    false_positives 验证失败（标记不可行）的路径数
    solver_timeouts 符号求解器超时次数
    taint_constraints_generated 从污点流生成的约束数量
    round_number 当前轮次编号（concolic loop iteration）
    """
    seeds_collected: int = 0
    paths_validated: int = 0
    false_positives: int = 0
    solver_timeouts: int = 0
    taint_constraints_generated: int = 0
    round_number: int = 0


# =============================================================================
# Seed变异流水线 — 种子变异流水线
# 在种子收集后、注入符号执行器前应用
# 三个变异算子，由 mut_rates 字典控制激活概率
# 变异率保持低位：破坏性低，多样性增益高
# =============================================================================
class SeedMutationPipeline:
    """Applies 变异 operators a seed corpus increase diversity
    
    Three operators 配置ured via mut_rates dict:
    byte_flip — flip random bits, 1% per-byte activation
    arith_tweak — +1 or -1 a random offset, 2% activation
    block_swap — swap two 4-byte chunks, 0.5% activation
    
    设计意图：在种子注入符号执行器之前引入轻量变异，增加路径多样性
    变异率保持低位以防止种子语义被完全破坏
    """

    def __init__(self, mut_rates: Optional[Dict[str, float]] = None) -> None:
        self.mut_rates = mut_rates if mut_rates is not None else {
            'byte_flip': 0.01,
            'arith_tweak': 0.02,
            'block_swap': 0.005,
        }

    # ---------- operator implementations ----------

    def _op_byte_flip(self, data: bytes) -> bytes:
        """Flip random bits byte mut_rates['byte_flip'] probability"""
        rate = self.mut_rates.get('byte_flip', 0.01)
        if len(data) < 1:
            return data
        out = bytearray(data)
        for i in range(len(out)):
            if random.random() < rate:
                out[i] ^= (1 << random.randint(0, 7))
        return bytes(out)

    def _op_arith_tweak(self, data: bytes) -> bytes:
        """+1 or -1 a random offset, gated mut_rates['arith_tweak']"""
        rate = self.mut_rates.get('arith_tweak', 0.02)
        if len(data) < 1 or random.random() >= rate:
            return data
        out = bytearray(data)
        pos = random.randint(0, len(out) - 1)
        delta = 1 if random.random() < 0.5 else -1
        out[pos] = (out[pos] + delta) & 0xFF
        return bytes(out)

    def _op_block_swap(self, data: bytes) -> bytes:
        """Swap two non-overlapping 4-byte chunks mut_rates['block_swap']"""
        rate = self.mut_rates.get('block_swap', 0.005)
        block_sz = 4
        if len(data) < block_sz * 2 or random.random() >= rate:
            return data
        out = bytearray(data)
        max_start = len(out) - block_sz
        a = random.randint(0, max_start)
        b = random.randint(0, max_start)
        # 窗口间距不足则跳过，避免破坏性重叠
        if abs(a - b) < block_sz:
            return bytes(out)
        out[a:a + block_sz], out[b:b + block_sz] = out[b:b + block_sz], out[a:a + block_sz]
        return bytes(out)

    def mutate(self, seeds: List[ConcolicSeed]) -> List[ConcolicSeed]:
        """Apply operators sequentially seed's value
        
        返回 same list (mutated -place) callers chain
        熵值在变异后重新计算，因为字节分布已变化
        """
        if not seeds:
            return seeds
        for seed in seeds:
            original = seed.value
            modified = self._op_byte_flip(original)
            modified = self._op_arith_tweak(modified)
            modified = self._op_block_swap(modified)
            if modified != original:
                seed.value = modified
                seed.entropy = _entropy_of(modified)
        return seeds


# =============================================================================
# _entropy_of — Shannon entropy over byte sequence
# 种子质量衰减：连续无覆盖率增长的轮次越多，新种子的注入权重越低
# 采用 sigmoid 衰减而非线性，避免过早放弃但能快速响应长期停滞
# =============================================================================
def _entropy_of(byte_seq: bytes) -> float:
    """计算 Shannon entropy over *byte_seq*. 返回 0.0 for empty input"""
    if not byte_seq:
        return 0.0
    freq = [0] * 256
    for b in byte_seq:
        freq[b] += 1
    n = len(byte_seq)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)
