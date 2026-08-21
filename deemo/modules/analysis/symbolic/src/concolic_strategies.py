#!/usr/bin/env python3
# (c) 2024-2025 h1016 — concolic 执行的约束求解优化策略

"""concolic 执行的约束求解优化策略。

从 concolic_execution.py 拆出的自包含策略组件, 可与主执行器独立组合:

CrashCategory / CrashTriageClassifier
基于约束签名的崩溃分类 — 融合地址、错误消息与符号约束模式信号

FuzzDictEntry / FuzzDictGenerator
高熵种子 → AFL/libFuzzer 字典流水线, 按综合有效性分数
(coverage_gain ∨ entropy) 排序

StructuredMetrics
逐轮指标累加器 — 用每轮 concolic 循环迭代的一张快照
替代分散的 log 语句

SeedMutationPipeline
三算子的轻量变异 (byte flip、arithmetic tweak、block swap),
在种子注入符号执行器前应用

_entropy_of
字节序列的 Shannon 熵 — 种子多样性的代理指标
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


# CrashCategory — triage 分类用的崩溃分类学
class CrashCategory(Enum):
    """triage 分类用的崩溃分类学。"""
    STACK_OVERFLOW = "stack_overflow"
    HEAP_CORRUPTION = "heap_corruption"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_deref"
    UNKNOWN = "unknown"


# FuzzDictEntry — AFL/libFuzzer 语料库的一个字典 token
@dataclass
class FuzzDictEntry:
    """AFL/libFuzzer 语料库的一个字典 token。"""
    key: str            # "SEED_xxx" label
    payload: bytes
    source_name: str
    entropy: float
    hit_round: int      # iteration first collected
    coverage_gain: float


# CrashTriageClassifier
#   基于崩溃地址+错误信息+约束模式的分类器
#   匹配优先级从具体到抽象 — 先检查特定函数偏移，再检查通用错误文本
#   约束模式匹配作为兜底，当崩溃地址无法解析时被激活
class CrashTriageClassifier:
    """把崩溃归类为 {stack_overflow, heap_corruption,
    format_string, integer_overflow, null_deref, unknown} 之一。

    三阶段分析流水线:
    1. 崩溃地址规范化 (去掉分页位, 标准化)
    2. 错误消息模式匹配 (canary、堆 guard、fmt specifier)
    3. 约束签名分析 (溢出边界、解引用 guard)

    设计取舍 — 不把符号解析作为必要条件, 地址信息缺失时仍可通过
    错误文本与约束模式完成分类, 确保 stripped binary 场景下也能
    输出有意义的标签。
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

    # triage_stage_address: 地址优先匹配 — 低地址段优先判断栈/空指针
    # 堆地址典型范围在 0x7f 开头附近 (libc 分配的 mmap 区域)
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
        """融合地址、消息与约束信号对崩溃分类。

        优先级: address > message > constraints, 当前信号缺失或
        不明确时交给下一信号。

        参数: crash_address 故障指令或数据地址 (原始值),
        error_message OS/信号/运行时错误文本 (如 SIGSEGV 详情),
        constraint_texts 崩溃时活跃的符号约束表达式。
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
        """分类并返回置信度估算 [0, 1]。

        置信度启发式: 基于地址 0.95 (近乎确定); 错误消息命中
        >= 2 个模式 0.85; 错误消息命中 1 个模式 0.70; 约束命中
        >= 2 处 0.55; 约束命中 1 处 0.35; 无法归类 0.0。
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


# FuzzDictGenerator: 从高熵种子生成 AFL/libFuzzer 字典
# 格式：每行 "SEED_xxx"="<hex bytes>" 或 "SEED_xxx"="<escaped ascii>"
# 按种子有效性排序：coverage_gain 降序 → entropy 降序 → 收集轮次升序
class FuzzDictGenerator:
    """从高熵种子生成 AFL/libFuzzer 兼容字典。

    字典条目 ``SEED_xxx`` 按综合有效性分数排序: coverage gain
    越高 + entropy 越高 + 收集轮次越早, 排名越靠前。

    输出格式遵循 AFL/libFuzzer 惯例:
    SEED_001="\\x48\\x65\\x6c\\x6c\\x6f" (hex-escaped)
    SEED_002="readable_ascii" (可打印)

    设计意图 — 高熵种子更可能携带魔术字节、结构签名或边界值,
    作为 fuzzer 字典条目可以加速路径发现。
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
        """把 bytes 转为 AFL 字典格式的 \\xHH 转义字面量。"""
        return "".join(f"\\x{b:02x}" for b in raw)

    def _is_printable_ascii(self, raw: bytes) -> bool:
        """bytes 全部为可打印 ASCII (0x20-0x7E, 不含反斜杠) 时返回 True。"""
        for byte in raw:
            if byte < 0x20 or byte > 0x7E or byte == 0x5C:
                return False
        return len(raw) > 0

    def _is_bmp_header(self, raw: bytes) -> bool:
        """BMP 魔数 'BM' — 启发式地把该种子纳入字典条目。"""
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
        """接受通过熵与长度门槛的种子, 加入条目集时返回 True。"""
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
        """批量接收 ConcolicSeed 对象列表。

        种子键为 source_name 与 round_collected; coverage_gains
        把种子索引映射到增益增量。
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
        """综合分数: coverage gain 为主, entropy 打破僵局。"""
        return entry.coverage_gain * 10.0 + entry.entropy * 0.5 - entry.hit_round * 0.1

    def generate_dict(self) -> str:
        """生成按有效性分数降序的字典文本, 截断到 max_entries 条。"""
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
        """把字典写入 filepath, 返回写入的条目数。"""
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


# StructuredMetrics — 结构化指标收集器
# 替代分散的 logger.info/warning 调用
# 每轮结束时调用 _snapshot_metrics() 一次性输出，避免日志碎片化
# 下游解析工具可直接读取此结构体而非 grep 日志行
@dataclass
class StructuredMetrics:
    """逐轮指标 — 替代分散的 logger 调用。

    字段说明:
    seeds_collected 本轮/累计收集的种子数
    paths_validated 成功验证 (动态重放通过) 的路径数
    false_positives 验证失败 (标记不可行) 的路径数
    solver_timeouts 符号求解器超时次数
    taint_constraints_generated 从污点流生成的约束数量
    round_number 当前轮次编号 (concolic loop iteration)
    """
    seeds_collected: int = 0
    paths_validated: int = 0
    false_positives: int = 0
    solver_timeouts: int = 0
    taint_constraints_generated: int = 0
    round_number: int = 0


# SeedMutationPipeline — 种子变异流水线
# 在种子收集后、注入符号执行器前应用
# 三个变异算子，由 mut_rates 字典控制激活概率
# 变异率保持低位：破坏性低，多样性增益高
class SeedMutationPipeline:
    """对种子语料库应用变异算子以增加多样性。

    三个算子经 mut_rates 字典配置:
    byte_flip — 随机位翻转, 每字节 1% 激活
    arith_tweak — 随机偏移处 +1 或 -1, 2% 激活
    block_swap — 交换两个 4 字节块, 0.5% 激活

    设计意图: 在种子注入符号执行器之前引入轻量变异, 增加路径
    多样性; 变异率保持低位以防止种子语义被完全破坏。
    """

    def __init__(self, mut_rates: Optional[Dict[str, float]] = None) -> None:
        self.mut_rates = mut_rates if mut_rates is not None else {
            'byte_flip': 0.01,
            'arith_tweak': 0.02,
            'block_swap': 0.005,
        }

# 算子实现

    def _op_byte_flip(self, data: bytes) -> bytes:
        """按 mut_rates['byte_flip'] 概率逐字节翻转随机位。"""
        rate = self.mut_rates.get('byte_flip', 0.01)
        if len(data) < 1:
            return data
        out = bytearray(data)
        for i in range(len(out)):
            if random.random() < rate:
                out[i] ^= (1 << random.randint(0, 7))
        return bytes(out)

    def _op_arith_tweak(self, data: bytes) -> bytes:
        """在随机偏移处 +1 或 -1, 受 mut_rates['arith_tweak'] 门控。"""
        rate = self.mut_rates.get('arith_tweak', 0.02)
        if len(data) < 1 or random.random() >= rate:
            return data
        out = bytearray(data)
        pos = random.randint(0, len(out) - 1)
        delta = 1 if random.random() < 0.5 else -1
        out[pos] = (out[pos] + delta) & 0xFF
        return bytes(out)

    def _op_block_swap(self, data: bytes) -> bytes:
        """交换两个不重叠的 4 字节块, 受 mut_rates['block_swap'] 门控。"""
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
        """对每个种子的值依次应用变异算子。

        返回同一列表 (原地变异), 供调用方链式使用;
        变异后重算熵值, 因为字节分布已变化。
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


# _entropy_of — 字节序列的 Shannon 熵
def _entropy_of(byte_seq: bytes) -> float:
    """计算 byte_seq 的 Shannon 熵, 空输入返回 0.0。"""
    if not byte_seq:
        return 0.0
    freq = [0] * 256
    for b in byte_seq:
        freq[b] += 1
    n = len(byte_seq)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)
