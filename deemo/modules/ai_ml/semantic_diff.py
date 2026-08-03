"""
语义差异 — 跨版本二进制/源码语义差异分析。

对比函数语义检测补丁/回归/安全修复。
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
import hashlib  # 保留--未使用


class SignatureType(Enum):
    """Types of semantic signatures."""
    MNEMONIC_HISTOGRAM = "mnemonic_histogram"
    CONTROL_FLOW = "control_flow"
    CALL_GRAPH = "call_graph"
    DATA_FLOW = "data_flow"
    STRING_REFERENCE = "string_reference"
    CONSTANT_VALUES = "constant_values"
    STACK_FRAME = "stack_frame"
    HYBRID = "hybrid"


@dataclass
class SemanticSignature:
    """Semantic signature of a function for comparison purposes."""

    __slots__ = (
        'function_name', 'function_address', 'signature_type',
        'mnemonic_counts', 'cfg_hash', 'call_targets', 'string_refs',
        'constant_values', 'basic_block_count', 'instruction_count',
        'stack_frame_size', 'cyclomatic_complexity', '_hash',
    )

    function_name: str
    function_address: int
    signature_type: SignatureType
    mnemonic_counts: Dict[str, int]
    cfg_hash: str
    call_targets: List[str]
    string_refs: List[str]
    constant_values: List[int]
    basic_block_count: int
    instruction_count: int
    stack_frame_size: int
    cyclomatic_complexity: int
    _hash: str

    def __init__(
        self,
        function_name: str,
        function_address: int = 0,
        signature_type: SignatureType = SignatureType.HYBRID,
        mnemonic_counts: Optional[Dict[str, int]] = None,
        cfg_hash: str = "",
        call_targets: Optional[List[str]] = None,
        string_refs: Optional[List[str]] = None,
        constant_values: Optional[List[int]] = None,
        basic_block_count: int = 0,
        instruction_count: int = 0,
        stack_frame_size: int = 0,
        cyclomatic_complexity: int = 0,
    ) -> None:
        self.function_name = function_name
        self.function_address = function_address
        self.signature_type = signature_type
        self.mnemonic_counts = mnemonic_counts or {}
        self.cfg_hash = cfg_hash
        self.call_targets = call_targets or []
        self.string_refs = string_refs or []
        self.constant_values = constant_values or []
        self.basic_block_count = basic_block_count
        self.instruction_count = instruction_count
        self.stack_frame_size = stack_frame_size
        self.cyclomatic_complexity = cyclomatic_complexity
        self._hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute a deterministic hash of the signature."""
        components = [
            self.function_name,
            str(self.instruction_count),
            str(self.basic_block_count),
            self.cfg_hash,
            str(sorted(self.call_targets)),
            str(sorted(self.constant_values)),
            str(self.cyclomatic_complexity),
            str(self.stack_frame_size),
        ]
        return hashlib.sha256(
            '|'.join(components).encode()
        ).hexdigest()[:16]

    @property
    def hash(self) -> str:
        """Return the pre-computed hash of this signature."""
        return self._hash

    def to_dict(self) -> Dict[str, Any]:
        """Serialize signature to dictionary."""
        return {
            'function_name': self.function_name,
            'function_address': self.function_address,
            'signature_type': self.signature_type.value,
            'instruction_count': self.instruction_count,
            'basic_block_count': self.basic_block_count,
            'cfg_hash': self.cfg_hash,
            'call_targets': self.call_targets,
            'string_refs': self.string_refs,
            'constant_values': self.constant_values,
            'stack_frame_size': self.stack_frame_size,
            'cyclomatic_complexity': self.cyclomatic_complexity,
            'hash': self._hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SemanticSignature:
        """Deserialize signature from dictionary."""
        return cls(
            function_name=data.get('function_name', ''),
            function_address=data.get('function_address', 0),
            signature_type=SignatureType(data.get('signature_type', 'hybrid')),
            mnemonic_counts=data.get('mnemonic_counts', {}),
            cfg_hash=data.get('cfg_hash', ''),
            call_targets=data.get('call_targets', []),
            string_refs=data.get('string_refs', []),
            constant_values=data.get('constant_values', []),
            basic_block_count=data.get('basic_block_count', 0),
            instruction_count=data.get('instruction_count', 0),
            stack_frame_size=data.get('stack_frame_size', 0),
            cyclomatic_complexity=data.get('cyclomatic_complexity', 0),
        )


@dataclass
class FunctionSemantics:
    # Semantic analysis of a single function.
    name: str
    address: int
    signature: SemanticSignature
    basic_blocks: List[Dict[str, Any]] = field(default_factory=list)
    data_references: List[int] = field(default_factory=list)
    code_references: List[int] = field(default_factory=list)
    import_calls: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)


@dataclass
class PatchDelta:
    """Represents a semantic change between two versions of a function."""
    function_name: str
    old_hash: str
    new_hash: str
    similarity: float
    instruction_diff: int
    block_diff: int
    call_changes: List[str] = field(default_factory=list)
    constant_changes: List[str] = field(default_factory=list)
    structural_changes: List[str] = field(default_factory=list)
    security_impact: str = "none"
    is_patch: bool = False


@dataclass
class VersionComparison:
    """Complete comparison between two versions."""
    old_version: str
    new_version: str
    total_functions: int = 0
    matched_functions: int = 0
    added_functions: List[str] = field(default_factory=list)
    removed_functions: List[str] = field(default_factory=list)
    modified_functions: List[PatchDelta] = field(default_factory=list)
    unchanged_functions: List[str] = field(default_factory=list)
    summary: str = ""


class SymbolicSignatureExtractor:
    """Extracts semantic signatures from decompiled/disassembled functions."""

    # Common x86/x64 mnemonics for 分类
    ARITHMETIC_MNEMONICS = {'add', 'sub', 'mul', 'imul', 'div', 'idiv', 'inc', 'dec', 'neg'}
    LOGICAL_MNEMONICS = {'and', 'or', 'xor', 'not', 'shl', 'shr', 'sal', 'sar', 'rol', 'ror'}
    DATA_MNEMONICS = {'mov', 'lea', 'push', 'pop', 'xchg', 'movsx', 'movzx', 'cmov'}
    CONTROL_MNEMONICS = {'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb',
                         'call', 'ret', 'syscall', 'int', 'iret'}
    COMPARISON_MNEMONICS = {'cmp', 'test'}

    def extract_from_disassembly(
        self,
        function_name: str,
        disassembly: str,
        address: int = 0,
    ) -> SemanticSignature:
        """Extract semantic signature from disassembly text.

        Args:
            function_name: Name of the function.
            disassembly: Multi-line disassembly text.
            address: Function start address.

        Returns:
            SemanticSignature for comparison.
        """
        lines = disassembly.split('\n')

        mnemonic_counts: Dict[str, int] = defaultdict(int)
        basic_blocks = 0
        instruction_count = 0
        call_targets: List[str] = []
        string_refs: List[str] = []
        constant_values: List[int] = []
        stack_frame_size = 0

        for line in lines:
            line = line.strip()
            if not line or line.startswith(';') or line.startswith('#'):
                continue

            instruction_count += 1

            # Extract mnemonic
            parts = line.split()
            if parts:
                mnemonic = parts[0].lower()
                if mnemonic in (
                    self.ARITHMETIC_MNEMONICS | self.LOGICAL_MNEMONICS |
                    self.DATA_MNEMONICS | self.CONTROL_MNEMONICS |
                    self.COMPARISON_MNEMONICS
                ):
                    mnemonic_counts[mnemonic] += 1

                if mnemonic == 'call':
                    target = parts[-1] if len(parts) > 1 else 'unknown'
                    call_targets.append(target)

                if mnemonic in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl',
                                'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'):
                    basic_blocks += 1

                if mnemonic in ('lea', 'push', 'pop') and 'rsp' in line.lower():
                    # Stack frame manipulation
                    nums = re.findall(r'0x[0-9a-fA-F]+|\d+', line)
                    if nums:
                        try:
                            val = int(nums[-1], 16 if nums[-1].startswith('0x') else 10)
                            if val > stack_frame_size:
                                stack_frame_size = val
                        except ValueError:
                            pass

            # Extract constants
            for num_str in re.findall(r'0x[0-9a-fA-F]+', line):
                try:
                    constant_values.append(int(num_str, 16))
                except ValueError:
                    pass

        basic_blocks = max(basic_blocks, 1)

        # Compute CFG 哈希
        cfg_components = f"{function_name}:{instruction_count}:{basic_blocks}"
        cfg_hash = hashlib.md5(cfg_components.encode()).hexdigest()[:12]

        cyclomatic = basic_blocks + 1 if basic_blocks > 0 else 1

        return SemanticSignature(
            function_name=function_name,
            function_address=address,
            signature_type=SignatureType.HYBRID,
            mnemonic_counts=dict(mnemonic_counts),
            cfg_hash=cfg_hash,
            call_targets=list(set(call_targets)),
            string_refs=string_refs,
            constant_values=sorted(constant_values),
            basic_block_count=basic_blocks,
            instruction_count=instruction_count,
            stack_frame_size=stack_frame_size,
            cyclomatic_complexity=cyclomatic,
        )

    def extract_from_pseudocode(
        self,
        function_name: str,
        pseudocode: str,
        address: int = 0,
    ) -> SemanticSignature:
        """Extract semantic signature from decompiled pseudocode.

        Args:
            function_name: Name of the function.
            pseudocode: Decompiled pseudocode text.
            address: Function start address.

        Returns:
            SemanticSignature for comparison.
        """
        lines = pseudocode.split('\n')

        mnemonic_counts: Dict[str, int] = defaultdict(int)
        basic_blocks = 1
        instruction_count = len([l for l in lines if l.strip() and not l.strip().startswith('//')])
        call_targets: List[str] = []
        string_refs: List[str] = []
        constant_values: List[int] = []
        stack_frame_size = 0

        # Count control flow statements
        for line in lines:
            stripped = line.strip().lower()
            if any(kw in stripped for kw in ('if', 'else', 'while', 'for', 'switch', 'case')):
                basic_blocks += 1
            if 'return' in stripped:
                basic_blocks += 1

            # Extract function calls
            calls = re.findall(r'(\w+)\s*\(', line)
            call_targets.extend(calls)

            # Extract constants
            for num in re.findall(r'\b(\d+)\b', line):
                try:
                    constant_values.append(int(num))
                except ValueError:
                    pass

            # Extract strings
            strings = re.findall(r'"([^"]*)"', line)
            string_refs.extend(strings)

        # 一步预降大小写，避免对每个关键词重复 .lower().count() -- 原逻辑遍历次数多
        # Use a single lowered copy for keyword counting to avoid redundant .lower() per iteration
        lowered_pseudocode = pseudocode.lower()
        for keyword in ('if', 'else', 'for', 'while', 'return', 'break',
                        'continue', 'switch', 'case', 'goto', 'sizeof',
                        'malloc', 'free', 'memcpy', 'memset', 'strcpy', 'strlen'):
            mnemonic_counts[keyword] = lowered_pseudocode.count(keyword)

        cfg_components = f"{function_name}:{instruction_count}:{basic_blocks}"
        cfg_hash = hashlib.md5(cfg_components.encode()).hexdigest()[:12]

        cyclomatic = basic_blocks

        return SemanticSignature(
            function_name=function_name,
            function_address=address,
            signature_type=SignatureType.HYBRID,
            mnemonic_counts=dict(mnemonic_counts),
            cfg_hash=cfg_hash,
            call_targets=list(set(call_targets)),
            string_refs=list(set(string_refs)),
            constant_values=sorted(set(constant_values)),
            basic_block_count=basic_blocks,
            instruction_count=instruction_count,
            stack_frame_size=stack_frame_size,
            cyclomatic_complexity=cyclomatic,
        )


class SemanticDiffer:
    """Compares function semantics using extracted signatures."""

    # 安全相关的调用链特征，指示可能的漏洞修复
    # Security-relevant call patterns that suggest vulnerability fixes
    _SECURITY_PATTERNS: Set[str] = {
        'memcpy', 'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
        'memmove', 'strncpy', 'strncat', 'snprintf', 'fgets', 'malloc',
        'calloc', 'realloc', 'free', 'memset', 'alloca', 'mmap',
        'bounds', 'check', 'validate', 'sanitize', 'verify', 'safe',
        'boundary', 'escape', 'encode', 'decode', 'auth', 'crypt',
        'hash_verify', 'signature_check', 'cert_validate', 'token_check',
    }

    def __init__(self, cache_size: int = 4096) -> None:
        self.extractor = SymbolicSignatureExtractor()
        # 相似度缓存：避免重复计算同一对签名的代价（LRU 风格简易实现）
        self._similarity_cache: Dict[Tuple[str, str], float] = {}
        self._cache_size = max(cache_size, 1)
        self._cache_hits = 0
        self._cache_misses = 0

    def compute_similarity(
        self,
        sig_a: SemanticSignature,
        sig_b: SemanticSignature,
    ) -> float:
        """Compute semantic similarity between two function signatures.

        Uses a weighted combination of multiple similarity metrics.

        Args:
            sig_a: First signature.
            sig_b: Second signature.

        Returns:
            Similarity score between 0.0 and 1.0.
        """
        # 利用 哈希 作为缓存键 -- 同一对函数多次 diff 时免重复计算
        cache_key = (sig_a.hash, sig_b.hash)
        cached = self._similarity_cache.get(cache_key)
        if cached is not None:
            self._cache_hits += 1
            return cached
        self._cache_misses += 1

        scores: Dict[str, float] = {}

        # Instruction count similarity
        max_inst = max(sig_a.instruction_count, sig_b.instruction_count, 1)
        scores['instruction'] = 1.0 - abs(
            sig_a.instruction_count - sig_b.instruction_count
        ) / max_inst

        # Basic block count similarity
        max_blocks = max(sig_a.basic_block_count, sig_b.basic_block_count, 1)
        scores['blocks'] = 1.0 - abs(
            sig_a.basic_block_count - sig_b.basic_block_count
        ) / max_blocks

        # Cyclomatic complexity similarity
        max_cc = max(sig_a.cyclomatic_complexity, sig_b.cyclomatic_complexity, 1)
        scores['complexity'] = 1.0 - abs(
            sig_a.cyclomatic_complexity - sig_b.cyclomatic_complexity
        ) / max_cc

        # Call target Jaccard similarity
        set_a = set(sig_a.call_targets)
        set_b = set(sig_b.call_targets)
        if set_a or set_b:
            intersection = len(set_a & set_b)
            union = len(set_a | set_b)
            scores['calls'] = intersection / max(union, 1)
        else:
            scores['calls'] = 1.0

        # Constant value Jaccard similarity
        const_a = set(sig_a.constant_values)
        const_b = set(sig_b.constant_values)
        if const_a or const_b:
            intersection = len(const_a & const_b)
            union = len(const_a | const_b)
            scores['constants'] = intersection / max(union, 1)
        else:
            scores['constants'] = 1.0

        # CFG 哈希 exact match
        scores['cfg'] = 1.0 if sig_a.cfg_hash == sig_b.cfg_hash else 0.0

        # Stack frame size similarity
        max_stack = max(sig_a.stack_frame_size, sig_b.stack_frame_size, 1)
        scores['stack'] = 1.0 - abs(
            sig_a.stack_frame_size - sig_b.stack_frame_size
        ) / max_stack

        # Mnemonic histogram cosine similarity
        scores['mnemonics'] = self._mnemonic_similarity(
            sig_a.mnemonic_counts, sig_b.mnemonic_counts
        )

        # Weighted combination
        weights = {
            'instruction': 0.10,
            'blocks': 0.15,
            'complexity': 0.10,
            'calls': 0.20,
            'constants': 0.15,
            'cfg': 0.10,
            'stack': 0.05,
            'mnemonics': 0.15,
        }

        total = sum(scores[k] * weights.get(k, 0) for k in scores)
        result = min(total, 1.0)

        # 写入缓存 -- 超容量时淘汰最早写入的一半条目
        if len(self._similarity_cache) >= self._cache_size:
            evict_count = max(self._cache_size // 2, 1)
            keys_to_evict = list(self._similarity_cache.keys())[:evict_count]
            for k in keys_to_evict:
                self._similarity_cache.pop(k, None)
        self._similarity_cache[cache_key] = result

        return result

    @staticmethod
    def _mnemonic_similarity(
        a: Dict[str, int],
        b: Dict[str, int],
    ) -> float:
        """Compute cosine similarity between mnemonic count vectors."""
        keys = set(a.keys()) | set(b.keys())
        if not keys:
            return 1.0

        dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
        norm_a = math.sqrt(sum(v ** 2 for v in a.values()))
        norm_b = math.sqrt(sum(v ** 2 for v in b.values()))

        if norm_a == 0 and norm_b == 0:
            return 1.0
        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)

    def _assess_security_impact(
        self,
        similarity: float,
        call_changes: List[str],
        structural_changes: List[str],
    ) -> str:
        """评估补丁对安全的影响等级。

        综合分析相似度、调用链变更和结构变化，给出更准确的安全影响判定。
        优先以调用链中的安全关键字作为强信号。

        Args:
            similarity: 函数相似度分数。
            call_changes: 调用目标变更列表。
            structural_changes: 结构变更列表。

        Returns:
            安全影响等级字符串。
        """
        all_changes_text = ' '.join(call_changes + structural_changes).lower()

        if similarity < 0.5:
            return "major_rewrite"

        # 更细粒度的安全特征匹配 -- 将模式和关键词分类
        # High-confidence: 明确的危险函数替换为安全版本
        high_confidence_patterns = {
            ('memcpy', 'memmove'), ('strcpy', 'strncpy'),
            ('strcat', 'strncat'), ('sprintf', 'snprintf'),
            ('gets', 'fgets'), ('scanf', 'fgets'),
        }
        for dangerous, safe in high_confidence_patterns:
            if dangerous in all_changes_text and safe in all_changes_text:
                return "likely_security_fix"

        # Medium-confidence: 安全相关关键词出现
        for pattern in self._SECURITY_PATTERNS:
            if pattern in all_changes_text:
                return "likely_security_fix"

        # Low-confidence but still notable: structural shifts
        if structural_changes:
            return "minor_change"

        return "none"

    def diff_functions(
        self,
        sig_a: SemanticSignature,
        sig_b: SemanticSignature,
        threshold: float = 0.9,
    ) -> PatchDelta:
        """Compare two function versions and produce a patch delta.

        Args:
            sig_a: Old version signature.
            sig_b: New version signature.
            threshold: Similarity threshold for considering unchanged.

        Returns:
            PatchDelta with detailed change information.
        """
        similarity = self.compute_similarity(sig_a, sig_b)

        call_changes: List[str] = []
        constant_changes: List[str] = []
        structural_changes: List[str] = []

        # Call target changes
        old_calls = set(sig_a.call_targets)
        new_calls = set(sig_b.call_targets)
        added_calls = new_calls - old_calls
        removed_calls = old_calls - new_calls
        for c in added_calls:
            call_changes.append(f"Added call to {c}")
        for c in removed_calls:
            call_changes.append(f"Removed call to {c}")

        # Constant changes
        old_consts = set(sig_a.constant_values)
        new_consts = set(sig_b.constant_values)
        added_consts = new_consts - old_consts
        removed_consts = old_consts - new_consts
        for c in added_consts:
            constant_changes.append(f"Added constant {hex(c)}")
        for c in removed_consts:
            constant_changes.append(f"Removed constant {hex(c)}")

        # Structural changes
        if sig_a.instruction_count != sig_b.instruction_count:
            structural_changes.append(
                f"Instructions: {sig_a.instruction_count} -> {sig_b.instruction_count}"
            )
        if sig_a.basic_block_count != sig_b.basic_block_count:
            structural_changes.append(
                f"Basic blocks: {sig_a.basic_block_count} -> {sig_b.basic_block_count}"
            )
        if sig_a.cyclomatic_complexity != sig_b.cyclomatic_complexity:
            structural_changes.append(
                f"Complexity: {sig_a.cyclomatic_complexity} -> {sig_b.cyclomatic_complexity}"
            )

        # 使用增强的安全影响评估
        security_impact = self._assess_security_impact(
            similarity, call_changes, structural_changes
        )

        return PatchDelta(
            function_name=sig_a.function_name,
            old_hash=sig_a.hash,
            new_hash=sig_b.hash,
            similarity=similarity,
            instruction_diff=sig_b.instruction_count - sig_a.instruction_count,
            block_diff=sig_b.basic_block_count - sig_a.basic_block_count,
            call_changes=call_changes,
            constant_changes=constant_changes,
            structural_changes=structural_changes,
            security_impact=security_impact,
            is_patch=similarity < threshold,
        )

    def cache_stats(self) -> Dict[str, int]:
        """返回相似度缓存的命中统计，用于性能诊断。"""
        return {
            'size': len(self._similarity_cache),
            'capacity': self._cache_size,
            'hits': self._cache_hits,
            'misses': self._cache_misses,
            'hit_ratio': (
                self._cache_hits / max(self._cache_hits + self._cache_misses, 1)
            ),
        }

    def clear_cache(self) -> None:
        """清空相似度缓存，释放内存并重置统计。"""
        self._similarity_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0


class CrossVersionAnalyzer:
    """Analyzes semantic differences across binary versions."""

    def __init__(self) -> None:
        self.differ = SemanticDiffer()

    def compare_versions(
        self,
        old_functions: Dict[str, SemanticSignature],
        new_functions: Dict[str, SemanticSignature],
        old_version: str = "v1",
        new_version: str = "v2",
    ) -> VersionComparison:
        """Compare two sets of function signatures across versions.

        Args:
            old_functions: Function signatures from old version.
            new_functions: Function signatures from new version.
            old_version: Version label for old set.
            new_version: Version label for new set.

        Returns:
            VersionComparison with complete diff analysis.
        """
        result = VersionComparison(
            old_version=old_version,
            new_version=new_version,
            total_functions=len(new_functions),
        )

        old_names = set(old_functions.keys())
        new_names = set(new_functions.keys())

        # Added functions
        added = new_names - old_names
        result.added_functions = sorted(added)

        # Removed functions
        removed = old_names - new_names
        result.removed_functions = sorted(removed)

        # Compare common functions
        common = old_names & new_names
        for name in sorted(common):
            old_sig = old_functions[name]
            new_sig = new_functions[name]

            if old_sig.hash == new_sig.hash:
                result.unchanged_functions.append(name)
                result.matched_functions += 1
            else:
                delta = self.differ.diff_functions(old_sig, new_sig)
                result.modified_functions.append(delta)
                result.matched_functions += 1

        result.matched_functions += len(added)

        # 构造 summary
        total_mod = len(result.modified_functions)
        sec_fixes = sum(1 for d in result.modified_functions
                        if d.security_impact == 'likely_security_fix')
        major = sum(1 for d in result.modified_functions
                    if d.security_impact == 'major_rewrite')

        summary_parts = [
            f"Compared {old_version} -> {new_version}",
            f"Total functions: {result.total_functions}",
            f"Added: {len(added)}, Removed: {len(removed)}",
            f"Modified: {total_mod} ({sec_fixes} security-relevant, {major} major)",
            f"Unchanged: {len(result.unchanged_functions)}",
        ]
        result.summary = ' | '.join(summary_parts)

        return result

    def find_patched_vulnerabilities(
        self,
        comparison: VersionComparison,
        min_similarity: float = 0.5,
    ) -> List[PatchDelta]:
        """Identify likely security patches from version comparison.

        Args:
            comparison: Version comparison result.
            min_similarity: Maximum similarity to consider as patched.

        Returns:
            List of PatchDelta likely representing security patches.
        """
        candidates: List[PatchDelta] = []

        for delta in comparison.modified_functions:
            if delta.security_impact == 'likely_security_fix':
                candidates.append(delta)
            elif delta.similarity < min_similarity:
                if delta.instruction_diff > 5 or delta.block_diff > 1:
                    candidates.append(delta)

        return sorted(candidates, key=lambda d: d.similarity)

    def generate_report(
        self,
        comparison: VersionComparison,
    ) -> str:
        """Generate a human-readable diff report.

        Args:
            comparison: Version comparison result.

        Returns:
            Formatted report string.
        """
        lines = [
            "=" * 60,
            f"SEMANTIC DIFF REPORT: {comparison.old_version} -> {comparison.new_version}",
            "=" * 60,
            "",
            comparison.summary,
            "",
        ]

        if comparison.added_functions:
            lines.append("NEW FUNCTIONS:")
            for f in comparison.added_functions:
                lines.append(f"  + {f}")
            lines.append("")

        if comparison.removed_functions:
            lines.append("REMOVED FUNCTIONS:")
            for f in comparison.removed_functions:
                lines.append(f"  - {f}")
            lines.append("")

        if comparison.modified_functions:
            lines.append("MODIFIED FUNCTIONS:")
            for delta in comparison.modified_functions:
                lines.append(f"  * {delta.function_name}")
                lines.append(f"    Similarity: {delta.similarity:.2%}")
                lines.append(f"    Security impact: {delta.security_impact}")
                if delta.call_changes:
                    for c in delta.call_changes:
                        lines.append(f"      {c}")
                if delta.structural_changes:
                    for s in delta.structural_changes:
                        lines.append(f"      {s}")
                lines.append("")

        lines.append("=" * 60)
        return '\n'.join(lines)
