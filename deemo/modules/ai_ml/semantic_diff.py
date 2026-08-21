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
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class SignatureType(Enum):
    FUNCTION_ENTRY = "function_entry"
    FUNCTION_EXIT = "function_exit"
    BASIC_BLOCK = "basic_block"
    CALL_SITE = "call_site"
    MEMORY_ACCESS = "memory_access"
    REGISTER_USE = "register_use"
    DATA_FLOW = "data_flow"
    STRING_REFERENCE = "string_reference"
    CONSTANT_VALUES = "constant_values"
    STACK_FRAME = "stack_frame"
    HYBRID = "hybrid"


@dataclass
class SemanticSignature:
    signature_type: SignatureType
    address: int
    features: Dict[str, Any]
    hash: str = ""
    function_name: Optional[str] = None
    call_targets: List[str] = field(default_factory=list)
    constant_values: List[int] = field(default_factory=list)
    instruction_count: int = 0
    basic_block_count: int = 0
    cyclomatic_complexity: int = 0

    def __post_init__(self):
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        feature_str = json.dumps(self.features, sort_keys=True)
        return hashlib.sha256(
            f"{self.signature_type.value}:{self.address}:{feature_str}".encode()
        ).hexdigest()


@dataclass
class FunctionSemantics:
    function_name: Optional[str]
    address: int
    signatures: List[SemanticSignature]
    control_flow_graph: Dict[int, List[int]]
    data_dependencies: Dict[int, Set[int]]
    side_effects: Set[str]

    def get_unique_signature(self) -> str:
        all_hashes = sorted(sig.hash for sig in self.signatures)
        return hashlib.sha256("".join(all_hashes).encode()).hexdigest()


@dataclass
class PatchDelta:
    type: str
    old_address: Optional[int]
    new_address: Optional[int]
    description: str
    severity: str
    trigger_condition: Optional[str]
    function_name: Optional[str] = None
    old_hash: str = ""
    new_hash: str = ""
    similarity: float = 1.0
    instruction_diff: int = 0
    block_diff: int = 0
    call_changes: List[str] = field(default_factory=list)
    constant_changes: List[str] = field(default_factory=list)
    structural_changes: List[str] = field(default_factory=list)
    security_impact: str = "none"
    is_patch: bool = False


@dataclass
class VersionComparison:
    version_old: str
    version_new: str
    functions_added: List[FunctionSemantics]
    functions_removed: List[FunctionSemantics]
    functions_changed: List[Tuple[FunctionSemantics, FunctionSemantics]]
    patches: List[PatchDelta]
    one_day_candidates: List[PatchDelta]


class SymbolicSignatureExtractor:
    def __init__(self, binary_analyzer):
        self.analyzer = binary_analyzer

    def extract_function_signature(self, func_addr: int) -> FunctionSemantics:
        function = self.analyzer.get_function(func_addr)
        if not function:
            raise ValueError(f"Function not found at address {hex(func_addr)}")

        signatures = []

        for block in function.basic_blocks:
            block_features = self._extract_block_features(block)
            sig = SemanticSignature(
                signature_type=SignatureType.BASIC_BLOCK,
                address=block.address,
                features=block_features
            )
            signatures.append(sig)

            for insn in block.instructions:
                if insn.is_call:
                    call_features = self._extract_call_features(insn)
                    sig = SemanticSignature(
                        signature_type=SignatureType.CALL_SITE,
                        address=insn.address,
                        features=call_features
                    )
                    signatures.append(sig)

                if insn.is_memory_access:
                    mem_features = self._extract_memory_features(insn)
                    sig = SemanticSignature(
                        signature_type=SignatureType.MEMORY_ACCESS,
                        address=insn.address,
                        features=mem_features
                    )
                    signatures.append(sig)

        return FunctionSemantics(
            function_name=function.name,
            address=func_addr,
            signatures=signatures,
            control_flow_graph=self._build_cfg(function),
            data_dependencies=self._extract_data_dependencies(function),
            side_effects=self._identify_side_effects(function)
        )

    def _extract_block_features(self, block) -> Dict[str, Any]:
        features = {
            "instruction_count": len(block.instructions),
            "has_conditional_jump": any(insn.is_conditional_jump for insn in block.instructions),
            "has_unconditional_jump": any(insn.is_unconditional_jump for insn in block.instructions),
            "has_call": any(insn.is_call for insn in block.instructions),
            "has_return": any(insn.is_return for insn in block.instructions),
            "stack_delta": block.stack_delta,
            "uses_flags": any(insn.affects_flags for insn in block.instructions),
            "memory_access_count": sum(1 for insn in block.instructions if insn.is_memory_access)
        }
        return features

    def _extract_call_features(self, insn) -> Dict[str, Any]:
        features = {
            "target": insn.call_target,
            "is_indirect": insn.is_indirect_call,
            "arguments_count": insn.arguments_count,
            "calls_unknown": insn.call_target is None,
            "stack_args": insn.stack_arguments,
            "register_args": insn.register_arguments
        }
        return features

    def _extract_memory_features(self, insn) -> Dict[str, Any]:
        features = {
            "is_write": insn.is_memory_write,
            "is_read": insn.is_memory_read,
            "size": insn.memory_access_size,
            "address_mode": insn.address_mode,
            "is_stack_access": insn.is_stack_access,
            "is_global_access": insn.is_global_access,
            "is_indirect": insn.is_indirect_memory_access
        }
        return features

    def _build_cfg(self, function) -> Dict[int, List[int]]:
        cfg = {}
        for block in function.basic_blocks:
            cfg[block.address] = [succ.address for succ in block.successors]
        return cfg

    def _extract_data_dependencies(self, function) -> Dict[int, Set[int]]:
        deps = {}
        for block in function.basic_blocks:
            deps[block.address] = set()
            for insn in block.instructions:
                for reg in insn.used_registers:
                    deps[block.address].add(reg)
        return deps

    def _identify_side_effects(self, function) -> Set[str]:
        effects = set()
        for block in function.basic_blocks:
            for insn in block.instructions:
                if insn.is_system_call:
                    effects.add(f"syscall:{insn.syscall_number}")
                if insn.is_memory_write and insn.is_global_access:
                    effects.add("global_memory_write")
                if insn.is_port_access:
                    effects.add("port_io")
        return effects


class SemanticDiffer:
    def __init__(self):
        self.signature_threshold = 0.8
        self._similarity_cache: Dict[Tuple[str, str], float] = {}
        self._cache_size = 1024
        self._cache_hits = 0
        self._cache_misses = 0

    def compare_functions(self, old_func: FunctionSemantics, new_func: FunctionSemantics) -> PatchDelta:
        old_sig = old_func.get_unique_signature()
        new_sig = new_func.get_unique_signature()

        if old_sig == new_sig:
            return PatchDelta(
                type="no_change",
                old_address=old_func.address,
                new_address=new_func.address,
                description="Function semantics unchanged",
                severity="none",
                trigger_condition=None
            )

        changed_features = self._find_changed_features(old_func, new_func)

        if self._is_security_fix(changed_features):
            return PatchDelta(
                type="security_fix",
                old_address=old_func.address,
                new_address=new_func.address,
                description=self._describe_security_change(old_func, new_func, changed_features),
                severity="critical",
                trigger_condition=self._infer_trigger_condition(old_func, changed_features)
            )

        if self._is_behavioral_change(changed_features):
            return PatchDelta(
                type="behavioral_change",
                old_address=old_func.address,
                new_address=new_func.address,
                description=f"Behavioral change detected: {changed_features}",
                severity="medium",
                trigger_condition=None
            )

        return PatchDelta(
            type="minor_change",
            old_address=old_func.address,
            new_address=new_func.address,
            description="Minor implementation change",
            severity="low",
            trigger_condition=None
        )

    def _find_changed_features(self, old_func: FunctionSemantics, new_func: FunctionSemantics) -> Dict[str, Any]:
        changes = {}

        old_sig_set = {sig.hash for sig in old_func.signatures}
        new_sig_set = {sig.hash for sig in new_func.signatures}

        added = new_sig_set - old_sig_set
        removed = old_sig_set - new_sig_set

        if added:
            changes["added_signatures"] = list(added)[:5]
        if removed:
            changes["removed_signatures"] = list(removed)[:5]

        if old_func.control_flow_graph != new_func.control_flow_graph:
            changes["cfg_changed"] = True

        if old_func.side_effects != new_func.side_effects:
            changes["side_effects_changed"] = {
                "added": list(new_func.side_effects - old_func.side_effects),
                "removed": list(old_func.side_effects - new_func.side_effects)
            }

        return changes

    def _is_security_fix(self, changes: Dict[str, Any]) -> bool:
        security_patterns = [
            "removed_signatures",
            "cfg_changed",
            "side_effects_changed"
        ]

        for pattern in security_patterns:
            if pattern in changes:
                if pattern == "side_effects_changed":
                    if "removed" in changes[pattern] and any("syscall" in e for e in changes[pattern]["removed"]):
                        return True
                else:
                    return True

        return False

    def _is_behavioral_change(self, changes: Dict[str, Any]) -> bool:
        return bool(changes)

    def _describe_security_change(self, old_func: FunctionSemantics, new_func: FunctionSemantics, changes: Dict[str, Any]) -> str:
        parts = []

        if "removed_signatures" in changes:
            parts.append(f"Removed {len(changes['removed_signatures'])} semantic signatures")

        if "cfg_changed" in changes:
            parts.append("Control flow graph modified")

        if "side_effects_changed" in changes:
            se = changes["side_effects_changed"]
            if se.get("removed"):
                parts.append(f"Removed side effects: {', '.join(se['removed'])}")
            if se.get("added"):
                parts.append(f"Added side effects: {', '.join(se['added'])}")

        return "; ".join(parts)

    def _infer_trigger_condition(self, old_func: FunctionSemantics, changes: Dict[str, Any]) -> Optional[str]:
        for sig in old_func.signatures:
            if sig.signature_type == SignatureType.MEMORY_ACCESS:
                if sig.features.get("is_write") and sig.features.get("is_indirect"):
                    return f"Indirect memory write at {hex(sig.address)}"

    def compute_similarity(self, sig_a: SemanticSignature, sig_b: SemanticSignature) -> float:
        """基于特征哈希和Jaccard相似度计算两签名的语义相似度。"""
        cache_key = (sig_a.hash, sig_b.hash)
        if cache_key in self._similarity_cache:
            self._cache_hits += 1
            return self._similarity_cache[cache_key]

        self._cache_misses += 1
        if sig_a.hash == sig_b.hash:
            sim = 1.0
        else:
            keys_a = set(sig_a.features.keys())
            keys_b = set(sig_b.features.keys())
            union = keys_a | keys_b
            if not union:
                sim = 0.0
            else:
                shared = keys_a & keys_b
                matching = sum(1 for k in shared if sig_a.features[k] == sig_b.features[k])
                sim = matching / len(union)

        if len(self._similarity_cache) < self._cache_size:
            self._similarity_cache[cache_key] = sim
        return sim

    def _assess_security_impact(self, similarity: float,
                                call_changes: List[str],
                                structural_changes: List[str]) -> str:
        """根据相似度和变更类型推断安全影响等级。"""
        if similarity < 0.3:
            return "critical"
        has_call_change = any("Removed call" in c for c in call_changes)
        has_struct_change = bool(structural_changes)
        if has_call_change and has_struct_change:
            return "high"
        if has_call_change or (similarity < 0.7 and has_struct_change):
            return "medium"
        return "low"

    def diff_functions(
        self,
        sig_a: SemanticSignature,
        sig_b: SemanticSignature,
        threshold: float = 0.9,
    ) -> PatchDelta:
        """Compare two function versions and produce a patch delta."""
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
    def __init__(self, old_binary_path: str, new_binary_path: str):
        self.old_binary = self._load_binary(old_binary_path)
        self.new_binary = self._load_binary(new_binary_path)
        self.extractor = SymbolicSignatureExtractor(self.old_binary)
        self.differ = SemanticDiffer()

    def _load_binary(self, path: str):
        # 加载二进制分析对象；此处为占位，实际使用时可替换为真实加载逻辑
        return None

    def analyze(self) -> VersionComparison:
        old_functions = self._extract_all_functions(self.old_binary)
        new_functions = self._extract_all_functions(self.new_binary)

        old_by_name = {f.function_name or hex(f.address): f for f in old_functions}
        new_by_name = {f.function_name or hex(f.address): f for f in new_functions}

        added = [f for name, f in new_by_name.items() if name not in old_by_name]
        removed = [f for name, f in old_by_name.items() if name not in new_by_name]
        changed = []
        patches = []
        one_day_candidates = []

        for name, old_func in old_by_name.items():
            if name in new_by_name:
                new_func = new_by_name[name]
                delta = self.differ.compare_functions(old_func, new_func)
                patches.append(delta)

                if delta.type == "security_fix" and delta.severity == "critical":
                    one_day_candidates.append(delta)

                if delta.type != "no_change":
                    changed.append((old_func, new_func))

        return VersionComparison(
            version_old=self._get_version(self.old_binary),
            version_new=self._get_version(self.new_binary),
            functions_added=added,
            functions_removed=removed,
            functions_changed=changed,
            patches=patches,
            one_day_candidates=one_day_candidates
        )

    def _extract_all_functions(self, binary) -> List[FunctionSemantics]:
        functions = []
        for func_addr in binary.get_function_addresses():
            try:
                func_sem = self.extractor.extract_function_signature(func_addr)
                functions.append(func_sem)
            except Exception:
                pass
        return functions

    def _get_version(self, binary) -> str:
        return "unknown"
