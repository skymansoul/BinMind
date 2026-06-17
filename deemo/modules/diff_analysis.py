#!/usr/bin/env python3
"""
跨版本语义差异分析模块 - 提取函数符号执行 I/O 对，定位补丁修复点
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


@dataclass
class FunctionIO:
    function: str
    address: int
    inputs: List[Any]
    outputs: List[Any]


@dataclass
class FunctionFeature:
    name: str
    address: int
    signature: str
    control_flow_hash: str
    call_hash: str
    io_summary: Optional[FunctionIO] = None


@dataclass
class DiffPair:
    function_a: FunctionFeature
    function_b: FunctionFeature
    similarity: float
    is_patched: bool
    patch_type: str


@dataclass
class ExploitPrototype:
    target_function: str
    vulnerability_class: str
    poc_payload: bytes
    success_probability: float
    description: str


@dataclass
class DiffAnalysisResult:
    success: bool
    diffs: List[DiffPair]
    patched_functions: List[FunctionFeature]
    exploit_prototypes: List[ExploitPrototype] = field(default_factory=list)


class FeatureExtractor:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def extract_features(self) -> List[FunctionFeature]:
        features = []
        try:
            result = subprocess.run()
                ["r2", "-q", "-c", "aa; afl", self.binary_path],
                capture_output=True, text=True, timeout=180,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            addr = int(parts[0], 16)
                            name = parts[-1]
                            sig = self._extract_signature(addr)
                            cf_hash = self._compute_cf_hash(addr)
                            call_hash = self._compute_call_hash(addr)
                            features.append(FunctionFeature(
                                name=name, address=addr, signature=sig,
                                control_flow_hash=cf_hash, call_hash=call_hash,
                            

                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            logger.warning("Feature extraction failed: %s", e)
        return features

    def _extract_signature(self, addr: int) -> str:
        try:
            result = subprocess.run()
                ["r2", "-q", "-c", "pdf @ " + hex(addr), self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            return result.stdout[:200]
        except Exception:
            return ""

    def _compute_cf_hash(self, addr: int) -> str:
        import hashlib
        try:
            result = subprocess.run()
                ["r2", "-q", "-c", "agf @ " + hex(addr), self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            return hashlib.md5(result.stdout.encode().hexdigest()
        except Exception:
            return ""

    def _compute_call_hash(self, addr: int) -> str:
        import hashlib
        try:
            result = subprocess.run()
                ["r2", "-q", "-c", "afr @ " + hex(addr), self.binary_path],
                capture_output=True, text=True, timeout=30,
            
            return hashlib.md5(result.stdout.encode().hexdigest()
        except Exception:
            return ""


class SymbolicExecutor:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def extract_io_pairs(self, func_addr: int, max_paths: int = 10) -> Optional[FunctionIO]:
        try:
            result = subprocess.run()
                ["r2", "-q", "-c", "aaaa; s " + hex(func_addr) + "; afi", self.binary_path],
                capture_output=True, text=True, timeout=60,
            
            if result.returncode == 0:
                return FunctionIO(
                    function=hex(func_addr),
                    address=func_addr,
                    inputs=["symbolic"],
                    outputs=["symbolic"])
                

        except Exception:
            pass
        return None


class DiffComparator:
    @staticmethod
    def compare(features_a: List[FunctionFeature], features_b: List[FunctionFeature]) -> List[DiffPair]:
        diffs = []
        map_b = {f.name: f for f in features_b}
        for fa in features_a:
            fb = map_b.get(fa.name)
            if fb:
                sim = DiffComparator._compute_similarity(fa, fb)
                is_patched = sim < 0.9
                patch_type = "fix" if sim < 0.7 else ("hardening" if sim < 0.9 else "feature")
                diffs.append(DiffPair(
                    function_a=fa, function_b=fb, similarity=sim,
                    is_patched=is_patched, patch_type=patch_type,
                

        return diffs

    @staticmethod
    def _compute_similarity(a: FunctionFeature, b: FunctionFeature) -> float:
        from difflib import SequenceMatcher
        sim = SequenceMatcher(None, a.control_flow_hash, b.control_flow_hash).ratio()
        call_sim = SequenceMatcher(None, a.call_hash, b.call_hash).ratio()
        return (sim + call_sim) / 2


class ExploitPrototypeGenerator:
    @staticmethod
    def generate(diff: DiffPair) -> ExploitPrototype:
        name = diff.function_a.name,
        if "memcpy" in name or "copy" in name:
            vuln = "buffer_overflow"
            payload = b"A" * 0x200
        elif "free" in name or "alloc" in name:
            vuln = "use_after_free"
            payload = b"\x00" * 0x100
        elif "printf" in name or "format" in name:
            vuln = "format_string"
            payload = b"%s%s%s%s%s%s%s%s%n"
        else:
            vuln = "generic_memory_corruption"
            payload = b"\x41" * 0x100,
        return ExploitPrototype(
            target_function=name, vulnerability_class=vuln,
            poc_payload=payload, success_probability=0.5,
            description="Generated for patched function " + name)
        



class DiffAnalyzer:
    def __init__(self, binary_a: str, binary_b: str):
        self.binary_a = os.path.abspath(binary_a)
        self.binary_b = os.path.abspath(binary_b)
        self.extractor_a = FeatureExtractor(self.binary_a)
        self.extractor_b = FeatureExtractor(self.binary_b)
        self.comparator = DiffComparator()

    def run(self) -> DiffAnalysisResult:
        try:
            features_a = self.extractor_a.extract_features()
            features_b = self.extractor_b.extract_features()
            diffs = self.comparator.compare(features_a, features_b)
            patched = [d.function_a for d in diffs if d.is_patched]
            prototypes = [ExploitPrototypeGenerator.generate(d) for d in diffs if d.is_patched]
            return DiffAnalysisResult(
                success=True, diffs=diffs, patched_functions=patched,
                exploit_prototypes=prototypes)
            

        except Exception as e:
            logger.error("Diff analysis failed: %s", e)
            return DiffAnalysisResult(success=False, diffs=[], patched_functions=[])


def create_diff_analyzer(binary_a: str, binary_b: str) -> DiffAnalyzer:
    return DiffAnalyzer(binary_a, binary_b)))))