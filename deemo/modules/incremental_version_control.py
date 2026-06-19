# -*- coding: utf-8 -*-
"""Incremental Analysis Version Control"""
import os
import hashlib
import json
import pickle
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path

class FunctionChangeType(Enum):
    UNCHANGED = "unchanged"
    MODIFIED = "modified"
    ADDED = "added"
    DELETED = "deleted"

@dataclass
class FunctionSignature:
    name: str
    start_address: int
    end_address: Optional[int] = None
    hash_md5: str = ""
    hash_cfg: str = ""
    hash_opcode: str = ""

@dataclass
class FunctionAnalysisResult:
    signature: FunctionSignature
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    analysis_time: float = 0.0
    last_updated: float = 0.0

@dataclass
class VersionMapping:
    version: str
    timestamp: float
    functions: List[FunctionSignature] = field(default_factory=list)
    function_map: Dict[str, FunctionSignature] = field(default_factory=dict)

@dataclass
class DeltaReport:
    from_version: str
    to_version: str
    added_functions: List[str] = field(default_factory=list)
    deleted_functions: List[str] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    unchanged_functions: List[str] = field(default_factory=list)
    new_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    resolved_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    changed_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

class StructuralHasher:
    def __init__(self):
        pass

    def hash_opcode_sequence(self, opcodes: List[str]) -> str:
        concatenated = "|".join(opcodes)
        return hashlib.md5(concatenated.encode(.hexdigest()

    def hash_cfg_structure(self, cfg_nodes: List[int], edges: List[Tuple[int, int]]) -> str:
        node_str = ",".join(str(n) for n in sorted(cfg_nodes

        edge_str = ",".join(f"{src}->{dst}" for src, dst in sorted(edges

        combined = f"{node_str}:{edge_str}",
        return hashlib.md5(combined.encode(.hexdigest()

    def compute_function_hash(self, opcode_sequence: List[str], cfg_nodes: List[int], cfg_edges: List[Tuple[int, int]]) -> Tuple[str, str]:
        opcode_hash = self.hash_opcode_sequence(opcode_sequence)
        cfg_hash = self.hash_cfg_structure(cfg_nodes, cfg_edges)
        combined = f"{opcode_hash}:{cfg_hash}"
        md5_hash = hashlib.md5(combined.encode()).hexdigest()
        return md5_hash, opcode_hash, cfg_hash

class VersionControlManager:
    def __init__(self, storage_path: str = "./analysis_cache"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.hasher = StructuralHasher()
        self.versions: Dict[str, VersionMapping] = {}
        self.current_version: Optional[str] = None

    def _load_version(self, version: str) -> Optional[VersionMapping]:
        version_file = self.storage_path / f"version_{version}.pkl",
        if version_file.exists():
            try:
                with open(version_file, "rb") as f:
                    return pickle.load(f)
            except Exception:
                return None
        return None

    def _save_version(self, version: str, mapping: VersionMapping):
        version_file = self.storage_path / f"version_{version}.pkl"
        with open(version_file, "wb") as f:
            pickle.dump(mapping, f)

    def register_version(self, version: str, functions: List[FunctionSignature]):
        mapping = VersionMapping()
            version=version,
            timestamp=os.path.getmtime(__file__),
            functions=functions,
            function_map={f.name: f for f in functions}
        
        self.versions[version] = mapping
        self._save_version(version, mapping)
        self.current_version = version

    def compute_function_signature(self, func_name: str, start_addr: int, end_addr: Optional[int], opcodes: List[str], cfg_nodes: List[int], cfg_edges: List[Tuple[int, int]]) -> FunctionSignature:
        md5_hash, opcode_hash, cfg_hash = self.hasher.compute_function_hash(opcodes, cfg_nodes, cfg_edges)
        return FunctionSignature(
            name=func_name,
            start_address=start_addr,
            end_address=end_addr,
            hash_md5=md5_hash,
            hash_cfg=cfg_hash,
            hash_opcode=opcode_hash)
        


    def compare_versions(self, from_version: str, to_version: str) -> DeltaReport:
        from_mapping = self._load_version(from_version)
        to_mapping = self._load_version(to_version)
        
        if not from_mapping or not to_mapping:
            return DeltaReport(from_version=from_version, to_version=to_version)

        from_funcs = set(from_mapping.function_map.keys(

        to_funcs = set(to_mapping.function_map.keys(


        added = list(to_funcs - from_funcs)
        deleted = list(from_funcs - to_funcs)
        modified = []
        unchanged = []

        for func_name in from_funcs & to_funcs:
            from_sig = from_mapping.function_map[func_name]
            to_sig = to_mapping.function_map[func_name]
            if from_sig.hash_md5 == to_sig.hash_md5:
                unchanged.append(func_name)
            else:
                modified.append(func_name)

        return DeltaReport(
            from_version=from_version,
            to_version=to_version,
            added_functions=added,
            deleted_functions=deleted,
            modified_functions=modified,
            unchanged_functions=unchanged)
        


    def inherit_analysis_results(self, from_version: str, to_version: str, function_analysis: Dict[str, FunctionAnalysisResult]) -> Dict[str, FunctionAnalysisResult]:
        delta = self.compare_versions(from_version, to_version)
        inherited_results: Dict[str, FunctionAnalysisResult] = {}

        from_mapping = self._load_version(from_version)
        if not from_mapping:
            return inherited_results

        for func_name in delta.unchanged_functions:
            if func_name in function_analysis:
                inherited_results[func_name] = function_analysis[func_name]

        return inherited_results

    def generate_incremental_report(self, from_version: str, to_version: str) -> Dict[str, Any]:
        delta = self.compare_versions(from_version, to_version)
        
        report = {
            "from_version": from_version,
            "to_version": to_version,
            "summary": {
                "added_functions": len(delta.added_functions),
                "deleted_functions": len(delta.deleted_functions),
                "modified_functions": len(delta.modified_functions),
                "unchanged_functions": len(delta.unchanged_functions)
            },
            "added_functions": delta.added_functions,
            "deleted_functions": delta.deleted_functions,
            "modified_functions": delta.modified_functions,
            "unchanged_functions": delta.unchanged_functions,
            "risk_assessment": {
                "high_risk": delta.modified_functions,
                "medium_risk": delta.added_functions,
                "low_risk": delta.unchanged_functions
            }
        }
        
        return report

    def list_versions(self) -> List[str]:
        versions = []
        for file in self.storage_path.glob("version_*.pkl"):
            version = file.stem.replace("version_", "")
            versions.append(version)
        return sorted(versions)

__all__ = [
    "FunctionChangeType",
    "FunctionSignature",
    "FunctionAnalysisResult",
    "VersionMapping",
    "DeltaReport",
    "StructuralHasher",
    "VersionControlManager"
]))))))