import os
import re
import hashlib
import logging
import json
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any

logger = logging.getLogger(__name__)

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logger.warning("ssdeep not installed, fuzzy hashing unavailable")

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False
    logger.warning("tlsh not installed, TLSH hashing unavailable")


class CloneType(str, Enum):
    EXACT = "exact"
    NEAR_MISS = "near_miss"
    SEMANTIC = "semantic"
    SYNTHETIC = "synthetic"
    UNKNOWN = "unknown"

class CloneConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


@dataclass
class FunctionInfo:
    name: str
    address: int
    size: int
    basic_blocks: int = 0
    instructions: int = 0
    calls: List[str] = field(default_factory=list)
    bytes_hash: str = ""
    fuzzy_hash: str = ""
    tlsh_hash: str = ""
    md5: str = ""
    control_flow: Dict[str, Any] = field(default_factory=dict)
    strings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloneMatch:
    clone_id: str
    clone_type: CloneType
    confidence: CloneConfidence
    confidence_score: float
    source_binary: str = ""
    source_function: str = ""
    source_address: int = 0
    source_size: int = 0
    target_binary: str = ""
    target_function: str = ""
    target_address: int = 0
    target_size: int = 0
    similarity_score: float = 0.0
    hash_match: bool = False
    fuzzy_match_score: float = 0.0
    likely_source: str = ""
    library_name: str = ""
    library_version: str = ""
    description: str = ""
    matched_bytes: int = 0
    total_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clone_id": self.clone_id,
            "clone_type": self.clone_type.value,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence_score,
            "source": {
                "binary": self.source_binary,
                "function": self.source_function,
                "address": hex(self.source_address),
                "size": self.source_size,
            },
            "target": {
                "binary": self.target_binary,
                "function": self.target_function,
                "address": hex(self.target_address),
                "size": self.target_size,
            },
            "similarity_score": self.similarity_score,
            "hash_match": self.hash_match,
            "likely_source": self.likely_source,
            "library_name": self.library_name,
            "library_version": self.library_version,
            "description": self.description,
        }


@dataclass
class CloneReport:
    source_binary: str
    target_binary: str
    analysis_time: float = 0.0
    total_functions_source: int = 0
    total_functions_target: int = 0
    total_clones_found: int = 0
    exact_clones: int = 0
    near_miss_clones: int = 0
    semantic_clones: int = 0
    clones: List[CloneMatch] = field(default_factory=list)
    reuse_graph: Dict[str, List[str]] = field(default_factory=dict)
    identified_libraries: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_binary": self.source_binary,
            "target_binary": self.target_binary,
            "analysis_time": f"{self.analysis_time:.2f}s",
            "statistics": {
                "total_functions_source": self.total_functions_source,
                "total_functions_target": self.total_functions_target,
                "total_clones_found": self.total_clones_found,
                "exact_clones": self.exact_clones,
                "near_miss_clones": self.near_miss_clones,
                "semantic_clones": self.semantic_clones,
            },
            "identified_libraries": self.identified_libraries,
            "clones": [c.to_dict() for c in self.clones],
        }


class CodeCloneDetector:

    KNOWN_LIBRARY_PATTERNS = {
        'libc': ['printf', 'scanf', 'malloc', 'free', 'strcpy', 'strlen',
                  'memcpy', 'memset', 'open', 'read', 'write', 'close'],
        'libstdc++': ['std::', '_Z', 'cxa_', '__cxa'],
        'libssl': ['SSL_', 'TLS_', 'BIO_'],
        'libcrypto': ['EVP_', 'RSA_', 'AES_'],
        'glibc': ['__libc_', 'dl_', '_dl_'],
    }

    LIBRARY_SIGNATURES = {
        'libc-2.31': ['GLIBC_2.31'],
        'libc-2.27': ['GLIBC_2.27'],
        'libc-2.23': ['GLIBC_2.23'],
    }

    def __init__(self,
        min_similarity: float = 0.7,
        fuzzy_threshold: int = 70,
        use_parallel: bool = True
    ):
        self.min_similarity = min_similarity
        self.fuzzy_threshold = fuzzy_threshold
        self.use_parallel = use_parallel

        self.function_db: Dict[str, Dict[str, FunctionInfo]] = {}
        self._cache: Dict[str, CloneReport] = {}

    def extract_functions(self,
        binary_path: str,
        functions: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, FunctionInfo]:
        logger.info("Extracting function info: %s", binary_path)

        binary_name = os.path.basename(binary_path)
        func_dict: Dict[str, FunctionInfo] = {}

        if functions:
            for func in functions:
                func_info = self._create_function_info(func)
                func_dict[func_info.name] = func_info
        else:
            logger.warning("No function info provided, external tool extraction needed")

        return func_dict

    def _create_function_info(self, func_data: Dict[str, Any]) -> FunctionInfo:
        name = func_data.get('name', 'unknown')
        address = func_data.get('address', 0)
        size = func_data.get('size', 0)

        bytes_data = func_data.get('bytes', b'')
        md5_hash = hashlib.md5(bytes_data).hexdigest()

        fuzzy_hash = ""
        if SSDEEP_AVAILABLE and bytes_data:
            fuzzy_hash = ssdeep.hash(bytes_data)

        tlsh_hash = ""
        if TLSH_AVAILABLE and len(bytes_data) > 256:
            try:
                tlsh_hash = tlsh.hash(bytes_data)
            except Exception:
                logger.debug("suppressed", exc_info=True)

        return FunctionInfo(
            name=name,
            address=address,
            size=size,
            basic_blocks=func_data.get('basic_blocks', 0),
            instructions=func_data.get('instructions', 0),
            calls=func_data.get('calls', []),
            bytes_hash=md5_hash,
            fuzzy_hash=fuzzy_hash,
            tlsh_hash=tlsh_hash,
            md5=md5_hash,
            control_flow=func_data.get('control_flow', {}),
            strings=func_data.get('strings', []),
            metadata=func_data.get('metadata', {}))

    def detect_clones(self,
        source_binary: str,
        target_binary: str,
        source_functions: Dict[str, FunctionInfo],
        target_functions: Dict[str, FunctionInfo]
    ) -> CloneReport:
        start_time = time.time()

        logger.info("Detecting code clones: %s vs %s", source_binary, target_binary)

        report = CloneReport(
            source_binary=source_binary,
            target_binary=target_binary,
        )

        report.total_functions_source = len(source_functions)
        report.total_functions_target = len(target_functions)

        self._match_by_hash(source_functions, target_functions, report)

        if SSDEEP_AVAILABLE:
            self._match_by_fuzzy_hash(source_functions, target_functions, report)

        if TLSH_AVAILABLE:
            self._match_by_tlsh(source_functions, target_functions, report)

        self._match_by_structural_features(source_functions, target_functions, report)

        self._match_by_call_patterns(source_functions, target_functions, report)

        self._identify_library_sources(report)

        report.analysis_time = time.time() - start_time

        logger.info("Clone detection complete: found %d clones", report.total_clones_found)

        return report

    def _match_by_hash(self,
        source: Dict[str, FunctionInfo],
        target: Dict[str, FunctionInfo],
        report: CloneReport
    ) -> None:
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                if src_func.md5 and src_func.md5 == tgt_func.md5:
                    clone = CloneMatch(
                        clone_id=f"exact_{src_name}_{tgt_name}",
                        clone_type=CloneType.EXACT,
                        confidence=CloneConfidence.HIGH,
                        confidence_score=1.0,
                        source_binary=report.source_binary,
                        source_function=src_name,
                        source_address=src_func.address,
                        source_size=src_func.size,
                        target_binary=report.target_binary,
                        target_function=tgt_name,
                        target_address=tgt_func.address,
                        target_size=tgt_func.size,
                        similarity_score=1.0,
                        hash_match=True,
                    )
                    report.clones.append(clone)
                    report.exact_clones += 1
                    report.total_clones_found += 1

    def _match_by_fuzzy_hash(self,
        source: Dict[str, FunctionInfo],
        target: Dict[str, FunctionInfo],
        report: CloneReport
    ) -> None:
        if not SSDEEP_AVAILABLE:
            return

        for src_name, src_func in source.items():
            if not src_func.fuzzy_hash:
                continue

            for tgt_name, tgt_func in target.items():
                if not tgt_func.fuzzy_hash:
                    continue

                if any(
                    c.source_function == src_name and c.target_function == tgt_name
                    for c in report.clones
                ):
                    continue

                try:
                    score = ssdeep.compare(
                        src_func.fuzzy_hash,
                        tgt_func.fuzzy_hash)

                    if score >= self.fuzzy_threshold:
                        clone_type = CloneType.NEAR_MISS if score >= 90 else CloneType.SYNTHETIC
                        confidence = self._score_to_confidence(score / 100.0)

                        clone = CloneMatch(
                            clone_id=f"fuzzy_{src_name}_{tgt_name}",
                            clone_type=clone_type,
                            confidence=confidence,
                            confidence_score=score / 100.0,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=score / 100.0,
                            fuzzy_match_score=score / 100.0,
                        )
                        report.clones.append(clone)
                        report.near_miss_clones += 1
                        report.total_clones_found += 1
                except Exception as e:
                    logger.debug("Fuzzy hash comparison failed: %s", e)

    def _match_by_tlsh(self,
        source: Dict[str, FunctionInfo],
        target: Dict[str, FunctionInfo],
        report: CloneReport
    ) -> None:
        if not TLSH_AVAILABLE:
            return

        for src_name, src_func in source.items():
            if not src_func.tlsh_hash:
                continue

            for tgt_name, tgt_func in target.items():
                if not tgt_func.tlsh_hash:
                    continue

                if any(
                    c.source_function == src_name and c.target_function == tgt_name
                    for c in report.clones
                ):
                    continue

                try:
                    score = 100 - tlsh.diff(src_func.tlsh_hash, tgt_func.tlsh_hash)
                    score = max(0, score)

                    if score >= self.min_similarity * 100:
                        clone = CloneMatch(
                            clone_id=f"tlsh_{src_name}_{tgt_name}",
                            clone_type=CloneType.SYNTHETIC,
                            confidence=self._score_to_confidence(score / 100.0),
                            confidence_score=score / 100.0,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=score / 100.0,
                        )
                        report.clones.append(clone)
                        report.semantic_clones += 1
                        report.total_clones_found += 1
                except Exception as e:
                    logger.debug("TLSH comparison failed: %s", e)

    def _match_by_structural_features(self,
        source: Dict[str, FunctionInfo],
        target: Dict[str, FunctionInfo],
        report: CloneReport
    ) -> None:
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                if any(
                    c.source_function == src_name and c.target_function == tgt_name
                    for c in report.clones
                ):
                    continue

                if src_func.size > 0 and tgt_func.size > 0:
                    size_ratio = min(src_func.size, tgt_func.size) / max(src_func.size, tgt_func.size)

                    bb_ratio = 1.0
                    if src_func.basic_blocks > 0 and tgt_func.basic_blocks > 0:
                        bb_ratio = min(src_func.basic_blocks, tgt_func.basic_blocks) / max(src_func.basic_blocks, tgt_func.basic_blocks)

                    inst_ratio = 1.0
                    if src_func.instructions > 0 and tgt_func.instructions > 0:
                        inst_ratio = min(src_func.instructions, tgt_func.instructions) / max(src_func.instructions, tgt_func.instructions)

                    combined_score = (size_ratio * 0.3 + bb_ratio * 0.4 + inst_ratio * 0.3)

                    if combined_score >= self.min_similarity and size_ratio >= 0.8:
                        clone = CloneMatch(
                            clone_id=f"struct_{src_name}_{tgt_name}",
                            clone_type=CloneType.SEMANTIC,
                            confidence=self._score_to_confidence(combined_score),
                            confidence_score=combined_score,
                            source_binary=report.source_binary,
                            source_function=src_name,
                            source_address=src_func.address,
                            source_size=src_func.size,
                            target_binary=report.target_binary,
                            target_function=tgt_name,
                            target_address=tgt_func.address,
                            target_size=tgt_func.size,
                            similarity_score=combined_score,
                        )
                        report.clones.append(clone)
                        report.semantic_clones += 1
                        report.total_clones_found += 1

    def _match_by_call_patterns(self,
        source: Dict[str, FunctionInfo],
        target: Dict[str, FunctionInfo],
        report: CloneReport
    ) -> None:
        for src_name, src_func in source.items():
            for tgt_name, tgt_func in target.items():
                if any(
                    c.source_function == src_name and c.target_function == tgt_name
                    for c in report.clones
                ):
                    continue

                if src_func.calls and tgt_func.calls:
                    src_calls_set = set(src_func.calls)
                    tgt_calls_set = set(tgt_func.calls)

                    if src_calls_set and tgt_calls_set:
                        intersection = len(src_calls_set & tgt_calls_set)
                        union = len(src_calls_set | tgt_calls_set)

                        if union > 0:
                            jaccard = intersection / union

                            if jaccard >= self.min_similarity:
                                clone = CloneMatch(
                                    clone_id=f"call_{src_name}_{tgt_name}",
                                    clone_type=CloneType.SEMANTIC,
                                    confidence=self._score_to_confidence(jaccard),
                                    confidence_score=jaccard,
                                    source_binary=report.source_binary,
                                    source_function=src_name,
                                    source_address=src_func.address,
                                    source_size=src_func.size,
                                    target_binary=report.target_binary,
                                    target_function=tgt_name,
                                    target_address=tgt_func.address,
                                    target_size=tgt_func.size,
                                    similarity_score=jaccard,
                                    description=f"Shared {intersection} call targets",
                                )
                                report.clones.append(clone)
                                report.semantic_clones += 1
                                report.total_clones_found += 1

    def _identify_library_sources(self, report: CloneReport) -> None:
        library_functions: Dict[str, Set[str]] = {}

        for clone in report.clones:
            for lib_name, patterns in self.KNOWN_LIBRARY_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() in clone.source_function.lower():
                        if lib_name not in library_functions:
                            library_functions[lib_name] = set()
                        library_functions[lib_name].add(clone.source_function)

                        clone.library_name = lib_name
                        clone.likely_source = f"{lib_name}:{clone.source_function}"
                        break

        report.identified_libraries = {
            lib: list(funcs) for lib, funcs in library_functions.items()
        }

    def _score_to_confidence(self, score: float) -> CloneConfidence:
        if score >= 0.9:
            return CloneConfidence.HIGH
        elif score >= 0.7:
            return CloneConfidence.MEDIUM
        elif score >= 0.5:
            return CloneConfidence.LOW
        else:
            return CloneConfidence.VERY_LOW

    def build_reuse_graph(self, report: CloneReport) -> Dict[str, List[str]]:
        graph: Dict[str, List[str]] = {}

        for clone in report.clones:
            key = f"{clone.source_binary}:{clone.source_function}"
            value = f"{clone.target_binary}:{clone.target_function}"

            if key not in graph:
                graph[key] = []
            graph[key].append(value)

        report.reuse_graph = graph
        return graph

    def search_in_database(self,
        function_hash: str,
        database_path: str
    ) -> List[Dict[str, Any]]:
        results = []

        if not os.path.exists(database_path):
            logger.warning("Database does not exist: %s", database_path)
            return results

        try:
            with open(database_path, 'r') as f:
                db = json.load(f)

            if function_hash in db:
                results.append(db[function_hash])
        except Exception as e:
            logger.error("Database search failed: %s", e)

        return results

    def export_to_json(self,
        report: CloneReport,
        output_path: str
    ) -> None:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info("Report exported: %s", output_path)


def detect_code_clones(source_binary: str, target_binary: str,
                       source_functions: List[Dict[str, Any]],
                       target_functions: List[Dict[str, Any]],
                       min_similarity: float = 0.7) -> CloneReport:
    detector = CodeCloneDetector(min_similarity=min_similarity)

    src_func_dict = {
        f['name']: detector._create_function_info(f)
        for f in source_functions
    }
    tgt_func_dict = {
        f['name']: detector._create_function_info(f)
        for f in target_functions
    }

    return detector.detect_clones(
        source_binary=source_binary,
        target_binary=target_binary,
        source_functions=src_func_dict,
        target_functions=tgt_func_dict)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    detector = CodeCloneDetector(min_similarity=0.7)

    source_funcs = {
        'printf': FunctionInfo(
            name='printf',
            address=0x401000,
            size=256,
            basic_blocks=5,
            instructions=20,
            calls=['write', 'strlen'],
            md5='abc123'),
        'malloc': FunctionInfo(
            name='malloc',
            address=0x401100,
            size=512,
            basic_blocks=10,
            instructions=45,
            md5='def456'),
    }

    target_funcs = {
        'my_printf': FunctionInfo(
            name='my_printf',
            address=0x501000,
            size=256,
            basic_blocks=5,
            instructions=20,
            calls=['write', 'strlen'],
            md5='abc123',
        ),
        'mem_alloc': FunctionInfo(
            name='mem_alloc',
            address=0x501100,
            size=500,
            basic_blocks=9,
            instructions=42,
            md5='ghi789'),
    }

    report = detector.detect_clones(
        source_binary='libc.so',
        target_binary='target_bin',
        source_functions=source_funcs,
        target_functions=target_funcs)

    print("\n" + "=" * 60)
    print("Code Clone Detection Results")
    print("=" * 60)
    print(f"Source binary: {report.source_binary}")
    print(f"Target binary: {report.target_binary}")
    print(f"Analysis time: {report.analysis_time:.2f}s")
    print(f"\nStatistics:")
    print(f"  Source functions: {report.total_functions_source}")
    print(f"  Target functions: {report.total_functions_target}")
    print(f"  Clones found: {report.total_clones_found}")
    print(f"  Exact matches: {report.exact_clones}")
    print(f"  Near-miss matches: {report.near_miss_clones}")
    print(f"  Semantic matches: {report.semantic_clones}")

    if report.identified_libraries:
        print(f"\nIdentified libraries:")
        for lib, funcs in report.identified_libraries.items():
            print(f"  {lib}: {funcs}")

    if report.clones:
        print(f"\nClone details:")
        for clone in report.clones:
            print(f"\n  [{clone.clone_type.value}] {clone.source_function} -> {clone.target_function}")
            print(f"    Confidence: {clone.confidence.value} ({clone.confidence_score:.2f})")
            print(f"    Similarity: {clone.similarity_score:.2f}")
