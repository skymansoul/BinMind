import logging, os, json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class LanguageType(Enum):
    RUST = "rust"
    GO = "go"
    CXX = "cxx"
    UNKNOWN = "unknown"

class AnalysisType:
    BORROW_CHECKING = "borrow_checking"; LIFETIME_ANALYSIS = "lifetime_analysis"
    DATA_RACE_DETECTION = "data_race_detection"; LOCK_SET_ANALYSIS = "lock_set_analysis"
    UNSAFE_ANALYSIS = "unsafe_analysis"

class RaceConditionType:
    DATA_RACE = "data_race"; USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"; NULL_DEREFERENCE = "null_dereference"
    DEADLOCK = "deadlock"; RACE_CONDITION = "race_condition"

class BorrowInfo:
    __slots__ = ('variable_name','borrow_type','borrow_scope','owner','lifetime','is_unsafe',)
    def __init__(self, variable_name, borrow_type, borrow_scope, owner=None,
                 lifetime=None, is_unsafe=False):
        self.variable_name = variable_name; self.borrow_type = borrow_type
        self.borrow_scope = borrow_scope; self.owner = owner
        self.lifetime = lifetime; self.is_unsafe = is_unsafe

class LockInfo:
    __slots__ = ('lock_name','lock_type','acquire_offset','release_offset','held_by',)
    def __init__(self, lock_name, lock_type, acquire_offset, release_offset=None, held_by=None):
        self.lock_name = lock_name; self.lock_type = lock_type
        self.acquire_offset = acquire_offset; self.release_offset = release_offset
        self.held_by = held_by

class RaceWarning:
    __slots__ = ('race_type','description','location','severity','variables','trace',)
    def __init__(self, race_type, description, location, severity="high",
                 variables=None, trace=None):
        self.race_type = race_type; self.description = description
        self.location = location; self.severity = severity
        self.variables = variables if variables is not None else []
        self.trace = trace if trace is not None else []

class OwnershipAnalysisResult:
    __slots__ = ('language','borrows','locks','warnings','unsafe_blocks','goroutine_points',)
    def __init__(self, language, borrows=None, locks=None, warnings=None,
                 unsafe_blocks=None, goroutine_points=None):
        self.language = language
        self.borrows = borrows if borrows is not None else []
        self.locks = locks if locks is not None else []
        self.warnings = warnings if warnings is not None else []
        self.unsafe_blocks = unsafe_blocks if unsafe_blocks is not None else []
        self.goroutine_points = goroutine_points if goroutine_points is not None else []

class BorrowAnalyzer:
    def analyze(self, binary_data: bytes) -> List[BorrowInfo]: pass

class RustBorrowAnalyzer(BorrowAnalyzer):
    def __init__(self):
        self.borrow_patterns = {
            b'\x48\x8b\x05': 'load_ptr', b'\x48\x89\x05': 'store_ptr',
            b'\x48\x8d\x05': 'lea_ptr', b'\xff\x15': 'indirect_call',
            b'\x48\x8b\x1d': 'load_ptr_32'}
    def analyze(self, binary_data: bytes) -> List[BorrowInfo]:
        borrows = []; offset = 0
        while offset < len(binary_data):
            matched = False
            for pat, ptype in self.borrow_patterns.items():
                if offset + len(pat) <= len(binary_data):
                    if binary_data[offset:offset+len(pat)] == pat:
                        borrows.append(BorrowInfo(
                            variable_name=f"var_{offset:08x}",
                            borrow_type="mut" if ptype == "store_ptr" else "immutable",
                            borrow_scope=(offset, offset + 16),
                            lifetime=self._infer_lifetime(offset),
                            is_unsafe=self._check_unsafe_context(binary_data, offset)))
                        offset += len(pat); matched = True; break
            if not matched: offset += 1
        logger.info("Rust borrow scan complete. Found %d borrow(s).", len(borrows))
        return borrows
    def _infer_lifetime(self, offset: int) -> str:
        return ["'a","'b","'c","'d","'static"][offset % 5]
    def _check_unsafe_context(self, data: bytes, offset: int) -> bool:
        sr = min(200, offset); sd = data[max(0, offset-sr):offset+200]
        return any(p in sd for p in [b'unchecked',b'unsafe',b'asm!',b'ptr::',b'mem::'])

class GoLockSetAnalyzer:
    def __init__(self):
        self.lock_patterns = {
            b'\x48\x8b\x0d': 'mutex_lock', b'\x48\x89\x0d': 'mutex_unlock',
            b'\x48\x8b\x15': 'rwlock_rlock', b'\x48\x8b\x1d': 'rwlock_wlock'}
        self.channel_patterns = [b'ch<-', b'<-ch', b"make(chan)"]
    def analyze(self, binary_data: bytes) -> Tuple[List[LockInfo], List[int]]:
        locks = []; goroutine_points = []; offset = 0
        while offset < len(binary_data):
            matched = False
            for pat, ltype in self.lock_patterns.items():
                if offset + len(pat) <= len(binary_data):
                    if binary_data[offset:offset+len(pat)] == pat:
                        locks.append(LockInfo(
                            lock_name=f"lock_{offset:08x}",
                            lock_type=self._map_lock_type(ltype),
                            acquire_offset=offset))
                        offset += len(pat); matched = True; break
            if not matched:
                if self._is_goroutine_point(binary_data, offset):
                    goroutine_points.append(offset)
                offset += 1
        logger.info("Go lock-set: %d lock(s), %d goroutine point(s).", len(locks), len(goroutine_points))
        return locks, goroutine_points
    def _map_lock_type(self, pt: str) -> str:
        return 'mutex' if 'mutex' in pt else 'rwlock' if 'rwlock' in pt else 'mutex'
    def _is_goroutine_point(self, data: bytes, offset: int) -> bool:
        return any(p in data[offset:offset+50]
                   for p in [b'runtime.goexit', b'runtime.gopark',
                             b'runtime.goready', b'runtime.schedule'])

class RaceDetector:
    def __init__(self):
        self.warning_types = {RaceConditionType.DATA_RACE: "data race",
                              RaceConditionType.USE_AFTER_FREE: "use-after-free",
                              RaceConditionType.DOUBLE_FREE: "double free",
                              RaceConditionType.DEADLOCK: "deadlock"}

    def detect_race_conditions(self, borrows: List[BorrowInfo],
                                locks: List[LockInfo],
                                goroutine_points: List[int]) -> List[RaceWarning]:
        warnings = []
        warnings.extend(self._detect_uaf(borrows))
        warnings.extend(self._detect_data_race(borrows, locks, goroutine_points))
        warnings.extend(self._detect_deadlock(locks))
        return warnings

    def _detect_uaf(self, borrows: List[BorrowInfo]) -> List[RaceWarning]:
        w = []
        for b in borrows:
            if b.is_unsafe and b.borrow_type == "mut":
                w.append(RaceWarning(race_type=RaceConditionType.USE_AFTER_FREE,
                    description=f"mutable borrow in unsafe block: {b.variable_name}",
                    location=b.borrow_scope[0], severity="critical",
                    variables=[b.variable_name]))
        return w

    def _detect_data_race(self, borrows, locks, goroutine_points) -> List[RaceWarning]:
        w = []; n = len(borrows); i = 0
        while i < n:
            j = i + 1
            while j < n:
                if self._may_conflict(borrows[i], borrows[j]):
                    if not self._has_lock_protection(borrows[i], locks):
                        w.append(RaceWarning(race_type=RaceConditionType.DATA_RACE,
                            description=f"potential data race: {borrows[i].variable_name} vs {borrows[j].variable_name}",
                            location=borrows[i].borrow_scope[0], severity="high",
                            variables=[borrows[i].variable_name, borrows[j].variable_name]))
                j += 1
            i += 1
        return w

    def _may_conflict(self, b1, b2) -> bool:
        return not (b1.borrow_scope[1] <= b2.borrow_scope[0] or b2.borrow_scope[1] <= b1.borrow_scope[0]) \
               and (b1.borrow_type == "mut" or b2.borrow_type == "mut")

    def _has_lock_protection(self, borrow, locks) -> bool:
        for l in locks:
            if l.acquire_offset < borrow.borrow_scope[0]:
                if l.release_offset is None or l.release_offset > borrow.borrow_scope[1]:
                    return True
        return False

    def _detect_deadlock(self, locks) -> List[RaceWarning]:
        w = []; n = len(locks); i = 0
        while i < n:
            j = i + 1
            while j < n:
                if locks[i].acquire_offset < locks[j].acquire_offset:
                    w.append(RaceWarning(race_type=RaceConditionType.DEADLOCK,
                        description="potential deadlock: inconsistent lock order",
                        location=locks[i].acquire_offset, severity="critical",
                        variables=[locks[i].lock_name, locks[j].lock_name]))
                j += 1
            i += 1
        return w


class OwnershipAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.rust_analyzer = RustBorrowAnalyzer(); self.go_analyzer = GoLockSetAnalyzer()
        self.race_detector = RaceDetector()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        binary_path = kwargs.get("binary_path"); binary_data = kwargs.get("binary_data")
        language = kwargs.get("language", "auto")
        logger.info("Starting ownership analysis: %s", binary_path)
        try:
            if binary_data is None and binary_path:
                if os.path.isfile(binary_path):
                    with open(binary_path, 'rb') as f: binary_data = f.read()
                else: return {"success": False, "error": f"文件不存在: {binary_path}"}
            if binary_data is None: return {"success": False, "error": "binary_data required"}
            detected_lang = self._detect_language(binary_data) if language == "auto" else LanguageType(language)
            result = OwnershipAnalysisResult(language=detected_lang)
            if detected_lang == LanguageType.RUST:
                result.borrows = self.rust_analyzer.analyze(binary_data)
                result.unsafe_blocks = self._find_unsafe_blocks(binary_data)
            elif detected_lang == LanguageType.GO:
                locks, goroutine_points = self.go_analyzer.analyze(binary_data)
                result.locks = locks; result.goroutine_points = goroutine_points
            result.warnings = self.race_detector.detect_race_conditions(
                result.borrows, result.locks, result.goroutine_points)
            return {"success": True, "result": {
                "language": detected_lang.value, "num_borrows": len(result.borrows),
                "num_locks": len(result.locks), "num_warnings": len(result.warnings),
                "num_unsafe_blocks": len(result.unsafe_blocks),
                "num_goroutine_points": len(result.goroutine_points),
                "warnings": [{"type": w.race_type, "description": w.description,
                              "location": hex(w.location), "severity": w.severity,
                              "variables": w.variables} for w in result.warnings],
                "summary": self._generate_summary(result)}}
        except Exception as e:
            logger.error("Ownership analysis failed: %s", e)
            return {"success": False, "error": str(e)}

    def _detect_language(self, binary_data: bytes):
        rust_sigs = [b'rust_', b'_ZN4core', b'_RNv', b'__rust_', b'rustc_demangle']
        go_sigs = [b'runtime.', b'main.', b'go.func.', b'gopanic', b'goexit']
        has_rust = any(s in binary_data for s in rust_sigs)
        has_go = any(s in binary_data for s in go_sigs)
        if has_rust and not has_go: return LanguageType.RUST
        if has_go and not has_rust: return LanguageType.GO
        return LanguageType.UNKNOWN

    def _find_unsafe_blocks(self, data: bytes) -> List[int]:
        blocks = []; off = data.find(b'unchecked')
        while off != -1: blocks.append(off); off = data.find(b'unchecked', off + 1)
        return blocks

    def _generate_summary(self, result) -> str:
        lang_name = {LanguageType.RUST: "Rust", LanguageType.GO: "Go",
                     LanguageType.CXX: "C++", LanguageType.UNKNOWN: "Unknown"}
        nw = len(result.warnings)
        if nw == 0:
            return f"{lang_name[result.language]} 分析完成，未发现并发问题"
        return f"{lang_name[result.language]} 分析完成，共 {nw} 个潜在并发问题"

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(name="OwnershipAnalyzer", ver="1.0.0",
                                author="BinaryAnalysisPlatform",
                                at=AnalyzerType.STATIC,
                                desc="Rust/Go 内存所有权与并发缺陷静态分析")

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        bp = kwargs.get("binary_path"); bd = kwargs.get("binary_data")
        if not bp and bd is None: return False, "必须提供 binary_path 或 binary_data"
        if bp and not os.path.isfile(bp): return False, f"文件不存在: {bp}"
        lang = kwargs.get("language", "auto")
        if lang not in ["auto","rust","go","cxx"]: return False, "language 必须是 auto/rust/go/cxx 之一"
        return True, None

    def cleanup(self) -> None: pass
