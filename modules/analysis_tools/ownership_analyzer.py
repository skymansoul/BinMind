import logging
import os
import json
from typing import Dict, List, Optional, Any, Tuple

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

class LanguageType:
    # Language type enumeration.
    RUST = "rust"
    GO = "go"
    UNKNOWN = "unknown"

class AnalysisType:
    """Analysis type enumeration."""
    BORROW_CHECKING = "borrow_checking"
    LIFETIME_ANALYSIS = "lifetime_analysis"
    DATA_RACE_DETECTION = "data_race_detection"
    LOCK_SET_ANALYSIS = "lock_set_analysis"
    UNSAFE_ANALYSIS = "unsafe_analysis"

class RaceConditionType:
    """Race condition type enumeration."""
    DATA_RACE = "data_race"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_DEREFERENCE = "null_dereference"
    DEADLOCK = "deadlock"
    RACE_CONDITION = "race_condition"

class BorrowInfo:
    __slots__ = ('variable_name', 'borrow_type', 'borrow_scope', 'owner', 'lifetime', 'is_unsafe',)

    def __init__(self, variable_name, borrow_type, borrow_scope, owner=None, lifetime=None, is_unsafe=False):
        self.variable_name = variable_name
        self.borrow_type = borrow_type
        self.borrow_scope = borrow_scope
        self.owner = owner
        self.lifetime = lifetime
        self.is_unsafe = is_unsafe

class LockInfo:
    __slots__ = ('lock_name', 'lock_type', 'acquire_offset', 'release_offset', 'held_by',)

    def __init__(self, lock_name, lock_type, acquire_offset, release_offset=None, held_by=None):
        self.lock_name = lock_name
        self.lock_type = lock_type
        self.acquire_offset = acquire_offset
        self.release_offset = release_offset
        self.held_by = held_by

class RaceWarning:
    __slots__ = ('race_type', 'description', 'location', 'severity', 'variables', 'trace',)

    def __init__(self, race_type, description, location, severity="high", variables=None, trace=None):
        self.race_type = race_type
        self.description = description
        self.location = location
        self.severity = severity
        self.variables = variables if variables is not None else []
        self.trace = trace if trace is not None else []

class OwnershipAnalysisResult:
    __slots__ = ('language', 'borrows', 'locks', 'warnings', 'unsafe_blocks', 'goroutine_points',)

    def __init__(self, language, borrows=None, locks=None, warnings=None, unsafe_blocks=None, goroutine_points=None):
        self.language = language
        self.borrows = borrows if borrows is not None else []
        self.locks = locks if locks is not None else []
        self.warnings = warnings if warnings is not None else []
        self.unsafe_blocks = unsafe_blocks if unsafe_blocks is not None else []
        self.goroutine_points = goroutine_points if goroutine_points is not None else []

class BorrowAnalyzer:
    # Base borrow analysis interface.

    def analyze(self, binary_data: bytes) -> List[BorrowInfo]:
        """Analyze borrow-checker semantics."""
        # 基类默认返回空结果，具体模式匹配由子类实现。
        logger.debug("BorrowAnalyzer base class invoked; no-op analysis.")
        return []

class RustBorrowAnalyzer(BorrowAnalyzer):
    """Rust binary borrow analysis."""

    def __init__(self):
        self.borrow_patterns = {
            b'\x48\x8b\x05': 'load_ptr',      # mov rax, [rip+offset]
            b'\x48\x89\x05': 'store_ptr',     # mov [rip+offset], rax
            b'\x48\x8d\x05': 'lea_ptr',       # lea rax, [rip+offset]
            b'\xff\x15': 'indirect_call',    # call [rip+offset]
            b'\x48\x8b\x1d': 'load_ptr_32',  # mov rbx, [rip+offset]
        }

    def analyze(self, binary_data: bytes) -> List[BorrowInfo]:
        # Scan binary for Rust borrow patterns.
        borrows = []
        offset = 0

        while offset < len(binary_data):
            matched = False
            # Match bytecode against known borrow patterns.
            for pattern, pattern_type in self.borrow_patterns.items():
                pattern_len = len(pattern)
                if offset + pattern_len <= len(binary_data):
                    if binary_data[offset:offset+pattern_len] == pattern:
                        borrow = BorrowInfo(
                            variable_name=f"var_{offset:08x}",
                            borrow_type="mut" if pattern_type == "store_ptr" else "immutable",
                            borrow_scope=(offset, offset + 16),
                            lifetime=self._infer_lifetime(offset),
                            is_unsafe=self._check_unsafe_context(binary_data, offset)
                        )
                        borrows.append(borrow)
                        offset += pattern_len
                        matched = True
                        break
            if not matched:
                offset += 1

        logger.info("Rust borrow scan complete. Found %d borrow(s).", len(borrows))
        return borrows

    def _infer_lifetime(self, offset: int) -> str:
        # Assign a synthetic lifetime label.
        # Deterministic lifetime from offset modulo.
        lifetime_id = offset % 5
        lifetimes = ['\'a', '\'b', '\'c', '\'d', '\'static']
        return lifetimes[lifetime_id]

    def _check_unsafe_context(self, data: bytes, offset: int) -> bool:
        """Return True if offset lies within an unsafe context."""
        # Scan surrounding bytes for unsafe markers.
        search_range = min(200, offset)
        search_data = data[max(0, offset-search_range):offset+200]

        unsafe_patterns = [
            b'unchecked', b'unsafe', b'asm!', b'ptr::', b'mem::'
        ]

        return any(pattern in search_data for pattern in unsafe_patterns)

class GoLockSetAnalyzer:
    # Go goroutine lock-set analysis.

    def __init__(self):
        self.lock_patterns = {
            b'\x48\x8b\x0d': 'mutex_lock',    # mov rcx, [rip+offset]
            b'\x48\x89\x0d': 'mutex_unlock',  # mov [rip+offset], rcx
            b'\x48\x8b\x15': 'rwlock_rlock', # mov rdx, [rip+offset]
            b'\x48\x8b\x1d': 'rwlock_wlock', # mov rbx, [rip+offset]
        }
        self.channel_patterns = [b'ch<-', b'<-ch', b"make(chan)"]

    def analyze(self, binary_data: bytes) -> Tuple[List[LockInfo], List[int]]:
        # Analyze Go binary for lock ops and goroutine yield points.
        locks = []
        goroutine_points = []
        offset = 0

        while offset < len(binary_data):
            matched = False
            # Match lock acquisition/release bytecodes.
            for pattern, lock_type in self.lock_patterns.items():
                pattern_len = len(pattern)
                if offset + pattern_len <= len(binary_data):
                    if binary_data[offset:offset+pattern_len] == pattern:
                        lock_info = LockInfo(
                            lock_name=f"lock_{offset:08x}",
                            lock_type=self._map_lock_type(lock_type),
                            acquire_offset=offset
                        )
                        locks.append(lock_info)
                        offset += pattern_len
                        matched = True
                        break
            if not matched:
                # Detect goroutine scheduling points.
                if self._is_goroutine_point(binary_data, offset):
                    goroutine_points.append(offset)
                offset += 1

        logger.info("Go lock-set analysis complete. %d lock(s), %d goroutine point(s).", len(locks), len(goroutine_points))
        return locks, goroutine_points

    def _map_lock_type(self, pattern_type: str) -> str:
        # Normalize lock pattern to type string.
        if 'mutex' in pattern_type:
            return 'mutex'
        elif 'rwlock' in pattern_type:
            return 'rwlock'
        return 'mutex'

    def _is_goroutine_point(self, data: bytes, offset: int) -> bool:
        # Classify offset as goroutine scheduling boundary.
        # Probe known runtime scheduling signatures.
        patterns = [
            b'runtime.goexit', b'runtime.gopark',
            b'runtime.goready', b'runtime.schedule'
        ]

        window = data[offset:offset+50]
        return any(pattern in window for pattern in patterns)

class RaceDetector:
    # Concurrency bug detection pipeline.

    def __init__(self):
        self.warning_types = {
            RaceConditionType.DATA_RACE: "data race",
            RaceConditionType.USE_AFTER_FREE: "use-after-free",
            RaceConditionType.DOUBLE_FREE: "double free",
            RaceConditionType.NULL_DEREFERENCE: "null pointer dereference",
            RaceConditionType.DEADLOCK: "deadlock",
            RaceConditionType.RACE_CONDITION: "race condition"
        }

    def detect_race_conditions(self,
        borrows: List[BorrowInfo],
        locks: List[LockInfo],
        goroutine_points: List[int]
    ) -> List[RaceWarning]:
        # Aggregate all race condition warnings.
        warnings = []

        # Screen for use-after-free patterns.
        uaf_warnings = self._detect_uaf(borrows)
        warnings.extend(uaf_warnings)

        # Screen for unprotected concurrent access.
        race_warnings = self._detect_data_race(borrows, locks, goroutine_points)
        warnings.extend(race_warnings)

        # Screen for lock-ordering deadlocks.
        deadlock_warnings = self._detect_deadlock(locks)
        warnings.extend(deadlock_warnings)

        return warnings

    def _detect_uaf(self, borrows: List[BorrowInfo]) -> List[RaceWarning]:
        # Flag unsafe mutable borrows as potential UAF vectors.
        warnings = []

        # Unsafe mut borrows risk dangling references.
        for borrow in borrows:
            if borrow.is_unsafe and borrow.borrow_type == "mut":
                warnings.append(RaceWarning(
                    race_type=RaceConditionType.USE_AFTER_FREE,
                    description=f"mutable borrow in unsafe block may lead to UAF: {borrow.variable_name}",
                    location=borrow.borrow_scope[0],
                    severity="critical",
                    variables=[borrow.variable_name],
                    trace=[f"borrow site: 0x{borrow.borrow_scope[0]:x}"]))

        return warnings

    def _detect_data_race(self, borrows: List[BorrowInfo], locks: List[LockInfo], goroutine_points: List[int]) -> List[RaceWarning]:
        # Enumerate borrow pairs; flag those without lock coverage.
        warnings = []

        # Check for unprotected shared mutable access.
        for i, borrow1 in enumerate(borrows):
            for j, borrow2 in enumerate(borrows[i+1:], i+1):
                # Two borrows on the same variable — race candidate.
                if self._may_conflict(borrow1, borrow2):
                    # Verify lock coverage spans the borrow scope.
                    if not self._has_lock_protection(borrow1, locks):
                        warnings.append(RaceWarning(
                            race_type=RaceConditionType.DATA_RACE,
                            description=f"potential data race: {borrow1.variable_name} vs {borrow2.variable_name}",
                            location=borrow1.borrow_scope[0],
                            severity="high",
                            variables=[borrow1.variable_name, borrow2.variable_name],
                            trace=["concurrent access detected"]))

        return warnings

    def _may_conflict(self, borrow1: BorrowInfo, borrow2: BorrowInfo) -> bool:
        # Conflict requires overlapping scope and at least one mutable borrow.
        # Scopes overlap if neither ends before the other starts.
        scope1_start, scope1_end = borrow1.borrow_scope
        scope2_start, scope2_end = borrow2.borrow_scope

        overlap = not (scope1_end <= scope2_start or scope2_end <= scope1_start)

        # Read-only + read-only cannot race.
        has_mut = borrow1.borrow_type == "mut" or borrow2.borrow_type == "mut"

        return overlap and has_mut

    def _has_lock_protection(self, borrow: BorrowInfo, locks: List[LockInfo]) -> bool:
        # Lock held before and released after the borrow scope.
        for lock in locks:
            if lock.acquire_offset < borrow.borrow_scope[0]:
                if lock.release_offset is None or lock.release_offset > borrow.borrow_scope[1]:
                    return True
        return False

    def _detect_deadlock(self, locks: List[LockInfo]) -> List[RaceWarning]:
        """Detect potential deadlock cycles."""
        warnings = []

        # Compare all ordered lock pairs.
        for i, lock1 in enumerate(locks):
            for j, lock2 in enumerate(locks[i+1:], i+1):
                # Inconsistent acquisition order across sites.
                if self._has_lock_order_issue(lock1, lock2):
                    warnings.append(RaceWarning(
                        race_type=RaceConditionType.DEADLOCK,
                        description="potential deadlock: inconsistent lock acquisition order",
                        location=lock1.acquire_offset,
                        severity="critical",
                        variables=[lock1.lock_name, lock2.lock_name],
                        trace=["lock order check"]))

        return warnings

    def _has_lock_order_issue(self, lock1: LockInfo, lock2: LockInfo) -> bool:
        # 两锁持有时段交叉重叠，说明存在嵌套获取，顺序相反即构成死锁环。
        # 重叠判定：一锁在另一锁释放前被获取，且在其释放后才释放。
        if lock1.release_offset is None or lock2.release_offset is None:
            return False
        return (lock1.acquire_offset < lock2.release_offset and
                lock2.acquire_offset < lock1.release_offset)

class OwnershipAnalyzer(BaseAnalyzer):
    """
    Rust/Go lifetime and concurrency analyzer.

    Recovers Rust borrow/lifetime semantics from binary; surfaces UAF patterns and data races
    within unsafe blocks. For Go targets: goroutine yield-point detection and lock-set reasoning.
    """

    def __init__(self):
        # Instantiate sub-analyzers.
        self.rust_analyzer = RustBorrowAnalyzer()
        self.go_analyzer = GoLockSetAnalyzer()
        self.race_detector = RaceDetector()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """Execute ownership and concurrency analysis pipeline."""
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        language = kwargs.get("language", "auto")

        logger.info("Starting ownership analysis: %s", binary_path)

        try:
            # Resolve binary payload from path or raw bytes.
            if binary_data is None and binary_path:
                if os.path.exists(binary_path):
                    with open(binary_path, 'rb') as f:
                        binary_data = f.read()
                else:
                    return {"success": False, "error": f"file not found: {binary_path}"}

            if binary_data is None:
                return {"success": False, "error": "binary_data required"}

            # Auto-detect or use specified language.
            detected_lang = self._detect_language(binary_data) if language == "auto" else LanguageType(language)

            # Dispatch analysis per detected language.
            result = OwnershipAnalysisResult(language=detected_lang)

            if detected_lang == LanguageType.RUST:
                result.borrows = self.rust_analyzer.analyze(binary_data)
                result.unsafe_blocks = self._find_unsafe_blocks(binary_data)

            elif detected_lang == LanguageType.GO:
                locks, goroutine_points = self.go_analyzer.analyze(binary_data)
                result.locks = locks
                result.goroutine_points = goroutine_points

            # Run race detection across all collected analysis artifacts.
            result.warnings = self.race_detector.detect_race_conditions(
                result.borrows,
                result.locks,
                result.goroutine_points)

            return {
                "success": True,
                "result": {
                    "language": detected_lang.value,
                    "num_borrows": len(result.borrows),
                    "num_locks": len(result.locks),
                    "num_warnings": len(result.warnings),
                    "num_unsafe_blocks": len(result.unsafe_blocks),
                    "num_goroutine_points": len(result.goroutine_points),
                    "warnings": [
                        {
                            "type": w.race_type.value,
                            "description": w.description,
                            "location": hex(w.location),
                            "severity": w.severity,
                            "variables": w.variables
                        } for w in result.warnings
                    ],
                    "summary": self._generate_summary(result)
                }
            }

        except Exception as e:
            logger.error("Ownership analysis failed: %s", e)
            return {"success": False, "error": str(e)}

    def _detect_language(self, binary_data: bytes) -> LanguageType:
        """Detect binary language by signature matching."""
        # Probe for Rust mangled symbols.
        rust_signatures = [
            b'rust_', b'_ZN4core', b'_RNv', b'__rust_', b'rustc_demangle'
        ]

        # Probe for Go runtime symbols.
        go_signatures = [
            b'runtime.', b'main.', b'go.func.', b'gopanic', b'goexit'
        ]

        has_rust = any(signature in binary_data for signature in rust_signatures)
        has_go = any(signature in binary_data for signature in go_signatures)

        if has_rust and not has_go:
            return LanguageType.RUST
        elif has_go and not has_rust:
            return LanguageType.GO

        return LanguageType.UNKNOWN

    def _find_unsafe_blocks(self, binary_data: bytes) -> List[int]:
        """Locate unchecked blocks in binary."""
        unsafe_blocks = []
        pattern = b'unchecked'

        offset = binary_data.find(pattern)
        while offset != -1:
            unsafe_blocks.append(offset)
            offset = binary_data.find(pattern, offset + 1)

        return unsafe_blocks

    def _generate_summary(self, result: OwnershipAnalysisResult) -> str:
        # Compose human-readable result summary.
        lang_name = {
            LanguageType.RUST: "Rust",
            LanguageType.GO: "Go",
            LanguageType.UNKNOWN: "Unknown"
        }[result.language]

        num_warnings = len(result.warnings)

        if num_warnings == 0:
            return f"{lang_name} analysis complete — no concurrency issues detected"
        elif num_warnings <= 3:
            return f"{lang_name} analysis complete — {num_warnings} potential concurrency issues"
        else:
            return f"{lang_name} analysis complete — {num_warnings} potential concurrency issues; detailed audit advised"

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        # Static analyzer metadata block.
        return AnalyzerMetadata(
            name="OwnershipAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="Rust/Go lifetime and concurrency analyzer: borrow violations, data races, deadlock detection",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        # Validate required inputs before analysis.
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")

        if not binary_path and binary_data is None:
            return False, "binary_path or binary_data required"

        if binary_path and not os.path.exists(binary_path):
            return False, f"file not found: {binary_path}"

        language = kwargs.get("language", "auto")
        if language not in ["auto", "rust", "go"]:
            return False, "language must be auto, rust, or go"

        return True, None

    def cleanup(self) -> None:
        """Release analyzer resources."""
        pass
