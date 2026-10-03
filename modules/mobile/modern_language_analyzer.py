from enum import StrEnum
import re
import struct
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


class LanguageType(StrEnum):
    RUST = "rust"
    GO = "go"
    SWIFT = "swift"


@dataclass
class LanguageRuntimeInfo:
    name: str = ""
    state_size: Any = None
    resume_fn: Any = None
    drop_fn: Any = None
    alloc_fn: Any = None
    addresses: Any = None


@dataclass
class RustCoroutine:
    name: str = ""
    state_size: int = 0
    resume_fn: int = 0
    drop_fn: int = 0
    alloc_fn: int = 0
    addresses: list = field(default_factory=list)


@dataclass
class GoRoutine:
    goid: int = 0
    state: str = ""
    stack_base: int = 0
    stack_limit: int = 0
    start_pc: int = 0
    func_name: str = ""


@dataclass
class SwiftARCVulnerability:
    type: str
    severity: str
    description: str
    location: str
    possible_fix: str = ""

class RustCoroutineAnalyzer:
    """Rust无栈协程分析器。解析Rust二进制中的协程结构与状态机。"""

    COROUTINE_PATTERNS = [
        b'_ZN4core8coroutine',
        b'_ZN8alloc4sync',
        b'_ZN4rust17initializer',
        b'async fn',
        b'await',
    ]

    RESUME_SYM_PREFIX = '_ZN.*7resume'
    DROP_SYM_PREFIX = '_ZN.*3drop'
    STATE_SYM_PREFIX = '_ZN.*5state'

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.data = self._read_binary()
        self.coroutines: List[RustCoroutine] = []

    def _read_binary(self) -> bytes:
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return b''

    def find_coroutine_symbols(self) -> List[Dict[str, Any]]:
        symbols = []

        string_data = self.data.decode('utf-8', errors='ignore')

        resume_pattern = r'_ZN[0-9a-zA-Z_]+7resume[0-9a-zA-Z_]*'
        drop_pattern = r'_ZN[0-9a-zA-Z_]+3drop[0-9a-zA-Z_]*'

        for match in re.finditer(resume_pattern, string_data):
            symbols.append({
                'name': match.group(),
                'type': 'resume',
                'offset': match.start()
            })

        for match in re.finditer(drop_pattern, string_data):
            symbols.append({
                'name': match.group(),
                'type': 'drop',
                'offset': match.start()
            })

        async_patterns = [
            r'(?:impl.*(?:Future|Iterator).*\{)',
            r'(?:async\s+(?:fn|block))',
            r'(?:await\s+)',
            r'(?:poll\s*\()',
        ]

        for pattern in async_patterns:
            for match in re.finditer(pattern, string_data):
                symbols.append({
                    'name': f'async_0x{match.start():x}',
                    'type': 'async_marker',
                    'offset': match.start()
                })

        logger.info(f"Found {len(symbols)} coroutine-related symbols")
        return symbols

    def analyze_coroutines(self) -> List[RustCoroutine]:
        symbols = self.find_coroutine_symbols()

        resume_syms = [s for s in symbols if s['type'] == 'resume']

        for resume in resume_syms:
            name = self._demangle_symbol(resume['name'])

            coroutine = RustCoroutine(
                name=name or 'unknown',
                state_size=0,
                resume_fn=resume['offset'],
                drop_fn=0,
                alloc_fn=0,
                addresses=[resume['offset']]
            )

            for sym in symbols:
                if sym['offset'] != resume['offset']:
                    if 'drop' in sym['name'] or 'state' in sym['name']:
                        coroutine.addresses.append(sym['offset'])

            self.coroutines.append(coroutine)

        return self.coroutines

    def _demangle_symbol(self, mangled: str) -> Optional[str]:
        if not mangled.startswith('_ZN'):
            return None

        try:
            parts = []
            remaining = mangled[3:]

            while remaining:
                if not remaining[0].isdigit():
                    break

                length = ''
                i = 0
                while i < len(remaining) and remaining[i].isdigit():
                    length += remaining[i]
                    i += 1

                if not length:
                    break

                length = int(length)

                if i + length > len(remaining):
                    break

                name = remaining[i:i+length]
                parts.append(name)
                remaining = remaining[i+length:]

                if remaining and remaining[0] == 'E':
                    break

        except Exception:
            return mangled

    def detect_coroutine_vulnerabilities(self) -> List[Dict[str, Any]]:
        vulns = []

        for coro in self.coroutines:
            if coro.state_size > 10000:
                vulns.append({
                    'type': 'Large Coroutine State',
                    'severity': 'Medium',
                    'description': f'Coroutine {coro.name} state too large: {coro.state_size} bytes',
                    'location': f'Address 0x{coro.resume_fn:x}'
                })

            if coro.drop_fn == 0:
                vulns.append({
                    'type': 'Missing Drop Implementation',
                    'severity': 'Low',
                    'description': f'Coroutine {coro.name} missing drop impl, may leak resources',
                    'location': f'Address 0x{coro.resume_fn:x}'
                })

        return vulns


class GoRoutineAnalyzer:
    """Go协程调用图恢复分析器。解析Go二进制中的goroutine调度结构。"""

    GOROUTINE_PATTERNS = [
        b'runtime.g0',
        b'runtime.main',
        b'runtime.goexit',
        b'runtime.goroutine',
        b'runtime.schedule',
        b'runtime.execute',
        b'runtime.newproc',
        b'runtime.startm',
        b'runtime.wakep',
    ]

    GOROUTINE_STATES = {
        0: 'idle',
        1: 'running',
        2: 'system',
        3: 'waiting',
        4: 'moribund',
        5: 'dead',
        6: 'enqueue',
    }

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.data = self._read_binary()
        self.routines: List[GoRoutine] = []
        self.call_graph: Dict[int, List[int]] = defaultdict(list)

    def _read_binary(self) -> bytes:
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return b''

    def _verify_go_binary(self) -> bool:
        return b'Go build ID:' in self.data or b'go.buildid' in self.data

    def find_goroutine_functions(self) -> List[Dict[str, Any]]:
        functions = []

        patterns = [
            (b'runtime.main', 'runtime_main'),
            (b'runtime.goexit', 'runtime_goexit'),
            (b'runtime.newproc', 'runtime_newproc'),
            (b'runtime.schedule', 'runtime_schedule'),
            (b'runtime.execute', 'runtime_execute'),
            (b'runtime.startm', 'runtime_startm'),
            (b'runtime.wakep', 'runtime_wakep'),
            (b'runtime.ready', 'runtime_ready'),
            (b'runtime.stop', 'runtime_stop'),
            (b'runtime.acquire', 'runtime_acquire'),
            (b'runtime.release', 'runtime_release'),
        ]

        for pattern, name in patterns:
            offset = self.data.find(pattern)
            if offset != -1:
                functions.append({
                    'name': name,
                    'offset': offset,
                    'type': 'goroutine_scheduler' if 'runtime' in name else 'user'
                })

        logger.info(f"Found {len(functions)} goroutine-related functions")
        return functions

    def recover_call_graph(self) -> Dict[int, List[int]]:
        scheduler_functions = [
            b'runtime.schedule',
            b'runtime.execute',
            b'runtime.newproc',
            b'runtime.startm',
        ]

        for sched_fn in scheduler_functions:
            offset = self.data.find(sched_fn)
            if offset == -1:
                continue

            call_targets = []

            for target_fn in scheduler_functions:
                target_offset = self.data.find(target_fn)
                if target_offset != -1 and target_offset != offset:
                    call_targets.append(target_offset)

            if call_targets:
                self.call_graph[offset] = call_targets

        for i, routine in enumerate(self.routines):
            for sched_fn in scheduler_functions:
                offset = self.data.find(sched_fn)
                if offset != -1:
                    if routine.start_pc not in self.call_graph:
                        self.call_graph[routine.start_pc] = []
                    if offset not in self.call_graph[routine.start_pc]:
                        self.call_graph[routine.start_pc].append(offset)

        return dict(self.call_graph)

    def analyze_goroutines(self) -> List[GoRoutine]:
        if not self._verify_go_binary():
            logger.warning("File may not be a Go binary")

        functions = self.find_goroutine_functions()

        runtime_main = None
        for fn in functions:
            if fn['name'] == 'runtime_main':
                runtime_main = fn['offset']
                break

        for i, fn in enumerate(functions):
            if 'runtime' in fn['name']:
                routine = GoRoutine(
                    goid=i,
                    state='running' if fn['name'] == 'runtime_main' else 'waiting',
                    stack_base=0x0,
                    stack_limit=0,
                    start_pc=fn['offset'],
                    func_name=fn['name']
                )
                self.routines.append(routine)

        return self.routines

    def detect_go_vulnerabilities(self) -> List[Dict[str, Any]]:
        vulns = []

        newproc_offset = None
        for fn in self.find_goroutine_functions():
            if fn['name'] == 'runtime_newproc':
                newproc_offset = fn['offset']
                break

        if newproc_offset:
            context = self.data[max(0, newproc_offset-100):newproc_offset+100]
            if b'strcpy' in context or b'strcat' in context:
                vulns.append({
                    'type': 'Potential Goroutine Injection',
                    'severity': 'High',
                    'description': 'Dangerous string operation near goroutine creation function',
                    'location': f'Address 0x{newproc_offset:x}'
                })

        return vulns


class SwiftARCAnalyzer:
    """Swift ARC漏洞检测器。扫描Swift二进制中自动引用计数的缺陷模式。"""

    SWIFT_PATTERNS = [
        b'_TMp',
        b'_TMn',
        b'_TMf',
        b'_TtC',
        b'_TtS',
        b'_TtO',
        b'_swift_',
        b'retainCount',
        b'_swift_release',
        b'_swift_retain',
        b'_swift_bridgeObjectRetain',
    ]

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.data = self._read_binary()
        self.classes: List[Dict[str, Any]] = []
        self.arc_functions: List[Dict[str, Any]] = []

    def _read_binary(self) -> bytes:
        try:
            with open(self.binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary: {e}")
            return b''

    def find_swift_metadata(self) -> List[Dict[str, Any]]:
        metadata = []

        class_pattern = b'_TtC'
        offset = 0

        while True:
            offset = self.data.find(class_pattern, offset)
            if offset == -1:
                break

            end = offset + len(class_pattern)
            while end < len(self.data) and 0x41 <= self.data[end] <= 0x5A:
                end += 1

            class_name = self.data[offset:end].decode('utf-8', errors='ignore')

            metadata.append({
                'type': 'class',
                'name': class_name,
                'offset': offset
            })

            offset = end

        logger.info(f"Found {len(metadata)} Swift metadata items")
        return metadata

    def find_arc_functions(self) -> List[Dict[str, Any]]:
        arc_functions = []

        patterns = [
            (b'_swift_retain', 'retain'),
            (b'_swift_release', 'release'),
            (b'_swift_retainCount', 'retainCount'),
            (b'_swift_bridgeObjectRetain', 'bridgeRetain'),
            (b'_swift_bridgeObjectRelease', 'bridgeRelease'),
            (b'_swift_unknownObjectRetain', 'unknownRetain'),
            (b'_swift_unknownObjectRelease', 'unknownRelease'),
        ]

        for pattern, name in patterns:
            offset = 0
            while True:
                offset = self.data.find(pattern, offset)
                if offset == -1:
                    break

                arc_functions.append({
                    'name': name,
                    'full_name': pattern.decode('utf-8', errors='replace'),
                    'offset': offset
                })

                offset += len(pattern)

        self.arc_functions = arc_functions
        logger.info(f"Found {len(arc_functions)} ARC functions")
        return arc_functions

    def detect_arc_vulnerabilities(self) -> List[SwiftARCVulnerability]:
        vulns = []

        for metadata in self.find_swift_metadata():
            class_name = metadata['name']

            has_init = False
            has_deinit = False
            has_copy = False

            for arc_fn in self.arc_functions:
                fn_offset = arc_fn['offset']
                context_start = max(0, fn_offset - 50)
                context_end = min(len(self.data), fn_offset + 50)
                context = self.data[context_start:context_end]

                if class_name.encode() in context:
                    if 'init' in arc_fn['name']:
                        has_init = True
                    if 'deinit' in arc_fn['name'] or 'release' in arc_fn['name']:
                        has_deinit = True
                    if 'copy' in arc_fn['name']:
                        has_copy = True

            if not has_deinit and len(class_name) > 5:
                vulns.append(SwiftARCVulnerability(
                    type='Missing Deinitializer',
                    severity='Medium',
                    description=f'Class {class_name} may lack deinitializer, resource leak risk',
                    location=f'Metadata offset 0x{metadata["offset"]:x}',
                    possible_fix='Add deinitializer to release resources'
                ))

            if has_copy and not has_deinit:
                vulns.append(SwiftARCVulnerability(
                    type='Potential Memory Leak',
                    severity='Medium',
                    description=f'Class {class_name} has copy method but may lack deinitializer',
                    location=f'Metadata offset 0x{metadata["offset"]:x}',
                    possible_fix='Ensure copied objects are properly released'
                ))

        strong_ref_cycles = self._detect_strong_reference_cycles()
        vulns.extend(strong_ref_cycles)

        return vulns

    def _detect_strong_reference_cycles(self) -> List[SwiftARCVulnerability]:
        vulns = []

        class_pairs = []
        for metadata in self.find_swift_metadata():
            if metadata['type'] == 'class':
                class_pairs.append(metadata['name'])

        for i, class1 in enumerate(class_pairs):
            for class2 in class_pairs[i+1:]:
                if class1.lower() in class2.lower() or class2.lower() in class1.lower():
                    vulns.append(SwiftARCVulnerability(
                        type='Potential Strong Reference Cycle',
                        severity='High',
                        description=f'Classes {class1} and {class2} may form strong reference cycle',
                        location='Class definition area',
                        possible_fix='Use weak or unowned references to break cycle'
                    ))

        return vulns


def analyze_modern_language(binary_path: str, language: str = 'auto') -> Dict[str, Any]:
    """现代语言二进制分析入口，自动检测语言类型并分发分析器。"""
    if language == 'auto':
        with open(binary_path, 'rb') as f:
            data = f.read(1024)

        if b'Go build ID:' in data or b'_cgo_' in data:
            language = 'go'
        elif b'_swift_' in data or b'_TtC' in data:
            language = 'swift'
        elif b'_ZN4core8coroutine' in data or b'_ZN4rust' in data:
            language = 'rust'
        else:
            return {'error': 'Cannot auto-detect language type'}

    result = {
        'language': language,
        'analysis': {}
    }

    if language == 'rust':
        analyzer = RustCoroutineAnalyzer(binary_path)
        result['analysis'] = {
            'coroutines': analyzer.analyze_coroutines(),
            'vulnerabilities': analyzer.detect_coroutine_vulnerabilities()
        }
    elif language == 'go':
        analyzer = GoRoutineAnalyzer(binary_path)
        result['analysis'] = {
            'goroutines': analyzer.analyze_goroutines(),
            'call_graph': analyzer.recover_call_graph(),
            'vulnerabilities': analyzer.detect_go_vulnerabilities()
        }
    elif language == 'swift':
        analyzer = SwiftARCAnalyzer(binary_path)
        result['analysis'] = {
            'metadata': analyzer.find_swift_metadata(),
            'arc_functions': analyzer.find_arc_functions(),
            'vulnerabilities': [
                v.__dict__ for v in analyzer.detect_arc_vulnerabilities()
            ]
        }

    return result
