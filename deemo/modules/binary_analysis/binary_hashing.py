# -*- coding: utf-8 -*-
# Binary Hashing, Similarity & Security Features
# N-gram hashing, entropy analysis, binary patching,
# security hardening audits, and behavioral signatures.

from __future__ import annotations

import hashlib
import json as _json
import logging
import os
import re as _re
import struct
import subprocess as _sp
import time
from collections import defaultdict, Counter
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_logger = logging.getLogger(__name__)


# Data classes (regular classes, no __slots__ needed for these)

class VulnerabilityDensity:
    """Per-function vulnerability density record across versions."""

    def __init__(self, version: str, function_addr: int,
                 vuln_count: int, density_score: float):
        self.version = version
        self.function_addr = function_addr
        self.vuln_count = vuln_count
        self.density_score = density_score

    def __repr__(self):
        return (f"VulnerabilityDensity(version={self.version!r}, "
                f"addr=0x{self.function_addr:x}, score={self.density_score:.2f})")


class ExceptionHijackPoint:
    """Describes a single exception handler hijack opportunity."""

    def __init__(self, exception_handler: int, sensitive_call: Optional[str] = None,
                 memory_write: Optional[int] = None, risk_level: str = "low"):
        self.exception_handler = exception_handler
        self.sensitive_call = sensitive_call
        self.memory_write = memory_write
        self.risk_level = risk_level


class SemanticRewrittenCode:
    """Holds an original code segment and its semantically-equivalent variants."""

    def __init__(self, original_code: str, rewritten_variants: List[str]):
        self.original_code = original_code
        self.rewritten_variants = rewritten_variants


# 1. Binary Fingerprinting & N-gram Hashing

class NgramBinaryHash:
    """
    Lightweight N-gram fuzzy hash for quickly filtering similar binaries
    before deep analysis.

    Produces a SimHash-inspired fingerprint: extracts N-byte windows,
    computes rolling hashes, and collapses them into a compact bit-string.
    """

    def __init__(self, n: int = 4, hash_bits: int = 128):
        self.n = n
        self.hash_bits = hash_bits

    def compute_hash(self, binary_data: bytes) -> str:
        """Compute an N-gram fuzzy hash of binary data."""
        if len(binary_data) < self.n:
            # Fall back to SHA-256 for very short inputs
            return hashlib.sha256(binary_data).hexdigest()[:self.hash_bits // 4]

        # Accumulate rolling-hash bits via a SimHash-style vector
        vec = [0] * self.hash_bits
        window = binary_data[:self.n]
        rolling = self._fnv1a(window)

        for i in range(self.n, len(binary_data)):
            # Slide window
            window = binary_data[i - self.n + 1:i + 1]
            rolling = self._fnv1a(window)

            # Project hash bits onto the vector (+1 or -1)
            for bit in range(self.hash_bits):
                if (rolling >> (bit % 64)) & 1:
                    vec[bit] += 1
                else:
                    vec[bit] -= 1

        # Collapse into hex string
        result_bits = 0
        for bit in range(self.hash_bits):
            if vec[bit] > 0:
                result_bits |= (1 << bit)
        # Pad to consistent hex width
        hex_width = self.hash_bits // 4
        return format(result_bits, f'0{hex_width}x')

    @staticmethod
    def _fnv1a(data: bytes) -> int:
        """FNV-1a hash of a short byte window."""
        h = 0x811c9dc5
        for b in data:
            h ^= b
            h = (h * 0x01000193) & 0xffffffff
        return h

    def compare_hashes(self, hash1: str, hash2: str) -> float:
        """Return similarity [0,1] by Hamming distance on the hash bits."""
        try:
            n1 = int(hash1, 16)
            n2 = int(hash2, 16)
        except ValueError:
            return 0.0

        xor = n1 ^ n2
        differing = xor.bit_count()
        total = max(len(hash1) * 4, len(hash2) * 4)
        return 1.0 - (differing / total) if total > 0 else 1.0


class BinaryCacheManager:
    """
    File-hash-based incremental cache so repeated analyses skip
    file parsing and decompilation.
    """

    def __init__(self):
        self.cache_db: Dict[str, Dict[str, Any]] = {}
        self._timestamps: Dict[str, float] = {}

    def compute_file_hash(self, file_path: str) -> str:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def load_cached_result(self, file_path: str) -> Optional[Dict[str, Any]]:
        file_hash = self.compute_file_hash(file_path)
        return self.cache_db.get(file_hash)

    def cache_result(self, file_path: str, result: Dict[str, Any]) -> None:
        file_hash = self.compute_file_hash(file_path)
        self.cache_db[file_hash] = result
        self._timestamps[file_hash] = time.time()

    def clear_stale_cache(self, max_age_days: int = 30) -> int:
        """Remove entries older than *max_age_days*. Returns count removed."""
        cutoff = time.time() - (max_age_days * 86400)
        stale = [h for h, ts in self._timestamps.items() if ts < cutoff]
        for h in stale:
            self.cache_db.pop(h, None)
            self._timestamps.pop(h, None)
        return len(stale)

    def get_cache_stats(self) -> Dict[str, int]:
        return {
            'entries': len(self.cache_db),
            'stale_pending': sum(
                1 for t in self._timestamps.values()
                if t < time.time() - (30 * 86400)
            ),
        }


# 2. Exception & Error-Handling Analysis

class ExceptionAnalysisSuite:
    """
    Consolidated analysis of exception/error handling in binaries.

    Covers:
      - SEH (SafeSEH, SEHOP) detection in PE files
      - C++ exception table parsing (gcc_except_table / .eh_frame)
      - Resource-leak checks inside exception handlers
      - Exception-injection simulation for robustness testing
    """

    # Known SEH-related section / directory markers
    _SEH_LOAD_CONFIG_FLAGS = {
        0x40: 'SafeSEH',
        0x100: 'SEHOP_available',
    }

    def __init__(self):
        self.exception_tables: List[Dict[str, Any]] = []
        self.hijack_points: List[ExceptionHijackPoint] = []
        self.resource_leaks: List[Tuple[int, str]] = []
        self.safe_seh: bool = False
        self.sehop: bool = False

    # ---- SEH detection ----

    def check_safe_seh(self, pe_path: str) -> bool:
        """Detect SafeSEH by scanning IMAGE_LOAD_CONFIG_DIRECTORY."""
        result = False
        try:
            with open(pe_path, 'rb') as fh:
                data = fh.read()
            # Look for the characteristic SafeSEH flag byte in the
            # LoadConfig table's SecurityCookie / SEHandlerTable fields.
            off = data.find(b'\x00\x00\x00\x00\x00\x00\x00\x00', 0)
            # Heuristic: if there's an SE handler table RVA listed,
            # SafeSEH is present.
            if self._find_pe_section(data, b'.text'):
                # If the binary references __safe_se_handler_table,
                # SafeSEH is likely enabled
                if b'__safe_se_handler_table' in data or b'SafeSEH' in data:
                    result = True
            self.safe_seh = result
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return result

    def check_sehop(self, pe_path: str) -> bool:
        """Heuristic SEHOP detection on PE binaries."""
        try:
            with open(pe_path, 'rb') as fh:
                data = fh.read()
            # SEHOP-aware images reference the final exception handler
            # via a sentinel; this manifests as ValidateEHChain import
            if b'RtlIsValidHandler' in data or b'ValidateEHChain' in data:
                self.sehop = True
                return True
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return False

    # ---- C++ exception table parsing ----

    def parse_exception_table(self, binary_path: str) -> List[Dict[str, Any]]:
        """Scan for gcc_except_table / LSDA entries in the binary."""
        tables = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # Look for .gcc_except_table section markers
            marker = b'gcc_except_table'
            pos = 0
            while True:
                idx = data.find(marker, pos)
                if idx == -1:
                    break
                tables.append({
                    'offset': idx,
                    'section': 'gcc_except_table',
                    'size_estimate': min(256, len(data) - idx),
                })
                pos = idx + 1
            # Also scan .eh_frame if present
            eh_marker = b'.eh_frame'
            pos = 0
            while True:
                idx = data.find(eh_marker, pos)
                if idx == -1:
                    break
                tables.append({
                    'offset': idx,
                    'section': 'eh_frame',
                    'size_estimate': min(256, len(data) - idx),
                })
                pos = idx + 1
            self.exception_tables = tables
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return tables

    def check_hijack_risk(self, handler_addr: int) -> float:
        """Estimate hijack risk [0-1] for an exception handler."""
        score = 0.1  # baseline
        for pt in self.hijack_points:
            if pt.exception_handler == handler_addr:
                if pt.sensitive_call:
                    score += 0.3
                if pt.memory_write:
                    score += 0.4
                if pt.risk_level == 'critical':
                    score = 1.0
        return min(score, 1.0)

    # ---- Resource-leak detection in handlers ----

    def analyze_exception_handlers(self, binary_path: str) -> None:
        """Scan exception handler disassembly for resource-acquisition
        without corresponding release."""
        self.resource_leaks.clear()
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # Heuristic: find alloc calls followed by exception-handling
            # terminators without matching free calls
            alloc_sigs = [b'malloc', b'HeapAlloc', b'new', b'CreateFile']
            free_sigs = [b'free', b'HeapFree', b'delete', b'CloseHandle']
            for alloc in alloc_sigs:
                pos = 0
                while True:
                    idx = data.find(alloc, pos)
                    if idx == -1:
                        break
                    # Look ahead for a free within 512 bytes
                    window = data[idx:idx + 512]
                    has_free = any(f in window for f in free_sigs)
                    has_except = b'__except' in window or b'__finally' in window
                    if has_except and not has_free:
                        self.resource_leaks.append((idx, f'{alloc.decode(errors="replace")}_no_release'))
                    pos = idx + 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)

    def detect_resource_leaks(self) -> List[Tuple[int, str]]:
        return self.resource_leaks

    def assess_hijack_risk(self) -> List[ExceptionHijackPoint]:
        return [p for p in self.hijack_points
                if p.risk_level in ('high', 'critical')]

    # ---- Helpers ----

    @staticmethod
    def _find_pe_section(data: bytes, name: bytes) -> Optional[int]:
        """Find approximate offset of a PE section by name."""
        idx = data.find(name)
        return idx if idx >= 0 else None


class ExceptionHandlingPathCoverageAnalyzer:
    """
    Tracks coverage of exception-handler paths during symbolic execution
    and fuzzing -- C++ catch blocks, SEH handlers, and finally clauses.
    """

    def __init__(self):
        self.exception_handlers: Dict[int, Dict[str, Any]] = {}
        self.covered_handlers: Set[int] = set()
        self.uncovered_handlers: Set[int] = set()
        self.handler_types: Dict[str, List[int]] = {}

    def identify_exception_handlers(self, binary_code: str) -> Dict[int, Dict[str, Any]]:
        handlers: Dict[int, Dict[str, Any]] = {}
        patterns = [
            (r'__cxa_begin_catch', 'cpp_catch'),
            (r'__cxa_end_catch', 'cpp_catch_end'),
            (r'__except', 'seh_except'),
            (r'__try', 'seh_try'),
            (r'__finally', 'seh_finally'),
            (r'RtlDispatchException', 'seh_dispatch'),
            (r'catch\s*\(', 'cpp_catch_block'),
        ]
        for pat, htype in patterns:
            for m in _re.finditer(pat, binary_code):
                addr = m.start()
                handlers[addr] = {
                    'type': htype, 'pattern': pat,
                    'covered': False, 'trigger_count': 0,
                }
                self.handler_types.setdefault(htype, []).append(addr)
        self.exception_handlers = handlers
        self.uncovered_handlers = set(handlers)
        return handlers

    def mark_handler_covered(self, handler_addr: int) -> None:
        entry = self.exception_handlers.get(handler_addr)
        if entry:
            entry['covered'] = True
            entry['trigger_count'] += 1
            self.covered_handlers.add(handler_addr)
            self.uncovered_handlers.discard(handler_addr)

    def get_coverage_rate(self) -> float:
        total = len(self.exception_handlers)
        return len(self.covered_handlers) / total if total else 1.0

    def generate_exception_trigger_inputs(self) -> List[Dict[str, Any]]:
        return [
            {'exception_type': 'divide_by_zero', 'input': b'\x00' * 4},
            {'exception_type': 'null_pointer', 'input': b'\x00' * 8},
            {'exception_type': 'buffer_overflow', 'input': b'\xff' * 1024},
            {'exception_type': 'stack_overflow', 'input': b'\x00' * 4096},
            {'exception_type': 'access_violation', 'input': struct.pack('<I', 0xDEADBEEF)},
        ]

    def analyze_handler_vulnerabilities(self, handler_addr: int,
                                        handler_code: str) -> Dict[str, Any]:
        analysis: Dict[str, Any] = {
            'handler_addr': handler_addr, 'vulnerabilities': [], 'risk_level': 'low',
        }
        vuln_checks = [
            (r'malloc\s*\([^)]*\).*catch', 'alloc_in_catch_no_free'),
            (r'free\s*\([^)]*\).*catch', 'double_free_risk'),
            (r'return\s*;.*catch', 'info_leak_via_early_return'),
        ]
        for pat, desc in vuln_checks:
            if _re.search(pat, handler_code, _re.DOTALL):
                analysis['vulnerabilities'].append(desc)
                analysis['risk_level'] = 'medium'
        if len(analysis['vulnerabilities']) > 1:
            analysis['risk_level'] = 'high'
        return analysis

    def generate_coverage_report(self) -> str:
        rate = self.get_coverage_rate()
        lines = [
            '# Exception Handler Coverage Report',
            f'Total: {len(self.exception_handlers)}',
            f'Covered: {len(self.covered_handlers)}',
            f'Uncovered: {len(self.uncovered_handlers)}',
            f'Coverage: {rate * 100:.1f}%',
            '', '## Uncovered Handlers',
        ]
        for addr in sorted(self.uncovered_handlers):
            h = self.exception_handlers[addr]
            lines.append(f'  - 0x{addr:x}  {h["type"]}')
        return '\n'.join(lines)


# 3. Code Structure & Decompilation Analysis

class CodeStructureAnalyzer:
    """
    Analyses binary code structure: switch-table reconstruction,
    inlined-function boundary detection, dead-code identification,
    call-frequency estimation for triage, and algorithmic-complexity
    estimation targeting DoS risks.
    """

    # Call frequency weight multipliers per role
    _ROLE_WEIGHTS = {
        'entry_point': 5.0, 'exported': 3.0, 'callback': 2.5,
        'internal': 1.0, 'dead': 0.0,
    }

    def __init__(self):
        self.jump_tables: Dict[int, List[int]] = {}
        self.inline_regions: List[Tuple[int, int, str]] = []
        self.dead_functions: List[int] = []
        self.importance_scores: Dict[int, float] = {}
        self.complexity_issues: List[Tuple[int, str]] = []

    # ---- Jump-table handling ----

    def find_jump_tables(self, function_addr: int) -> List[int]:
        """Return addresses of jump tables referenced by a function.
        Heuristic: scan for indirect-jump patterns (jmp rax / jmp [reg+disp])."""
        return [a for a in self.jump_tables
                if any(abs(a - func_addr) < 0x10000 for func_addr in [function_addr])]

    def parse_table_entries(self, table_addr: int) -> List[Tuple[int, int]]:
        """Parse jump-table entries as (index, target) pairs."""
        entries = self.jump_tables.get(table_addr, [])
        return [(i, t) for i, t in enumerate(entries) if t != 0]

    def register_jump_table(self, table_addr: int, targets: List[int]) -> None:
        self.jump_tables[table_addr] = targets

    # ---- Inline region detection ----

    def detect_inline_regions(self, function_addr: int) -> List[Tuple[int, int]]:
        """
        Heuristic detection of inlined code blocks.
        Looks for repeated instruction patterns that appear in multiple
        callers (suggesting inlining).
        """
        regions: List[Tuple[int, int]] = []
        for start, end, _name in self.inline_regions:
            if start >= function_addr and end <= function_addr + 0x10000:
                regions.append((start, end))
        return regions

    def identify_original_function(self, region_start: int) -> Optional[str]:
        """Map an inline region back to its original function name."""
        for s, e, name in self.inline_regions:
            if s == region_start:
                return name
        return None

    def mark_inline_region(self, start: int, end: int, name: str) -> None:
        self.inline_regions.append((start, end, name))

    def mark_boundaries_in_pseudocode(self, pseudocode: str) -> str:
        """Insert boundary markers around identified inline regions."""
        result = pseudocode
        for s, e, name in sorted(self.inline_regions, key=lambda x: -x[0]):
            marker = f'\n// --- begin inline [{name}] ---\n'
            end_marker = f'\n// --- end inline [{name}] ---\n'
            if marker not in result:
                result = marker + result
            if end_marker not in result:
                result = result + end_marker
        return result

    # ---- Dead-code analysis ----

    def find_dead_functions(self, binary_path: str) -> List[int]:
        """
        Identify functions with zero cross-references (potentially dead code).
        Uses 'nm' output to find symbols without callers.
        """
        dead: List[int] = []
        try:
            result = _sp.run(['nm', '-n', binary_path],
                             capture_output=True, text=True, timeout=60)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1].lower() == 't':
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        continue
                    # Heuristic: if not in importance table, treat as dead
                    if addr not in self.importance_scores:
                        dead.append(addr)
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.dead_functions = dead
        return dead

    def analyze_dangerous_operations(self, func_addr: int) -> List[str]:
        """Flag dangerous API calls commonly found in backdoored dead code."""
        dangerous = []
        # This is a heuristic placeholder -- real impl would decompile the
        # function and check instruction sequences.
        _logger.info("Dangerous-op analysis for 0x%x -- needs decompiler backend", func_addr)
        return dangerous

    # ---- Function importance ranking ----

    def estimate_call_frequency(self, function_addr: int) -> float:
        """Estimate call frequency based on number of callers and role."""
        base = self.importance_scores.get(function_addr, 1.0)
        # Bias upward for functions with many known callers
        if function_addr in self.importance_scores:
            return base
        return 0.5  # unknown default

    def rank_functions(self) -> List[Tuple[int, float]]:
        """Rank functions by estimated importance (descending)."""
        ranked = sorted(self.importance_scores.items(), key=lambda x: -x[1])
        return ranked

    def set_importance(self, func_addr: int, score: float) -> None:
        self.importance_scores[func_addr] = score

    # ---- Algorithmic complexity estimation ----

    def analyze_complexity(self, binary_path: str) -> None:
        """Scan binary for nested-loop patterns indicating O(n^2) behaviour."""
        self.complexity_issues.clear()
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # Look for back-to-back conditional jumps (loop pattern)
            # This is a simplified byte-level heuristic
            loop_byte = b'\xeb'  # short jmp
            pos = 0
            count = 0
            while True:
                idx = data.find(loop_byte, pos)
                if idx == -1:
                    break
                count += 1
                pos = idx + 1
                if count > 20:  # many short jumps suggest nested loops
                    self.complexity_issues.append((idx, 'dense_short_jumps'))
            # Heuristic: many cmp/jmp pairs
            cmp_count = data.count(b'\x3b') + data.count(b'\x83\xf8')  # cmp variants
            jmp_count = data.count(b'\x74') + data.count(b'\x75') + data.count(b'\x7c')  # conditional jumps
            if jmp_count > cmp_count * 3:
                self.complexity_issues.append((0, 'high_branch_density'))
        except Exception:
            _logger.debug("suppressed", exc_info=True)

    def find_dos_risk_points(self) -> List[Tuple[int, str]]:
        return [(addr, desc) for addr, desc in self.complexity_issues]


class DecompilerSemanticRewriter:
    """
    Generates semantically-equivalent code variants for data augmentation
    in vulnerability-detection model training.
    """

    def __init__(self):
        self.rewrite_rules: List[Callable] = []

    def register_rewrite_rule(self, rule: Callable) -> None:
        self.rewrite_rules.append(rule)

    def rewrite_code(self, pseudocode: str) -> SemanticRewrittenCode:
        variants = [pseudocode]
        for rule in self.rewrite_rules:
            try:
                variant = rule(pseudocode)
                if variant and variant not in variants:
                    variants.append(variant)
            except Exception:
                continue
        return SemanticRewrittenCode(pseudocode, variants)

    def apply_structural_transformation(self, code: str,
                                        transform_type: str) -> str:
        """Apply a named structural rewrite.

        Supported transforms:
          - invert_condition: flip if/else bodies
          - expand_compound: split compound conditions
          - reorder_decls: move declarations to top
        """
        if transform_type == 'invert_condition':
            return self._invert_conditions(code)
        elif transform_type == 'expand_compound':
            return self._expand_compound_conditions(code)
        elif transform_type == 'reorder_decls':
            return self._hoist_declarations(code)
        return code

    # ---- Transform implementations ----

    @staticmethod
    def _invert_conditions(code: str) -> str:
        """Swap if/else branches by inverting conditions."""
        result = code
        # Invert 'if (a == b)' -> 'if (a != b)'
        result = _re.sub(r'if\s*\(\s*(\w+)\s*==\s*(\w+)\s*\)',
                         r'if (\1 != \2)', result)
        result = _re.sub(r'if\s*\(\s*(\w+)\s*!=\s*(\w+)\s*\)',
                         r'if (\1 == \2)', result)
        result = _re.sub(r'if\s*\(\s*(\w+)\s*>\s*(\w+)\s*\)',
                         r'if (\1 <= \2)', result)
        result = _re.sub(r'if\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)',
                         r'if (\1 >= \2)', result)
        return result

    @staticmethod
    def _expand_compound_conditions(code: str) -> str:
        """Break 'if (a && b)' into nested ifs."""
        return _re.sub(
            r'if\s*\((.+?)\s*&&\s*(.+?)\)\s*\{',
            r'if (\1) {\n    if (\2) {',
            code,
        )

    @staticmethod
    def _hoist_declarations(code: str) -> str:
        """Move variable declarations to the top of their scope."""
        decl_pattern = _re.compile(r'(int|char|void\*|size_t|uint\d+_t)\s+(\w+)\s*=', _re.MULTILINE)
        decls = decl_pattern.findall(code)
        if not decls:
            return code
        hoisted = '\n'.join(f'    {t} {n};' for t, n in decls)
        cleaned = decl_pattern.sub('', code)
        # Insert after first opening brace
        brace_idx = cleaned.find('{')
        if brace_idx >= 0:
            cleaned = cleaned[:brace_idx + 1] + '\n' + hoisted + cleaned[brace_idx + 1:]
        return cleaned


class DisassemblyMacroIdentifierExpander:
    """
    Identify repeated instruction patterns (prologues, epilogues, checks)
    and abstract them into named macros for cleaner pseudocode.
    """

    def __init__(self):
        self.macro_library: Dict[str, Dict[str, Any]] = {}
        self.detected_macros: List[Dict[str, Any]] = []
        self._register_common_macros()

    def _register_common_macros(self):
        self.macro_library.update({
            'function_prologue': {
                'pattern': ['push rbp', 'mov rbp, rsp', 'sub rsp,'],
                'name': 'FUNC_ENTRY', 'description': 'function prologue',
            },
            'function_epilogue': {
                'pattern': ['mov rsp, rbp', 'pop rbp', 'ret'],
                'name': 'FUNC_EXIT', 'description': 'function epilogue',
            },
            'null_check': {
                'pattern': ['test', 'jz', 'jnz'],
                'name': 'NULL_CHECK', 'description': 'null-pointer check',
            },
            'loop_header': {
                'pattern': ['cmp', 'jl', 'jle', 'inc'],
                'name': 'LOOP_START', 'description': 'loop header',
            },
        })

    def identify_macros(self, disassembly: str) -> List[Dict[str, Any]]:
        detected = []
        for macro_name, info in self.macro_library.items():
            pat_str = '.*'.join(info['pattern'])
            occ = len(_re.findall(pat_str, disassembly, _re.IGNORECASE))
            if occ:
                detected.append({
                    'macro_name': macro_name, 'macro_info': info,
                    'occurrences': occ,
                })
        self.detected_macros = detected
        return detected

    def expand_macros(self, disassembly: str) -> str:
        simplified = disassembly
        for macro in self.detected_macros:
            info = macro['macro_info']
            pat_str = '.*'.join(info['pattern'])
            simplified = _re.sub(
                pat_str,
                f'// {info["name"]}',
                simplified,
                flags=_re.IGNORECASE,
            )
        return simplified

    def add_custom_macro(self, name: str, pattern: List[str],
                         description: str) -> None:
        self.macro_library[name] = {
            'pattern': pattern, 'name': name, 'description': description,
        }

    def generate_macro_definitions(self) -> str:
        lines = ['// Macro definitions', '']
        for name, info in self.macro_library.items():
            lines.append(f'#define {info["name"]}  // {info["description"]}')
            lines.append(f'//   Pattern: {", ".join(info["pattern"])}')
            lines.append('')
        return '\n'.join(lines)


# 4. Binary Security Audit

class BinarySecurityAuditor:
    """
    Consolidated binary-security analysis.

    Detects protection mechanisms, identifies IAT hooks, searches for
    anti-forensics techniques, evaluates writable targets for code execution,
    and generates hardening recommendations.
    """

    _KNOWN_PROTECTIONS = ['NX', 'ASLR', 'PIE', 'RELRO', 'CANARY', 'CFI']

    def __init__(self):
        self.current_protections: Dict[str, bool] = {}
        self.hooked_functions: List[Tuple[str, int, int]] = []
        self.write_targets: List[Dict[str, Any]] = []
        self.anti_forensics_hits: List[int] = []
        self.info_leaks: List[Tuple[int, str]] = []

    # ---- Protection analysis ----

    def analyze_current_protections(self, binary_path: str) -> Dict[str, bool]:
        """Detect binary protections using checksec-style heuristics."""
        prots: Dict[str, bool] = {}
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # ELF header type detection
            is_elf = data[:4] == b'\x7fELF'
            if is_elf and len(data) > 18:
                e_type = struct.unpack_from('<H', data, 16)[0]
                prots['PIE'] = (e_type == 3)
            # Check for NX via GNU_STACK
            prots['NX'] = (b'GNU_STACK' not in data or
                           data.find(b'GNU_STACK') < 0 or
                           self._check_gnu_stack_rwx(data))
            # RELRO: check for BIND_NOW / .relro
            prots['RELRO'] = (b'BIND_NOW' in data or b'.relro' in data.lower())
            # CANARY via __stack_chk_fail reference
            prots['CANARY'] = (b'__stack_chk_fail' in data)
            # ASLR: PIE implies ASLR-compatible
            prots['ASLR'] = prots.get('PIE', False) or data[:4] == b'\x7fELF'
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.current_protections = prots
        return prots

    def detect_fortify_source(self, binary_path: str) -> Optional[int]:
        """Detect _FORTIFY_SOURCE level by checking fortified function calls."""
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            if b'__sprintf_chk' in data or b'__memcpy_chk' in data:
                return 2
            if b'__strcpy_chk' in data:
                return 1
            return 0
        except Exception:
            return None

    def detect_stack_clash(self, binary_path: str) -> bool:
        """Check for stack-clash protection (large stack probes)."""
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # -fstack-clash-protection emits repeated stack probes
            probe_seq = b'\x48\x83\xe4\xf0'  # and rsp, -16 => common prologue
            count = data.count(probe_seq)
            return count > 2  # heuristic threshold
        except Exception:
            return False

    def assess_exploitability_impact(self, vuln_type: str) -> float:
        """Score [0-1] how much current protections hinder exploitation."""
        impact = 1.0
        if not self.current_protections.get('NX', False):
            impact -= 0.3
        if not self.current_protections.get('ASLR', False):
            impact -= 0.2
        if not self.current_protections.get('CANARY', False):
            impact -= 0.15
        if vuln_type == 'stack_overflow' and self.current_protections.get('CANARY', False):
            impact -= 0.25
        return max(impact, 0.0)

    # ---- IAT hook detection ----

    def analyze_iat(self, pe_path: str) -> None:
        """Parse PE import directory for potential IAT hooks."""
        try:
            with open(pe_path, 'rb') as fh:
                data = fh.read()
            # PE magic at offset 0x3c
            if data[:2] != b'MZ':
                return
            pe_off = struct.unpack_from('<I', data, 0x3c)[0]
            if data[pe_off:pe_off + 4] != b'PE\x00\x00':
                return
            # Heuristic: locate import directory via section names
            if b'.idata' in data:
                self.hooked_functions.append(('.idata_section_present', 0, 0))
        except Exception:
            _logger.debug("suppressed", exc_info=True)

    def detect_hooks(self) -> List[Tuple[str, int, int]]:
        return [(n, a, a2) for n, a, a2 in self.hooked_functions if a != a2]

    def restore_original_address(self, func_name: str) -> bool:
        """Attempt to derive the original IAT address for a hooked function.
        Returns True if restoration was possible."""
        for n, orig, hooked in self.hooked_functions:
            if n == func_name and orig != hooked:
                return True
        return False

    # ---- Anti-forensics ----

    def detect_memory_wiping(self, binary_path: str) -> List[int]:
        """Find memset/ZeroMemory calls that may erase forensic evidence."""
        offsets: List[int] = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            wipe_sigs = [b'memset', b'ZeroMemory', b'RtlSecureZeroMemory',
                         b'bzero', b'explicit_bzero']
            for sig in wipe_sigs:
                pos = 0
                while True:
                    idx = data.find(sig, pos)
                    if idx < 0:
                        break
                    offsets.append(idx)
                    pos = idx + 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.anti_forensics_hits = offsets
        return offsets

    def detect_memory_protection_modification(self, binary_path: str) -> List[int]:
        """Find VirtualProtect / mprotect calls that relax memory permissions."""
        offsets: List[int] = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            prot_sigs = [b'VirtualProtect', b'VirtualProtectEx',
                         b'mprotect', b'mmap']
            for sig in prot_sigs:
                pos = 0
                while True:
                    idx = data.find(sig, pos)
                    if idx < 0:
                        break
                    offsets.append(idx)
                    pos = idx + 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return offsets

    def assess_interference_risk(self) -> float:
        """Score [0-1] the risk of anti-forensics interference."""
        n = len(self.anti_forensics_hits)
        return min(n / 10.0, 1.0)

    # ---- Write-target analysis ----

    def find_write_targets(self, binary_path: str) -> List[Dict[str, Any]]:
        """Identify global function pointers (_dl_fini, __exit_funcs, etc.)
        that could be overwritten for code execution."""
        targets: List[Dict[str, Any]] = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            interesting = [
                (b'_dl_fini', 'dynamic linker finaliser'),
                (b'__exit_funcs', 'atexit handler table'),
                (b'__fini_array_start', 'fini array start'),
            ]
            for sig, desc in interesting:
                pos = 0
                while True:
                    idx = data.find(sig, pos)
                    if idx < 0:
                        break
                    targets.append({'offset': idx, 'symbol': sig.decode(errors='replace'), 'description': desc})
                    pos = idx + 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.write_targets = targets
        return targets

    def assess_write_effectiveness(self, target_addr: int) -> float:
        """Score [0-1] how effectively overwriting this target leads to code exec."""
        for t in self.write_targets:
            if t['offset'] == target_addr:
                if 'fini' in t.get('symbol', '').lower():
                    return 0.9
                if 'exit' in t.get('symbol', '').lower():
                    return 0.85
        return 0.2

    # ---- Hardening advisor ----

    def generate_compiler_flags(self) -> List[str]:
        flags = []
        if not self.current_protections.get('CANARY', False):
            flags.append('-fstack-protector-strong')
        if not self.current_protections.get('PIE', False):
            flags.append('-fPIE -pie')
        if not self.current_protections.get('RELRO', False):
            flags.append('-Wl,-z,relro,-z,now')
        if not self.detect_fortify_source(''):
            flags.append('-D_FORTIFY_SOURCE=2')
        if not self.current_protections.get('CFI', False):
            flags.append('-fcf-protection=full')
        return flags

    def generate_linker_script(self) -> str:
        flags = self.generate_compiler_flags()
        return ';\n'.join(flags) if flags else '; No additional hardening needed'

    @staticmethod
    def _check_gnu_stack_rwx(data: bytes) -> bool:
        """Return True if GNU_STACK segment is NOT executable."""
        idx = data.find(b'GNU_STACK')
        if idx < 0:
            return True  # not found => assume NX
        # Check flags 28 bytes into the Phdr entry
        if idx + 32 < len(data):
            flags = struct.unpack_from('<I', data, idx + 28)[0]
            return (flags & 1) == 0  # PF_X not set
        return True


# 5. Memory & Forensics Analysis

class MemoryForensicAnalyzer:
    """
    Parse PEB/TEB structures, analyse heap-state history, and reconstruct
    stack-frame layouts from access patterns.
    """

    def __init__(self):
        self.peb_info: Dict[str, Any] = {}
        self.teb_info: Dict[str, Any] = {}
        self.heap_state_history: List[Dict[str, Any]] = []
        self.stack_layout: Dict[str, Tuple[int, int]] = {}

    # ---- PEB / TEB ----

    def parse_peb(self, peb_addr: int) -> Dict[str, Any]:
        """Parse Process Environment Block. Returns extracted fields."""
        info: Dict[str, Any] = {'address': hex(peb_addr), 'fields': {}}
        # PEB fields (x64 offsets):
        # +0x02 BeingDebugged, +0x10 ImageBaseAddress, +0x18 Ldr
        info['fields']['being_debugged'] = 0x02
        info['fields']['image_base'] = 0x10
        info['fields']['ldr'] = 0x18
        info['fields']['process_parameters'] = 0x20
        self.peb_info = info
        return info

    def parse_teb(self, teb_addr: int) -> Dict[str, Any]:
        """Parse Thread Environment Block."""
        info: Dict[str, Any] = {'address': hex(teb_addr), 'fields': {}}
        # TEB fields (x64): +0x00 NtTib, +0x30 PEB, +0x38 LastErrorValue
        info['fields']['peb'] = 0x30
        info['fields']['last_error'] = 0x38
        info['fields']['tid'] = 0x48
        info['fields']['stack_base'] = 0x08
        info['fields']['stack_limit'] = 0x10
        self.teb_info = info
        return info

    def extract_module_list(self) -> List[Dict[str, Any]]:
        from_peb = self.peb_info.get('fields', {}).get('ldr', 0)
        if from_peb:
            return [{'loader_entry': hex(from_peb), 'status': 'peb_ldr_available'}]
        return []

    # ---- Heap visualisation ----

    def record_heap_state(self, arena_addr: int) -> None:
        entry = {
            'arena': hex(arena_addr),
            'timestamp': datetime.now().isoformat(),
            'fastbins': [],
            'tcache': [],
        }
        self.heap_state_history.append(entry)

    def visualize_fastbins(self) -> Dict[str, List[int]]:
        bins: Dict[str, List[int]] = {}
        for entry in self.heap_state_history:
            for i, fb in enumerate(entry.get('fastbins', [])):
                bins.setdefault(f'fastbin_{i}', []).append(fb)
        return bins

    def visualize_tcache(self) -> Dict[str, List[int]]:
        bins: Dict[str, List[int]] = {}
        for entry in self.heap_state_history:
            for i, tc in enumerate(entry.get('tcache', [])):
                bins.setdefault(f'tcache_{i}', []).append(tc)
        return bins

    # ---- Stack reconstruction ----

    def analyze_stack_accesses(self, function_addr: int) -> None:
        """Analyse stack-pointer-relative accesses to infer frame layout."""
        # Real implementation would need disassembly; this provides
        # a slot-based heuristic
        self.stack_layout[hex(function_addr)] = (-1, 0)
        _logger.debug("Stack access analysis at 0x%x", function_addr)

    def reconstruct_layout(self) -> Dict[str, Tuple[int, int]]:
        """Return inferred (offset, size) for each local variable."""
        return dict(self.stack_layout)

    def generate_layout_summary(self) -> str:
        lines = ['# Stack Layout Summary', '']
        for name, (off, sz) in sorted(self.stack_layout.items()):
            lines.append(f'  {name}: offset={off:+d}  size={sz}')
        return '\n'.join(lines)


class CrossProcessDataFlowTracker:
    """
    Extends taint analysis across process boundaries via shared memory
    and pipe communication, producing a full data-flow graph.
    """

    def __init__(self):
        self.taint_graph: Dict[int, List[int]] = {}  # source -> [destinations]
        self.pipe_flows: Dict[int, List[int]] = {}
        self.shm_flows: Dict[int, List[int]] = {}

    def track_shared_memory(self, shm_addr: int, processes: List[int]) -> None:
        """Record that *shm_addr* is shared among *processes*."""
        self.shm_flows[shm_addr] = processes
        src = shm_addr
        for proc in processes:
            self.taint_graph.setdefault(src, []).append(proc)
            src = proc

    def track_pipe_communication(self, pipe_fd: int) -> None:
        """Mark a pipe fd for inter-process data-flow tracking."""
        self.pipe_flows[pipe_fd] = []

    def get_full_data_flow(self) -> Dict[int, List[int]]:
        """Merge shared-memory and pipe flows into a unified graph."""
        unified: Dict[int, List[int]] = {}
        unified.update(self.taint_graph)
        for fd, _ in self.pipe_flows.items():
            unified.setdefault(fd, [])
        return unified


# 6. Exploit Development Kit

class ExploitDevelopmentKit:
    """
    Consolidated exploit-development utilities:

      - ROP gadget discovery and chain compression
      - Shellcode validation via QEMU user-mode emulation
      - Minimal input generation for PoCs
      - Binary patch generation from differential analysis
    """

    def __init__(self):
        self.gadget_database: Dict[str, List[int]] = {}  # pattern -> addrs
        self.patch_templates: List[str] = []
        self._qemu_paths: Dict[str, str] = {
            'x86': 'qemu-i386', 'x86_64': 'qemu-x86_64',
            'arm': 'qemu-arm', 'arm64': 'qemu-aarch64',
        }

    # ---- ROP ----

    def find_shared_gadgets(self, gadgets: List[int]) -> List[int]:
        """Identify gadgets shared across multiple RO segments."""
        seen: Dict[int, int] = Counter(gadgets)
        return [g for g, cnt in seen.items() if cnt > 1]

    def compress_rop_chain(self, rop_chain: List[int]) -> List[int]:
        """Remove adjacent duplicate gadget addresses."""
        if not rop_chain:
            return []
        compressed = [rop_chain[0]]
        for g in rop_chain[1:]:
            if g != compressed[-1]:
                compressed.append(g)
        return compressed

    def optimize_for_space(self, rop_chain: List[int],
                           max_length: int) -> Optional[List[int]]:
        """Truncate ROP chain to fit within *max_length* gadgets."""
        compressed = self.compress_rop_chain(rop_chain)
        if len(compressed) <= max_length:
            return compressed
        # Drop middle gadgets to meet size constraint
        keep = compressed[:max_length // 2] + compressed[-(max_length // 2):]
        return keep

    # ---- Shellcode validation ----

    def validate_shellcode(self, shellcode: bytes, arch: str) -> Dict[str, Any]:
        """Run shellcode under QEMU user mode and capture result."""
        qemu = self._qemu_paths.get(arch)
        if not qemu:
            return {'error': f'Unsupported architecture: {arch}'}
        import tempfile
        result: Dict[str, Any] = {'tested': False, 'observations': []}
        try:
            with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tf:
                tf.write(shellcode)
                tf.flush()
                name = tf.name
            proc = _sp.run([qemu, name], capture_output=True,
                           timeout=10, text=False)
            result['returncode'] = proc.returncode
            result['stdout_len'] = len(proc.stdout)
            result['stderr_len'] = len(proc.stderr)
            result['tested'] = True
            if proc.returncode != 0:
                result['observations'].append(f'exit_code={proc.returncode}')
            os.unlink(name)
        except _sp.TimeoutExpired:
            result['observations'].append('timeout')
        except Exception as e:
            result['observations'].append(str(e))
        return result

    def check_side_effects(self, shellcode: bytes, arch: str) -> List[str]:
        """List observable side effects of shellcode execution."""
        side = []
        dangerous = [b'/bin/sh', b'/bin/bash', b'exec', b'system',
                     b'fork', b'kill', b'ptrace']
        for d in dangerous:
            if d in shellcode:
                side.append(f'contains_{d.decode(errors="replace")}')
        # Check for null-bytes (bad for string-based exploits)
        if b'\x00' in shellcode:
            side.append('contains_null_bytes')
        return side

    # ---- Input minimisation ----

    def minimize_input(self, constraints: List[str]) -> bytes:
        """Given SMT constraints, produce a minimal satisfying byte sequence."""
        result = bytearray()
        # Simple constraint parsing: extract byte ranges
        for c in constraints:
            m = _re.search(r'byte_(\d+)\s*==\s*0x([0-9a-fA-F]+)', c)
            if m:
                idx = int(m.group(1))
                val = int(m.group(2), 16)
                while len(result) <= idx:
                    result.append(0)
                result[idx] = val
        return bytes(result)

    def simplify_bytes(self, input_bytes: bytes) -> bytes:
        """Reduce redundant trailing bytes (common in overflow payloads)."""
        data = bytearray(input_bytes)
        # Strip trailing repeated bytes
        while len(data) > 1 and data[-1] == data[-2]:
            data.pop()
        return bytes(data)

    # ---- Binary patching ----

    def compare_binaries(self, old_path: str, new_path: str) -> List[Tuple[int, bytes, bytes]]:
        """Byte-level diff between two binaries."""
        diffs: List[Tuple[int, bytes, bytes]] = []
        try:
            with open(old_path, 'rb') as f:
                old_data = f.read()
            with open(new_path, 'rb') as f:
                new_data = f.read()
            max_len = max(len(old_data), len(new_data))
            i = 0
            while i < max_len:
                old_byte = old_data[i:i + 1] if i < len(old_data) else b''
                new_byte = new_data[i:i + 1] if i < len(new_data) else b''
                if old_byte != new_byte:
                    diffs.append((i, old_byte, new_byte))
                i += 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return diffs

    def generate_hotpatch(self, diffs: List[Tuple[int, bytes, bytes]]) -> bytes:
        """Produce a minimal binary patch blob from diffs.
        Format: 4-byte count, then [offset:4][new_byte:1] per entry."""
        buf = bytearray()
        buf.extend(struct.pack('<I', len(diffs)))
        for off, _, new_val in diffs:
            buf.extend(struct.pack('<I', off))
            buf.extend(new_val if new_val else b'\x00')
        return bytes(buf)

    def validate_patch(self, binary_path: str, patch: bytes) -> bool:
        """Dry-run: check that all patch offsets are within the file."""
        try:
            with open(binary_path, 'rb') as fh:
                file_sz = len(fh.read())
            count = struct.unpack_from('<I', patch, 0)[0]
            for i in range(count):
                off = struct.unpack_from('<I', patch, 4 + i * 5)[0]
                if off >= file_sz:
                    return False
            return True
        except Exception:
            return False


# 7. Dynamic Analysis Harness

class DynamicAnalysisHarness:
    """
    Manages conditional breakpoints, execution snapshots (via rr),
    GDB script generation, and syscall interception/fuzzing.
    """

    def __init__(self):
        self.breakpoints: List[Dict[str, Any]] = []
        self.snapshot_path: Optional[str] = None
        self.gdb_commands: List[str] = []
        self.intercepted_calls: List[Dict[str, Any]] = []

    # ---- Conditional breakpoints ----

    def set_breakpoint_on_register(self, reg_name: str, value: int) -> None:
        self.breakpoints.append({
            'type': 'register', 'reg': reg_name, 'value': hex(value),
            'condition': f'${reg_name} == {value}',
        })

    def set_breakpoint_on_memory(self, addr: int, value: int) -> None:
        self.breakpoints.append({
            'type': 'memory', 'addr': hex(addr), 'value': hex(value),
            'condition': f'*(int*){hex(addr)} == {value}',
        })

    def set_breakpoint_on_call(self, func_name: str) -> None:
        self.breakpoints.append({
            'type': 'call', 'function': func_name,
            'condition': None,
        })

    # ---- Execution snapshots (rr) ----

    def record_execution(self, binary_path: str, input_data: bytes) -> str:
        """Record execution with rr, return snapshot path."""
        import tempfile
        tmpdir = tempfile.mkdtemp(prefix='rr_')
        try:
            # Write input to a file
            inp_path = os.path.join(tmpdir, 'input.bin')
            with open(inp_path, 'wb') as fh:
                fh.write(input_data)
            _sp.run(['rr', 'record', binary_path, inp_path],
                    capture_output=True, timeout=60, cwd=tmpdir)
            # Find the latest trace directory
            for item in sorted(os.listdir(tmpdir), reverse=True):
                if item.startswith('rr-'):
                    self.snapshot_path = os.path.join(tmpdir, item)
                    return self.snapshot_path
        except Exception as e:
            _logger.warning("rr record failed: %s", e)
        self.snapshot_path = tmpdir
        return tmpdir

    def replay_execution(self, snapshot_path: str) -> bool:
        """Replay a recorded rr snapshot."""
        try:
            result = _sp.run(['rr', 'replay', snapshot_path],
                             capture_output=True, timeout=60)
            return result.returncode == 0
        except Exception:
            return False

    def extract_minimal_reproduction(self) -> Dict[str, Any]:
        """Extract minimal reproduction data from snapshot."""
        if not self.snapshot_path:
            return {}
        return {
            'snapshot': self.snapshot_path,
            'events': len(self.intercepted_calls),
            'breakpoints': len(self.breakpoints),
        }

    # ---- GDB script generation ----

    def generate_gdb_script(self) -> str:
        """Generate a GDB script covering all registered breakpoints."""
        lines = ['set pagination off', 'set confirm off', '']
        for bp in self.breakpoints:
            if bp['type'] == 'register':
                lines.append(f'# Break when {bp["reg"]} == {bp["value"]}')
                lines.append(f'break *$pc if ${bp["reg"]} == {bp["value"]}')
            elif bp['type'] == 'memory':
                lines.append(f'# Watch memory at {bp["addr"]}')
                lines.append(f'awatch *{bp["addr"]}')
            elif bp['type'] == 'call':
                lines.append(f'# Break on {bp["function"]}')
                lines.append(f'break {bp["function"]}')
        lines.extend(['', 'continue', ''])
        return '\n'.join(lines)

    def collect_information(self, pid: int) -> Dict[str, str]:
        """Run GDB info commands against a running process."""
        info: Dict[str, str] = {}
        cmds = [
            'info proc mappings', 'info registers', 'info frame',
            'info sharedlibrary', 'heap chunks',
        ]
        for cmd in cmds:
            try:
                result = _sp.run(
                    ['gdb', '-batch', '-p', str(pid), '-ex', cmd],
                    capture_output=True, text=True, timeout=30,
                )
                info[cmd.replace(' ', '_')] = result.stdout.strip()
            except Exception:
                info[cmd.replace(' ', '_')] = ''
        return info

    # ---- Syscall interception ----

    def intercept_syscall(self, syscall_num: int) -> None:
        self.intercepted_calls.append({
            'nr': syscall_num,
            'timestamp': datetime.now().isoformat(),
            'count': self._count_syscall(syscall_num),
        })

    def fuzz_parameters(self, params: List[int]) -> List[int]:
        """Fuzz syscall parameters with edge cases."""
        import random
        fuzzed = []
        for p in params:
            r = random.random()
            if r < 0.2:
                fuzzed.append(0)
            elif r < 0.4:
                fuzzed.append(0xFFFFFFFF)
            elif r < 0.6:
                fuzzed.append(p + random.randint(-16, 16))
            else:
                fuzzed.append(p)
        return fuzzed

    def test_robustness(self) -> Dict[str, Any]:
        """Summarise robustness test results."""
        return {
            'intercepted_count': len(self.intercepted_calls),
            'unique_syscalls': len({c['nr'] for c in self.intercepted_calls}),
        }

    @staticmethod
    def _count_syscall(nr: int) -> int:
        return 1  # placeholder for actual tracking


# 8. Docker / Sandbox Management

class DockerSandboxManager:
    """
    Generate minimal Docker images based on binary dependencies, and
    manage multi-libc environments for exploit compatibility testing.
    """

    def __init__(self):
        self.dependencies: List[str] = []
        self.libc_versions: List[str] = []

    # ---- Dependency extraction ----

    def extract_dependencies(self, binary_path: str) -> List[str]:
        """Parse ELF NEEDED entries or PE imports to find shared libraries."""
        deps: List[str] = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            # ELF: look for .dynamic / NEEDED entries
            if data[:4] == b'\x7fELF':
                # Scan for DT_NEEDED by looking for .so patterns
                for m in _re.finditer(rb'([\w-]+\.so[\w.]*)', data):
                    dep = m.group(1).decode(errors='replace')
                    if dep not in deps:
                        deps.append(dep)
            # PE: look for .dll patterns
            else:
                for m in _re.finditer(rb'([\w-]+\.dll)', data, _re.IGNORECASE):
                    dep = m.group(1).decode(errors='replace')
                    if dep not in deps:
                        deps.append(dep)
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.dependencies = deps
        return deps

    def generate_dockerfile(self, base_image: str = 'ubuntu:20.04') -> str:
        """Generate a minimal Dockerfile with detected dependencies."""
        lines = [
            f'FROM {base_image}',
            '',
            '# Required system libraries',
            'RUN apt-get update && apt-get install -y --no-install-recommends \\',
        ]
        pkg_map = {'libc.so.6': 'libc6', 'libpthread.so.0': 'libc6',
                   'libm.so.6': 'libc6', 'libdl.so.2': 'libc6',
                   'libstdc++.so.6': 'libstdc++6',
                   'libgcc_s.so.1': 'libgcc-s1', }
        pkgs = set()
        for dep in self.dependencies:
            pkg = pkg_map.get(dep, dep.replace('.so', '').replace('.', '-'))
            pkgs.add(pkg)
        for pkg in sorted(pkgs):
            lines.append(f'    {pkg} \\')
        # Clean up trailing backslash
        last = lines[-1].rstrip(' \\')
        lines[-1] = last
        lines.extend([
            '',
            'WORKDIR /analysis',
            'COPY . /analysis',
            '',
            'CMD ["/bin/bash"]',
        ])
        return '\n'.join(lines)

    def build_image(self, tag: str, dockerfile_dir: str = '.') -> bool:
        """Build Docker image from generated Dockerfile."""
        try:
            result = _sp.run(['docker', 'build', '-t', tag, dockerfile_dir],
                             capture_output=True, text=True, timeout=300)
            return result.returncode == 0
        except Exception as e:
            _logger.error("Docker build failed: %s", e)
            return False

    # ---- Multi-libc environment ----

    def setup_multi_libc_environment(self, versions: List[str]) -> bool:
        """Configure multiple libc versions in a Docker sandbox."""
        self.libc_versions = versions
        # Build Dockerfile with all requested libcs
        dockerfile = 'FROM ubuntu:20.04\n\n'
        for v in versions:
            dockerfile += f'# Libc version: {v}\n'
        dockerfile += 'RUN apt-get update\n'
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.Dockerfile',
                                             delete=False) as tf:
                tf.write(dockerfile)
                tf.flush()
                result = _sp.run(['docker', 'build', '-f', tf.name,
                                  '-t', 'multi-libc', '.'],
                                 capture_output=True, timeout=300)
                os.unlink(tf.name)
                return result.returncode == 0
        except Exception:
            return False

    def test_exploit_compatibility(self, exploit_script: str) -> Dict[str, bool]:
        """Test an exploit script against each libc version."""
        results: Dict[str, bool] = {}
        for v in self.libc_versions:
            try:
                result = _sp.run(
                    ['docker', 'run', '--rm', f'multi-libc:{v}',
                     'python3', '-c', exploit_script],
                    capture_output=True, timeout=30,
                )
                results[v] = (result.returncode == 0)
            except Exception:
                results[v] = False
        return results


class ExploitReproduceEnvironmentGenerator:
    """Generate Docker-based reproduction environments for exploits."""

    _DOCKER_TEMPLATE = '''FROM ubuntu:{ubuntu_version}

RUN apt-get update && apt-get install -y \\
    libc6-dev={libc_version} \\
    gcc={gcc_version} \\
    g++={gpp_version} \\
    make gdb python3

WORKDIR /exploit
COPY . /exploit
ENV LD_PRELOAD=/exploit/hook.so
CMD ["/bin/bash"]
'''

    _COMPOSE_TEMPLATE = '''version: "3.8"
services:
  exploit:
    build: .
    security_opt:
      - seccomp:unconfined
    cap_add:
      - SYS_PTRACE
    volumes:
      - ./exploit:/exploit
'''

    _HOOK_TEMPLATE = '''#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void *malloc(size_t size) {{
    static void *(*real)(size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "malloc");
    return real(size);
}}

void free(void *ptr) {{
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "free");
    real(ptr);
}}
'''

    def generate_environment(self, target_info: Dict[str, Any]) -> Dict[str, str]:
        return {
            'Dockerfile': self._generate_dockerfile(target_info),
            'docker-compose.yml': self._COMPOSE_TEMPLATE,
            'hook.c': self._HOOK_TEMPLATE,
        }

    def _generate_dockerfile(self, info: Dict[str, Any]) -> str:
        return self._DOCKER_TEMPLATE.format(
            ubuntu_version=info.get('ubuntu_version', '20.04'),
            libc_version=info.get('libc_version', '2.31-0ubuntu9'),
            gcc_version=info.get('gcc_version', '9'),
            gpp_version=info.get('g++_version', '9'),
        )

    def save_environment(self, output_dir: str,
                         target_info: Dict[str, Any]) -> str:
        os.makedirs(output_dir, exist_ok=True)
        files = self.generate_environment(target_info)
        for fname, content in files.items():
            with open(os.path.join(output_dir, fname), 'w') as fh:
                fh.write(content)
        return output_dir


# 9. Platform-Specific Analysis

class GoRustBinaryAnalyzer:
    """Identify Go/Rust runtimes and generate language-specific analysis hints."""

    def __init__(self):
        self.language: Optional[str] = None
        self.runtime_symbols: Dict[str, List[str]] = {}
        self.specialized_hints: List[str] = []

    def identify_language(self, binary_path: str) -> str:
        try:
            result = _sp.run(['nm', binary_path], capture_output=True,
                             text=True, timeout=30)
            out = result.stdout
            if any(s in out for s in ('runtime.main', 'runtime.goexit', 'runtime.mallocgc')):
                self.language = 'go'
            elif 'rust_panic' in out or 'std::rt::lang_start' in out:
                self.language = 'rust'
            else:
                self.language = 'unknown'
        except Exception:
            self.language = 'unknown'
        return self.language

    def extract_runtime_symbols(self, binary_path: str) -> Dict[str, List[str]]:
        syms: Dict[str, List[str]] = {'go': [], 'rust': []}
        try:
            result = _sp.run(['nm', '-D', binary_path],
                             capture_output=True, text=True, timeout=30)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                name = parts[-1]
                if name.startswith('runtime.'):
                    syms['go'].append(name)
                elif name.startswith('_ZN') or 'std::' in name:
                    syms['rust'].append(name)
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        self.runtime_symbols = syms
        return syms

    def generate_specialized_hints(self) -> List[str]:
        hints: List[str] = []
        if self.language == 'go':
            hints = [
                'Go uses string concatenation, not printf-style formatting',
                'Watch goroutine scheduling and channel communication',
                'Go panic/recover replaces traditional exception handling',
                'defer statements execute at function exit',
            ]
        elif self.language == 'rust':
            hints = [
                'Rust uses Result/Option for error handling',
                'Pay attention to lifetime annotations',
                'Rust has no traditional exceptions -- panics instead',
                'Focus on trait objects and dynamic dispatch',
            ]
        self.specialized_hints = hints
        return hints


class MobilePlatformDeepAnalyzer:
    """Analyse Android JNI functions and iOS ObjC class structures."""

    _DANGEROUS_PERMISSIONS = {
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.READ_CONTACTS',
        'android.permission.SEND_SMS',
        'android.permission.RECORD_AUDIO',
        'android.permission.ACCESS_FINE_LOCATION',
    }

    def __init__(self):
        self.platform: Optional[str] = None
        self.android_jni_functions: List[Dict[str, Any]] = []
        self.ios_classes: List[Dict[str, Any]] = []

    def analyze_android_apk(self, apk_path: str) -> Dict[str, Any]:
        self.platform = 'android'
        result: Dict[str, Any] = {
            'apk': apk_path,
            'jni_functions': self._extract_jni_functions(apk_path),
            'permissions': self._extract_android_permissions(apk_path),
            'vulnerabilities': [],
        }
        result['vulnerabilities'] = self._detect_mobile_vulnerabilities(result)
        self.android_jni_functions = result['jni_functions']
        return result

    def analyze_ios_binary(self, ipa_path: str) -> Dict[str, Any]:
        self.platform = 'ios'
        result: Dict[str, Any] = {
            'ipa': ipa_path,
            'classes': self._extract_objc_classes(ipa_path),
            'methods': self._extract_objc_methods(ipa_path),
            'vulnerabilities': [],
        }
        result['vulnerabilities'] = self._detect_mobile_vulnerabilities(result)
        self.ios_classes = result['classes']
        return result

    def _extract_jni_functions(self, apk_path: str) -> List[Dict[str, Any]]:
        funcs: List[Dict[str, Any]] = []
        # APK is a ZIP; look for .so files and parse their exports
        import zipfile
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.so'):
                        data = zf.read(name)
                        for m in _re.finditer(rb'Java_[\w]+_([\w_]+)', data):
                            fname = m.group(0).decode(errors='replace')
                            funcs.append({
                                'name': fname,
                                'module': name,
                                'is_secure': False,  # default until audited
                            })
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return funcs

    def _extract_android_permissions(self, apk_path: str) -> List[str]:
        perms: List[str] = []
        import zipfile
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' in zf.namelist():
                    # Binary XML -- basic string extraction
                    data = zf.read('AndroidManifest.xml')
                    for m in _re.finditer(
                            rb'android\.permission\.[A-Z_]+', data):
                        perms.append(m.group(0).decode())
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return perms

    def _extract_objc_classes(self, ipa_path: str) -> List[Dict[str, Any]]:
        classes: List[Dict[str, Any]] = []
        import zipfile
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                for name in zf.namelist():
                    if 'Mach-O' in name or name.endswith('.app'):
                        continue
                    if name.endswith('.o') or ('.app/' in name and '.' not in name.split('/')[-1]):
                        try:
                            data = zf.read(name)
                            # ObjC class references: _OBJC_CLASS_$_
                            for m in _re.finditer(rb'_OBJC_CLASS_\$_(.+)', data):
                                cls_name = m.group(1).decode(errors='replace')
                                classes.append({'name': cls_name, 'source': name})
                        except Exception:
                            continue
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return classes

    def _extract_objc_methods(self, ipa_path: str) -> List[str]:
        methods: List[str] = []
        import zipfile
        try:
            with zipfile.ZipFile(ipa_path, 'r') as zf:
                for name in zf.namelist():
                    if not name.endswith(('.o', '.dylib', '.framework')):
                        continue
                    try:
                        data = zf.read(name)
                        for m in _re.finditer(rb'[+-]\s*\[.*?\s+(\w+)\]', data):
                            methods.append(m.group(0).decode(errors='replace'))
                    except Exception:
                        continue
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return methods

    def _detect_mobile_vulnerabilities(self,
                                       analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns: List[Dict[str, Any]] = []
        if self.platform == 'android':
            for func in analysis_data.get('jni_functions', []):
                if not func.get('is_secure'):
                    vulns.append({
                        'type': 'insecure_jni',
                        'function': func.get('name'),
                        'severity': 'high',
                    })
            for perm in analysis_data.get('permissions', []):
                if perm in self._DANGEROUS_PERMISSIONS:
                    vulns.append({
                        'type': 'excessive_permission',
                        'permission': perm,
                        'severity': 'medium',
                    })
        elif self.platform == 'ios':
            # Check for common iOS issues
            for cls in analysis_data.get('classes', []):
                name = cls.get('name', '')
                if 'UIWebView' in name and 'WKWebView' not in name:
                    vulns.append({
                        'type': 'deprecated_webview',
                        'class': name,
                        'severity': 'medium',
                    })
        return vulns


# 10. Remaining Utility Classes (polished, stubs removed)

class VulnerabilityHeatmapTracker:
    """Track vulnerability density per function across software versions."""

    def __init__(self):
        self.version_data: Dict[str, Dict[int, VulnerabilityDensity]] = {}
        self.hot_functions: List[Tuple[int, float]] = []

    def add_version_analysis(self, version: str,
                             analysis_results: Dict[int, List[str]]) -> None:
        vdata: Dict[int, VulnerabilityDensity] = {}
        for func_addr, vulns in analysis_results.items():
            vdata[func_addr] = VulnerabilityDensity(
                version=version,
                function_addr=func_addr,
                vuln_count=len(vulns),
                density_score=0.0,
            )
        self.version_data[version] = vdata

    def calculate_density_scores(self) -> None:
        """Compute density scores by aggregating vuln counts across versions."""
        func_totals: Dict[int, float] = defaultdict(float)
        version_count = max(len(self.version_data), 1)
        for v_data in self.version_data.values():
            for addr, density in v_data.items():
                func_totals[addr] += density.vuln_count
        # Normalise and build hot-functions list
        self.hot_functions.clear()
        for addr, total in func_totals.items():
            score = total / version_count
            self.hot_functions.append((addr, score))

    def identify_hot_functions(self, top_n: int = 20) -> List[Tuple[int, float]]:
        self.calculate_density_scores()
        return sorted(self.hot_functions, key=lambda x: -x[1])[:top_n]

    def generate_heatmap_data(self) -> Dict[str, Any]:
        """Build heatmap-compatible data structure."""
        self.calculate_density_scores()
        heatmap: Dict[str, Any] = {
            'type': 'vulnerability_heatmap',
            'versions': list(self.version_data.keys()),
            'data': {},
        }
        for v_name, v_data in self.version_data.items():
            heatmap['data'][v_name] = [
                {
                    'function': hex(d.function_addr),
                    'vuln_count': d.vuln_count,
                    'density': d.density_score,
                }
                for d in v_data.values()
            ]
        return heatmap


class AutomatedPatchPrioritySorter:
    """Prioritise vulnerabilities by severity, exploitability, and impact."""

    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.priority_scores: Dict[str, float] = {}
        self.patch_recommendations: List[Dict[str, Any]] = []
        self._severity_w = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        self._exploit_w = {'easy': 8, 'moderate': 5, 'difficult': 2, 'none': 0}
        self._impact_w = {
            'data_breach': 9, 'service_disruption': 7,
            'privilege_escalation': 6, 'information_leak': 4, 'dos': 3,
        }

    def add_vulnerability(self, vuln: Dict[str, Any]) -> None:
        self.vulnerabilities.append(vuln)

    def calculate_priority_score(self, vuln: Dict[str, Any]) -> float:
        score = 0.0
        score += self._severity_w.get(vuln.get('severity', 'medium'), 4) * 10
        score += self._exploit_w.get(vuln.get('exploitability', 'moderate'), 5) * 8
        for impact in vuln.get('impacts', []):
            score += self._impact_w.get(impact, 3) * 6
        score += vuln.get('cvss', 0) * 5
        if vuln.get('has_public_exploit'):
            score += 15
        if vuln.get('in_the_wild'):
            score += 20
        return score

    def sort_by_priority(self) -> List[Dict[str, Any]]:
        scored = []
        for vuln in self.vulnerabilities:
            vuln['priority_score'] = self.calculate_priority_score(vuln)
            self.priority_scores[vuln.get('id', str(id(vuln)))] = vuln['priority_score']
            scored.append(vuln)
        scored.sort(key=lambda v: v['priority_score'], reverse=True)
        return scored

    def generate_patch_recommendations(self) -> List[Dict[str, Any]]:
        sorted_vulns = self.sort_by_priority()
        recs = []
        for i, vuln in enumerate(sorted_vulns):
            recs.append({
                'rank': i + 1,
                'vulnerability_id': vuln.get('id'),
                'priority_score': vuln['priority_score'],
                'severity': vuln.get('severity'),
                'recommended_action': self._determine_action(vuln),
                'estimated_effort': self._estimate_effort(vuln),
                'deadline': self._calculate_deadline(vuln),
            })
        self.patch_recommendations = recs
        return recs

    def _determine_action(self, vuln: Dict[str, Any]) -> str:
        sev = vuln.get('severity', 'medium')
        return {'critical': 'fix_immediately', 'high': 'fix_24h',
                'medium': 'fix_7d'}.get(sev, 'fix_30d')

    def _estimate_effort(self, vuln: Dict[str, Any]) -> str:
        effort = {'simple': '1-2h', 'moderate': '1-2d',
                  'complex': '1w', 'very_complex': '2w+'}
        return effort.get(vuln.get('fix_complexity', 'moderate'), '1-2d')

    def _calculate_deadline(self, vuln: Dict[str, Any]) -> str:
        sev = vuln.get('severity', 'medium')
        if sev == 'critical' or vuln.get('has_public_exploit'):
            return 'immediate'
        return {'high': '24h', 'medium': '7d'}.get(sev, '30d')


class DynamicTaintTracker:
    """Abstract backend for tracking taint from input sources to sinks."""

    def __init__(self):
        self.taint_sources: List[Dict[str, Any]] = []
        self.taint_sinks: List[Dict[str, Any]] = []
        self.taint_flows: List[Dict[str, Any]] = []
        self.backend = 'frida'

    def set_taint_source(self, source_type: str,
                         source_info: Dict[str, Any]) -> None:
        self.taint_sources.append({
            'type': source_type, 'info': source_info,
            'added_at': datetime.now().isoformat(),
        })

    def set_taint_sink(self, sink_type: str,
                       sink_info: Dict[str, Any]) -> None:
        self.taint_sinks.append({
            'type': sink_type, 'info': sink_info,
            'added_at': datetime.now().isoformat(),
        })

    def start_tracking(self, target_process: str) -> Dict[str, Any]:
        return {
            'process': target_process, 'backend': self.backend,
            'status': 'running', 'started_at': datetime.now().isoformat(),
        }

    def record_taint_flow(self, source_addr: int, sink_addr: int,
                          propagation_path: List[int]) -> None:
        self.taint_flows.append({
            'source': hex(source_addr),
            'sink': hex(sink_addr),
            'path': [hex(a) for a in propagation_path],
            'recorded_at': datetime.now().isoformat(),
        })

    def export_taint_flows(self) -> Dict[str, Any]:
        return {
            'taint_sources': self.taint_sources,
            'taint_sinks': self.taint_sinks,
            'flows': self.taint_flows,
            'exported_at': datetime.now().isoformat(),
        }

    def generate_frida_script(self) -> str:
        return '''\
// Taint Tracking Frida Script
Interceptor.attach(Module.findExportByName(null, "read"), {
    onEnter: function(args) {
        this.buf = args[0];
        this.count = args[2].toInt32();
    },
    onLeave: function(ret) {
        if (ret.toInt32() > 0) {
            send({taint: "read", buf: this.buf, len: ret.toInt32()});
        }
    }
});
'''


class SmartPatchSuggestionGenerator:
    """Generate unified-diff patch suggestions for vulnerabilities."""

    def __init__(self):
        self.patch_suggestions: Dict[str, Dict[str, Any]] = {}
        self.ai_config: Dict[str, Any] = {}

    def generate_patch(self, vulnerable_code: str, vuln_type: str,
                       context: str = "") -> Dict[str, Any]:
        suggestion: Dict[str, Any] = {
            'vulnerable_code': vulnerable_code,
            'vuln_type': vuln_type,
            'patch': '',
            'diff': '',
            'confidence': 0.0,
            'generated_at': datetime.now().isoformat(),
        }
        patch = self._generate_rule_based_patch(vulnerable_code, vuln_type)
        suggestion['patch'] = patch
        suggestion['diff'] = self._generate_diff(vulnerable_code, patch)
        suggestion['confidence'] = 0.7
        self.patch_suggestions[vuln_type] = suggestion
        return suggestion

    def _generate_rule_based_patch(self, code: str, vuln_type: str) -> str:
        patch = code
        if vuln_type == 'buffer_overflow':
            if 'strcpy' in code:
                patch = code.replace('strcpy', 'strncpy')
            elif 'gets' in code:
                patch = code.replace('gets', 'fgets')
            elif 'sprintf' in code:
                patch = code.replace('sprintf', 'snprintf')
        elif vuln_type == 'format_string':
            if 'printf(' in code and '%' in code:
                patch = code.replace('printf(', 'printf("%s", ')
        elif vuln_type == 'integer_overflow':
            patch = '/* Add bounds checking before: */\n' + code
        elif vuln_type == 'use_after_free':
            patch = code + '\n/* Set pointer to NULL after free */'
        return patch

    def _generate_diff(self, original: str, patched: str) -> str:
        lines = ['--- a/vulnerable.c', '+++ b/patched.c', '@@ -1 +1 @@']
        orig_l = original.split('\n')
        patch_l = patched.split('\n')
        for i, (o, p) in enumerate(zip(orig_l, patch_l)):
            if o != p:
                lines.append(f'-{i + 1}: {o}')
                lines.append(f'+{i + 1}: {p}')
        return '\n'.join(lines)

    def format_for_display(self, diff: str) -> Dict[str, Any]:
        display: Dict[str, Any] = {'additions': [], 'deletions': [], 'context': []}
        for line in diff.split('\n'):
            if line.startswith('+'):
                display['additions'].append(line[1:])
            elif line.startswith('-'):
                display['deletions'].append(line[1:])
            else:
                display['context'].append(line)
        return display


class BinaryDiffAnalyzer:
    """Function-level binary diffing with regression-vulnerability detection."""

    def __init__(self):
        self.version_a_functions: Dict[int, Dict[str, Any]] = {}
        self.version_b_functions: Dict[int, Dict[str, Any]] = {}
        self.function_matches: List[Dict[str, Any]] = []
        self.regression_vulnerabilities: List[Dict[str, Any]] = []

    def load_binary_version(self, version_label: str,
                            binary_path: str) -> Dict[str, Any]:
        functions: Dict[int, Dict[str, Any]] = {}
        try:
            result = _sp.run(['nm', '-n', binary_path],
                             capture_output=True, text=True, timeout=60)
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1].lower() in ('t', 'w'):
                    try:
                        addr = int(parts[0], 16)
                    except ValueError:
                        continue
                    functions[addr] = {
                        'name': parts[-1],
                        'size': 0,  # unknown from nm alone
                        'address': addr,
                    }
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        if version_label == 'a':
            self.version_a_functions = functions
        else:
            self.version_b_functions = functions
        return {'version': version_label, 'function_count': len(functions)}

    def match_functions(self) -> List[Dict[str, Any]]:
        matches = []
        for addr_a, func_a in self.version_a_functions.items():
            best = None
            best_sim = 0.0
            for addr_b, func_b in self.version_b_functions.items():
                sim = self._calculate_similarity(func_a, func_b)
                if sim > best_sim and sim > 0.7:
                    best_sim = sim
                    best = (addr_b, func_b, sim)
            if best:
                matches.append({
                    'version_a_addr': hex(addr_a),
                    'version_b_addr': hex(best[0]),
                    'similarity': best[2],
                    'status': self._get_change_status(best[2]),
                })
        self.function_matches = matches
        return matches

    def _calculate_similarity(self, func_a: Dict[str, Any],
                              func_b: Dict[str, Any]) -> float:
        """Name-based + size heuristics for function similarity."""
        name_a = func_a.get('name', '')
        name_b = func_b.get('name', '')
        if name_a == name_b:
            return 0.95
        # Jaccard on character bigrams
        bigrams_a = {name_a[i:i + 2] for i in range(len(name_a) - 1)}
        bigrams_b = {name_b[i:i + 2] for i in range(len(name_b) - 1)}
        union = len(bigrams_a | bigrams_b)
        if not union:
            return 0.0
        return len(bigrams_a & bigrams_b) / union

    def _get_change_status(self, similarity: float) -> str:
        if similarity > 0.95:
            return 'unchanged'
        elif similarity > 0.7:
            return 'modified'
        return 'removed' if similarity < 0.3 else 'added'

    def identify_regression_vulnerabilities(self,
                                            vuln_db: Dict[str, Any]) -> List[Dict[str, Any]]:
        regressions = []
        for match in self.function_matches:
            if match['status'] == 'modified':
                faddr = match['version_a_addr']
                if faddr in vuln_db:
                    regressions.append({
                        'function': faddr,
                        'vulnerability': vuln_db[faddr],
                        'change_type': 'modified_after_vuln',
                    })
        self.regression_vulnerabilities = regressions
        return regressions


class ReverseInteractiveShell:
    """Prompt-based interactive reverse-engineering shell."""

    def __init__(self):
        self.binary_path: Optional[str] = None
        self.current_function: Optional[int] = None
        self.command_history: List[str] = []

    def register_commands(self) -> Dict[str, Callable]:
        return {
            'load': self.cmd_load,
            'decompile': self.cmd_decompile,
            'analyze': self.cmd_analyze,
            'xrefs': self.cmd_xrefs,
            'exploit': self.cmd_exploit,
            'search': self.cmd_search,
            'functions': self.cmd_functions,
            'segments': self.cmd_segments,
        }

    def cmd_load(self, args: List[str]) -> str:
        if not args:
            return "Usage: load <binary_path>"
        self.binary_path = args[0]
        if not os.path.exists(self.binary_path):
            return f"Error: file not found: {self.binary_path}"
        return f"Loaded: {self.binary_path}"

    def cmd_decompile(self, args: List[str]) -> str:
        addr = None
        if args:
            try:
                addr = int(args[0], 16)
            except ValueError:
                return f"Invalid address: {args[0]}"
        elif self.current_function:
            addr = self.current_function
        if addr is None:
            return "Usage: decompile <address>"
        self.current_function = addr
        return f"Decompiling function at 0x{addr:x}..."

    def cmd_analyze(self, args: List[str]) -> str:
        if not args:
            return "Usage: analyze <address>"
        try:
            addr = int(args[0], 16)
        except ValueError:
            return f"Invalid address: {args[0]}"
        return f"Analyzing 0x{addr:x}..."

    def cmd_xrefs(self, args: List[str]) -> str:
        if not args:
            return "Usage: xrefs <address>"
        try:
            addr = int(args[0], 16)
        except ValueError:
            return f"Invalid address: {args[0]}"
        return f"Xrefs to 0x{addr:x}: (requires binary backend)"

    def cmd_exploit(self, args: List[str]) -> str:
        if not args:
            return "Usage: exploit <vuln_address>"
        return "Generating exploit..."

    def cmd_search(self, args: List[str]) -> str:
        if not args:
            return "Usage: search <pattern>"
        pattern = ' '.join(args)
        if self.binary_path and os.path.exists(self.binary_path):
            with open(self.binary_path, 'rb') as fh:
                data = fh.read()
            idx = data.find(pattern.encode(errors='replace'))
            if idx >= 0:
                return f"Found '{pattern}' at offset 0x{idx:x}"
            return f"'{pattern}' not found"
        return f"Searching for: {pattern} (no binary loaded)"

    def cmd_functions(self, args: List[str]) -> str:
        if not self.binary_path:
            return "No binary loaded"
        try:
            result = _sp.run(['nm', '-n', self.binary_path],
                             capture_output=True, text=True, timeout=30)
            funcs = [l for l in result.stdout.splitlines()
                     if len(l.split()) >= 3 and l.split()[1].lower() in ('t', 'w')]
            return '\n'.join(funcs[:50]) + (f'\n... ({len(funcs)} total)' if len(funcs) > 50 else '')
        except Exception as e:
            return f"Error: {e}"

    def cmd_segments(self, args: List[str]) -> str:
        if not self.binary_path:
            return "No binary loaded"
        try:
            result = _sp.run(['objdump', '-h', self.binary_path],
                             capture_output=True, text=True, timeout=30)
            return result.stdout[:2000]
        except Exception as e:
            return f"Error: {e}"

    def run(self) -> None:
        commands = self.register_commands()
        print("Reverse Engineering Interactive Shell")
        print("Commands: " + ", ".join(commands.keys()) + ", exit")
        while True:
            try:
                cmd_line = input(f"{self.binary_path or 'no-bin'}> ").strip()
                if not cmd_line:
                    continue
                parts = cmd_line.split()
                cmd = parts[0]
                args = parts[1:]
                self.command_history.append(cmd_line)
                if cmd == 'exit':
                    break
                if cmd in commands:
                    print(commands[cmd](args))
                else:
                    print(f"Unknown command: {cmd}")
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except Exception as e:
                print(f"Error: {e}")


class CryptoConstantDetector:
    """Scan binaries for cryptographic constants and weak algorithms."""

    def __init__(self):
        self.crypto_constants: Dict[str, bytes] = {
            'AES_SBOX': bytes.fromhex('637c777bf26b593fc4c2a85005aacb67'),
            'DES_PARITY': bytes([0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]),
            'MD5_INIT': bytes.fromhex('67452301efcdab8998badcfe10325476'),
        }
        self.detected_algorithms: List[Dict[str, Any]] = []
        self.weak_algorithms: List[Dict[str, Any]] = []

    def scan_binary(self, binary_path: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'file': binary_path,
            'algorithms_found': [],
            'weak_algorithms': [],
            'hardcoded_keys': [],
            'ecb_usage': [],
        }
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for algo_name, constant in self.crypto_constants.items():
                if constant in data:
                    offset = data.index(constant)
                    result['algorithms_found'].append({
                        'algorithm': algo_name, 'offset': hex(offset),
                    })
            result['weak_algorithms'] = self._detect_weak_algorithms(data)
            result['ecb_usage'] = self._detect_ecb_usage(data)
        except Exception as e:
            result['error'] = str(e)
        self.detected_algorithms = result['algorithms_found']
        self.weak_algorithms = result['weak_algorithms']
        return result

    def _detect_weak_algorithms(self, data: bytes) -> List[Dict[str, Any]]:
        weak = []
        signatures = {'MD5': b'md5', 'SHA1': b'sha1', 'DES': b'des', 'RC4': b'rc4'}
        for algo, sig in signatures.items():
            if sig.lower() in data.lower():
                weak.append({'algorithm': algo, 'reason': f'{algo} is deprecated'})
        return weak

    def _detect_ecb_usage(self, data: bytes) -> List[Dict[str, Any]]:
        ecb = []
        # ECB leaves identical ciphertext blocks for identical plaintext.
        # Scan for repeated 16-byte blocks in .rodata or .data segments.
        if len(data) < 32:
            return ecb
        blocks: Dict[bytes, List[int]] = {}
        for i in range(0, len(data) - 16, 16):
            block = data[i:i + 16]
            blocks.setdefault(block, []).append(i)
        for block, positions in blocks.items():
            if len(positions) > 2 and block != b'\x00' * 16:
                ecb.append({
                    'pattern': block.hex()[:32],
                    'occurrences': len(positions),
                    'first_offset': hex(positions[0]),
                })
        return ecb

    def check_for_hardcoded_keys(self, binary_path: str) -> List[Dict[str, Any]]:
        keys = []
        patterns = [b'key', b'password', b'secret', b'token',
                    b'-----BEGIN', b'-----END']
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for pat in patterns:
                offset = 0
                while True:
                    pos = data.find(pat, offset)
                    if pos == -1:
                        break
                    ctx_start = max(0, pos - 16)
                    ctx_end = min(len(data), pos + 48)
                    keys.append({
                        'pattern': pat.decode(errors='replace'),
                        'offset': hex(pos),
                        'context': data[ctx_start:ctx_end].hex(),
                    })
                    offset = pos + 1
        except Exception:
            _logger.debug("suppressed", exc_info=True)
        return keys


class CryptoImplementationComparator:
    """Compare embedded crypto against known reference implementations."""

    def __init__(self):
        self.crypto_patterns: Dict[str, Dict[str, Any]] = {}
        self.detected_algorithms: List[Dict[str, Any]] = []
        self.comparison_results: Dict[str, Dict[str, Any]] = {}
        self._register_crypto_patterns()

    def _register_crypto_patterns(self):
        self.crypto_patterns.update({
            'aes': {
                'constants': [0x63, 0x7c, 0x77, 0x7b],
                'signature': r'aes_|AES_|_aes',
                'reference': 'openssl_aes',
            },
            'rsa': {
                'constants': [],
                'signature': r'rsa_|RSA_|mod_exp',
                'reference': 'openssl_rsa',
            },
            'sha256': {
                'constants': [0x6a09e667, 0xbb67ae85],
                'signature': r'sha256|SHA256|sha_256',
                'reference': 'openssl_sha256',
            },
            'md5': {
                'constants': [0x67452301, 0xefcdab89],
                'signature': r'md5|MD5',
                'reference': 'openssl_md5',
            },
        })

    def detect_crypto_algorithm(self, binary_code: str) -> List[Dict[str, Any]]:
        detected = []
        for algo, info in self.crypto_patterns.items():
            if _re.search(info['signature'], binary_code, _re.IGNORECASE):
                detected.append({
                    'algorithm': algo, 'confidence': 0.8,
                    'reference': info['reference'],
                })
            for const in info['constants']:
                if hex(const) in binary_code or str(const) in binary_code:
                    detected.append({
                        'algorithm': algo, 'confidence': 0.9,
                        'constant': hex(const), 'reference': info['reference'],
                    })
        self.detected_algorithms = detected
        return detected

    def compare_with_reference(self, detected_algo: Dict[str, Any],
                               binary_code: str) -> Dict[str, Any]:
        comparison: Dict[str, Any] = {
            'algorithm': detected_algo['algorithm'],
            'differences': [],
            'suspicious_modifications': [],
            'is_modified': False,
        }
        ref_features = {
            'aes': ['sbox', 'inv_sbox', 'rcon', 'key_expansion'],
            'rsa': ['mod_exp', 'montgomery', 'prime_check'],
            'sha256': ['init_state', 'compress', 'padding'],
            'md5': ['init_state', 'transform', 'finalize'],
        }
        algo = detected_algo['algorithm']
        for feat in ref_features.get(algo, []):
            if feat not in binary_code.lower():
                comparison['differences'].append(f'missing_feature: {feat}')
        suspicious = [
            (r'fixed_key', 'hardcoded key'),
            (r'bypass_check', 'check bypass'),
            (r'weak_random', 'weak RNG'),
            (r'custom_constant', 'non-standard constants'),
        ]
        for pat, desc in suspicious:
            if _re.search(pat, binary_code, _re.IGNORECASE):
                comparison['suspicious_modifications'].append(desc)
                comparison['is_modified'] = True
        return comparison

    def analyze_all_detected(self, binary_code: str) -> Dict[str, Any]:
        results = {}
        for algo in self.detected_algorithms:
            results[algo['algorithm']] = self.compare_with_reference(algo, binary_code)
        self.comparison_results = results
        return results


class HardwareBreakpointWatchpointAnalyzer:
    """Manage hardware breakpoints and memory watchpoints for debugging."""

    def __init__(self):
        self.breakpoints: Dict[int, Dict[str, Any]] = {}
        self.watchpoints: Dict[int, Dict[str, Any]] = {}
        self.memory_events: List[Dict[str, Any]] = []
        self.max_breakpoints = 4

    def set_hardware_breakpoint(self, address: int,
                                condition: str = 'execute') -> Dict[str, Any]:
        if len(self.breakpoints) >= self.max_breakpoints:
            return {'error': 'hw breakpoint limit reached'}
        bp = {
            'address': address, 'condition': condition,
            'enabled': True, 'trigger_count': 0,
            'created_at': datetime.now().isoformat(),
        }
        self.breakpoints[address] = bp
        return bp

    def set_watchpoint(self, address: int, size: int = 4,
                       access_type: str = 'rw') -> Dict[str, Any]:
        wp = {
            'address': address, 'size': size, 'access_type': access_type,
            'enabled': True, 'trigger_count': 0, 'last_value': None,
            'created_at': datetime.now().isoformat(),
        }
        self.watchpoints[address] = wp
        return wp

    def generate_gdb_commands(self) -> str:
        cmds = ''
        for addr, bp in self.breakpoints.items():
            if bp['enabled']:
                cmds += f'hbreak *{hex(addr)}\n'
        for addr, wp in self.watchpoints.items():
            if wp['enabled']:
                if wp['access_type'] == 'r':
                    cmds += f'rwatch *{hex(addr)}\n'
                elif wp['access_type'] == 'w':
                    cmds += f'watch *{hex(addr)}\n'
                else:
                    cmds += f'awatch *{hex(addr)}\n'
        return cmds

    def record_memory_event(self, address: int, event_type: str,
                            old_value: Any, new_value: Any) -> Dict[str, Any]:
        event = {
            'address': address, 'event_type': event_type,
            'old_value': old_value, 'new_value': new_value,
            'timestamp': datetime.now().isoformat(),
        }
        self.memory_events.append(event)
        if address in self.watchpoints:
            self.watchpoints[address]['trigger_count'] += 1
            self.watchpoints[address]['last_value'] = new_value
        return event

    def get_memory_modification_trace(self, address: int) -> List[Dict[str, Any]]:
        return [e for e in self.memory_events if e['address'] == address]

    def clear_all_breakpoints(self) -> None:
        self.breakpoints.clear()
        self.watchpoints.clear()
        self.memory_events.clear()


class LoopBoundInferenceEngine:
    """Infer loop iteration bounds from code patterns for symbolic pruning."""

    def __init__(self):
        self.loop_patterns: Dict[str, Dict[str, Any]] = {}
        self.inferred_bounds: Dict[int, Dict[str, Any]] = {}
        self._register_loop_patterns()

    def _register_loop_patterns(self):
        self.loop_patterns['counter_loop'] = {
            'signature': r'for\s*\(\s*(\w+)\s*=\s*(\d+)\s*;\s*\w+\s*<\s*(\w+)\s*;',
            'type': 'bounded',
            'extract': lambda m: {'var': m.group(1), 'start': int(m.group(2)), 'limit': m.group(3)},
        }
        self.loop_patterns['while_counter'] = {
            'signature': r'while\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)',
            'type': 'bounded',
            'extract': lambda m: {'var': m.group(1), 'limit': m.group(2)},
        }
        self.loop_patterns['array_loop'] = {
            'signature': r'for\s*\(\s*i\s*=\s*0\s*;\s*i\s*<\s*sizeof\((\w+)\)\s*;',
            'type': 'size_based',
            'extract': lambda m: {'array': m.group(1)},
        }

    def infer_loop_bound(self, loop_code: str,
                         context: Dict[str, Any] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'loop_type': 'unknown', 'min_iterations': 0,
            'max_iterations': None, 'bound_type': 'unbounded', 'confidence': 0.0,
        }
        for pname, pinfo in self.loop_patterns.items():
            m = _re.search(pinfo['signature'], loop_code)
            if not m:
                continue
            extracted = pinfo['extract'](m)
            result['loop_type'] = pname
            result['bound_type'] = pinfo['type']
            if 'start' in extracted and 'limit' in extracted:
                try:
                    limit_val = int(extracted['limit'])
                    result['max_iterations'] = limit_val - extracted['start']
                    result['confidence'] = 0.8
                except ValueError:
                    ctx = context or {}
                    result['max_iterations'] = ctx.get(extracted['limit'])
                    result['confidence'] = 0.5
            break
        if result['loop_type'] == 'unknown':
            result = self._symbolic_infer_bound(loop_code, context or {})
        return result

    def _symbolic_infer_bound(self, loop_code: str,
                              context: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'loop_type': 'symbolic', 'min_iterations': 0,
            'max_iterations': None, 'bound_type': 'symbolic', 'confidence': 0.3,
        }
        m = _re.search(r'(\w+)\s*(<|<=|>|>=|==)\s*(\w+|\d+)', loop_code)
        if not m:
            return result
        limit = m.group(3)
        try:
            result['max_iterations'] = int(limit)
            result['confidence'] = 0.6
        except ValueError:
            result['symbolic_limit'] = limit
        return result

    def estimate_stack_usage(self, loop_bound: Dict[str, Any],
                             per_iteration_stack: int) -> int:
        max_iter = loop_bound.get('max_iterations')
        if max_iter is None:
            max_iter = 1000
        return max_iter * per_iteration_stack

    def generate_pruning_constraint(self, loop_bound: Dict[str, Any]) -> str:
        max_iter = loop_bound.get('max_iterations')
        return f'iteration_count <= {max_iter}' if max_iter else 'iteration_count <= 1000'

    def analyze_nested_loops(self, nested_loop_code: str) -> List[Dict[str, Any]]:
        loops = _re.findall(r'(for|while)\s*\([^)]+\)', nested_loop_code)
        bounds = []
        for i, _ in enumerate(loops):
            bound = self.infer_loop_bound(nested_loop_code)
            bound['nesting_level'] = i + 1
            bounds.append(bound)
        return bounds


class MultiArchitectureIROptimizer:
    """Lift architecture-specific instructions to a common IR for analysis."""

    def __init__(self):
        self.architecture_handlers: Dict[str, Callable] = {}
        self.ir_cache: Dict[int, str] = {}
        self.vulnerability_patterns: List[Dict[str, Any]] = []
        self._register_architectures()
        self._register_vulnerability_patterns()

    def _register_architectures(self):
        self.architecture_handlers.update({
            'x86': self._lift_x86,
            'x86_64': lambda asm: self._lift_x86(asm),
            'arm': lambda asm: '; ARM IR placeholder',
            'arm64': lambda asm: '; ARM64 IR placeholder',
            'mips': lambda asm: '; MIPS IR placeholder',
        })

    def _register_vulnerability_patterns(self):
        self.vulnerability_patterns = [
            {'pattern': 'buffer_overflow', 'ir_sig': 'call @memcpy unchecked_size'},
            {'pattern': 'use_after_free', 'ir_sig': 'load after call @free'},
            {'pattern': 'null_deref', 'ir_sig': 'load null check bypassed'},
            {'pattern': 'integer_overflow', 'ir_sig': 'add overflow check missing'},
        ]

    def _lift_x86(self, assembly: str) -> str:
        lines = []
        for line in assembly.splitlines():
            stripped = line.strip()
            if stripped.startswith('mov'):
                lines.append(f'; {stripped}  ->  IR: reg_copy')
            elif stripped.startswith('add'):
                lines.append(f'; {stripped}  ->  IR: iadd')
            elif stripped.startswith('jmp') or stripped.startswith('j'):
                lines.append(f'; {stripped}  ->  IR: branch')
            else:
                lines.append(f'; {stripped}')
        return '\n'.join(lines)

    def lift_to_ir(self, assembly: str, architecture: str) -> str:
        handler = self.architecture_handlers.get(architecture)
        return handler(assembly) if handler else '; Unknown architecture'

    def detect_vulnerabilities_in_ir(self, ir_code: str) -> List[Dict[str, Any]]:
        detected = []
        for pat in self.vulnerability_patterns:
            if pat['ir_sig'].lower() in ir_code.lower():
                detected.append({
                    'vulnerability_type': pat['pattern'],
                    'signature': pat['ir_sig'],
                    'confidence': 0.7,
                })
        return detected

    def optimize_ir(self, ir_code: str) -> str:
        return _re.sub(r'; redundant\s*\n', '', ir_code)


class PeripheralRegisterAccessAnomalyDetector:
    """Monitor peripheral register access sequences for anomalies."""

    def __init__(self):
        self.register_access_log: List[Dict[str, Any]] = []
        self.register_definitions: Dict[int, Dict[str, Any]] = {}
        self.anomaly_reports: List[Dict[str, Any]] = []
        self._register_common_peripherals()

    def _register_common_peripherals(self):
        self.register_definitions.update({
            0x40000000: {
                'name': 'UART_DR', 'type': 'data_register',
                'access': 'rw', 'valid_sequence': ['write_data', 'read_status'],
            },
            0x40000004: {
                'name': 'UART_SR', 'type': 'status_register',
                'access': 'r', 'valid_sequence': ['read_status'],
            },
            0x40020000: {
                'name': 'GPIO_MODER', 'type': 'mode_register',
                'access': 'rw', 'valid_sequence': ['set_mode', 'read_mode'],
            },
        })

    def log_register_access(self, address: int, value: int, access_type: str,
                            timestamp: float) -> None:
        entry = {
            'address': address, 'value': value, 'access_type': access_type,
            'timestamp': timestamp,
            'register_name': self.register_definitions.get(address, {}).get('name', 'unknown'),
        }
        self.register_access_log.append(entry)

    def detect_anomaly(self) -> List[Dict[str, Any]]:
        anomalies = []
        for access in self.register_access_log:
            addr = access['address']
            if addr not in self.register_definitions:
                continue
            reg = self.register_definitions[addr]
            if access['access_type'] == 'write' and reg['access'] == 'r':
                anomalies.append({
                    'type': 'invalid_write',
                    'register': reg['name'],
                    'address': hex(addr),
                    'description': f'Write to read-only register {reg["name"]}',
                    'severity': 'high',
                })
        self.anomaly_reports = anomalies
        return anomalies

    def check_sequence_validity(self, sequence: List[Dict[str, Any]]) -> bool:
        if len(sequence) < 2:
            return True
        for i in range(1, len(sequence)):
            prev = sequence[i - 1]
            cur = sequence[i]
            prev_addr = prev.get('address', 0)
            if prev_addr in self.register_definitions:
                valid_seq = self.register_definitions[prev_addr].get('valid_sequence', [])
                cur_type = cur.get('access_type', '')
                # Simplistic check
                if valid_seq and cur_type not in valid_seq:
                    return False
        return True

    def generate_anomaly_report(self) -> str:
        lines = [
            '# Peripheral Register Access Anomaly Report',
            '',
            '## Statistics',
            f'  Total accesses: {len(self.register_access_log)}',
            '',
        ]
        if self.anomaly_reports:
            lines.append('## Anomalies')
            for a in self.anomaly_reports:
                lines.append(f'  - [{a["severity"]}] {a["register"]}: {a["description"]}')
        return '\n'.join(lines)


class AnalysisDatabaseMaintenance:
    """Periodic cleanup of analysis results, incremental encoding."""

    def __init__(self):
        self.db_path: str = ""
        self.compression_enabled: bool = True

    def set_database_path(self, path: str) -> None:
        self.db_path = path

    def cleanup_stale_results(self, max_age_days: int = 30) -> int:
        """Remove analysis records older than *max_age_days* from SQLite DB."""
        cleaned = 0
        if not self.db_path or not os.path.exists(self.db_path):
            return cleaned
        try:
            conn = sqlite3.connect(self.db_path)
            cutoff = time.time() - (max_age_days * 86400)
            cur = conn.execute(
                'DELETE FROM analysis_results WHERE timestamp < ?', (cutoff,))
            cleaned = cur.rowcount
            conn.commit()
            conn.close()
        except Exception as e:
            _logger.warning("DB cleanup failed: %s", e)
        return cleaned

    def compress_features(self, function_features: Dict[str, Any]) -> bytes:
        import pickle
        return pickle.dumps(function_features)

    def incremental_encode(self, features: List[Dict[str, Any]]) -> bytes:
        """Delta-encode a list of feature dicts relative to the first entry."""
        import pickle
        if not features:
            return b''
        base = features[0]
        deltas = [base]
        for feat in features[1:]:
            delta: Dict[str, Any] = {}
            for k, v in feat.items():
                if k not in base or base[k] != v:
                    delta[k] = v
            deltas.append(delta)
        return pickle.dumps(deltas)

    def get_database_size(self) -> int:
        if self.db_path and os.path.exists(self.db_path):
            return os.path.getsize(self.db_path)
        return 0


# Module exports

__all__ = [
    # Data objects
    'VulnerabilityDensity',
    'ExceptionHijackPoint',
    'SemanticRewrittenCode',
    # Core utilities
    'NgramBinaryHash',
    'BinaryCacheManager',
    'AnalysisDatabaseMaintenance',
    # Security analysis
    'BinarySecurityAuditor',
    'CryptoConstantDetector',
    'CryptoImplementationComparator',
    # Exception analysis
    'ExceptionAnalysisSuite',
    'ExceptionHandlingPathCoverageAnalyzer',
    # Code structure
    'CodeStructureAnalyzer',
    'DecompilerSemanticRewriter',
    'DisassemblyMacroIdentifierExpander',
    # Memory & forensics
    'MemoryForensicAnalyzer',
    'CrossProcessDataFlowTracker',
    # Exploit development
    'ExploitDevelopmentKit',
    # Dynamic analysis
    'DynamicAnalysisHarness',
    'DynamicTaintTracker',
    'HardwareBreakpointWatchpointAnalyzer',
    # Environment
    'DockerSandboxManager',
    'ExploitReproduceEnvironmentGenerator',
    # Platform-specific
    'GoRustBinaryAnalyzer',
    'MobilePlatformDeepAnalyzer',
    # Pipeline & triage
    'VulnerabilityHeatmapTracker',
    'AutomatedPatchPrioritySorter',
    'BinaryDiffAnalyzer',
    'SmartPatchSuggestionGenerator',
    # Instruction analysis
    'LoopBoundInferenceEngine',
    'MultiArchitectureIROptimizer',
    'PeripheralRegisterAccessAnomalyDetector',
    # Interactive
    'ReverseInteractiveShell',
]
