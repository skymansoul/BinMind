"""Fingerprint compiler toolchain and optimization level from binary artifacts."""

import re
import struct
import os
from collections import Counter
from enum import IntEnum

module = "compiler_opt_analyzer"
name = "CompilerOptAnalyzer"

# ── Compiler fingerprint database ──────────────────────────────────────────
_GCC_PROLOGUE = re.compile(
    rb'\x55\x48\x89\xe5'          # push rbp; mov rbp, rsp — GCC standard frame
    rb'|'
    rb'\xf3\x0f\x1e\xfa'          # endbr64 — CET-enabled GCC 8+
)
_GCC_STRING = re.compile(rb'GCC:\s*\(.*?\)\s*[\d.]+', re.DOTALL)
_GCC_GO_SIGNATURE = re.compile(rb'Go build ID:')

_MSVC_PROLOGUE = re.compile(
    rb'\x48\x89\x5c\x24[\x08\x10]' # MSVC prologue — mov [rsp+8/10h], rbx
    rb'|'
    rb'\x40\x55'                    # push rbp — REX prefix variant
)
_MSVC_RTC = re.compile(rb'_RTC_|__RTC_|_CrtDbgReport|__security_check_cookie')
_MSVC_STRING = re.compile(rb'Microsoft\s*\(R\)|Visual\s*C\+\+|MSVC|cl\.exe', re.IGNORECASE)

_CLANG_PROLOGUE = re.compile(
    rb'\x55\x48\x89\xe5\x48\x83\xec[\x10\x20\x30\x40\x50\x60\x70]'  # clang standard stack frame
    rb'|'
    rb'\x6a\x00' * 4                # clang zero-init via repeated push
)
_CLANG_STRING = re.compile(rb'clang\s+version\s+[\d.]+', re.IGNORECASE)
_CLANG_ASAN_SIG = re.compile(rb'__asan_|__ubsan_|__tsan_')

# ── Optimization level detection ──────────────────────────────────────────
_OPT_PATTERNS = {
    0: re.compile(
        # O0: maximal stack spill, zero register reuse
        rb'(mov\s+%[a-z]{2,3},\s*-?0x[0-9a-f]*\(%rbp\).*){3,}',
        re.DOTALL
    ),
    2: re.compile(
        # O2/O3: xor-zeroing, lea arithmetic, aggressive register reuse
        rb'xor\s+%[a-z]{2,3},\s*%[a-z]{2,3}\s*\n.*lea\s+'
        rb'|'
        rb'vpcmpeqd\s+%ymm\d+,\s*%ymm\d+,\s*%ymm\d+'
    ),
}

# O2/O3 discrimination is imprecise; apply this pattern for O3 classification
_O3_AUTOVEC = re.compile(
    rb'(v)?mov(dqu|dqa|aps|upd|aps|apd)|padd[bdqw]|pmul[lh]|pshuf[bwd]',
    re.DOTALL
)


class CompilerType:
    GCC = "gcc"
    CLANG = "clang"
    MSVC = "msvc"
    UNKNOWN = "unknown"

class OptimizationLevel(IntEnum):
    O0 = 0
    O1 = 1
    O2 = 2
    O3 = 3
    Os = -1       # size-optimized (-Os)
    UNKNOWN = -2


class SecurityRisk:
    def __init__(self, level, description, mitigations=None):
        self.level = level            # severity: low, medium, high
        self.description = description
        self.mitigations = mitigations or []


class CompilerOptAnalyzer:
    """Compiler fingerprinting from raw binary data."""

    def __init__(self):
        self._binary_data = b''
        self._section_names = []

    def analyze(self, binary):
        """Accept file path or raw bytes. Returns fingerprint results."""
        if isinstance(binary, str) and os.path.isfile(binary):
            with open(binary, 'rb') as fh:
                self._binary_data = fh.read()
            # Truncate to 1 MiB for signature analysis
            self._sample = self._binary_data[:min(len(self._binary_data), 2**20)]
        else:
            self._binary_data = binary if isinstance(binary, bytes) else b''
            self._sample = self._binary_data[:min(len(self._binary_data), 2**20)]

        compiler = self._detect_compiler()
        opt_level = self._detect_opt_level(compiler)
        risks = self._assess_security_risks(compiler, opt_level)
        return {
            'compiler': compiler,
            'optimization_level': opt_level.name if hasattr(opt_level, 'name') else str(opt_level),
            'confidence': self._confidence,
            'security_risks': [{'level': r.level, 'desc': r.description, 'mitigations': r.mitigations} for r in risks],
            'indicators': self._indicators,
        }

    # ── Internal detection logic ────────────────────────────────────────

    def _detect_compiler(self):
        scores = Counter()
        self._indicators = Counter()
        self._confidence = 0.0

        # String-table signatures — weight: 30
        if _GCC_STRING.search(self._sample):
            scores['gcc'] += 30; self._indicators['gcc_string'] += 1
        if _MSVC_STRING.search(self._sample):
            scores['msvc'] += 30; self._indicators['msvc_string'] += 1
        if _CLANG_STRING.search(self._sample):
            scores['clang'] += 30; self._indicators['clang_string'] += 1

        # Prologue patterns — weight: 5 per hit
        gcc_prologues = len(_GCC_PROLOGUE.findall(self._sample))
        msvc_prologues = len(_MSVC_PROLOGUE.findall(self._sample))
        clang_prologues = len(_CLANG_PROLOGUE.findall(self._sample))

        scores['gcc'] += gcc_prologues * 5
        scores['msvc'] += msvc_prologues * 5
        scores['clang'] += clang_prologues * 5
        self._indicators['gcc_prologue'] = gcc_prologues
        self._indicators['msvc_prologue'] = msvc_prologues
        self._indicators['clang_prologue'] = clang_prologues

        # Runtime/sanitizer imports — varying weight
        if _MSVC_RTC.search(self._sample):
            scores['msvc'] += 10; self._indicators['msvc_rtc'] += 1
        if _CLANG_ASAN_SIG.search(self._sample):
            scores['clang'] += 10; self._indicators['clang_asan'] += 1
        if _GCC_GO_SIGNATURE.search(self._sample):
            scores['gcc'] += 8; self._indicators['gcc_go'] += 1

        # PE: validate linker version in optional header
        pe_sig = self._sample[:2]
        if pe_sig == b'MZ':
            try:
                pe_offset = struct.unpack_from('<I', self._sample, 0x3c)[0]
                if self._sample[pe_offset:pe_offset+4] == b'PE\0\0':
                    # Inspect debug directory for compiler-specific GUIDs
                    rsds = self._sample.find(b'RSDS')
                    if rsds != -1:
                        # CodeView RSDS: compiler GUID precedes PDB path
                        self._indicators['rsds_guid'] += 1
            except (struct.error, IndexError):
                pass

        total = sum(scores.values()) or 1
        if not scores:
            # 无任何签名命中：判定为 unknown，置信度 0
            self._confidence = 0.0
            return CompilerType.UNKNOWN
        best_compiler, best_score = scores.most_common(1)[0]
        self._confidence = min(best_score / total, 1.0)

        return best_compiler

    def _detect_opt_level(self, compiler):
        # Extract code sections via heuristic sampling
        code_regions = []
        if self._binary_data[:2] == b'MZ':
            # PE: parse section headers to locate .text
            try:
                pe_offset = struct.unpack_from('<I', self._binary_data, 0x3c)[0]
                if self._binary_data[pe_offset:pe_offset+4] == b'PE\0\0':
                    num_sections = struct.unpack_from('<H', self._binary_data, pe_offset + 6)[0]
                    opt_size = struct.unpack_from('<H', self._binary_data, pe_offset + 20)[0]
                    sec_table = pe_offset + 24 + opt_size
                    for i in range(num_sections):
                        sec_off = sec_table + i * 40
                        sec_name = self._binary_data[sec_off:sec_off+8].rstrip(b'\0')
                        if sec_name == b'.text':
                            vsize = struct.unpack_from('<I', self._binary_data, sec_off + 8)[0]
                            raw_ptr = struct.unpack_from('<I', self._binary_data, sec_off + 20)[0]
                            raw_size = struct.unpack_from('<I', self._binary_data, sec_off + 16)[0]
                            chunk = self._binary_data[raw_ptr:raw_ptr+min(raw_size, vsize)]
                            code_regions.append(chunk)
                            break
            except (struct.error, IndexError):
                pass
        elif self._binary_data[:4] == b'\x7fELF':
            # ELF: sample fixed offsets in lieu of full section header parse
            for offset in [0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000]:
                chunk = self._binary_data[offset:offset+4096]
                if len(chunk) == 4096:
                    code_regions.append(chunk)

        if not code_regions:
            code_regions = [self._sample[0x400:0x400+4096 * 4]]

        combined = b'\n'.join(code_regions)

        # O0 detection: stack spill density
        o0_hits = len(_OPT_PATTERNS[0].findall(combined[:65536]))
        # O2 detection: xor-zeroing with lea arithmetic
        o2_hits = len(_OPT_PATTERNS[2].findall(combined[:65536]))
        # O3 detection: SIMD auto-vectorization density
        o3_hits = len(_O3_AUTOVEC.findall(combined[:65536]))

        if o0_hits > 20:
            return OptimizationLevel.O0
        if o3_hits > 10 and o2_hits > 5:
            return OptimizationLevel.O3
        if o2_hits > 5:
            return OptimizationLevel.O2
        if o0_hits > 5:
            return OptimizationLevel.O1
        return OptimizationLevel.Os if o2_hits == 0 and o0_hits == 0 else OptimizationLevel.UNKNOWN

    def _assess_security_risks(self, compiler, opt_level):
        risks = []
        if opt_level == OptimizationLevel.O0:
            risks.append(SecurityRisk('medium',
                'Debug build (O0): stack canaries and CFG may be disabled. '
                'No inlining means more gadget surface.'))
        if compiler == 'msvc' and opt_level in (OptimizationLevel.O0, OptimizationLevel.O1):
            risks.append(SecurityRisk('high',
                'MSVC debug builds lack /GS in some configs; RTC checks disabled at O1.',
                ['Compile with /GS /DYNAMICBASE /NXCOMPAT']))
        return risks


# ── Module-level convenience exports ─────────────────────────────────────

analyze_compiler_opt = CompilerOptAnalyzer().analyze


def format_compiler_opt_report(result):
    lines = [f"Compiler: {result['compiler']}",
             f"Optimization: {result['optimization_level']}",
             f"Confidence: {result['confidence']:.1%}"]
    for r in result.get('security_risks', []):
        lines.append(f"  [{r['level'].upper()}] {r['desc']}")
    return '\n'.join(lines)


def export_compiler_opt_report(result, path):
    import json
    with open(path, 'w') as fh:
        json.dump(result, fh, indent=2, default=str)
