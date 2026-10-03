"""JIT engine fingerprinting, spray-pattern detection, and exploit-guidance synthesis."""

import re
import struct
from collections import defaultdict
from enum import Enum

__test__ = False

# ── Engine fingerprint database ─────────────────────────────────────────────
#
# Every JIT engine deposits structurally distinct artifacts in the binary.
# V8: snapshot blob + TurboFan linkage. SpiderMonkey: JSOP_* opcode table.
# JSC: bmalloc/WTF symbols. LuaJIT: lj_* dispatch stubs and NYI markers.
# These signatures are orthogonal — a binary can carry multiple engines.

_V8_SNAPSHOT_MAGIC = rb'\x88\x4d\x0a\x20'        # V8 embedded snapshot blob magic bytes
_V8_TURBOFAN_PAT = re.compile(rb'TurboFan|V8\.version|v8::internal')
_V8_WASM_SIG = re.compile(rb'\x00asm\x01\x00\x00\x00')

_SPIDERMONKEY_OPCODES = re.compile(
    rb'JSOP_\w+|js\s*::\s*[A-Z]\w+|ion::|baseline::|GetElem|SetElem|CallProp'
)
_SPIDERMONKEY_WASM = re.compile(rb'spiderweb|wasm::Instance')

_JSC_PATTERNS = re.compile(
    rb'WTF::|bmalloc::|JSC::|WebCore::|JavaScriptCore|FTL::|DFG::|B3::'
)

_LUAJIT_BYTECODES = re.compile(
    rb'lj_(?:bc|func|dispatch|trace|ff|crecord|snap|asm|ir|opt)|'
    rb'luaJIT\s+\d|LJ\.\d'
)
_LUAJIT_NYI = re.compile(rb'NYI|not yet implemented|LJ_TRERR')

# JIT spraying: consecutive MOV-reg-immediate chains exploitable as NOP-sled equivalents
_JIT_SPRAY_PATTERNS = re.compile(
    rb'((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})'
    rb'\s*'
    rb'((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})'
    rb'\s*'
    rb'((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})'
    , re.DOTALL
)

# ── Type definitions ───────────────────────────────────────────────────────

class JITEngineType(Enum):
    V8 = "v8"
    SPIDERMONKEY = "spidermonkey"
    JSC = "jsc"
    LUAJIT = "luajit"
    UNKNOWN = "unknown"

class JITAnalysisResult:
    def __init__(self):
        self.engine = JITEngineType.UNKNOWN
        self.confidence = 0.0
        self.jit_regions = []       # (start, end, size) tuples per identified code page
        self.spray_indicators = []
        self.findings = []
        self.recommendations = []

    def add_finding(self, severity, message):
        self.findings.append({'severity': severity, 'message': message})


class JITVulnerability:
    def __init__(self, name='', engine='', description='', exploitability='medium'):
        self.name = name
        self.engine = engine
        self.description = description
        self.exploitability = exploitability


# ── Engine-specific feature extractors ─────────────────────────────────────

class V8JITAnalyzer:
    def __init__(self):
        self._turbofan_opcodes = {
            rb'\xf2\x0f\x10': 'movsd', rb'\xf3\x0f\x10': 'movss',
            rb'\xf2\x0f\x11': 'movsd', rb'\xf3\x0f\x11': 'movss',
        }

    def feature_vector(self, data):
        vec = {'turbofan_hits': len(_V8_TURBOFAN_PAT.findall(data)),
               'snapshot_magic': 1 if _V8_SNAPSHOT_MAGIC in data else 0,
               'wasm_sections': len(_V8_WASM_SIG.findall(data))}
        vec['score'] = (
            vec['snapshot_magic'] * 50 +
            min(vec['turbofan_hits'], 5) * 10 +
            min(vec['wasm_sections'], 3) * 3
        )
        return vec


class LuaJITAnalyzer:
    def __init__(self):
        self._trace_abi = {
            'lj_vm_inshook', 'lj_vm_record', 'lj_vm_rethook',
            'lj_ccallback_enter', 'lj_ccallback_leave',
        }

    def feature_vector(self, data):
        nyi = len(_LUAJIT_NYI.findall(data))
        bc = len(_LUAJIT_BYTECODES.findall(data))
        score = min(bc, 10) * 7 + min(nyi, 3) * 15
        return {'bc_patterns': bc, 'nyi_count': nyi, 'score': score}


# ── Composite analyser — delegates to per-engine feature extractors ────────

class JITAnalyzer:
    def __init__(self):
        self.v8_analyzer = V8JITAnalyzer()
        self.luajit_analyzer = LuaJITAnalyzer()
        self._data = b''

    def detect_jit_engine(self, binary):
        """Identify the JIT engine by matching embedded signatures against known patterns."""
        if isinstance(binary, bytes):
            self._data = binary
        else:
            with open(binary, 'rb') as jf:
                self._data = jf.read()

        engines = []

        v8_vec = self.v8_analyzer.feature_vector(self._data)
        engines.append((JITEngineType.V8, v8_vec['score']))

        sm_score = len(_SPIDERMONKEY_OPCODES.findall(self._data))
        engines.append((JITEngineType.SPIDERMONKEY, min(sm_score, 10) * 8))

        jsc_score = len(_JSC_PATTERNS.findall(self._data))
        engines.append((JITEngineType.JSC, min(jsc_score, 10) * 7))

        lj_vec = self.luajit_analyzer.feature_vector(self._data)
        engines.append((JITEngineType.LUAJIT, lj_vec['score']))

        engines.sort(key=lambda x: x[1], reverse=True)
        best, best_score = engines[0]

        if best_score < 5:
            return JITEngineType.UNKNOWN
        return best

    def generate_exploit_guidance(self, engine):
        guidance = {
            JITEngineType.V8: (
                "V8: Focus on TurboFan/Sparkplug tier transitions. Check for "
                "Map deprecation races and array type confusion (CVE-2021-30551 pattern). "
                "WASM RWX pages are prime targets for shellcode staging."
            ),
            JITEngineType.SPIDERMONKEY: (
                "SpiderMonkey: IonBuilder is the main attack surface. CacheIR stubs "
                "are generated without type barriers in some paths. Warp/Ion bailout "
                "loops can be forced via repeated deoptimisation."
            ),
            JITEngineType.JSC: (
                "JSC: FTLLoweredNodeValue can be confused across DFG/FTL tiers. "
                "StructureID transitions in concurrent JIT are prime race condition targets. "
                "The FTL JIT uses B3 IR—look for Check node elision bugs."
            ),
            JITEngineType.LUAJIT: (
                "LuaJIT: IR_CONV + IR_TOBIT type widening is the classic vector. "
                "NYI fallback paths from JIT -> interpreter can leave inconsistent state. "
                "lj_record.c aliasing violations are a recurrent CVE source."
            ),
            JITEngineType.UNKNOWN: (
                "Unknown engine: check for RWX memory regions with executable "
                "code generation patterns (constant loads + arithmetic)."
            ),
        }
        return guidance.get(engine, guidance[JITEngineType.UNKNOWN])

    def hardening_recommendations(self):
        return [
            "Enable Intel CET (IBT + Shadow Stack)",
            "Enable Windows CFG or clang CFI",
            "Set W^X policy on JIT code pages (mprotect to RX after compilation)",
            "Enable JIT code signing where available",
            "Sandbox JIT compilation threads with seccomp/AppContainer",
            "Randomise JIT code page offsets within the heap",
        ]

    def detect_jit_spray(self):
        """Scan for JIT spray indicators — contiguous MOV imm chains usable as NOP sleds."""
        indicators = []
        for m in _JIT_SPRAY_PATTERNS.finditer(self._data):
            chunk = m.group()
            # Unpack 32-bit immediates from MOV r, imm32 opcodes (B8–BF)
            imms = []
            for i in range(0, len(chunk) - 4, 5):
                opcode = chunk[i]
                if opcode in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
                    val = struct.unpack_from('<I', chunk, i + 1)[0]
                    imms.append(val)
            if len(imms) >= 3:
                nop_sled = f'0x{imms[0]:08x}'
                indicators.append({
                    'address': hex(m.start()),
                    'immediates': [hex(v) for v in imms],
                    'nop_equivalent': nop_sled,
                })
                if len(indicators) >= 20:
                    break
        return indicators

    def extract_jitted_regions(self):
        """Identify page-aligned regions exhibiting JIT code density characteristics."""
        regions = []
        min_region = 0x200  # reject fragments below 512 bytes

        # Page-boundary scan for function prologue signatures
        prologue = re.compile(
            rb'(\x55\x48\x89\xe5|push\s+rbp.*mov\s+rbp,\s*rsp)'
        )

        page_size = 0x1000
        for page_start in range(0, len(self._data), page_size):
            page_end = min(page_start + page_size, len(self._data))
            chunk = self._data[page_start:page_end]
            if len(chunk) < min_region:
                continue
            # High prologue density is the primary heuristic for JIT code pages
            prologue_count = len(prologue.findall(chunk))
            if prologue_count >= 2:
                regions.append((page_start, page_end, page_end - page_start))
        return regions


# ── Module-level entry point — single-call JIT security audit ──────────────

def analyze_jit_security(binary):
    analyser = JITAnalyzer()
    result = JITAnalysisResult()
    result.engine = analyser.detect_jit_engine(binary)
    result.jit_regions = analyser.extract_jitted_regions()
    result.spray_indicators = analyser.detect_jit_spray()
    result.recommendations = analyser.hardening_recommendations()

    if result.spray_indicators:
        result.add_finding('HIGH',
            f'{len(result.spray_indicators)} JIT spray indicators detected')

    if result.engine != JITEngineType.UNKNOWN:
        result.add_finding('INFO',
            f'JIT engine: {result.engine.value}')

    return result
