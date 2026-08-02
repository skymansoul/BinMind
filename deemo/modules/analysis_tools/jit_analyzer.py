"""JIT engine fingerprinting, spray-pattern detection, and exploit-guidance synthesis.
2025 升级: JIT代码年龄评估——通过分析JIT代码页的时间戳模式识别
"热"页面（频繁重编译）和"冷"页面（稳定代码），辅助利用策略选择。
"""

import re, struct, math as _math
from collections import defaultdict
from enum import Enum

__test__ = False

_V8_SNAPSHOT_MAGIC = rb'\x88\x4d\x0a\x20'
_V8_TURBOFAN_PAT = re.compile(rb'TurboFan|V8\.version|v8::internal')
_V8_WASM_SIG = re.compile(rb'\x00asm\x01\x00\x00\x00')
_SPIDERMONKEY_OPCODES = re.compile(rb'JSOP_\w+|js\s*::\s*[A-Z]\w+|ion::|baseline::|GetElem|SetElem|CallProp')
_JSC_PATTERNS = re.compile(rb'WTF::|bmalloc::|JSC::|WebCore::|JavaScriptCore|FTL::|DFG::|B3::')
_LUAJIT_BYTECODES = re.compile(rb'lj_(?:bc|func|dispatch|trace|ff|crecord|snap|asm|ir|opt)|luaJIT\s+\d|LJ\.\d')
_LUAJIT_NYI = re.compile(rb'NYI|not yet implemented|LJ_TRERR')
_JIT_SPRAY_PATTERNS = re.compile(
    rb'((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})\s*((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})\s*'
    rb'((?:\xbb|\xb8|\xb9|\xba|\xbd|\xbe|\xbf).{4})', re.DOTALL)

class JITEngineType(Enum):
    V8 = "v8"; SPIDERMONKEY = "spidermonkey"; JSC = "jsc"; LUAJIT = "luajit"; UNKNOWN = "unknown"

class JITAnalysisResult:
    def __init__(self):
        self.engine = JITEngineType.UNKNOWN; self.confidence = 0.0
        self.jit_regions = []; self.spray_indicators = []; self.findings = []
        self.recommendations = []; self._engine_scores: dict = {}
        self.hot_pages: List[int] = []  # 频繁重编译的页
        self.code_age_estimate: float = 0.0  # JIT代码页的平均"年龄" (0=new, 1=old)
    def add_finding(self, severity, message):
        self.findings.append({'severity': severity, 'message': message})

class V8JITAnalyzer:
    def __init__(self):
        self._turbofan_opcodes = {
            rb'\xf2\x0f\x10': 'movsd', rb'\xf3\x0f\x10': 'movss',
            rb'\xf2\x0f\x11': 'movsd', rb'\xf3\x0f\x11': 'movss'}
    def feature_vector(self, data):
        vec = {'turbofan_hits': len(_V8_TURBOFAN_PAT.findall(data)),
               'snapshot_magic': 1 if _V8_SNAPSHOT_MAGIC in data else 0,
               'wasm_sections': len(_V8_WASM_SIG.findall(data))}
        vec['score'] = vec['snapshot_magic'] * 50 + min(vec['turbofan_hits'], 5) * 10 + min(vec['wasm_sections'], 3) * 3
        return vec

class LuaJITAnalyzer:
    def __init__(self):
        self._trace_abi = {'lj_vm_inshook', 'lj_vm_record', 'lj_vm_rethook',
                           'lj_ccallback_enter', 'lj_ccallback_leave'}
    def feature_vector(self, data):
        nyi = len(_LUAJIT_NYI.findall(data)); bc = len(_LUAJIT_BYTECODES.findall(data))
        return {'bc_patterns': bc, 'nyi_count': nyi, 'score': min(bc, 10) * 7 + min(nyi, 3) * 15}


# ── JIT 代码页年龄/热度评估 ────────────────────────────────────────────────
# JIT 引擎动态生成代码页。通过分析代码密度、重编译痕迹（同一函数
# 的多个版本）、以及页内指令的"新鲜度"模式来推断页面的年龄。
# 热页面（新编译的代码）可能还包含调试信息，更容易被利用。

class JITPageAgeEstimator:
    """JIT 代码页年龄估计器——基于代码密度和重编译痕迹。"""
    _PROLOGUE_DENSITY_THRESHOLD = 3  # 每页至少3个函数序言才算"活跃"

    @classmethod
    def estimate_page_age(cls, page_data: bytes) -> float:
        """估计单个 JIT 代码页的"年龄"——0.0=刚生成, 1.0=稳定老代码。"""
        if len(page_data) < 64: return 1.0
        # 序言密度: push rbp; mov rbp, rsp
        prologue = rb'\x55\x48\x89\xe5'
        prologue_count = 0; pos = 0
        while True:
            idx = page_data.find(prologue, pos)
            if idx == -1: break
            prologue_count += 1; pos = idx + 1
        # 高序言密度 = 新代码（频繁生成函数体）
        if prologue_count >= cls._PROLOGUE_DENSITY_THRESHOLD:
            return 0.2  # 年轻
        elif prologue_count >= 1:
            return 0.5  # 中年
        return 0.85  # 老化

    @classmethod
    def find_hot_pages(cls, data: bytes, page_size: int = 0x1000) -> List[int]:
        """返回"热"页面（年龄 < 0.4）的偏移列表——JIT 活跃区域。"""
        hot_offsets: List[int] = []
        for off in range(0, len(data), page_size):
            chunk = data[off:min(off + page_size, len(data))]
            age = cls.estimate_page_age(chunk)
            if age < 0.4: hot_offsets.append(off)
        return hot_offsets


class JITAnalyzer:
    def __init__(self):
        self.v8_analyzer = V8JITAnalyzer(); self.luajit_analyzer = LuaJITAnalyzer()
        self._data = b''

    def detect_jit_engine(self, binary):
        if isinstance(binary, bytes): self._data = binary
        else:
            with open(binary, 'rb') as jf: self._data = jf.read()
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
        if best_score < 5: return JITEngineType.UNKNOWN
        return best

    def generate_exploit_guidance(self, engine):
        guidance = {
            JITEngineType.V8: "V8: Focus on TurboFan/Sparkplug tier transitions.",
            JITEngineType.SPIDERMONKEY: "SpiderMonkey: IonBuilder main attack surface.",
            JITEngineType.JSC: "JSC: FTLLoweredNodeValue confusion across DFG/FTL tiers.",
            JITEngineType.LUAJIT: "LuaJIT: IR_CONV + IR_TOBIT type widening.",
            JITEngineType.UNKNOWN: "Unknown: check for RWX regions with code gen patterns.",
        }
        return guidance.get(engine, guidance[JITEngineType.UNKNOWN])

    def hardening_recommendations(self):
        return [
            "Enable Intel CET (IBT + Shadow Stack)",
            "Enable Windows CFG or clang CFI",
            "Set W^X policy on JIT code pages",
            "Randomise JIT code page offsets within the heap",
        ]

    def detect_jit_spray(self):
        indicators = []
        for m in _JIT_SPRAY_PATTERNS.finditer(self._data):
            chunk = m.group(); imms = []
            for i in range(0, len(chunk) - 4, 5):
                opcode = chunk[i]
                if opcode in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
                    imms.append(struct.unpack_from('<I', chunk, i + 1)[0])
            if len(imms) >= 3:
                indicators.append({'address': hex(m.start()),
                                    'immediates': [hex(v) for v in imms],
                                    'nop_equivalent': f'0x{imms[0]:08x}'})
                if len(indicators) >= 20: break
        return indicators

    def detect_constant_blinding(self) -> bool:
        xor_imm = re.compile(rb'\x48\x81\xf0.{4}|\x48\x81\xf3.{4}|\x48\x81\xf1.{4}')
        return len(xor_imm.findall(self._data)) > 50

    def extract_jitted_regions(self):
        regions = []; min_region = 0x200
        prologue = re.compile(rb'(\x55\x48\x89\xe5|push\s+rbp.*mov\s+rbp,\s*rsp)')
        for page_start in range(0, len(self._data), 0x1000):
            page_end = min(page_start + 0x1000, len(self._data))
            chunk = self._data[page_start:page_end]
            if len(chunk) < min_region: continue
            if len(prologue.findall(chunk)) >= 2:
                regions.append((page_start, page_end, page_end - page_start))
        return regions


def analyze_jit_security(binary):
    analyser = JITAnalyzer()
    result = JITAnalysisResult()
    result.engine = analyser.detect_jit_engine(binary)
    result.jit_regions = analyser.extract_jitted_regions()
    result.spray_indicators = analyser.detect_jit_spray()
    result.recommendations = analyser.hardening_recommendations()
    constant_blinded = analyser.detect_constant_blinding()
    result.hot_pages = JITPageAgeEstimator.find_hot_pages(
        binary if isinstance(binary, bytes) else open(binary, 'rb').read())
    if result.spray_indicators:
        result.add_finding('HIGH', f'{len(result.spray_indicators)} JIT spray indicators detected')
    if result.engine != JITEngineType.UNKNOWN:
        result.add_finding('INFO', f'JIT engine: {result.engine.value}')
    if constant_blinded:
        result.add_finding('INFO', 'Constant blinding detected')
    if result.hot_pages:
        result.add_finding('INFO', f'{len(result.hot_pages)} hot JIT pages — recently compiled code')
    return result
