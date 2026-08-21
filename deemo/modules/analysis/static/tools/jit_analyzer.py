"""JIT 引擎指纹识别、喷射模式检测与漏洞利用引导。

分析 JIT 引擎（V8/SpiderMonkey/JSC/LuaJIT）的二进制特征：
- 引擎指纹：特征向量 + 加权评分，识别目标 JIT 引擎。
- JIT 喷射模式：识别反汇编中的立即数序列模式。
- 代码页年龄评估：通过序言密度推断 JIT 代码页的"新鲜度"。
- 漏洞利用引导：针对已识别漏洞类型给出利用技术与前提条件。
"""
import re
import struct
import math as _math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

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
    V8 = "v8"
    SPIDERMONKEY = "spidermonkey"
    JSC = "jsc"
    LUAJIT = "luajit"
    UNKNOWN = "unknown"


@dataclass
class JITVulnerability:
    """JIT 漏洞描述。"""
    vuln_type: str = ""
    severity: str = "Medium"
    address: int = 0
    description: str = ""
    code_snippet: str = ""
    exploitation_potential: str = "中"


@dataclass
class JITDumpAnalysisResult:
    """JIT dump 解析结果。"""
    engine_type: JITEngineType = JITEngineType.UNKNOWN
    vulnerabilities: List[JITVulnerability] = field(default_factory=list)
    optimization_passes: List[str] = field(default_factory=list)
    risk_score: float = 0.0


class JITAnalysisResult:
    """完整 JIT 分析结果。"""
    def __init__(self):
        self.engine = JITEngineType.UNKNOWN
        self.confidence = 0.0
        self.jit_regions = []
        self.spray_indicators = []
        self.findings = []
        self.recommendations = []
        self._engine_scores = {}
        self.hot_pages = []
        self.code_age_estimate = 0.0

    def add_finding(self, severity, message):
        self.findings.append({'severity': severity, 'message': message})


class V8JITAnalyzer:
    """V8 引擎 JIT dump 与二进制特征分析。"""

    _VULN_MARKERS = {
        'bounds check': 'bounds_check_elimination',
        'type confusion': 'type_confusion',
        'use after free': 'use_after_free',
        'oob': 'out_of_bounds',
        'checkbounds removed': 'bounds_check_elimination',
    }

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

    def analyze_jit_dump(self, jit_dump: str) -> JITDumpAnalysisResult:
        """解析 V8 优化日志（jit dump），识别漏洞类型与优化阶段。"""
        result = JITDumpAnalysisResult(engine_type=JITEngineType.V8)
        text = jit_dump or ""
        lowered = text.lower()

        for marker, vuln_type in self._VULN_MARKERS.items():
            if marker in lowered:
                result.vulnerabilities.append(JITVulnerability(
                    vuln_type=vuln_type,
                    severity='Critical' if vuln_type == 'use_after_free' else 'High',
                    address=0,
                    description=f'{vuln_type} detected in JIT dump',
                    exploitation_potential='高'))

        for line in text.splitlines():
            line = line.strip()
            if 'optimiz' in line.lower() or 'seal' in line.lower() or 'escape' in line.lower():
                result.optimization_passes.append(line)

        result.risk_score = min(1.0, len(result.vulnerabilities) * 0.5)
        return result


class LuaJITAnalyzer:
    """LuaJIT trace dump 与二进制特征分析。"""

    def __init__(self):
        self._trace_abi = {'lj_vm_inshook', 'lj_vm_record', 'lj_vm_rethook',
                           'lj_ccallback_enter', 'lj_ccallback_leave'}

    def feature_vector(self, data):
        nyi = len(_LUAJIT_NYI.findall(data))
        bc = len(_LUAJIT_BYTECODES.findall(data))
        return {'bc_patterns': bc, 'nyi_count': nyi, 'score': min(bc, 10) * 7 + min(nyi, 3) * 15}

    def analyze_jit_dump(self, jit_dump: str) -> JITDumpAnalysisResult:
        """解析 LuaJIT trace 日志，提取优化阶段与风险。"""
        result = JITDumpAnalysisResult(engine_type=JITEngineType.LUAJIT)
        text = jit_dump or ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('[') or 'JIT mcode' in line or 'guard' in line:
                result.optimization_passes.append(line)
        if 'NYI' in text or 'not yet implemented' in text:
            result.vulnerabilities.append(JITVulnerability(
                vuln_type='nyi_fallback',
                severity='Medium',
                description='NYI fallback path may miss security checks',
                exploitation_potential='中'))
        result.risk_score = min(1.0, len(result.vulnerabilities) * 0.4)
        return result

# JIT 代码页年龄/热度评估
# JIT 引擎动态生成代码页。通过分析代码密度、重编译痕迹（同一函数
# 的多个版本）、以及页内指令的"新鲜度"模式来推断页面的年龄
# 热页面（新编译的代码）可能还包含调试信息，更容易被利用

class JITPageAgeEstimator:
    """JIT 代码页年龄估计器, 基于代码密度和重编译痕迹。"""

    _PROLOGUE_DENSITY_THRESHOLD = 3

    @classmethod
    def estimate_page_age(cls, page_data: bytes) -> float:
        if len(page_data) < 64:
            return 1.0
        prologue = rb'\x55\x48\x89\xe5'
        prologue_count = 0
        pos = 0
        while True:
            idx = page_data.find(prologue, pos)
            if idx == -1:
                break
            prologue_count += 1
            pos = idx + 1
        if prologue_count >= cls._PROLOGUE_DENSITY_THRESHOLD:
            return 0.2
        elif prologue_count >= 1:
            return 0.5
        return 0.85

    @classmethod
    def find_hot_pages(cls, data: bytes, page_size: int = 0x1000) -> List[int]:
        hot_offsets = []
        for off in range(0, len(data), page_size):
            chunk = data[off:min(off + page_size, len(data))]
            age = cls.estimate_page_age(chunk)
            if age < 0.4:
                hot_offsets.append(off)
        return hot_offsets


class JITAnalyzer:
    """JIT 引擎分析与漏洞利用引导。"""

    _ENGINE_GUIDANCE = {
        JITEngineType.V8: {
            'techniques': ['turbo_fan_tier_confusion', 'check_bounds_elimination', 'type_confusion'],
            'conditions': ['RWX JIT region', 'CheckBounds elimination reachable', 'object layout disclosure'],
        },
        JITEngineType.SPIDERMONKEY: {
            'techniques': ['ion_builder_type_confusion', 'wasm_to_js_type_conv'],
            'conditions': ['Wasm module JIT', 'ion builder reachable'],
        },
        JITEngineType.JSC: {
            'techniques': ['ftl_lowered_value_confusion', 'dfg_to_ftl_osr'],
            'conditions': ['DFG/FTL tier reachable', 'value node confusion'],
        },
        JITEngineType.LUAJIT: {
            'techniques': ['ir_conv_type_widening', 'ir_tobit_truncation'],
            'conditions': ['trace recording active', 'FFI call reachable'],
        },
        JITEngineType.UNKNOWN: {
            'techniques': ['rwx_region_shellcode', 'code_gen_pivot'],
            'conditions': ['RWX region present', 'indirect call into generated code'],
        },
    }

    def __init__(self):
        self.v8_analyzer = V8JITAnalyzer()
        self.luajit_analyzer = LuaJITAnalyzer()
        self._data = b''

    def detect_jit_engine(self, binary) -> JITEngineType:
        """识别 JIT 引擎。

        binary 可为二进制路径、字节串，或包含 filename/imports/strings
        的元信息字典。
        """
        if isinstance(binary, dict):
            imports = [str(i).lower() for i in binary.get('imports', [])]
            strings = [str(s).lower() for s in binary.get('strings', [])]
            text = ' '.join(imports + strings)
            if 'v8' in imports or 'turbofan' in imports or 'ignition' in strings or 'sparkplug' in strings:
                return JITEngineType.V8
            if 'spidermonkey' in imports or 'jsop_' in strings or 'ion' in strings:
                return JITEngineType.SPIDERMONKEY
            if 'jsc' in imports or 'javascriptcore' in strings or 'wtf::' in strings:
                return JITEngineType.JSC
            if 'luajit' in imports or 'lj_' in text:
                return JITEngineType.LUAJIT
            return JITEngineType.UNKNOWN

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

    def generate_exploit_guidance(self, vuln: JITVulnerability) -> Dict[str, Any]:
        """根据漏洞类型生成利用技术与前提条件。"""
        engine = JITEngineType.V8
        base = self._ENGINE_GUIDANCE.get(engine, self._ENGINE_GUIDANCE[JITEngineType.UNKNOWN])
        guidance = {
            'vuln_type': vuln.vuln_type,
            'severity': vuln.severity,
            'exploitation_techniques': list(base['techniques']),
            'required_conditions': list(base['conditions']),
        }
        if vuln.vuln_type == 'bounds_check_elimination':
            guidance['exploitation_techniques'] = ['check_bounds_elimination', 'oob_read_write']
            guidance['required_conditions'] = ['CheckBounds eliminated by JIT', 'object array adjacent']
        elif vuln.vuln_type == 'type_confusion':
            guidance['exploitation_techniques'] = ['type_confusion', 'fake_object']
            guidance['required_conditions'] = ['confusable types', 'sprayed object map']
        return guidance

    def get_jit_hardening_recommendations(self, engine: JITEngineType) -> List[str]:
        """返回针对指定引擎的加固建议。"""
        base = [
            "Enable Intel CET (IBT + Shadow Stack)",
            "Enable Windows CFG or clang CFI",
            "Set W^X policy on JIT code pages",
            "Randomise JIT code page offsets within the heap",
        ]
        if engine == JITEngineType.V8:
            base.insert(0, "Apply TurboFan hardening mitigations")
        elif engine == JITEngineType.LUAJIT:
            base.insert(0, "Enable LuaJIT 2.1 hardening and memory limits")
        return base

    def hardening_recommendations(self):
        return self.get_jit_hardening_recommendations(JITEngineType.UNKNOWN)

    def detect_jit_spray(self):
        indicators = []
        for m in _JIT_SPRAY_PATTERNS.finditer(self._data):
            chunk = m.group()
            imms = []
            for i in range(0, len(chunk) - 4, 5):
                opcode = chunk[i]
                if opcode in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
                    imms.append(struct.unpack_from('<I', chunk, i + 1)[0])
            if len(imms) >= 3:
                indicators.append({'address': hex(m.start()),
                                   'immediates': [hex(v) for v in imms],
                                   'nop_equivalent': f'0x{imms[0]:08x}'})
                if len(indicators) >= 20:
                    break
        return indicators

    def detect_constant_blinding(self) -> bool:
        xor_imm = re.compile(rb'\x48\x81\xf0.{4}|\x48\x81\xf3.{4}|\x48\x81\xf1.{4}')
        return len(xor_imm.findall(self._data)) > 50

    def extract_jitted_regions(self):
        regions = []
        min_region = 0x200
        prologue = re.compile(rb'(\x55\x48\x89\xe5|push\s+rbp.*mov\s+rbp,\s*rsp)')
        for page_start in range(0, len(self._data), 0x1000):
            page_end = min(page_start + 0x1000, len(self._data))
            chunk = self._data[page_start:page_end]
            if len(chunk) < min_region:
                continue
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
        result.add_finding('INFO', f'{len(result.hot_pages)} hot JIT pages, recently compiled code')
    return result
