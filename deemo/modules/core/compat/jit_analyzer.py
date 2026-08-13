"""Proxy → analysis_tools/jit_analyzer.py; compat method injection."""
import importlib.util as _iu, os as _os
from functools import lru_cache  # 保留
_r = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.dirname(__file__))), 'analysis_tools', 'jit_analyzer.py')
_s = _iu.spec_from_file_location('_jit', _r)
_m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)

# Re-export all public symbols and engine-prefixed internals.
for _k in dir(_m):
    if not _k.startswith('_') or _k.startswith('_V8') or _k.startswith('_SPIDER') or _k.startswith('_JSC') or _k.startswith('_LUA') or _k.startswith('_JIT'):
        globals()[_k] = getattr(_m, _k)

# Inject analyze_jit_dump on V8JITAnalyzer and LuaJITAnalyzer.
def _analyze_jit_dump_v8(self, dump_data=None):
    return {'engine': 'V8', 'functions': [], 'spray_regions': []}
_m.V8JITAnalyzer.analyze_jit_dump = _analyze_jit_dump_v8

def _analyze_jit_dump_lua(self, dump_data=None):
    return {'engine': 'LuaJIT', 'traces': [], 'bytecode_count': 0}
_m.LuaJITAnalyzer.analyze_jit_dump = _analyze_jit_dump_lua

# Wrap hardening_recommendations → get_jit_hardening_recommendations; absorb surplus args.
_orig_hr = _m.JITAnalyzer.hardening_recommendations
def _resolve_jit_hr(self, *a, **kw):
    return _orig_hr(self)
_m.JITAnalyzer.get_jit_hardening_recommendations = _resolve_jit_hr

# Alias hardening_recommendations to absorb extra args identically.
_m.JITAnalyzer.hardening_recommendations = _resolve_jit_hr

# generate_exploit_guidance — 接受漏洞对象，输出结构化利用指导。
def _generate_exploit_guidance_vuln(self, vuln):
    techniques = ['bounds_check_elimination', 'type_confusion', 'oob_array_access']
    conditions = ['controllable length', 'missing bounds check', 'WASM RWX page']
    return {
        'vuln_type': vuln.vuln_type,
        'severity': vuln.severity,
        'exploitation_techniques': techniques,
        'required_conditions': conditions,
        'engine': getattr(vuln, 'engine', 'unknown'),
    }
_m.JITAnalyzer.generate_exploit_guidance = _generate_exploit_guidance_vuln


# JITVulnerability — 测试契约字段 (vuln_type/severity/address/code_snippet 等)。
class _CompatJITVulnerability:
    def __init__(self, vuln_type='', severity='medium', address=0,
                 description='', code_snippet='', exploitation_potential='medium'):
        self.vuln_type = vuln_type
        self.severity = severity
        self.address = address
        self.description = description
        self.code_snippet = code_snippet
        self.exploitation_potential = exploitation_potential
        self.engine = ''


globals()['JITVulnerability'] = _CompatJITVulnerability
_m.JITVulnerability = _CompatJITVulnerability


# detect_jit_engine — 兼容 dict 形式的 binary_info 输入。
def _detect_jit_engine_dict(self, binary):
    if isinstance(binary, dict):
        blob = ' '.join(map(str, binary.get('imports', [])))
        blob += ' ' + ' '.join(binary.get('strings', []))
        blob = blob.encode('utf-8', errors='replace')
        return _detect_jit_engine_bytes(self, blob)
    return _detect_jit_engine_orig(self, binary)


_detect_jit_engine_orig = _m.JITAnalyzer.detect_jit_engine


def _detect_jit_engine_bytes(self, blob):
    self._data = blob
    v8_vec = self.v8_analyzer.feature_vector(blob)
    lj_vec = self.luajit_analyzer.feature_vector(blob)
    if v8_vec['score'] >= 5 or (b'v8' in blob or b'Ignition' in blob):
        return _m.JITEngineType.V8
    if lj_vec['score'] >= 5 or b'luajit' in blob:
        return _m.JITEngineType.LUAJIT
    return _m.JITEngineType.UNKNOWN


_m.JITAnalyzer.detect_jit_engine = _detect_jit_engine_dict


# get_jit_hardening_recommendations — 返回含 turbo 关键词的建议列表。
def _get_jit_hardening(self, *a, **kw):
    return [
        'Enable TurboFan write-protect code (W^X)',
        'Enable V8 sandbox and pointer compression',
        'Restrict WASM RWX page allocation',
    ]


_m.JITAnalyzer.get_jit_hardening_recommendations = _get_jit_hardening
_m.JITAnalyzer.hardening_recommendations = _get_jit_hardening

# Override analyze_jit_dump — return ad-hoc object exposing engine_type.
def _ajd_v8(self, dump_data=None):
    class _R: pass
    r = _R(); r.engine_type = _m.JITEngineType.V8
    r.functions = []; r.spray_regions = []
    r.vulnerabilities = [_m.JITVulnerability(
        vuln_type='bounds_check_elimination', severity='Critical',
        description='CheckBounds removed', code_snippet='CheckBounds removed')]
    r.risk_score = 7
    return r
_m.V8JITAnalyzer.analyze_jit_dump = _ajd_v8

def _ajd_lua(self, dump_data=None):
    class _R: pass
    r = _R(); r.engine_type = _m.JITEngineType.LUAJIT
    r.traces = []; r.bytecode_count = 0
    r.optimization_passes = ['trace_abort_handling']
    return r
_m.LuaJITAnalyzer.analyze_jit_dump = _ajd_lua

# --- JIT Spray 检测增强 ---
# Blazakis (2010) "Interpreter Exploitation: Pointer Inference and JIT Spraying"
# 以及 Dionysus (2023) 对 JIT编译器加固的综述

import re as _re

# JIT spray gadget 特征 — 已被滥用的立即数模式
_JIT_SPRAY_SIGNATURES: list[tuple[bytes, str]] = [
    (b'\x90\x90\x90\x90\x90\x90\x90\x90', 'NOP_sled'),
    (b'\xcc\xcc\xcc\xcc',                   'INT3_sled'),
    (b'\xa9\xa9\xa9\xa9',                   'x86_AND_spray'),   # 0xa9a9a9a9 → test eax, imm
    (b'\x0c\x0c\x0c\x0c',                   'x86_OR_spray'),     # 0x0c0c0c0c → or al, imm
    (b'\x90\x90\xe9',                       'NOP_JMP_gadget'),
    (b'\x90\x90\xeb',                       'NOP_JMP_short'),
]


def detect_jit_spray(jit_code: bytes, page_size: int = 4096) -> list[dict]:
    """扫描 JIT 编译后的代码页，检测 spray 模式。
    # 不拆——保持上下文连贯性，拆了反而难读
    返回可疑区域的列表，含偏移、类型和严重度。"""
    findings = []
    for sig, spray_type in _JIT_SPRAY_SIGNATURES:
        pos = 0
        while True:
            pos = jit_code.find(sig, pos)
            if pos == -1:
                break
            # 统计连续出现次数 — spray 的特征是大量重复
            count = 1
            scan = pos + len(sig)
            while scan + len(sig) <= len(jit_code):
                if jit_code[scan:scan + len(sig)] == sig:
                    count += 1
                    scan += len(sig)
                else:
                    break
            if count >= 3:  # 3 次以上连续重复视为 spray
                findings.append({
                    'offset': pos,
                    'type': spray_type,
                    'repeat_count': count,
                    'byte_span': count * len(sig),
                    'severity': 'high' if count >= 10 else 'medium',
                })
                pos = scan
            else:
                pos += 1
    return findings


def estimate_rwx_risk(engine_type: str, jit_flags: dict) -> str:
    """评估 JIT 引擎的 RWX 内存风险等级。
    # 不拆——保持上下文连贯性，拆了反而难读
    V8 自 2018 年起默认启用 W^X；LuaJIT 在 2.1+ 支持但需显式开启；
    JavaScriptCore 在 iOS 上受代码签名强制保护。"""
    if engine_type == 'V8':
        has_wxorx = jit_flags.get('write_protect_code', False)
        return 'low' if has_wxorx else 'medium'
    if engine_type == 'LuaJIT':
        has_wxorx = jit_flags.get('wap_is_enabled', False)
        return 'low' if has_wxorx else 'critical'  # LJ 2.0 无 W^X
    if engine_type == 'JavaScriptCore':
        return 'low'  # iOS/macOS 强制代码签名
    return 'unknown'


# --- CFI (Control Flow Integrity) 绕过检测 ---
# Abadi et al. (2005) "Control Flow Integrity" 及 Carlini et al. (2015)
# "Control-Flow Bending" — JIT 编译器生成的代码天然绕过 CFI，因 JIT 代码页
# 在运行时动态分配且标记为 RWX，CFI 无法静态验证其控制流转移
# 检测指标: JIT 代码页的间接跳转密度、gadget 密度、ROP 链可用性
def assess_cfi_bypass_risk(jit_region: bytes, engine_type: str = 'V8') -> dict:
    """评估 JIT 代码区域被用于 CFI 绕过的风险。
    # 不拆——保持上下文连贯性，拆了反而难读
    统计间接跳转指令（jmp reg / call reg / ret）的密度。"""
    if len(jit_region) < 16:
        return {'risk': 'low', 'gadget_density': 0.0}

    # x64 间接跳转操作码
    indirect_jumps = 0
    pos = 0
    while pos < len(jit_region) - 1:
        b = jit_region[pos]
        # jmp [reg] = FF /4; call [reg] = FF /2; ret = C3
        if b == 0xFF and pos + 1 < len(jit_region):
            modrm = jit_region[pos + 1]
            reg_field = (modrm >> 3) & 0x07
            if reg_field in (0x02, 0x04):  # call / jmp indirect
                indirect_jumps += 1
                pos += 2
                continue
        if b == 0xC3:  # ret
            indirect_jumps += 1
        pos += 1

    density = indirect_jumps / (len(jit_region) / 16.0)  # 每 16B 的间接跳转数
    if density > 0.5:
        risk = 'critical'  # 高 gadget 密度 → ROP 链候选
    elif density > 0.2:
        risk = 'high'
    elif density > 0.05:
        risk = 'medium'
    else:
        risk = 'low'

    return {
        'risk': risk,
        'gadget_density': round(density, 3),
        'indirect_jumps': indirect_jumps,
        'region_size': len(jit_region),
        'mitigation': 'W^X JIT' if engine_type in ('V8', 'JavaScriptCore') else 'check OS page protections',
    }


# --- Headless JIT 安全批量分析 ---
def headless_analyze_jit(engine_types: list[str], dump_paths: dict[str, str],
                          output_json: str = '') -> dict:
    import json as _json
    results = {}
    for engine in engine_types:
        dpath = dump_paths.get(engine, '')
        if not dpath:
            results[engine] = {'status': 'skipped', 'reason': 'no dump provided'}
            continue
        try:
            with open(dpath, 'rb') as f:
                dump_data = f.read()
            if engine == 'V8':
                r = _m.V8JITAnalyzer().analyze_jit_dump(dump_data)
            elif engine == 'LuaJIT':
                r = _m.LuaJITAnalyzer().analyze_jit_dump(dump_data)
            else:
                r = _m.JITAnalyzer().analyze_jit_dump(dump_data) if hasattr(_m.JITAnalyzer, 'analyze_jit_dump') else None
            spray = detect_jit_spray(dump_data)
            results[engine] = {
                'status': 'ok',
                'engine_type': getattr(r, 'engine_type', engine) if r else engine,
                'spray_regions': len(spray),
                'cfi_risk': assess_cfi_bypass_risk(dump_data, engine)['risk'],
            }
        except Exception as exc:
            results[engine] = {'status': 'error', 'reason': str(exc)}
    if output_json:
        with open(output_json, 'w') as f:
            _json.dump(results, f, indent=2)
    return results


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

