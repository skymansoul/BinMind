#!/usr/bin/env python3
"""Fingerprint 编译器 toolchain 优化 level binary artifacts

2025 升级: Remill/Anvill 启发的 IR 质量评估 (Trail Bits ecosystem)
将二进制提升到 LLVM IR 后，IR 的可优化程度反向指示原始代码的质量
高 O0/IROpt 转换率→原始二进制是 Debug 构建；低比率→高度优化的 Release
"""

import re, struct, os
from collections import Counter
from enum import IntEnum

module = "compiler_opt_analyzer"
name = "CompilerOptAnalyzer"

# 编译器 fingerprint 数据库
_GCC_PROLOGUE = re.compile(
    rb'\x55\x48\x89\xe5' rb'|' rb'\xf3\x0f\x1e\xfa')
_GCC_STRING = re.compile(rb'GCC:\s*\(.*?\)\s*[\d.]+', re.DOTALL)
_GCC_GO_SIGNATURE = re.compile(rb'Go build ID:')

_MSVC_PROLOGUE = re.compile(
    rb'\x48\x89\x5c\x24[\x08\x10]' rb'|' rb'\x40\x55')
_MSVC_RTC = re.compile(rb'_RTC_|__RTC_|_CrtDbgReport|__security_check_cookie')
_MSVC_STRING = re.compile(rb'Microsoft\s*\(R\)|Visual\s*C\+\+|MSVC|cl\.exe', re.IGNORECASE)

_CLANG_PROLOGUE = re.compile(
    rb'\x55\x48\x89\xe5\x48\x83\xec[\x10\x20\x30\x40\x50\x60\x70]'
    rb'|' rb'\x6a\x00' * 4)
_CLANG_STRING = re.compile(rb'clang\s+version\s+[\d.]+', re.IGNORECASE)
_CLANG_ASAN_SIG = re.compile(rb'__asan_|__ubsan_|__tsan_')

_OPT_PATTERNS = {
    0: re.compile(rb'(mov\s+%[a-z]{2,3},\s*-?0x[0-9a-f]*\(%rbp\).*){3,}', re.DOTALL),
    2: re.compile(rb'xor\s+%[a-z]{2,3},\s*%[a-z]{2,3}\s*\n.*lea\s+'
                   rb'|' rb'vpcmpeqd\s+%ymm\d+,\s*%ymm\d+,\s*%ymm\d+'),
}
_O3_AUTOVEC = re.compile(
    rb'(v)?mov(dqu|dqa|aps|upd|aps|apd)|padd[bdqw]|pmul[lh]|pshuf[bwd]', re.DOTALL)

_GCC_LTO_MAGIC = re.compile(rb'\.gnu\.lto_')
_CLANG_LTO_SIG = re.compile(rb'\xde\xc0\x17\x0b')
_RUSTC_SIGNATURE = re.compile(rb'rustc\s+\d+\.\d+|rust_panic|_ZN3std')

# Remill/Anvill 启发的 liftability 指标
# Trail Bits lifting-bits ecosystem (Remill + Anvill + Rellic)
# "可提升性"衡量二进制代码能被准确翻译为 LLVM IR 的程度
# 某些编译器模式（如跳板、间接跳转表、自修改代码）使提升困难


class CompilerType:
    GCC = "gcc"; CLANG = "clang"; MSVC = "msvc"; RUSTC = "rustc"; UNKNOWN = "unknown"

class OptimizationLevel(IntEnum):
    O0 = 0; O1 = 1; O2 = 2; O3 = 3; Os = -1; UNKNOWN = -2


class SecurityRisk:
    def __init__(self, level, description, mitigations=None):
        self.level = level; self.description = description
        self.mitigations = mitigations or []


# 提升障碍检测——识别使二进制难以提升到 LLVM IR 的编译器模式
_LIFT_BARRIERS = {
    'indirect_jump_table': re.compile(
        rb'(?:jmp\s+(?:qword\s+)?\[r\w+\s*\*?\s*[0-8]\])|'
        rb'(?:jmp\s+(?:rax|rbx|rcx|rdx|rsi|rdi|r[89]))'),
    'tail_call_optimization': re.compile(
        rb'jmp\s+(?:qword\s+)?\[r\w+\]\s*$', re.MULTILINE),
    'self_modifying': re.compile(
        rb'(?:mov\s+\[r\w+\+0x[0-9a-f]+\],\s*(?:0x[0-9a-f]+|r\w+)\s*\n.*'
        rb'(?:jmp|cmp|test).*\1)', re.DOTALL),
    'opaque_predicate': re.compile(
        rb'(?:xor\s+%[a-z]{2,3},\s*%[a-z]{2,3})\s*\n'
        rb'(?:\s*j\w+\s+0x[0-9a-f]+)', re.DOTALL),
}


class CompilerOptAnalyzer:
    """编译器 fingerprinting raw binary data"""

    def __init__(self):
        self._binary_data = b''; self._section_names = []

    def analyze(self, binary):
        if isinstance(binary, str) and os.path.isfile(binary):
            with open(binary, 'rb') as fh:
                self._binary_data = fh.read()
            self._sample = self._binary_data[:min(len(self._binary_data), 2**20)]
        else:
            self._binary_data = binary if isinstance(binary, bytes) else b''
            self._sample = self._binary_data[:min(len(self._binary_data), 2**20)]

        compiler = self._detect_compiler()
        opt_level = self._detect_opt_level(compiler)
        lto_detected = self._detect_lto()
        liftability = self._assess_liftability()
        risks = self._assess_security_risks(compiler, opt_level, lto_detected, liftability)
        return {
            'compiler': compiler,
            'optimization_level': opt_level.name if hasattr(opt_level, 'name') else str(opt_level),
            'lto_enabled': lto_detected,
            'confidence': self._confidence,
            'liftability': liftability,
            'security_risks': [{'level': r.level, 'desc': r.description, 'mitigations': r.mitigations}
                              for r in risks],
            'indicators': self._indicators,
        }

    def _detect_compiler(self):
        scores = Counter(); self._indicators = Counter(); self._confidence = 0.0
        if _GCC_STRING.search(self._sample): scores['gcc'] += 30; self._indicators['gcc_string'] += 1
        if _MSVC_STRING.search(self._sample): scores['msvc'] += 30; self._indicators['msvc_string'] += 1
        if _CLANG_STRING.search(self._sample): scores['clang'] += 30; self._indicators['clang_string'] += 1
        if _RUSTC_SIGNATURE.search(self._sample): scores['rustc'] += 30; self._indicators['rustc_string'] += 1
        gcc_p = len(_GCC_PROLOGUE.findall(self._sample))
        msvc_p = len(_MSVC_PROLOGUE.findall(self._sample))
        clang_p = len(_CLANG_PROLOGUE.findall(self._sample))
        scores['gcc'] += gcc_p * 5; scores['msvc'] += msvc_p * 5; scores['clang'] += clang_p * 5
        self._indicators['gcc_prologue'] = gcc_p; self._indicators['msvc_prologue'] = msvc_p
        self._indicators['clang_prologue'] = clang_p
        if _MSVC_RTC.search(self._sample): scores['msvc'] += 10; self._indicators['msvc_rtc'] += 1
        if _CLANG_ASAN_SIG.search(self._sample): scores['clang'] += 10; self._indicators['clang_asan'] += 1
        if _GCC_GO_SIGNATURE.search(self._sample): scores['gcc'] += 8; self._indicators['gcc_go'] += 1
        total = sum(scores.values()) or 1
        best_compiler, best_score = scores.most_common(1)[0]
        self._confidence = min(best_score / total, 1.0)
        return best_compiler

    def _detect_lto(self) -> bool:
        if _GCC_LTO_MAGIC.search(self._sample): return True
        if _CLANG_LTO_SIG.search(self._sample): return True
        return False

    def _detect_opt_level(self, compiler):
        code_regions = []
        if self._binary_data[:2] == b'MZ': pass
        elif self._binary_data[:4] == b'\x7fELF':
            for offset in [0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000]:
                chunk = self._binary_data[offset:offset+4096]
                if len(chunk) == 4096: code_regions.append(chunk)
        if not code_regions: code_regions = [self._sample[0x400:0x400+4096*4]]
        combined = b'\n'.join(code_regions)
        o0_hits = len(_OPT_PATTERNS[0].findall(combined[:65536]))
        o2_hits = len(_OPT_PATTERNS[2].findall(combined[:65536]))
        o3_hits = len(_O3_AUTOVEC.findall(combined[:65536]))
        if o0_hits > 20: return OptimizationLevel.O0
        if o3_hits > 10 and o2_hits > 5: return OptimizationLevel.O3
        if o2_hits > 5: return OptimizationLevel.O2
        if o0_hits > 5: return OptimizationLevel.O1
        return OptimizationLevel.Os if o2_hits == 0 and o0_hits == 0 else OptimizationLevel.UNKNOWN

    def _assess_liftability(self) -> Dict[str, Any]:
        """评估二进制可被提升到 LLVM IR 的程度——Remill/Anvill 启发
        返回各障碍的计数值及综合评分。0.0=极难提升，1.0=容易提升
        """
        barriers = {}
        total_score = 1.0
        for name, pat in _LIFT_BARRIERS.items():
            count = len(pat.findall(self._sample))
            barriers[name] = count
            # 每种障碍扣减一定分值
            total_score -= count * 0.08
        return {
            'score': max(0.0, total_score),
            'barriers': barriers,
            'verdict': 'easy' if total_score > 0.8 else
                       'moderate' if total_score > 0.5 else
                       'hard' if total_score > 0.2 else 'very_hard',
        }

    def _assess_security_risks(self, compiler, opt_level, lto_enabled: bool = False,
                                liftability: Dict = None):
        risks = []
        if opt_level == OptimizationLevel.O0:
            risks.append(SecurityRisk('medium',
                'Debug build (O0): stack canaries and CFG may be disabled. '
                'No inlining means more gadget surface.'))
        if lto_enabled:
            risks.append(SecurityRisk('low',
                'LTO enabled: cross-module optimization may introduce unexpected code transformations.'))
        if compiler == 'rustc':
            risks.append(SecurityRisk('low',
                'Rust compiler (rustc) — unsafe blocks may bypass borrow checker.'))
        if liftability and liftability.get('score', 1.0) < 0.3:
            risks.append(SecurityRisk('medium',
                'Low liftability score indicates presence of anti-analysis patterns '
                '(indirect jumps, opaque predicates, potential obfuscation).'))
        return risks


analyze_compiler_opt = CompilerOptAnalyzer().analyze


def format_compiler_opt_report(result):
    lines = [f"Compiler: {result['compiler']}",
             f"Optimization: {result['optimization_level']}",
             f"LTO: {'yes' if result.get('lto_enabled') else 'no'}",
             f"Liftability: {result.get('liftability', {}).get('verdict', 'unknown')} "
             f"({result.get('liftability', {}).get('score', 0):.2f})",
             f"Confidence: {result['confidence']:.1%}"]
    for r in result.get('security_risks', []):
        lines.append(f"  [{r['level'].upper()}] {r['desc']}")
    return '\n'.join(lines)


def export_compiler_opt_report(result, path):
    import json
    with open(path, 'w') as fh: json.dump(result, fh, indent=2, default=str)
