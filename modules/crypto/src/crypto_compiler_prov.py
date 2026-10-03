"""
密码学编译器溯源 — 从密码学实现的编译产物推断编译器家族/版本/优化级别。

设计意图:
  编译器对密码学实现的安全性有决定性影响:
    (a) GCC vs Clang: 对常量时间代码的处理不同 — Clang更积极地将控制流转换为
        数据选择(cmov), GCC倾向于保留分支 → 任何一方的"优化"都可能破坏CT保证。
    (b) -O0 vs -O2 vs -O3: 低优化保留查表结构, 高优化可能将查表转为bit-sliced
        向量化实现 → 安全性属性完全改变。
    (c) -Os: 尺寸优化可能将循环展开恢复为紧凑循环 → 时序特征变化。
    (d) MSVC: 对SIMD intrinsic的处理与GCC/Clang不同 → 不同的向量代码布局。

  这些差异在二进制中留下可检测的指纹。特别是密码学代码 — 由于其高度结构化的
  循环/SIMD密集/常量表等特征 — 编译器指纹比通用代码更显著且更稳定。

  既有编译器溯源工具(MulCPI/ToolPhet/ViT-based)针对通用二进制, 本模块聚焦于
  密码学特有的编译指纹:
    1. S-box布局: 编译器对齐策略 — GCC 16-byte对齐 vs Clang 32-byte对齐 vs MSVC任意。
    2. 循环结构: 轮函数循环的展开模式 — -O3全展开 vs -O2部分展开 vs -Os紧凑循环。
    3. 寄存器分配: XOR密集型代码的寄存器压力 → 溢出模式差异。
    4. SIMD向量化: SSE vs AVX vs NEON → 编译器向量宽度选择差异。
    5. 常量加载模式: 立即数 vs RIP相对 vs 常量池加载 → 编译器代码模型差异。

  - Schneider et al.: "Breaking Bad: How Compilers Break
    Constant-Time Implementations" — GCC/Clang优化破坏CT保证的具体pass分析。
  - MulCPI: 编译器家族+优化级别识别, 99.3%准确率。
    本项目补充其缺失的密码学特化维度。
  - ToolPhet: 新兴编译器(Rust/Go/Nim)识别。本项目同样支持
    Go/Rust的密码学库(如crypto/tls, ring)的编译器特征。

边界条件:
  - 编译器指纹需要足够的密码学代码量(≥512字节) — 小函数可能无法可靠识别。
  - 手写汇编的密码学实现无编译器指纹 → 报告为HANDWRITTEN_ASM。
  - 编译器版本指纹(如GCC 11.2 vs 11.4)在当前实现中不可靠 → 仅到家族级别。
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class CompilerProvenance:
    compiler_family: str = ""       # GCC / Clang / MSVC / Go / Rustc / HANDWRITTEN
    compiler_version_hint: str = "" # 版本提示(如 'GCC 11+')
    optimization_level: str = ""    # O0 / O1 / O2 / O3 / Os / Oz / UNKNOWN
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    ct_preservation: str = ""       # 常量时间代码的编译器保护状态
    simd_used: str = ""             # SSE / AVX2 / AVX-512 / NEON / NONE

# 编译器指纹库

# 函数序言模式 — 编译器特有
_PROLOGUE_PATTERNS: Dict[str, List[bytes]] = {
    'GCC': [b'\x55\x48\x89\xE5',           # push rbp; mov rbp,rsp
            b'\x55\x48\x89\xE5\x48\x83\xEC', # + sub rsp, imm
            b'\xF3\x0F\x1E\xFA',            # endbr64 (GCC 8+, CET)
            ],
    'Clang': [b'\x55\x48\x89\xE5',          # 相同基础序列, 但sub rsp顺序不同
              b'\x50\x48\x89\xE5',          # push rax; mov rbp,rsp (Clang特有)
              b'\x55\x48\x89\xE5\x48\x81\xEC', # + sub rsp, large imm
              ],
    'MSVC': [b'\x40\x55',                   # push rbp (REX prefix)
             b'\x48\x83\xEC',               # sub rsp, imm (无push rbp—MSVC特有)
             b'\x48\x89\x5C\x24',           # mov [rsp+imm], rbx (MSVC保存方式)
             ],
}

# 循环展开模式 — 优化级别指纹
# 密码学轮函数循环在不同优化级别下展开程度不同
_UNROLL_PATTERNS: Dict[str, List[Tuple[bytes, str]]] = [
    # (重复的操作码序列, 对应的优化级别)
    (b'\x31\xD8\xC1\xE0\x03\x31\xC3' * 8, 'O3'),   # XOR+SHL+XOR 重复8次以上→完全展开
    (b'\x31\xD8\xC1\xE0\x03\x31\xC3' * 4, 'O2'),   # 部分展开
    (b'\x75' + b'\x00' * 50 + b'\x31\xD8', 'Os'),  # 条件跳回+单个迭代体→紧凑循环
]

# SIMD向量化模式
_SIMD_PATTERNS: Dict[str, List[bytes]] = {
    'AVX-512': [b'\x62', b'zmm', b'vpternlog'],
    'AVX2': [b'\xC5', b'\xC4', b'vpbroadcast', b'vpadd', b'vpxor',
             b'ymm', b'vaesenc'],
    'SSE': [b'\x66\x0F\x38', b'xmm', b'pxor', b'pshufb',
            b'aesenc', b'aesenclast'],
    'NEON': [b'\x4E', b'\x0F', b'veor', b'vaese', b'vmov'],
}

# 常量加载模式 — 代码模型指纹
_CONST_LOAD_PATTERNS: Dict[str, List[bytes]] = {
    'RIP-relative': [b'\x48\x8D\x05', b'\x4C\x8D\x05'],   # lea rax/r8, [rip+disp]
    'immediate':    [b'\x48\xC7\xC0', b'\xB8'],            # mov rax, imm64
    'const-pool':   [b'\x48\x8B\x05', b'\x4C\x8B\x05'],   # mov rax/r8, [rip+disp]
}

# CT保护标志 — 编译器是否保留了常量时间结构
_CT_PRESERVATION_PATTERNS: List[Tuple[bytes, str, str]] = [
    (b'cmov', 'Clang', 'Clang将分支转为cmov(利于CT但可能非预期)'),
    (b'set', 'GCC', 'GCC保留条件set(可能产生分支)'),
    # 编译器barrier指令
    (b'mfence', 'MSVC', 'MSVC显式屏障(保守CT策略)'),
    (b'lfence', 'GCC', 'GCC Spectre缓解(间接CT保护)'),
]

def _detect_compiler_family(data: bytes, offset: int = 0) -> Tuple[str, float, List[str]]:
    """检测编译器家族。分析函数序言模式和代码布局特征。"""
    window = data[offset:offset + 2048] if offset + 2048 <= len(data) else data[offset:]
    scores: Dict[str, int] = {}
    evidence: List[str] = []

    for family, patterns in _PROLOGUE_PATTERNS.items():
        score = 0
        for pat in patterns:
            if pat in window:
                score += 1
                evidence.append(f'{family} prologue: {pat.hex()}')
        scores[family] = score

    if not scores:
        return 'UNKNOWN', 0.2, []

    best = max(scores, key=scores.get)
    max_score = scores[best]
    if max_score == 0:
        return 'UNKNOWN', 0.2, evidence

    # 置信度: 1个匹配→0.55, 2个→0.75, 3+个→0.88
    conf = min(0.88, 0.40 + max_score * 0.16)
    return best, conf, evidence

def _detect_optimization_level(data: bytes, offset: int = 0) -> Tuple[str, float, List[str]]:
    """从循环展开模式推断优化级别。"""
    window = data[offset:offset + 4096] if offset + 4096 <= len(data) else data[offset:]
    evidence: List[str] = []

    # 统计指令序列中的循环结构
    # 搜索后向条件跳转(循环结构)
    loop_back_edges = []
    for i in range(len(window) - 6):
        if window[i] in (0x75, 0x7E, 0x7F, 0xEB):  # JNZ/JLE/JG/JMP
            rel = window[i + 1]
            if rel < 0x80:  # 正向跳转忽略
                continue
            target = i + 2 + (rel - 256 if rel >= 0x80 else rel)  # 符号扩展
            if target < i:  # 后向跳转=循环
                loop_back_edges.append(i - target)  # 循环体大小

    if not loop_back_edges:
        return 'UNKNOWN', 0.2, evidence

    avg_loop_size = sum(loop_back_edges) / len(loop_back_edges)

    # 密码学轮函数典型大小: AES-128每轮≈32-64条指令
    # O3全展开: 无循环结构或循环体极大(>200字节=多轮展开成一个)
    # O2部分展开: 循环体中等(64-200字节=2-4轮/迭代)
    # Os紧凑: 循环体小(16-64字节=1轮/迭代)
    if len(loop_back_edges) <= 1 and max(loop_back_edges, default=0) > 200:
        return 'O3', 0.72, [f'fully unrolled: {len(loop_back_edges)} loops, max body={max(loop_back_edges, default=0)}B']
    elif avg_loop_size > 100:
        return 'O2', 0.65, [f'partially unrolled: avg loop body={avg_loop_size:.0f}B']
    elif avg_loop_size < 64:
        return 'Os', 0.60, [f'compact: avg loop body={avg_loop_size:.0f}B']
    else:
        return 'O1/O2', 0.50, [f'moderate: {len(loop_back_edges)} loops, avg body={avg_loop_size:.0f}B']

def _detect_simd(data: bytes, offset: int = 0) -> Tuple[str, float]:
    """检测SIMD向量化级别。"""
    window = data[offset:offset + 4096] if offset + 4096 <= len(data) else data[offset:]
    scores: Dict[str, int] = {}

    for level, patterns in _SIMD_PATTERNS.items():
        hits = 0
        for pat in patterns:
            hits += window.count(pat)
        scores[level] = hits

    # 按向量宽度从高到低检测
    for level in ['AVX-512', 'AVX2', 'SSE', 'NEON']:
        if scores.get(level, 0) >= 3:
            return level, min(0.90, 0.55 + scores[level] * 0.05)
    return 'NONE', 0.70

def _detect_ct_preservation(data: bytes, compiler_family: str) -> str:
    """评估编译器是否保留了常量时间结构。"""
    findings = []
    for pat, compiler, note in _CT_PRESERVATION_PATTERNS:
        if pat in data:
            findings.append(note)

    if not findings:
        if compiler_family == 'Clang':
            return 'Clang通常保留CT结构(cmov优先生成)'
        elif compiler_family == 'GCC':
            return 'GCC可能破坏CT — 检查分支优化(-fno-tree-vectorize)'
        elif compiler_family == 'MSVC':
            return 'MSVC对CT结构保守, 但SIMD intrinsic可能引入时序变化'
    return '; '.join(findings[:3])

def _check_handwritten_asm(data: bytes) -> bool:
    """检测手写汇编特征: 无标准函数序言/异常的寄存器使用/人工对齐模式。"""
    # 手写汇编通常无push rbp; mov rbp,rsp序言
    has_standard_prologue = any(
        pat in data[:256] for pats in _PROLOGUE_PATTERNS.values() for pat in pats)
    # 但可能有异常的对齐(NOP填充>16字节)和寄存器保存模式
    nop_density = data[:512].count(0x90) / min(512, len(data))
    return not has_standard_prologue and nop_density > 0.05

def infer_compiler_provenance(data: bytes, anchor_offset: int = 0,
                              algorithm: str = "") -> CompilerProvenance:
    """
    从密码学实现的二进制区域推断编译器溯源。
    anchor_offset: 密码学锚点偏移(从crypto_detector获取)。
    """
    region_start = max(0, anchor_offset - 256)

    # 手写汇编检测
    if _check_handwritten_asm(data):
        return CompilerProvenance(
            compiler_family='HANDWRITTEN_ASM',
            optimization_level='N/A (hand-optimized)',
            confidence=0.82,
            evidence=['non-standard function prologue', 'manual alignment patterns'],
            ct_preservation='取决于手写质量',
            simd_used=_detect_simd(data, region_start)[0])

    family, fam_conf, evidence = _detect_compiler_family(data, region_start)
    opt_level, opt_conf, opt_evidence = _detect_optimization_level(data, region_start)
    simd, simd_conf = _detect_simd(data, region_start)
    ct_status = _detect_ct_preservation(data, family)

    evidence.extend(opt_evidence)
    if simd != 'NONE':
        evidence.append(f'SIMD: {simd}')

    avg_conf = (fam_conf + opt_conf) / 2.0

    return CompilerProvenance(
        compiler_family=family,
        optimization_level=opt_level,
        confidence=round(avg_conf, 3),
        evidence=evidence,
        ct_preservation=ct_status,
        simd_used=simd)
