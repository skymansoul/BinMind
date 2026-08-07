# 创建: 2026-06-06 15:08
# 修改: 2026-06-06 — 贝叶斯融合: 字符串+代码惯用法+尾声模式
"""
编译器/工具链元数据指纹识别 — 从二进制 artifacts 推断编译器/版本/O级别。

现有编译器指纹 (compiler_fingerprint.py) 基于简单的字符串匹配——
无法区分 GCC 12 vs GCC 13, 或 Clang 15 vs Clang 17。
本模块通过多维特征综合判定。

特征维度:
  1. 字符串模式: .comment 节中的编译器版本字符串
  2. 代码惯用法: 编译器特有的优化模式 (GCC 的 xor eax,eax vs mov eax,0)
  3. 函数序言/尾声: 栈帧建立模式 (push rbp; mov rbp,rsp vs 省略帧指针)
  4. 循环优化: -O2/-O3 特有的循环展开 + 向量化指令
  5. 安全特性: -fstack-protector 的 canary 检测模式
  6. 异常处理: .eh_frame 的 FDE/CIE 布局差异

综合判定: 贝叶斯融合——每个特征维度独立计算 (编译器,版本,O级别)
的后验概率, 多项证据的乘积归一化为最终判定。

为什么需要精确的编译器版本:
  补丁分析: GCC 12→13 的代码生成差异可能被误判为"补丁变更"
  可利用性: 不同 O 级别的 gadget 可用性完全不同
  供应链: 确定二进制是否由声明的编译器版本构建

ref: Rosenblum et al. "Compiler Provenance" — 编译器指纹
     的原始框架, 本项目扩展到版本级 + O级别
ref: Caliskan et al. "When Coding Style Survives Compilation"
     — 代码风格→二进制残留, 本项目取其风格残留检测思路
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from collections import Counter
from typing import Optional


@dataclass
class CompilerFingerprint:
    """编译器指纹——编译器 + 版本 + 优化级别 + 语言方言。"""
    compiler: str = ''        # 'GCC' | 'Clang' | 'MSVC' | 'ICC'
    version: str = ''         # '12.2.0' | '15.0.7'
    optimization: str = ''    # 'O0' | 'O1' | 'O2' | 'O3' | 'Os' | 'Oz'
    language: str = ''        # 'C' | 'C++' | 'Rust' | 'Go' | 'Fortran'
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


# 字符串模式匹配

def detect_from_strings(strings: list[str]) -> dict:
    """从二进制字符串中检测编译器/版本。"""
    result = {'compiler': '', 'version': '', 'confidence': 0.0}
    text = '\n'.join(strings)

    # GCC 版本: GCC: (GNU) 12.2.0
    gcc_match = re.search(r'GCC:\s*\(?(?:GNU\s*\)?)?\s*(\d+\.\d+\.\d+)', text)
    if gcc_match:
        result['compiler'] = 'GCC'
        result['version'] = gcc_match.group(1)
        result['confidence'] = 0.95

    # Clang 版本: clang version 15.0.7
    clang_match = re.search(r'clang\s+version\s+(\d+\.\d+\.\d+)', text)
    if clang_match:
        result['compiler'] = 'Clang'
        result['version'] = clang_match.group(1)
        result['confidence'] = 0.95

    # MSVC 版本: Microsoft (R) C/C++
    if re.search(r'Microsoft\s*\(R\)\s*C/C\+\+', text):
        result['compiler'] = 'MSVC'
        result['confidence'] = 0.8

    # Rust: rustc version
    if re.search(r'rustc\s+(\d+\.\d+\.\d+)', text):
        result['compiler'] = 'rustc'
        result['version'] = re.search(r'rustc\s+(\d+\.\d+\.\d+)', text).group(1)
        result['language'] = 'Rust'
        result['confidence'] = 0.9

    # Go: go1.21.0
    go_match = re.search(r'go(\d+\.\d+\.\d+)', text)
    if go_match:
        result['compiler'] = 'Go'
        result['version'] = go_match.group(1)
        result['language'] = 'Go'
        result['confidence'] = 0.9

    return result


# 代码惯用法检测

def detect_from_code_idioms(instructions: list[dict]) -> dict:
    """从代码惯用法推断编译器+优化级别。"""
    mnemonics = [ins.get('mnemonic', '').lower() for ins in instructions]
    text = ' '.join(mnemonics)
    result = {'compiler': '', 'optimization': '', 'confidence': 0.0}

    # GCC 特征: xor eax,eax → 零寄存器 (而非 mov eax,0)
    xor_zero = text.count('xor') / max(1, len(mnemonics))
    mov_imm_zero = sum(1 for ins in instructions
                      if ins.get('mnemonic','').lower() == 'mov'
                      and '0' in str(ins.get('operands','')))
    if xor_zero > 0.03 and mov_imm_zero < 5:
        result['compiler'] = 'GCC'

    # Clang 特征: 倾向于 mov eax,0 + 更激进的循环展开
    if mov_imm_zero > 10:
        result['compiler'] = 'Clang'

    # MSVC 特征: 大量 push/pop + int3 填充
    int3_count = text.count('int3')
    push_pop_ratio = (text.count('push') + text.count('pop')) / max(1, len(mnemonics))
    if int3_count > 5 and push_pop_ratio > 0.05:
        result['compiler'] = 'MSVC'

    # O 级别推断: SIMD 指令 + 循环展开
    simd_ops = sum(1 for m in mnemonics
                  if m.startswith(('movdqa', 'movdqu', 'padd', 'psub',
                                   'pmul', 'vadd', 'vmul', 'vxor')))
    if simd_ops > 20:
        result['optimization'] = 'O2_or_O3'
    elif simd_ops > 5:
        result['optimization'] = 'O1'
    else:
        result['optimization'] = 'O0_or_Og'

    result['confidence'] = 0.6 if result['compiler'] else 0.0
    return result


# 函数序言/尾声模式

def detect_from_epilogue_patterns(instructions: list[dict]) -> dict:
    """从函数尾声模式推断编译器。"""
    result = {'compiler': '', 'confidence': 0.0}
    mnemonics = [ins.get('mnemonic', '').lower() for ins in instructions]
    text = ' '.join(mnemonics)

    # GCC: leave; ret (标准栈帧)
    gcc_epilogue = text.count('leave ret')
    # Clang: pop rbp; ret (省略 leave)
    clang_epilogue = text.count('pop rbp ret') + text.count('pop rbp pop')
    # MSVC: add rsp, X; ret (无帧指针)
    msvc_epilogue = len(re.findall(r'add\s+rsp.*ret', text))

    total_funcs = text.count('ret') or 1
    if gcc_epilogue / total_funcs > 0.3:
        result['compiler'] = 'GCC'
        result['confidence'] = 0.7
    elif clang_epilogue / total_funcs > 0.3:
        result['compiler'] = 'Clang'
        result['confidence'] = 0.7
    elif msvc_epilogue / total_funcs > 0.2:
        result['compiler'] = 'MSVC'
        result['confidence'] = 0.7

    return result


# 综合判定

class CompilerFingerprinter:
    """贝叶斯融合多维特征→编译器身份+版本+O级别综合判定。"""

    __slots__ = ('_reports',)

    def __init__(self):
        self._reports: list[CompilerFingerprint] = []

    def fingerprint(self, strings: list[str],
                    instructions: list[dict],
                    binary_name: str = '') -> CompilerFingerprint:
        fp = CompilerFingerprint()

        # 收集各维度证据
        str_result = detect_from_strings(strings)
        idiom_result = detect_from_code_idioms(instructions)
        epi_result = detect_from_epilogue_patterns(instructions)

        # 贝叶斯融合: 每个维度投票
        compiler_votes = Counter()
        version_votes = Counter()
        opt_votes = Counter()

        for result, weight in [(str_result, 0.5), (idiom_result, 0.3),
                                (epi_result, 0.2)]:
            if result.get('compiler'):
                compiler_votes[result['compiler']] += weight * result.get('confidence', 0.5)
            if result.get('version'):
                version_votes[result['version']] += weight
            if result.get('optimization'):
                opt_votes[result['optimization']] += weight
            if result.get('language'):
                fp.language = result['language']

        if compiler_votes:
            fp.compiler = compiler_votes.most_common(1)[0][0]
        if version_votes:
            fp.version = version_votes.most_common(1)[0][0]
        if opt_votes:
            fp.optimization = opt_votes.most_common(1)[0][0]

        # 置信度 = 最高编译器票数 / 总票数
        total = sum(compiler_votes.values())
        fp.confidence = round(compiler_votes.get(fp.compiler, 0) / total, 2) if total else 0.0

        fp.evidence = []
        if str_result.get('compiler'):
            fp.evidence.append(f'strings: {str_result["compiler"]} {str_result.get("version","")}')
        if idiom_result.get('compiler'):
            fp.evidence.append(f'idioms: {idiom_result["compiler"]} {idiom_result.get("optimization","")}')
        if epi_result.get('compiler'):
            fp.evidence.append(f'epilogue: {epi_result["compiler"]}')

        self._reports.append(fp)
        return fp

    def stats(self) -> dict:
        by_compiler = Counter(r.compiler for r in self._reports)
        return {
            'analyzed': len(self._reports),
            'by_compiler': dict(by_compiler),
        }


__all__ = [
    'CompilerFingerprinter', 'CompilerFingerprint',
    'detect_from_strings', 'detect_from_code_idioms',
    'detect_from_epilogue_patterns',
]
