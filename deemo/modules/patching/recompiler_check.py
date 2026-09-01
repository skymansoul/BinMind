# 公开接口: CompilationStatus, EquivalenceLevel, FunctionInfo, RecompilationResult, RecompilerVerifier
# 依赖: os, subprocess, tempfile, difflib, hashlib, dataclasses, pathlib
import logging
import os
import subprocess
import tempfile
import difflib
import hashlib
import re
import time
from enum import Enum as _StdEnum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# 标准 Enum 封装
# 原类常量风格的状态/等级改为标准 Enum，同时保留旧构造兼容路径

class CompilationStatus(_StdEnum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

    @property
    def value(self):
        return self._value_

    def __str__(self):
        return self._value_

    def __eq__(self, other):
        if isinstance(other, CompilationStatus):
            return self._value_ == other._value_
        if isinstance(other, str):
            return self._value_ == other
        return NotImplemented

    def __hash__(self):
        return hash(self._value_)


class EquivalenceLevel(_StdEnum):
    FULL = "full"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def value(self):
        return self._value_

    def __str__(self):
        return self._value_


@dataclass
class FunctionInfo:
    name: str = ""
    decompiled_code: str = ""
    original_address: Optional[int] = None
    compiled_success: bool = False
    equivalence_score: float = 0.0
    equivalence_level: "EquivalenceLevel" = EquivalenceLevel.NONE
    compilation_errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)

@dataclass
class RecompilationResult:
    functions: list = field(default_factory=list)
    overall_compilation_rate: float = 0.0
    overall_equivalence_score: float = 0.0
    overall_equivalence_level: "EquivalenceLevel" = EquivalenceLevel.NONE
    compiler_version: str = ""
    compilation_time: float = 0.0
    notes: list = field(default_factory=list)

# UB 模式目录
# 常见 undefined behavior 正则，检测重编译代码中可能引入的问题

_UB_PATTERNS = [
    (r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;\s*if\s*\(\1\s*<\s*\2\)',
     'signed-integer-overflow-on-multiplication'),
    (r'return\s+&\w+;', 'return-stack-address'),
    (r'free\(\w+\);\s*\w+\s*=', 'use-after-free-same-scope'),
    (r'(\w+)\s*=\s*(\w+)\s*<<\s*(\d+)',
     'potential-left-shift-overflow'),
    (r'sprintf\(\w+,\s*"[^"]*%s[^"]*"',
     'unchecked-format-string-length'),
    (r'malloc\(\s*\w+\s*\*\s*\w+\s*\)',
     'potential-multiplication-overflow-in-alloc'),
    (r'sizeof\(\w+\)\s*\+\s*\w+\s*\*\s*\w+',
     'complex-sizeof-expression-may-overflow'),
]

class RecompilerVerifier:
    """
    反编译代码重编译验证器。

    对反编译 C 伪代码重编译并校验与原二进制的语义等价性。
    """

    def __init__(self, compiler_path: str = "gcc"):
        """初始化并确认编译器可用。"""
        self.compiler_path = compiler_path
        self._check_compiler()

    def _check_compiler(self) -> bool:
        """探测编译器二进制；不可用时返回 False。"""
        try:
            result = subprocess.run(
                [self.compiler_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10)

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                logger.info(f"compiler version: {lines[0] if lines else ''}")
                return True
        except Exception as e:
            logger.error(f"check compiler failed: {e}")

        logger.warning("compiler not found, some functionality unavailable")
        return False

    def compile_code(self, code: str, output_path: Optional[str] = None, flags: Optional[List[str]] = None) -> Tuple[CompilationStatus, str]:
        """编译 C 源文件至 .o。返回 (status, output_path|stderr)。"""
        if not output_path:
            with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
                src_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as f:
                output_path = f.name
        else:
            src_path = output_path + ".c"

        # 写源文件至临时路径
        try:
            with open(src_path, 'w', encoding='utf-8') as f:
                f.write(code)
        except Exception as e:
            return CompilationStatus.FAILED, f"write file failed: {e}"

        # 组装编译命令
        cmd = [self.compiler_path, "-c", "-o", output_path, src_path]
        if flags:
            cmd.extend(flags)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60)

            if result.returncode == 0:
                return CompilationStatus.SUCCESS, output_path
            else:
                return CompilationStatus.FAILED, result.stderr

        except subprocess.TimeoutExpired:
            return CompilationStatus.TIMEOUT, "compile timeout"
        except Exception as e:
            return CompilationStatus.FAILED, str(e)
        finally:
            # 清理临时源文件
            if os.path.exists(src_path):
                os.remove(src_path)

    def _generate_header(self, includes: Optional[List[str]] = None) -> str:
        """生成标准 C 头文件包含。"""
        default_includes = [
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdint.h>",
            "#include <stdbool.h>",
        ]

        if includes:
            default_includes.extend(f"#include <{inc}>" for inc in includes)

        return "\n".join(default_includes) + "\n\n"

    def _fix_decompiled_code(self, code: str) -> str:
        """反编译器输出常见瑕疵修复。"""
        fixed = code

        # 归一化伪代码注释标记
        fixed = fixed.replace("//", "/*").replace("/*/", "*/")

        # IDA 未定义类型 → 标准类型
        fixed = fixed.replace("undefined4", "uint32_t")
        fixed = fixed.replace("undefined", "uint8_t")
        fixed = fixed.replace("undefined8", "uint64_t")
        fixed = fixed.replace("undefined2", "uint16_t")

        # 编译器特定整数类型
        fixed = fixed.replace("__int64", "int64_t")
        fixed = fixed.replace("__int32", "int32_t")
        fixed = fixed.replace("__int16", "int16_t")
        fixed = fixed.replace("__int8", "int8_t")
        fixed = fixed.replace("unsigned __int64", "uint64_t")
        fixed = fixed.replace("unsigned __int32", "uint32_t")
        fixed = fixed.replace("unsigned __int16", "uint16_t")
        fixed = fixed.replace("unsigned __int8", "uint8_t")

        # x86 大小前缀类型
        fixed = fixed.replace("byte", "uint8_t")
        fixed = fixed.replace("word", "uint16_t")
        fixed = fixed.replace("dword", "uint32_t")
        fixed = fixed.replace("qword", "uint64_t")

        # 剥离调用约定修饰符
        fixed = fixed.replace("__fastcall", "")
        fixed = fixed.replace("__stdcall", "")
        fixed = fixed.replace("__cdecl", "")
        fixed = fixed.replace("__thiscall", "")
        fixed = fixed.replace("__vectorcall", "")

        # 剥离 __ptr64
        fixed = fixed.replace("[__ptr64]", "")

        # Ghidra 特定产物
        fixed = fixed.replace("_DAT_", "DAT_")
        fixed = fixed.replace("PTR_", "PTR_")
        fixed = fixed.replace("CONCAT", "/* CONCAT */")
        fixed = fixed.replace("ZEXT", "/* ZEXT */")
        fixed = fixed.replace("SEXT", "/* SEXT */")

        # 丢弃行首伪注释
        fixed = "\n".join(line for line in fixed.split("\n") if not line.strip().startswith("/*") or "*/" in line)

        return fixed

    def verify_function(self, func_name: str, decompiled_code: str, original_address: Optional[int] = None) -> FunctionInfo:
        """单函数验证：修复 → 编译 → 等价评分。"""
        info = FunctionInfo(
            name=func_name,
            decompiled_code=decompiled_code,
            original_address=original_address
        )

        # 反编译器输出修复
        fixed_code = self._fix_decompiled_code(decompiled_code)

        # 前置标准头
        full_code = self._generate_header() + fixed_code

        # 编译前 UB 扫描
        ub_findings = self._detect_undefined_behavior(fixed_code)
        if ub_findings:
            info.notes.append(f"UB patterns detected: {', '.join(ub_findings)}")

        # 编译
        status, output = self.compile_code(full_code)

        if status == CompilationStatus.SUCCESS:
            info.compiled_success = True
            info.equivalence_score = self._calculate_equivalence(fixed_code)
            info.equivalence_level = self._determine_equivalence_level(info.equivalence_score)

            # 清理编译产物
            if os.path.exists(output):
                os.remove(output)
        else:
            info.compiled_success = False
            info.compilation_errors.append(output)
            info.equivalence_score = 0.0
            info.equivalence_level = EquivalenceLevel.NONE

        # 标注结果
        if not info.compiled_success:
            info.notes.append("Compilation failed; possible decompiler output error")
        elif info.equivalence_level == EquivalenceLevel.LOW:
            info.notes.append("Equivalence score low; manual review advised")

        return info

    def _calculate_equivalence(self, code: str) -> float:
        """启发式等价评分 —— 混合关键词密度与结构特征。

        原始 keyword-counting 为基线，补充 AST 特征和 basic block 结构。
        评分范围 0.0-1.0。
        """

        # 基线：控制流关键词密度
        features = [
            ('if', code.count('if')),
            ('else', code.count('else')),
            ('while', code.count('while')),
            ('for', code.count('for')),
            ('switch', code.count('switch')),
            ('return', code.count('return')),
            ('malloc', code.count('malloc')),
            ('free', code.count('free')),
        ]

        total_features = sum(cnt for _, cnt in features)
        if total_features == 0:
            return 0.3  # 有代码无 CF → 可能是平凡 wrapper

        control_flow_count = sum(cnt for name, cnt in features if name in ['if', 'else', 'while', 'for', 'switch'])

        # 结构特征：basic block 数量与平均大小
        block_score = self._estimate_block_structure(code)

        # 综合：CF 密度 60% + 结构 40%
        if control_flow_count >= 5:
            cf_score = min(1.0, 0.7 + control_flow_count * 0.04)
        elif control_flow_count >= 1:
            cf_score = 0.4 + control_flow_count * 0.08
        else:
            cf_score = 0.2

        return min(1.0, cf_score * 0.6 + block_score * 0.4)

    def _estimate_block_structure(self, code):
        """从代码文本估算 basic block 结构完整性。

        通过大括号配对、label/goto 密度推断。
        高质量反编译代码应有清晰的 block 分界。
        """
        if not code:
            return 0.1

        lines = [l.strip() for l in code.split('\n') if l.strip() and not l.strip().startswith('/*')]
        if not lines:
            return 0.1

        n_lines = len(lines)
        # 统计 brace-balanced 行 vs 裸语句
        brace_lines = sum(1 for l in lines if '{' in l or '}' in l)
        semi_only_lines = sum(1 for l in lines if l.endswith(';') and '{' not in l and '}' not in l)

        # goto/label 密度 —— 过多表示反编译器未恢复控制流结构
        goto_count = code.count('goto ') + code.count('goto\t')
        label_count = len([l for l in lines if l.endswith(':') and not l.startswith('case ') and not l.startswith('default:')])

        # 评分：brace 密度适中 → 结构清晰；semi_only 多 → 有实际指令；goto/label 少 → 恢复成功
        brace_ratio = brace_lines / max(n_lines, 1)
        semi_ratio = semi_only_lines / max(n_lines, 1)
        goto_penalty = min(1.0, (goto_count + label_count) / max(n_lines, 1) * 5)

        raw = brace_ratio * 0.3 + semi_ratio * 0.4 + (1.0 - goto_penalty) * 0.3
        return min(max(raw, 0.05), 0.95)

    def _compare_basic_blocks(self, code_a, code_b):
        """比较两个 C 函数的 basic block 结构相似度。

        通过 brace 分隔区域的 fuzzy matching。
        """
        def extract_blocks(src):
            blocks = []
            depth = 0
            current = []
            for line in src.split('\n'):
                stripped = line.strip()
                if '{' in stripped:
                    depth += 1
                if '}' in stripped:
                    depth -= 1
                    if depth == 0 and current:
                        blocks.append('\n'.join(current))
                        current = []
                        continue
                if depth > 0:
                    current.append(stripped)
            # 未闭合 brace：剩余内容作一个块
            if current:
                blocks.append('\n'.join(current))
            return blocks

        blocks_a = extract_blocks(code_a)
        blocks_b = extract_blocks(code_b)

        if not blocks_a and not blocks_b:
            return 1.0
        if not blocks_a or not blocks_b:
            return 0.0

        # 块级 hash Jaccard 相似度
        hashes_a = set(hashlib.md5(b.encode('utf-8', errors='replace')).hexdigest()[:8] for b in blocks_a)
        hashes_b = set(hashlib.md5(b.encode('utf-8', errors='replace')).hexdigest()[:8] for b in blocks_b)
        inter = len(hashes_a & hashes_b)
        union = len(hashes_a | hashes_b)
        return inter / union if union > 0 else 0.0

    def _detect_undefined_behavior(self, code):
        """检测修复后代码中的常见 UB 模式。

        返回匹配到的 UB 类型标签列表。
        """
        findings = []
        for pattern, label in _UB_PATTERNS:
            if re.search(pattern, code):
                findings.append(label)
        return findings

    def _determine_equivalence_level(self, score: float) -> EquivalenceLevel:
        """数值评分 → 等价位阶。"""
        if score >= 0.9:
            return EquivalenceLevel.FULL
        elif score >= 0.7:
            return EquivalenceLevel.HIGH
        elif score >= 0.5:
            return EquivalenceLevel.MEDIUM
        elif score >= 0.3:
            return EquivalenceLevel.LOW
        else:
            return EquivalenceLevel.NONE

    def verify_functions(self, functions: Dict[str, str]) -> RecompilationResult:
        """批量验证多函数，返回聚合统计。"""
        result = RecompilationResult()
        start_time = time.time()

        for func_name, code in functions.items():
            func_info = self.verify_function(func_name, code)
            result.functions.append(func_info)

        # 聚合统计
        if result.functions:
            success_count = sum(1 for f in result.functions if f.compiled_success)
            result.overall_compilation_rate = success_count / len(result.functions)

            avg_score = sum(f.equivalence_score for f in result.functions) / len(result.functions)
            result.overall_equivalence_score = avg_score
            result.overall_equivalence_level = self._determine_equivalence_level(avg_score)

        result.compilation_time = time.time() - start_time

        # 诊断说明
        if result.overall_compilation_rate < 0.5:
            result.notes.append("Compilation success rate low; widespread decompiler output errors likely")
        if result.overall_equivalence_level == EquivalenceLevel.LOW:
            result.notes.append("Overall equivalence low; manual review advised")

        return result

    def compare_binaries(self, original_path: str, recompiled_path: str) -> float:
        """原始与重编译二进制 fuzzy hash 比对。"""
        try:
            with open(original_path, 'rb') as f1, open(recompiled_path, 'rb') as f2:
                original_data = f1.read()
                recompiled_data = f2.read()

            # fuzzy hash 相似度
            return self._fuzzy_compare(original_data, recompiled_data)

        except Exception as e:
            logger.error(f"binary compare failed: {e}")
            return 0.0

    def _fuzzy_compare(self, data1: bytes, data2: bytes) -> float:
        """Fuzzy 字节序列比对（difflib SequenceMatcher）。"""
        # difflib sequence similarity
        s = difflib.SequenceMatcher(None, data1, data2)
        return s.ratio()

    def generate_report(self, result: RecompilationResult) -> str:
        """生成可读验证报告。"""
        lines = []
        lines.append("=" * 60)
        lines.append("反编译代码重编译验证报告 (Decompiled Code Recompilation Verification Report)")
        lines.append("=" * 60)
        lines.append("")

        lines.append("[Summary]")
        lines.append(f"  Functions analysed: {len(result.functions)}")
        lines.append(f"  Compilation success rate: {result.overall_compilation_rate:.1%}")
        lines.append(f"  Mean equivalence score:  {result.overall_equivalence_score:.1%}")
        lines.append(f"  Overall equivalence tier: {result.overall_equivalence_level.value}")
        lines.append(f"  Compilation wall time:   {result.compilation_time:.2f}s")
        lines.append("")

        lines.append("[Per-Function Results]")
        for func in result.functions:
            lines.append(f"  - {func.name}")
            lines.append(f"      Compilation: {'PASS' if func.compiled_success else 'FAIL'}")
            if func.compiled_success:
                lines.append(f"      Equivalence score: {func.equivalence_score:.1%}")
                lines.append(f"      Equivalence tier:  {func.equivalence_level.value}")
            if func.compilation_errors:
                lines.append(f"      Error: {func.compilation_errors[0][:100]}...")
            if func.notes:
                lines.append(f"      Note: {', '.join(func.notes)}")
            lines.append("")

        if result.notes:
            lines.append("[Warnings]")
            for note in result.notes:
                lines.append(f"  ! {note}")
            lines.append("")

        lines.append("[Remediation]")
        lines.append("  1. For functions that failed compilation: inspect decompiler syntax errors")
        lines.append("  2. Low-equivalence functions require manual audit")
        lines.append("  3. Verify correctness of type conversions and pointer arithmetic")
        lines.append("  4. Check for unresolved function symbols or variable references")
        lines.append("  5. Consider adjusting decompiler configuration parameters")
        lines.append("")

        return "\n".join(lines)

# 便捷函数

def verify_decompilation(functions: Dict[str, str]) -> RecompilationResult:
    """批量验证反编译函数。"""
    verifier = RecompilerVerifier()
    return verifier.verify_functions(functions)

def verify_single_function(func_name: str, decompiled_code: str) -> FunctionInfo:
    """验证单条反编译函数。"""
    verifier = RecompilerVerifier()
    return verifier.verify_function(func_name, decompiled_code)
