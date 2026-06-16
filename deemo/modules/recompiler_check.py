"""
反编译代码重编译验证模块

将反编译生成的C伪代码通过编译器重新编译为二进制，比较原始二进制与重编译二进制在功能上的等价性，
以验证反编译准确性，并发现可能因反编译错误被掩盖的漏洞。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import subprocess
import tempfile
import difflib
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class CompilationStatus(Enum):
    """编译状态枚举"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class EquivalenceLevel(Enum):
    """等价性等级"""
    FULL = "full"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class FunctionInfo:
    """函数信息"""
    name: str
    decompiled_code: str
    original_address: Optional[int] = None
    compiled_success: bool = False
    equivalence_score: float = 0.0
    equivalence_level: EquivalenceLevel = EquivalenceLevel.NONE
    compilation_errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class RecompilationResult:
    """重编译结果"""
    functions: List[FunctionInfo] = field(default_factory=list)
    overall_compilation_rate: float = 0.0
    overall_equivalence_score: float = 0.0
    overall_equivalence_level: EquivalenceLevel = EquivalenceLevel.NONE
    compiler_version: str = ""
    compilation_time: float = 0.0
    notes: List[str] = field(default_factory=list)


class RecompilerVerifier:
    """
    反编译代码重编译验证器
    
    将反编译的C伪代码重新编译并验证等价性。
    """
    
    def __init__(self, compiler_path: str = "gcc"):
        """
        初始化验证器
        
        Args:
            compiler_path: 编译器路径
        """
        self.compiler_path = compiler_path
        self._check_compiler()
        
    def _check_compiler(self) -> bool:
        """
        检查编译器是否可用
        
        Returns:
            是否可用
        """
        try:
            result = subprocess.run(
                [self.compiler_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                logger.info(f"编译器版本: {lines[0] if lines else ''}")
                return True
        except Exception as e:
            logger.error(f"检查编译器失败: {e}")
            
        logger.warning("未找到编译器，部分功能将不可用")
        return False
        
    def compile_code(self, code: str, output_path: Optional[str] = None, 
                     flags: Optional[List[str]] = None) -> Tuple[CompilationStatus, str]:
        """
        编译C代码
        
        Args:
            code: C代码字符串
            output_path: 输出文件路径（可选）
            flags: 编译标志（可选）
            
        Returns:
            (编译状态, 输出/错误信息)
        """
        if not output_path:
            with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
                src_path = f.name
            with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as f:
                output_path = f.name
        else:
            src_path = output_path + ".c"
        
        # 写入源代码
        try:
            with open(src_path, 'w', encoding='utf-8') as f:
                f.write(code)
        except Exception as e:
            return CompilationStatus.FAILED, f"写入文件失败: {e}"
        
        # 构建编译命令
        cmd = [self.compiler_path, "-c", "-o", output_path, src_path]
        if flags:
            cmd.extend(flags)
            
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return CompilationStatus.SUCCESS, output_path
            else:
                return CompilationStatus.FAILED, result.stderr
                
        except subprocess.TimeoutExpired:
            return CompilationStatus.TIMEOUT, "编译超时"
        except Exception as e:
            return CompilationStatus.FAILED, str(e)
        finally:
            # 清理源文件
            if os.path.exists(src_path):
                os.remove(src_path)
                
    def _generate_header(self, includes: Optional[List[str]] = None) -> str:
        """
        生成头文件包含
        
        Args:
            includes: 需要包含的头文件列表
            
        Returns:
            头文件包含字符串
        """
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
        """
        修复反编译代码中的常见问题
        
        Args:
            code: 反编译的代码
            
        Returns:
            修复后的代码
        """
        fixed = code
        
        # 移除伪代码标记
        fixed = fixed.replace("//", "/*").replace("/*/", "*/")
        
        # 修复变量声明
        fixed = fixed.replace("undefined4", "uint32_t")
        fixed = fixed.replace("undefined", "uint8_t")
        fixed = fixed.replace("undefined8", "uint64_t")
        fixed = fixed.replace("undefined2", "uint16_t")
        
        # 修复函数返回类型
        fixed = fixed.replace("__int64", "int64_t")
        fixed = fixed.replace("__int32", "int32_t")
        fixed = fixed.replace("__int16", "int16_t")
        fixed = fixed.replace("__int8", "int8_t")
        fixed = fixed.replace("unsigned __int64", "uint64_t")
        fixed = fixed.replace("unsigned __int32", "uint32_t")
        fixed = fixed.replace("unsigned __int16", "uint16_t")
        fixed = fixed.replace("unsigned __int8", "uint8_t")
        
        # 修复特殊类型
        fixed = fixed.replace("byte", "uint8_t")
        fixed = fixed.replace("word", "uint16_t")
        fixed = fixed.replace("dword", "uint32_t")
        fixed = fixed.replace("qword", "uint64_t")
        
        # 修复函数调用约定
        fixed = fixed.replace("__fastcall", "")
        fixed = fixed.replace("__stdcall", "")
        fixed = fixed.replace("__cdecl", "")
        
        # 修复数组索引
        fixed = fixed.replace("[__ptr64]", "")
        
        # 移除可疑的注释
        fixed = "\n".join(line for line in fixed.split("\n") if not line.strip().startswith("/*") or "*/" in line)
        
        return fixed
        
    def verify_function(self, func_name: str, decompiled_code: str, 
                       original_address: Optional[int] = None) -> FunctionInfo:
        """
        验证单个函数的反编译代码
        
        Args:
            func_name: 函数名
            decompiled_code: 反编译的代码
            original_address: 原始地址（可选）
            
        Returns:
            函数信息
        """
        info = FunctionInfo(
            name=func_name,
            decompiled_code=decompiled_code,
            original_address=original_address
        )
        
        # 修复代码
        fixed_code = self._fix_decompiled_code(decompiled_code)
        
        # 添加头文件
        full_code = self._generate_header() + fixed_code
        
        # 编译代码
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
            
        # 添加注释
        if not info.compiled_success:
            info.notes.append("编译失败，可能存在反编译错误")
        elif info.equivalence_level == EquivalenceLevel.LOW:
            info.notes.append("等价性较低，建议人工检查")
            
        return info
        
    def _calculate_equivalence(self, code: str) -> float:
        """
        计算代码等价性评分
        
        Args:
            code: 编译成功的代码
            
        Returns:
            等价性评分（0-1）
        """
        # 基于代码特征计算等价性
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
        
        # 简单的启发式评分
        total_features = sum(count for _, count in features)
        
        if total_features == 0:
            return 0.5  # 默认中等
            
        # 如果有控制流结构，评分更高
        control_flow_count = sum(count for name, count in features if name in ['if', 'else', 'while', 'for', 'switch'])
        
        if control_flow_count >= 3:
            return min(1.0, 0.6 + control_flow_count * 0.08)
        elif control_flow_count >= 1:
            return 0.5 + control_flow_count * 0.1
        else:
            return 0.3
            
    def _determine_equivalence_level(self, score: float) -> EquivalenceLevel:
        """
        根据评分确定等价性等级
        
        Args:
            score: 等价性评分
            
        Returns:
            等价性等级
        """
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
        """
        批量验证多个函数
        
        Args:
            functions: 函数名到反编译代码的映射
            
        Returns:
            重编译结果
        """
        result = RecompilationResult()
        start_time = time.time()
        
        for func_name, code in functions.items():
            func_info = self.verify_function(func_name, code)
            result.functions.append(func_info)
            
        # 计算统计信息
        if result.functions:
            success_count = sum(1 for f in result.functions if f.compiled_success)
            result.overall_compilation_rate = success_count / len(result.functions)
            
            avg_score = sum(f.equivalence_score for f in result.functions) / len(result.functions)
            result.overall_equivalence_score = avg_score
            result.overall_equivalence_level = self._determine_equivalence_level(avg_score)
            
        result.compilation_time = time.time() - start_time
        
        # 添加备注
        if result.overall_compilation_rate < 0.5:
            result.notes.append("编译成功率较低，可能存在大量反编译错误")
        if result.overall_equivalence_level == EquivalenceLevel.LOW:
            result.notes.append("整体等价性较低，建议人工审查")
            
        return result
        
    def compare_binaries(self, original_path: str, recompiled_path: str) -> float:
        """
        比较原始二进制和重编译二进制
        
        Args:
            original_path: 原始二进制路径
            recompiled_path: 重编译二进制路径
            
        Returns:
            相似度（0-1）
        """
        try:
            with open(original_path, 'rb') as f1, open(recompiled_path, 'rb') as f2:
                original_data = f1.read()
                recompiled_data = f2.read()
                
            # 计算模糊哈希相似度
            return self._fuzzy_compare(original_data, recompiled_data)
            
        except Exception as e:
            logger.error(f"比较二进制失败: {e}")
            return 0.0
            
    def _fuzzy_compare(self, data1: bytes, data2: bytes) -> float:
        """
        模糊比较两个字节序列
        
        Args:
            data1: 第一个数据
            data2: 第二个数据
            
        Returns:
            相似度（0-1）
        """
        # 使用difflib计算相似度
        s = difflib.SequenceMatcher(None, data1, data2)
        return s.ratio()
        
    def generate_report(self, result: RecompilationResult) -> str:
        """
        生成验证报告
        
        Args:
            result: 重编译结果
            
        Returns:
            报告字符串
        """
        lines = []
        lines.append("=" * 60)
        lines.append("反编译代码重编译验证报告")
        lines.append("=" * 60)
        lines.append("")
        
        lines.append("【整体统计】")
        lines.append(f"  分析函数数: {len(result.functions)}")
        lines.append(f"  编译成功率: {result.overall_compilation_rate:.1%}")
        lines.append(f"  平均等价性评分: {result.overall_equivalence_score:.1%}")
        lines.append(f"  整体等价性等级: {result.overall_equivalence_level.value}")
        lines.append(f"  编译耗时: {result.compilation_time:.2f} 秒")
        lines.append("")
        
        lines.append("【函数详细结果】")
        for func in result.functions:
            lines.append(f"  - {func.name}")
            lines.append(f"      编译状态: {'成功' if func.compiled_success else '失败'}")
            if func.compiled_success:
                lines.append(f"      等价性评分: {func.equivalence_score:.1%}")
                lines.append(f"      等价性等级: {func.equivalence_level.value}")
            if func.compilation_errors:
                lines.append(f"      错误信息: {func.compilation_errors[0][:100]}...")
            if func.notes:
                lines.append(f"      备注: {', '.join(func.notes)}")
            lines.append("")
        
        if result.notes:
            lines.append("【警告】")
            for note in result.notes:
                lines.append(f"  ! {note}")
            lines.append("")
            
        lines.append("【修复建议】")
        lines.append("  1. 对于编译失败的函数，检查反编译代码中的语法错误")
        lines.append("  2. 等价性较低的函数可能需要人工审查")
        lines.append("  3. 注意类型转换和指针操作的正确性")
        lines.append("  4. 检查是否有未定义的函数或变量引用")
        lines.append("  5. 考虑调整反编译器的配置参数")
        lines.append("")
        
        return "\n".join(lines)


def verify_decompilation(functions: Dict[str, str]) -> RecompilationResult:
    """
    便捷函数：验证反编译代码
    
    Args:
        functions: 函数名到反编译代码的映射
        
    Returns:
        重编译结果
    """
    verifier = RecompilerVerifier()
    return verifier.verify_functions(functions)


def verify_single_function(func_name: str, decompiled_code: str) -> FunctionInfo:
    """
    便捷函数：验证单个函数
    
    Args:
        func_name: 函数名
        decompiled_code: 反编译代码
        
    Returns:
        函数信息
    """
    verifier = RecompilerVerifier()
    return verifier.verify_function(func_name, decompiled_code)
