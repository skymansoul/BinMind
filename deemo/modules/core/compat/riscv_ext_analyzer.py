"""RISC-V 扩展分析兼容层——扁平命名空间入口。

实现位于 modules/platform/mobile/src/riscv_ext_analyzer.py，本模块仅转发符号，保持 modules.riscv_ext_analyzer 导入路径可用。
"""
from modules.platform.mobile.src.riscv_ext_analyzer import (
    RISCVVectorInstruction,
    RISCVVectorLoop,
    RISCV_CryptoInstruction,
    RISCVExtAnalysisResult,
    RISCVExtAnalyzer,
)

__all__ = [
    'RISCVVectorInstruction', 'RISCVVectorLoop', 'RISCV_CryptoInstruction',
    'RISCVExtAnalysisResult', 'RISCVExtAnalyzer',
]
