"""CHERI 分析兼容层——扁平命名空间入口。

实现位于 modules/mobile/cheri_analyzer.py，本模块仅转发符号，保持 modules.cheri_analyzer 导入路径可用。
"""
from modules.mobile.cheri_analyzer import (
    CHERIInstruction,
    CHERICapability,
    CHERIAnalysisResult,
    CHERIAnalyzer,
)

__all__ = ['CHERIInstruction', 'CHERICapability', 'CHERIAnalysisResult', 'CHERIAnalyzer']
