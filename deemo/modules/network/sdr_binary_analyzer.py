"""SDR 二进制分析器入口——从子模块聚合导出。

原始 518 行单文件拆分为 sdr_types / sdr_parser / sdr_detectors / sdr_analyzer，
本文件仅做 __all__ 聚合以保持 import 路径不变。
"""
# 扁平导入 modes.xxx 走 _FlatFinder 时 __package__="network" 不存在，
# 需回退至完整路径 modules.network.xxx 才能正确解析子模块
try:
    from .sdr_types import (
        SDRComponentType,
        SignalType,
        VulnerabilityType,
        SDRComponent,
        FlowGraph,
        ParameterValidation,
        Vulnerability,
        SDRAnalysisResult,
    )
    from .sdr_parser import (
        GNURadioParser,
        GNURadioXMLParser,
        analyze_binary_sdr,
        infer_signal_type,
        is_xml_flowgraph,
    )
    from .sdr_detectors import (
        ParameterAnalyzer,
        SignalInjectionDetector,
        IQSampleIntegrityChecker,
    )
    from .sdr_analyzer import SDRBinaryAnalyzer
except ImportError:
    from modules.network.sdr_types import (
        SDRComponentType,
        SignalType,
        VulnerabilityType,
        SDRComponent,
        FlowGraph,
        ParameterValidation,
        Vulnerability,
        SDRAnalysisResult,
    )
    from modules.network.sdr_parser import (
        GNURadioParser,
        GNURadioXMLParser,
        analyze_binary_sdr,
        infer_signal_type,
        is_xml_flowgraph,
    )
    from modules.network.sdr_detectors import (
        ParameterAnalyzer,
        SignalInjectionDetector,
        IQSampleIntegrityChecker,
    )
    from modules.network.sdr_analyzer import SDRBinaryAnalyzer

__all__ = [
    "SDRComponentType",
    "SignalType",
    "VulnerabilityType",
    "SDRComponent",
    "FlowGraph",
    "ParameterValidation",
    "Vulnerability",
    "SDRAnalysisResult",
    "GNURadioParser",
    "GNURadioXMLParser",
    "analyze_binary_sdr",
    "infer_signal_type",
    "is_xml_flowgraph",
    "ParameterAnalyzer",
    "SignalInjectionDetector",
    "IQSampleIntegrityChecker",
    "SDRBinaryAnalyzer",
]
