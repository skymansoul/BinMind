"""
模块导出
"""

from .dynamic_taint import (
    DynamicTaintTracker,
    FridaTaintTracker,
    QBDITaintTracker,
    DynamicTaintSource,
    DynamicTaintSink,
    DynamicTaintFlow,
    DynamicVulnerability,
    run_dynamic_taint_analysis,
    create_dynamic_taint_tracker,
    FRIDA_AVAILABLE,
    QBDI_AVAILABLE
)

from .diff_analysis import (
    BinaryDiffAnalyzer,
    FunctionFeatures
)

from .interactive_shell import (
    InteractiveReversingShell
)

from .knowledge_graph import (
    VulnKnowledgeGraph,
    KnowledgeGraphEntity,
    KnowledgeGraphRelation
)

from .pyinstaller_unpacker import (
    PyInstallerUnpacker,
    PycFile,
    UnpackResult,
    PYTHON_MAGIC_NUMBERS
)

from .behavior_tracer import (
    BehaviorTracer,
    ApiCall,
    BehaviorCategory,
    BehaviorSequence,
    TraceResult,
    trace_and_analyze
)

from .pseudocode_explainer import (
    PseudocodeExplainer,
    CodeExplanation,
    FunctionAnalysis,
    ExplanationLevel
)

from .k8s_scanner import (
    K8sClusterScanner,
    ScanScope,
    ContainerInfo,
    BinaryRisk,
    ClusterScanResult
)

from .nuclei_generator import (
    NucleiTemplateGenerator,
    NucleiTemplate,
    VulnerabilityInfo,
    generate_nuclei_template
)

from .memory_forensics import (
    MemoryForensicsAnalyzer,
    SensitiveData,
    ForensicsResult,
    ProcessInfo,
    MemoryString,
    FileHandle
)

# 移动平台分析模块
from .mobile_analysis import (
    MobileBinaryAnalyzer,
    MobilePlatform,
    MobileAnalysisResult,
    JNIFunction,
    ObjectiveCClass,
    SensitiveString,
    MobileVulnerability
)

# Unicorn 混合分析模块
from .unicorn_hybrid import (
    UnicornHybridAnalyzer,
    HybridAnalysisResult,
    MemoryRegion as UnicornMemoryRegion,
    ExecutionResult,
    UNICORN_AVAILABLE
)

# 漏洞利用链分析模块
from .exploit_chaining import (
    ExploitChainComposer,
    AttackTarget,
    VulnerabilityCapability,
    VulnerabilityNode,
    ExploitChain,
    AttackGraph,
    ChainAnalysisResult,
    NETWORKX_AVAILABLE
)

# UEFI 固件分析模块
from .uefi_analyzer import (
    UEFIFirmwareAnalyzer,
    UEFIModuleInfo,
    FirmwareVolumeInfo
)

# 容器镜像扫描模块
from .container_scanner import (
    ContainerImageScanner,
    LayerInfo,
    BinaryFileInfo,
    ContainerSecurityReport
)

# Spectre/Meltdown 检测模块
from .spectre_detector import (
    SpectreGadgetDetector,
    SpectreGadget,
    SpectreType,
    RiskLevel,
    SpectreAnalysisResult
)

__all__ = [
    'DynamicTaintTracker',
    'FridaTaintTracker',
    'QBDITaintTracker',
    'DynamicTaintSource',
    'DynamicTaintSink',
    'DynamicTaintFlow',
    'DynamicVulnerability',
    'run_dynamic_taint_analysis',
    'create_dynamic_taint_tracker',
    'FRIDA_AVAILABLE',
    'QBDI_AVAILABLE',
    
    'BinaryDiffAnalyzer',
    'FunctionFeatures',
    
    'InteractiveReversingShell',
    
    'VulnKnowledgeGraph',
    'KnowledgeGraphEntity',
    'KnowledgeGraphRelation',
    
    'PyInstallerUnpacker',
    'PycFile',
    'UnpackResult',
    'PYTHON_MAGIC_NUMBERS',
    
    'BehaviorTracer',
    'ApiCall',
    'BehaviorCategory',
    'BehaviorSequence',
    'TraceResult',
    'trace_and_analyze',
    
    'PseudocodeExplainer',
    'CodeExplanation',
    'FunctionAnalysis',
    'ExplanationLevel',
    
    'K8sClusterScanner',
    'ScanScope',
    'ContainerInfo',
    'BinaryRisk',
    'ClusterScanResult',
    
    'NucleiTemplateGenerator',
    'NucleiTemplate',
    'VulnerabilityInfo',
    'generate_nuclei_template',
    
    'MemoryForensicsAnalyzer',
    'SensitiveData',
    'ForensicsResult',
    'ProcessInfo',
    'MemoryString',
    'FileHandle',
    
    # 移动平台分析模块
    'MobileBinaryAnalyzer',
    'MobilePlatform',
    'MobileAnalysisResult',
    'JNIFunction',
    'ObjectiveCClass',
    'SensitiveString',
    'MobileVulnerability',
    
    # Unicorn 混合分析模块
    'UnicornHybridAnalyzer',
    'HybridAnalysisResult',
    'UnicornMemoryRegion',
    'ExecutionResult',
    'UNICORN_AVAILABLE',
    
    # 漏洞利用链分析模块
    'ExploitChainComposer',
    'AttackTarget',
    'VulnerabilityCapability',
    'VulnerabilityNode',
    'ExploitChain',
    'AttackGraph',
    'ChainAnalysisResult',
    'NETWORKX_AVAILABLE',
    
    # UEFI 固件分析模块
    'UEFIFirmwareAnalyzer',
    'UEFIModuleInfo',
    'FirmwareVolumeInfo',
    
    # 容器镜像扫描模块
    'ContainerImageScanner',
    'LayerInfo',
    'BinaryFileInfo',
    'ContainerSecurityReport',
    
    # Spectre/Meltdown 检测模块
    'SpectreGadgetDetector',
    'SpectreGadget',
    'SpectreType',
    'RiskLevel',
    'SpectreAnalysisResult'
]