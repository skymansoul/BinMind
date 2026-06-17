"""
模块导出
"""

# 日志框架模块
from .logging_config import (
    StructuredLogger,
    PerformanceTimer,
    get_logger,
    init_logging,
    mask_sensitive_data,
    SensitiveDataFilter,
    get_global_logger,
    LOGURU_AVAILABLE,
)

from .task_scheduler import (
    TaskScheduler,
    TaskStatus,
    TaskType,
    TaskResult,
    TaskDependency,
    BaseTask,
    SimpleTask,
    AnalysisTask,
    AnalysisPipeline,
    create_default_pipeline
)

from .plugin_manager import (
    PluginManager,
    BaseAnalyzer,
    AnalyzerType,
    AnalyzerMetadata,
    get_plugin_manager
)

from .config_manager import (
    ConfigManager,
    ConfigSource,
    TargetConfig,
    AnalyzerConfig,
    create_config_manager
)

from .resource_control import (
    ResourceController,
    ResourceLimits,
    SandboxType,
    SandboxExecutor,
    TimeoutExecutor,
    MemoryLimiter,
    IncrementalAnalysisCache,
    ExecutionResult
)

from .error_handling import (
    ErrorHandler,
    ErrorContext,
    ErrorRecord,
    ErrorSeverity,
    ErrorCategory,
    SafeExecution,
    RetryHandler,
    get_error_handler
)

# 核心分析模块
from .info_collect import *
from .static_analysis import *
from .decomp_ai import *
from .symbolic_exe import *
from .crash_analysis import *
from .exploit_gen import *
from .vuln_db import *
from .report import *
from .hooks import *

# 新增功能模块
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

from .attack_to_exploit import (
    AttackToExploitMapper,
    AttackTechnique,
    TargetArch,
    TargetOS,
    TechniqueMapping,
    ExploitPrototype,
    DetectionRule,
    MappingResult
)

from .digital_twin_risk import (
    DigitalTwinRiskAnalyzer,
    RiskLevel,
    FuzzerType,
    EmulationStatus,
    FirmwareInfo,
    EmulationConfig,
    VulnerabilityFinding,
    RiskAssessment,
    PenetrationScript
)

from .forensic_path_recorder import (
    ForensicPathRecorder,
    RecordType,
    Architecture,
    RegisterState,
    MemoryRegion,
    SymbolicConstraint,
    ExecutionPath,
    VulnerabilityEvidence,
    ForensicSnapshot,
    ForensicRecord
)

from .exploit_video_renderer import (
    ExploitVideoRenderer,
    VideoFormat,
    RenderMode,
    VideoConfig,
    ExploitStep,
    VideoFrame,
    RenderedVideo,
    RegisterVisualization,
    MemoryVisualization,
    VideoOverlay
)

from .binary_contract_verifier import (
    BinaryContractVerifier,
    ContractType,
    VerificationStatus,
    ContractClause,
    FunctionContract,
    VerificationResult,
    SymbolicPath
)

from .information_flow_verifier import (
    InformationFlowVerifier,
    SecurityLevel,
    FlowPolicy,
    SecurityLabel,
    FlowRule,
    FlowViolation,
    FlowVerificationResult
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

# 协议模型检查模块
from .protocol_model_checker import (
    ProtocolModelChecker,
    ModelCheckerType,
    PropertyType,
    ProtocolState,
    ProtocolTransition,
    LTLProperty,
    ModelCheckResult,
    ProtocolFSM
)

# GPU 内核分析模块
from .gpu_kernel_analyzer import (
    GPUKernelAnalyzer,
    GPUArchitecture,
    VulnCategory,
    GPUVulnerability,
    KernelInfo,
    MemoryAccess,
    ThreadSynchronization,
    AnalysisReport,
    PTXParser,
    SASSAnalyzer,
    CUBINParser,
    DataRaceDetector
)

# 神经网络模型扫描模块
from .nn_model_scanner import (
    NNModelScanner,
    ModelFormat,
    ThreatCategory,
    Severity,
    ModelMetadata,
    SuspiciousPattern,
    SecurityFinding,
    ScanResult,
    ONNXParser,
    TFLiteParser,
    BackdoorDetector,
    SubgraphAnalyzer,
    SerializationAttackDetector
)

# TEE 可信应用验证模块
from .tee_ta_verifier import (
    TEETAVerifier,
    TEEType,
    InterfaceType,
    SideChannelRisk,
    TrustedFunction,
    MemoryRegion,
    InterfaceVulnerability,
    SideChannelFinding,
    VerificationReport,
    SGXEnclaveParser,
    TrustZoneParser,
    InterfaceAnalyzer,
    SideChannelAnalyzer,
    MemoryLayoutAnalyzer
)

# 逻辑漏洞检测模块
from .logic_vuln_detector import (
    LogicVulnDetector,
    SimpleLogicVulnDetector,
    AngrLogicVulnDetector,
    TOCTORuleEngine,
    PermissionAnalysisEngine,
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityFinding,
    TOCTOUMatch,
    PermissionCheck,
    create_logic_vuln_detector,
    analyze_logic_vulnerabilities
)

# Concolic执行模块
from .concolic_execution import (
    ConcolicExecutor,
    ConcolicMode,
    ConcolicStatus,
    ConcolicSeed,
    ConcolicPath,
    ConcolicResult,
    create_concolic_executor,
    run_concolic_analysis
)

# 协作与Git版本管理模块
from .collaboration import (
    CollaborationManager,
    UserRole,
    User,
    ProjectMember,
    AuditLogEntry,
    Comment,
    VulnerabilityStatus,
    GitRepository,
    BinaryVersion,
    VersionDiff,
    get_collaboration_manager
)

# CLI模块
from .cli import (
    app,
    analyze_command,
    batch_command,
    health_command,
    test_command,
    server_command,
    version_command
)

# 代码匿名化模块
from .anonymizer import (
    CodeAnonymizer,
    Anonymizer,
    AnonymizationLevel,
    AnonymizationRule,
    AnonymizationResult,
    AnonymizationContextManager,
    get_anonymizer,
    anonymize_code,
    is_sensitive_content
)

# LLM管理器模块
from .llm_manager import (
    LLMManager,
    LLMBackend,
    LLMBackendType,
    LLMConfig,
    LLMResponse,
    EmbeddingResult,
    OpenAIBackend,
    AnthropicBackend,
    GoogleBackend,
    OllamaBackend,
    TransformersBackend,
    MockBackend,
    get_llm_manager,
    generate_text,
    generate_embedding
)

# Payload混淆模块
from .payload_obfuscator import (
    PayloadObfuscator,
    XOREncryptionEngine,
    Base64EncodingEngine,
    CompressionEngine,
    PolymorphicEngine,
    AntiDebugEngine,
    ObfuscationTechnique,
    AntiDetectionType,
    obfuscate_payload
)

# 后渗透模板模块
from .post_exploit_templates import (
    PostExploitTemplates,
    PostExploitTemplate,
    PostExploitModuleType,
    PlatformType,
    get_post_exploit_templates
)

# 可靠性预测模块
from .reliability_predictor import (
    ReliabilityPredictor,
    RuleBasedModel,
    MachineLearningModel,
    ReliabilityLevel,
    FeatureVector,
    predict_reliability
)

# 多阶段利用链编排模块
from .multi_stage_orchestrator import (
    MultiStageOrchestrator,
    VulnerabilityType,
    Capability,
    TargetType,
    ChainStatus,
    VulnerabilityNode,
    ExploitChainStep,
    ExploitChain,
    ChainAnalysisResult,
    orchestrate_exploit_chain
)

__all__ = [
    # 日志框架模块
    'StructuredLogger',
    'PerformanceTimer',
    'get_logger',
    'init_logging',
    'mask_sensitive_data',
    'SensitiveDataFilter',
    'get_global_logger',
    'LOGURU_AVAILABLE',
    
    # 任务调度模块
    'TaskScheduler',
    'TaskStatus',
    'TaskType',
    'TaskResult',
    'TaskDependency',
    'BaseTask',
    'SimpleTask',
    'AnalysisTask',
    'AnalysisPipeline',
    'create_default_pipeline',
    
    # 插件管理器模块
    'PluginManager',
    'BaseAnalyzer',
    'AnalyzerType',
    'AnalyzerMetadata',
    'get_plugin_manager',
    
    # 配置管理模块
    'ConfigManager',
    'ConfigSource',
    'TargetConfig',
    'AnalyzerConfig',
    'create_config_manager',
    
    # 资源控制模块
    'ResourceController',
    'ResourceLimits',
    'SandboxType',
    'SandboxExecutor',
    'TimeoutExecutor',
    'MemoryLimiter',
    'IncrementalAnalysisCache',
    'ExecutionResult',
    
    # 错误处理模块
    'ErrorHandler',
    'ErrorContext',
    'ErrorRecord',
    'ErrorSeverity',
    'ErrorCategory',
    'SafeExecution',
    'RetryHandler',
    'get_error_handler',
    
    # Python解包模块
    'PyInstallerUnpacker',
    'PycFile',
    'UnpackResult',
    'PYTHON_MAGIC_NUMBERS',
    
    # 行为追踪模块
    'BehaviorTracer',
    'ApiCall',
    'BehaviorCategory',
    'BehaviorSequence',
    'TraceResult',
    'trace_and_analyze',
    
    # 伪代码解释模块
    'PseudocodeExplainer',
    'CodeExplanation',
    'FunctionAnalysis',
    'ExplanationLevel',
    
    # K8s扫描模块
    'K8sClusterScanner',
    'ScanScope',
    'ContainerInfo',
    'BinaryRisk',
    'ClusterScanResult',
    
    # Nuclei生成模块
    'NucleiTemplateGenerator',
    'NucleiTemplate',
    'VulnerabilityInfo',
    'generate_nuclei_template',
    
    # 内存取证模块
    'MemoryForensicsAnalyzer',
    'SensitiveData',
    'ForensicsResult',
    'ProcessInfo',
    'MemoryString',
    'FileHandle',
    
    # ATT&CK映射模块
    'AttackToExploitMapper',
    'AttackTechnique',
    'TargetArchitecture',
    'TargetOS',
    'TechniqueMapping',
    'ExploitPrototype',
    'DetectionRule',
    'MappingResult',
    
    # 数字孪生模块
    'DigitalTwinRiskAnalyzer',
    'RiskLevel',
    'FuzzerType',
    'EmulationStatus',
    'FirmwareInfo',
    'EmulationConfig',
    'VulnerabilityFinding',
    'RiskAssessment',
    'PenetrationScript',
    
    # 取证记录模块
    'ForensicPathRecorder',
    'RecordType',
    'Architecture',
    'RegisterState',
    'MemoryRegion',
    'SymbolicConstraint',
    'ExecutionPath',
    'VulnerabilityEvidence',
    'ForensicSnapshot',
    'ForensicRecord',
    
    # 视频渲染模块
    'ExploitVideoRenderer',
    'VideoFormat',
    'RenderMode',
    'VideoConfig',
    'ExploitStep',
    'VideoFrame',
    'RenderedVideo',
    'RegisterVisualization',
    'MemoryVisualization',
    'VideoOverlay',
    
    # 合约验证模块
    'BinaryContractVerifier',
    'ContractType',
    'VerificationStatus',
    'ContractClause',
    'FunctionContract',
    'VerificationResult',
    'SymbolicPath',
    
    # 信息流验证模块
    'InformationFlowVerifier',
    'SecurityLevel',
    'FlowPolicy',
    'SecurityLabel',
    'FlowRule',
    'FlowViolation',
    'FlowVerificationResult',
    
    # 协议模型检查模块
    'ProtocolModelChecker',
    'ModelCheckerType',
    'PropertyType',
    'ProtocolState',
    'ProtocolTransition',
    'LTLProperty',
    'ModelCheckResult',
    'ProtocolFSM',

    # GPU 内核分析模块
    'GPUKernelAnalyzer',
    'GPUArchitecture',
    'VulnCategory',
    'GPUVulnerability',
    'KernelInfo',
    'MemoryAccess',
    'ThreadSynchronization',
    'AnalysisReport',
    'PTXParser',
    'SASSAnalyzer',
    'CUBINParser',
    'DataRaceDetector',
    
    # 逻辑漏洞检测模块
    'LogicVulnDetector',
    'SimpleLogicVulnDetector',
    'AngrLogicVulnDetector',
    'TOCTORuleEngine',
    'PermissionAnalysisEngine',
    'VulnerabilityType',
    'VulnerabilitySeverity',
    'VulnerabilityFinding',
    'TOCTOUMatch',
    'PermissionCheck',
    'create_logic_vuln_detector',
    'analyze_logic_vulnerabilities',

    # 神经网络模型扫描模块
    'NNModelScanner',
    'ModelFormat',
    'ThreatCategory',
    'Severity',
    'ModelMetadata',
    'SuspiciousPattern',
    'SecurityFinding',
    'ScanResult',
    'ONNXParser',
    'TFLiteParser',
    'BackdoorDetector',
    'SubgraphAnalyzer',
    'SerializationAttackDetector',

    # TEE 可信应用验证模块
    'TEETAVerifier',
    'TEEType',
    'InterfaceType',
    'SideChannelRisk',
    'TrustedFunction',
    'MemoryRegion',
    'InterfaceVulnerability',
    'SideChannelFinding',
    'VerificationReport',
    'SGXEnclaveParser',
    'TrustZoneParser',
    'InterfaceAnalyzer',
    'SideChannelAnalyzer',
    'MemoryLayoutAnalyzer',

    # Concolic执行模块
    'ConcolicExecutor',
    'ConcolicMode',
    'ConcolicStatus',
    'ConcolicSeed',
    'ConcolicPath',
    'ConcolicResult',
    'create_concolic_executor',
    'run_concolic_analysis',

    # 协作与Git版本管理模块
    'CollaborationManager',
    'UserRole',
    'User',
    'ProjectMember',
    'AuditLogEntry',
    'Comment',
    'VulnerabilityStatus',
    'GitRepository',
    'BinaryVersion',
    'VersionDiff',
    'get_collaboration_manager',

    # CLI模块
    'app',
    'analyze_command',
    'batch_command',
    'health_command',
    'test_command',
    'server_command',
    'version_command',

    # 代码匿名化模块
    'CodeAnonymizer',
    'Anonymizer',
    'AnonymizationLevel',
    'AnonymizationRule',
    'AnonymizationResult',
    'AnonymizationContextManager',
    'get_anonymizer',
    'anonymize_code',
    'is_sensitive_content',

    # LLM管理器模块
    'LLMManager',
    'LLMBackend',
    'LLMBackendType',
    'LLMConfig',
    'LLMResponse',
    'EmbeddingResult',
    'OpenAIBackend',
    'AnthropicBackend',
    'GoogleBackend',
    'OllamaBackend',
    'TransformersBackend',
    'MockBackend',
    'get_llm_manager',
    'generate_text',
    'generate_embedding',
    
    # Payload混淆模块
    'PayloadObfuscator',
    'XOREncryptionEngine',
    'Base64EncodingEngine',
    'CompressionEngine',
    'PolymorphicEngine',
    'AntiDebugEngine',
    'ObfuscationTechnique',
    'AntiDetectionType',
    'obfuscate_payload',
    
    # 后渗透模板模块
    'PostExploitTemplates',
    'PostExploitTemplate',
    'PostExploitModuleType',
    'PlatformType',
    'get_post_exploit_templates',
    
    # 可靠性预测模块
    'ReliabilityPredictor',
    'RuleBasedModel',
    'MachineLearningModel',
    'ReliabilityLevel',
    'FeatureVector',
    'predict_reliability',
    
    # 多阶段利用链编排模块
    'MultiStageOrchestrator',
    'VulnerabilityType',
    'Capability',
    'TargetType',
    'ChainStatus',
    'VulnerabilityNode',
    'ExploitChainStep',
    'ExploitChain',
    'ChainAnalysisResult',
    'orchestrate_exploit_chain',
]

# 保留旧版兼容性别名
ConfigMgr = ConfigManager
ResourceCtrl = ResourceController
ErrHandler = ErrorHandler
TaskSched = TaskScheduler