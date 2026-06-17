"""
模块导出
"""

# 日志框架模块
from .logging_config import ()
    StructuredLogger,
    PerformanceTimer,
    get_logger,
    init_logging,
    mask_sensitive_data,
    SensitiveDataFilter,
    get_global_logger,
    LOGURU_AVAILABLE,


from .task_scheduler import ()
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


from .plugin_manager import ()
    PluginManager,
    BaseAnalyzer,
    AnalyzerType,
    AnalyzerMetadata,
    get_plugin_manager


from .config_manager import ()
    ConfigManager,
    ConfigSource,
    TargetConfig,
    AnalyzerConfig,
    create_config_manager


from .resource_control import ()
    ResourceController,
    ResourceLimits,
    SandboxType,
    SandboxExecutor,
    TimeoutExecutor,
    MemoryLimiter,
    IncrementalAnalysisCache,
    ExecutionResult


from .error_handling import ()
    ErrorHandler,
    ErrorContext,
    ErrorRecord,
    ErrorSeverity,
    ErrorCategory,
    SafeExecution,
    RetryHandler,
    get_error_handler


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
from .pyinstaller_unpacker import ()
    PyInstallerUnpacker,
    PycFile,
    UnpackResult,
    PYTHON_MAGIC_NUMBERS


from .behavior_tracer import ()
    BehaviorTracer,
    ApiCall,
    BehaviorCategory,
    BehaviorSequence,
    TraceResult,
    trace_and_analyze


from .pseudocode_explainer import ()
    PseudocodeExplainer,
    CodeExplanation,
    FunctionAnalysis,
    ExplanationLevel


from .k8s_scanner import ()
    K8sClusterScanner,
    ScanScope,
    ContainerInfo,
    BinaryRisk,
    ClusterScanResult


from .nuclei_generator import ()
    NucleiTemplateGenerator,
    NucleiTemplate,
    VulnerabilityInfo,
    generate_nuclei_template


from .memory_forensics import ()
    MemoryForensicsAnalyzer,
    SensitiveData,
    ForensicsResult,
    ProcessInfo,
    MemoryString,
    FileHandle


from .attack_to_exploit import ()
    ATTCKMapper,
    AttackTechnique,
    TargetArch,
    TargetOS,
    MITREKnowledgeBase,
    ExploitCodeGenerator,
    ExploitPrototype,
    DetectionRule,
    MappingResult,
    create_attck_mapper


from .digital_twin_risk import ()
    DigitalTwinRiskAnalyzer,
    RiskLevel,
    FuzzerType,
    EmulationStatus,
    FirmwareInfo,
    EmulationConfig,
    VulnerabilityFinding,
    RiskAssessment,
    PenetrationScript


from .forensic_path_recorder import ()
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


from .exploit_video_renderer import ()
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


from .binary_contract_verifier import ()
    BinaryContractVerifier,
    ContractType,
    VerificationStatus,
    ContractClause,
    FunctionContract,
    VerificationResult,
    SymbolicPath


from .information_flow_verifier import ()
    InformationFlowVerifier,
    SecurityLevel,
    FlowPolicy,
    SecurityLabel,
    FlowRule,
    FlowViolation,
    FlowVerificationResult


# 移动平台分析模块
from .mobile_analysis import ()
    MobileBinaryAnalyzer,
    MobilePlatform,
    MobileAnalysisResult,
    JNIFunction,
    ObjectiveCClass,
    SensitiveString,
    MobileVulnerability


# Unicorn 混合分析模块
from .unicorn_hybrid import ()
    UnicornHybridAnalyzer,
    HybridAnalysisResult,
    MemoryRegion as UnicornMemoryRegion,
    ExecutionResult,
    UNICORN_AVAILABLE


# 漏洞利用链分析模块
from .exploit_chaining import ()
    ExploitChainComposer,
    AttackTarget,
    VulnerabilityCapability,
    VulnerabilityNode,
    ExploitChain,
    AttackGraph,
    ChainAnalysisResult,
    NETWORKX_AVAILABLE


# 协议模型检查模块
from .protocol_model_checker import ()
    ProtocolModelChecker,
    ModelCheckerType,
    PropertyType,
    ProtocolState,
    ProtocolTransition,
    LTLProperty,
    ModelCheckResult,
    ProtocolFSM


# GPU 内核分析模块
from .gpu_kernel_analyzer import ()
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


# 神经网络模型扫描模块
from .nn_model_scanner import ()
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


# TEE 可信应用验证模块
from .tee_ta_verifier import ()
    TEEAnalyzer,
    TEEType,
    TEEDetector,
    FunctionExtractor,
    TrustedFunction,
    SharedMemoryRegion,
    InterfaceVulnerability,
    SideChannelFinding,
    TEEResult,
    create_tee_analyzer


# 逻辑漏洞检测模块
from .logic_vuln_detector import ()
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


# Concolic执行模块
from .concolic_execution import ()
    ConcolicExecutor,
    ConcolicMode,
    ConcolicStatus,
    ConcolicSeed,
    ConcolicPath,
    ConcolicResult,
    create_concolic_executor,
    run_concolic_analysis


# 协作与Git版本管理模块
from .collaboration import ()
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


# CLI模块
from .cli import ()
    app,
    analyze_command,
    batch_command,
    health_command,
    test_command,
    server_command,
    version_command


# 代码匿名化模块
from .anonymizer import ()
    CodeAnonymizer,
    Anonymizer,
    AnonymizationLevel,
    AnonymizationRule,
    AnonymizationResult,
    AnonymizationContextManager,
    get_anonymizer,
    anonymize_code,
    is_sensitive_content


# LLM管理器模块
from .llm_manager import ()
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


# Payload混淆模块
from .payload_obfuscator import ()
    PayloadObfuscator,
    XOREncryptionEngine,
    Base64EncodingEngine,
    CompressionEngine,
    PolymorphicEngine,
    AntiDebugEngine,
    ObfuscationTechnique,
    AntiDetectionType,
    obfuscate_payload


# 后渗透模板模块
from .post_exploit_templates import ()
    PostExploitTemplates,
    PostExploitTemplate,
    PostExploitModuleType,
    PlatformType,
    get_post_exploit_templates


# 可靠性预测模块
from .reliability_predictor import ()
    ReliabilityPredictor,
    RandomnessFactor,
    PredictionResult,
    EntropyEstimator,
    MonteCarloSimulator,
    create_reliability_predictor


# 多阶段利用链编排模块
from .multi_stage_orchestrator import ()
    ChainOrchestrator,
    ExploitStage,
    StageCapability,
    ChainStep,
    AttackChain,
    OrchestrationResult,
    DependencyResolver,
    ScriptGenerator,
    create_orchestrator


# 高级分析功能模块 (60个新功能)
from .advanced_analysis_features import ()
    ComplexityRiskPredictor, ComplexityFeature, ComplexityFeatureType,
    IndirectCallResolver, IndirectCallTarget,
    OpaquePredicateAnalyzer, OpaquePredicateType, BranchAnalysisResult,
    StackLifetimeTracker, StackVariable,
    DataFlowEquationSolver, ConstantValue,
    LoopAnalyzer, LoopInvariant, InductionVariable,
    ExceptionSensitiveDataFlow, ExceptionPath,
    ThreadHappensBeforeAnalyzer, ThreadCreate, LockOperation, HappensBeforeRelation,
    HeapAllocatorStateAnalyzer, HeapBlock,
    ExploitPrimitiveDSL, ExploitPrimitive, PrimitiveType,
    ROPSemanticEquivalenceVerifier, ROPChain, SemanticEquivalenceResult,
    ShellcodeMicrocodeGenerator, Microcode, MicroOp,
    DynamicFormatReverseEngineer, GrammarRule,
    HotReloadAnalysisManager, AnalysisRule,
    SymbolicMergerWithWidening, SymbolicState,
    VMDecompilerAccelerator, VMSchedulerInfo,
    FunctionInlineRecovery, InlineSite,
    CrossBinaryGlobalAnalyzer, GlobalBinding,
    FuzzyCryptoMatcher, CryptoFingerprint,
    SymbolicPointerTracker, PointerInfo,
    RegisterAllocationClassifier, RegisterAllocationPattern,
    DebugInfoRepair, DebugInfoFix,
    HeapFuzzGenerator, HeapOperation,
    HeapSprayAutoCalibrator, HeapSprayCalibration,
    InformationLeakRater, LeakValueType, LeakImpactAssessment,
    SymbolicSummaryCache, FunctionSummary,
    IncrementalAnalysisDatabase,
    MultiTargetAnalysisDatabase, BinaryTarget,
    VulnerabilityContextMinimizer, VulnerabilityContext,
    ShadowStackSimulator, ShadowStackInfo,
    MTEBarrierAnalyzer, MTEBarrier,
    StructArrayBoundsChecker, ArrayAccess,
    KernelUserSharedMemoryChecker, SharedMemoryRegion,
    SyscallPatternMatcher, DangerousSyscallSequence,
    ELFBinaryHardeningAuditor, HardeningFeature,
    PathConvergenceTracker, BasicBlockCoverage,
    ContextSensitiveSummaryGraph, ContextSensitiveSummary,
    FalsePositiveFilter,
    VulnerabilityKnowledgeGraph, VulnerabilityKnowledgeNode, InferenceRule,
    EmbeddedScriptAnalyzer, ScriptExtensionBridge,
    SeccompFilterGenerator,
    SensitiveDataComplianceChecker, DataTag, DataFlowPath,
    CVEAffectedCodeAnalyzer, CVEFootprint,
    FunctionEntropyAnalyzer,
    PasswordBypassSimulator,
    HeapFengShuiRecorder, HeapOperationRecord,
    ASLREntropyEvaluator, ASLREntropyInfo,
    InstructionSemanticClusterer, SemanticCluster,
    KernelObjectReconstructor, KernelObjectSpec,
    DynamicImportResolver, DynamicImportInfo,
    CostBasedPathSelector, PathCost,
    MemoryAccessVisualizationExporter, MemoryAccessEvent,
    MicroBenchmarkFramework, BenchmarkResult,
    AnalysisExchangeFormat,
    VulnerabilityHeatmapTracker, VulnerabilityDensity,
    ExceptionHandlerHijackDetector, ExceptionHijackPoint,
    DelayLoadAnalyzer,
    DecompilerSemanticRewriter, SemanticRewrittenCode,
    AnalysisDatabaseMaintenance,
    SymbolicAntiAnalysisEngine, AntiAnalysisBypass,
    
    # 功能61-120
    ASLREntropyOptimizer,
    BinaryCacheManager,
    SecurityMigrationAdvisor,
    KernelSymbolAssociator,
    IOCTLHandlerAnalyzer,
    ArbitraryWritePrimitivesFinder,
    HeapAllocatorVisualizer,
    ROPChainOptimizer,
    SecurityFeatureDetector,
    IndirectJumpTableParser,
    InlineFunctionRestorer,
    StackFrameReconstructor,
    SEHSecurityAnalyzer,
    ShellcodeValidator,
    PathReachabilityQuery,
    DockerEnvironmentGenerator,
    ExploitEffectVerifier,
    FormatStringExploiter,
    CppExceptionAnalyzer,
    FunctionHeatmapGenerator,
    CryptoPatternMatcher,
    ConditionalBreakpointManager,
    BinaryPatchGenerator,
    IATHookDetector,
    LLMExploitReviewer,
    DataSectionPointerAnalyzer,
    MinimalInputGenerator,
    AntiForensicsDetector,
    DelayedBindingResolver,
    CppObjectGraphGenerator,
    KernelPrimitiveAbstraction,
    OptimizationImpactAnalyzer,
    CrossProcessDataFlowTracker,
    WriteTargetAnalyzer,
    CVEPatternLearner,
    EmbeddedVMDetector,
    CodeImportanceAnalyzer,
    InjectionScriptGenerator,
    DeadCodeAnalyzer,
    NgramBinaryHash,
    IDLGenerator,
    ExceptionInjectionExplorer,
    APIDocumentationGenerator,
    RaceConditionAnalyzer,
    ExecutionSnapshotManager,
    PEBTEBAnalyzer,
    VulnerabilitySignatureGenerator,
    SyscallInterceptor,
    BinaryDiffHeatmap,
    CppComplexTypeRestorer,
    AIStackVariableAnalyzer,
    DecompiledCodeOptimizer,
    ExceptionResourceLeakDetector,
    GDBInfoCollector,
    AlgorithmComplexityAnalyzer,
    MultiLibcEnvironmentSimulator,
    EncryptedConfigExtractor,
    CTFKnowledgeBaseBuilder,
    AnalysisTimeEstimator,
    PrivilegeEscalationDetector,


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
    'ATTCKMapper',
    'AttackTechnique',
    'TargetArch',
    'TargetOS',
    'MITREKnowledgeBase',
    'ExploitCodeGenerator',
    'ExploitPrototype',
    'DetectionRule',
    'MappingResult',
    'create_attck_mapper',
    
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
    'TEEAnalyzer',
    'TEEType',
    'TEEDetector',
    'FunctionExtractor',
    'TrustedFunction',
    'SharedMemoryRegion',
    'InterfaceVulnerability',
    'SideChannelFinding',
    'TEEResult',
    'create_tee_analyzer',

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
    'RandomnessFactor',
    'PredictionResult',
    'EntropyEstimator',
    'MonteCarloSimulator',
    'create_reliability_predictor',
    
    # 多阶段利用链编排模块
    'ChainOrchestrator',
    'ExploitStage',
    'StageCapability',
    'ChainStep',
    'AttackChain',
    'OrchestrationResult',
    'DependencyResolver',
    'ScriptGenerator',
    'create_orchestrator',

    # 高级分析功能模块 (60个新功能)
    # 功能1: 二进制级代码复杂度与风险热点预测
    'ComplexityRiskPredictor',
    'ComplexityFeature',
    'ComplexityFeatureType',

    # 功能2: 跨函数间接调用目标推理
    'IndirectCallResolver',
    'IndirectCallTarget',

    # 功能3: 条件分支反转与路径可达性精化
    'OpaquePredicateAnalyzer',
    'OpaquePredicateType',
    'BranchAnalysisResult',

    # 功能4: 栈变量生命周期精确追踪
    'StackLifetimeTracker',
    'StackVariable',

    # 功能5: 基于数据流方程的常量传播与折叠
    'DataFlowEquationSolver',
    'ConstantValue',

    # 功能6: 循环不变量外提与归纳变量识别
    'LoopAnalyzer',
    'LoopInvariant',
    'InductionVariable',

    # 功能7: 异常敏感的数据流分析
    'ExceptionSensitiveDataFlow',
    'ExceptionPath',

    # 功能8: 多线程程序的静态发生前关系分析
    'ThreadHappensBeforeAnalyzer',
    'ThreadCreate',
    'LockOperation',
    'HappensBeforeRelation',

    # 功能9: 动态内存分配器内部状态解析
    'HeapAllocatorStateAnalyzer',
    'HeapBlock',

    # 功能10: 利用原语能力的形式化描述语言
    'ExploitPrimitiveDSL',
    'ExploitPrimitive',
    'PrimitiveType',

    # 功能11: ROP链的语义等价性验证
    'ROPSemanticEquivalenceVerifier',
    'ROPChain',
    'SemanticEquivalenceResult',

    # 功能12: Shellcode的跨平台微码生成器
    'ShellcodeMicrocodeGenerator',
    'Microcode',
    'MicroOp',

    # 功能13: 基于DSE的输入格式逆向
    'DynamicFormatReverseEngineer',
    'GrammarRule',

    # 功能14: 分析任务的热重载与实时更新
    'HotReloadAnalysisManager',
    'AnalysisRule',

    # 功能15: 符号状态合并与抽象解释加速
    'SymbolicMergerWithWidening',
    'SymbolicState',

    # 功能16: 面向虚拟化的反编译加速
    'VMDecompilerAccelerator',
    'VMSchedulerInfo',

    # 功能17: 函数内联与外联的智能恢复
    'FunctionInlineRecovery',
    'InlineSite',

    # 功能18: 跨二进制的全局变量绑定关系分析
    'CrossBinaryGlobalAnalyzer',
    'GlobalBinding',

    # 功能19: 加密常量的模糊指纹匹配
    'FuzzyCryptoMatcher',
    'CryptoFingerprint',

    # 功能20: 符号指针的标记与追踪
    'SymbolicPointerTracker',
    'PointerInfo',

    # 功能21: 基于机器学习的寄存器分配模式识别
    'RegisterAllocationClassifier',
    'RegisterAllocationPattern',

    # 功能22: DWARF/PDB调试信息自动修复与补全
    'DebugInfoRepair',
    'DebugInfoFix',

    # 功能23: 堆分配序列的模糊测试
    'HeapFuzzGenerator',
    'HeapOperation',

    # 功能24: 利用稳定性增强的"堆喷射"自动校准
    'HeapSprayAutoCalibrator',
    'HeapSprayCalibration',

    # 功能25: 信息泄露漏洞的定量评级
    'InformationLeakRater',
    'LeakValueType',
    'LeakImpactAssessment',

    # 功能26: 自动化的符号摘要缓存
    'SymbolicSummaryCache',
    'FunctionSummary',

    # 功能27: 分析结果的增量更新机制
    'IncrementalAnalysisDatabase',

    # 功能28: 多目标关联分析数据库
    'MultiTargetAnalysisDatabase',
    'BinaryTarget',

    # 功能29: 漏洞路径的最小化上下文提取
    'VulnerabilityContextMinimizer',
    'VulnerabilityContext',

    # 功能30: 影子栈模拟检测ROP攻击面
    'ShadowStackSimulator',
    'ShadowStackInfo',

    # 功能31: 针对内存标签扩展（MTE）的利用障碍分析
    'MTEBarrierAnalyzer',
    'MTEBarrier',

    # 功能32: 结构体数组内的索引越界检测
    'StructArrayBoundsChecker',
    'ArrayAccess',

    # 功能33: 内核与用户态共享内存的边界检查
    'KernelUserSharedMemoryChecker',
    'SharedMemoryRegion',

    # 功能34: 系统调用序列的模板化漏洞模式
    'SyscallPatternMatcher',
    'DangerousSyscallSequence',

    # 功能35: ELF构造加固评估器
    'ELFBinaryHardeningAuditor',
    'HardeningFeature',

    # 功能36: 运行时路径汇聚统计
    'PathConvergenceTracker',
    'BasicBlockCoverage',

    # 功能37: 上下文敏感的函数摘要图
    'ContextSensitiveSummaryGraph',
    'ContextSensitiveSummary',

    # 功能38: 基于出现概率的误报过滤
    'FalsePositiveFilter',

    # 功能39: 本地化的漏洞知识图谱推理
    'VulnerabilityKnowledgeGraph',
    'VulnerabilityKnowledgeNode',
    'InferenceRule',

    # 功能40: 针对脚本语言扩展的二进制分析
    'EmbeddedScriptAnalyzer',
    'ScriptExtensionBridge',

    # 功能41: 系统调用过滤规则自动推断
    'SeccompFilterGenerator',

    # 功能42: 敏感数据使用合规检查
    'SensitiveDataComplianceChecker',
    'DataTag',
    'DataFlowPath',

    # 功能43: 自动化CVE影响范围分析
    'CVEAffectedCodeAnalyzer',
    'CVEFootprint',

    # 功能44: 函数级别的熵分析
    'FunctionEntropyAnalyzer',

    # 功能45: 基于模拟的解锁密码暴力测试
    'PasswordBypassSimulator',

    # 功能46: 堆风水操作的录制与回放
    'HeapFengShuiRecorder',
    'HeapOperationRecord',

    # 功能47: 细粒度的ASLR熵评估
    'ASLREntropyEvaluator',
    'ASLREntropyInfo',

    # 功能48: 指令序列的语义聚类
    'InstructionSemanticClusterer',
    'SemanticCluster',

    # 功能49: 内核对象结构自动重建
    'KernelObjectReconstructor',
    'KernelObjectSpec',

    # 功能50: 动态导入表解析与API模糊匹配
    'DynamicImportResolver',
    'DynamicImportInfo',

    # 功能51: 基于执行成本的路径选择
    'CostBasedPathSelector',
    'PathCost',

    # 功能52: 内存访问模式的可视化数据导出
    'MemoryAccessVisualizationExporter',
    'MemoryAccessEvent',

    # 功能53: 分析模块的微基准测试框架
    'MicroBenchmarkFramework',
    'BenchmarkResult',

    # 功能54: 插件分析结果的标准交换格式
    'AnalysisExchangeFormat',

    # 功能55: 二进制生存周期内的漏洞热力演变
    'VulnerabilityHeatmapTracker',
    'VulnerabilityDensity',

    # 功能56: 基于异常处理的控制流劫持检测
    'ExceptionHandlerHijackDetector',
    'ExceptionHijackPoint',

    # 功能57: 延迟加载模块的静态预分析
    'DelayLoadAnalyzer',

    # 功能58: 反编译代码的语义等价重写
    'DecompilerSemanticRewriter',
    'SemanticRewrittenCode',

    # 功能59: 分析数据库的自动维护与压缩
    'AnalysisDatabaseMaintenance',

    # 功能60: 基于符号执行的反反分析引擎
    'SymbolicAntiAnalysisEngine',
    'AntiAnalysisBypass',

    # 功能61: 自动化利用ASLR熵源分析与信息泄露组合优化
    'ASLREntropyOptimizer',

    # 功能62: 基于缓存的二进制加载加速
    'BinaryCacheManager',

    # 功能63: 安全机制配置自动化迁移
    'SecurityMigrationAdvisor',

    # 功能64: 内核模块符号自动关联与vmlinux匹配
    'KernelSymbolAssociator',

    # 功能65: 驱动IOCTL处理函数自动发现与参数建模
    'IOCTLHandlerAnalyzer',

    # 功能66: 基于符号执行的任意写原语自动定位
    'ArbitraryWritePrimitivesFinder',

    # 功能67: 堆分配器内部状态可视化
    'HeapAllocatorVisualizer',

    # 功能68: ROP链自动优化与长度压缩
    'ROPChainOptimizer',

    # 功能69: 安全特性版本感知
    'SecurityFeatureDetector',

    # 功能70: 间接跳转表自动化解析
    'IndirectJumpTableParser',

    # 功能71: 内联函数自动还原与边界标识
    'InlineFunctionRestorer',

    # 功能72: 基于变量访问模式的栈帧布局重建
    'StackFrameReconstructor',

    # 功能73: 异常处理安全机制分析（SafeSEH/SEHOP）
    'SEHSecurityAnalyzer',

    # 功能74: 多架构shellcode自动验证平台
    'ShellcodeValidator',

    # 功能75: 基于符号执行的路径可达性查询
    'PathReachabilityQuery',

    # 功能76: 二进制运行时环境自动生成（Dockerfile）
    'DockerEnvironmentGenerator',

    # 功能77: 自动利用效果展示（弹出计算器/反弹shell验证）
    'ExploitEffectVerifier',

    # 功能78: 格式化字符串写原语自动化利用
    'FormatStringExploiter',

    # 功能79: C++异常处理（Exception Handling）检测
    'CppExceptionAnalyzer',

    # 功能80: 基于执行计数的函数热力图生成
    'FunctionHeatmapGenerator',

    # 功能81: 自动识别加密算法的模式匹配优化
    'CryptoPatternMatcher',

    # 功能82: 复杂条件断点自动设置
    'ConditionalBreakpointManager',

    # 功能83: 二进制补丁自动反向生成
    'BinaryPatchGenerator',

    # 功能84: IAT钩子检测与恢复
    'IATHookDetector',

    # 功能85: 基于LLM的漏洞利用代码自动审查
    'LLMExploitReviewer',

    # 功能86: 静态数据段指针污染分析
    'DataSectionPointerAnalyzer',

    # 功能87: 基于约束求解的最小化漏洞触发输入
    'MinimalInputGenerator',

    # 功能88: 自动分析二进制中的抗内存取证技术
    'AntiForensicsDetector',

    # 功能89: 延迟绑定符号解析与利用
    'DelayedBindingResolver',

    # 功能90: 基于RTTI的C++对象实例关系图生成
    'CppObjectGraphGenerator',

    # 功能91: 内核漏洞利用原语自动抽象
    'KernelPrimitiveAbstraction',

    # 功能92: 编译优化选项对代码逻辑影响的变更摘要
    'OptimizationImpactAnalyzer',

    # 功能93: 基于共享内存的跨进程数据流追踪
    'CrossProcessDataFlowTracker',

    # 功能94: 自动搜索漏洞利用的"写何处"目标
    'WriteTargetAnalyzer',

    # 功能95: 基于历史CVE的漏洞特征化模板学习
    'CVEPatternLearner',

    # 功能96: 二进制内嵌虚拟机/解释器检测与分离
    'EmbeddedVMDetector',

    # 功能97: 基于活跃度分析的代码重要性排序
    'CodeImportanceAnalyzer',

    # 功能98: 自动化ELF/PE注入脚本生成
    'InjectionScriptGenerator',

    # 功能99: 自动分析二进制中"死亡代码"中的隐藏功能
    'DeadCodeAnalyzer',

    # 功能100: 基于N-gram的二进制相似度快速哈希
    'NgramBinaryHash',

    # 功能101: 接口描述语言（IDL）自动生成
    'IDLGenerator',

    # 功能102: 基于异常注入的错误处理路径探索
    'ExceptionInjectionExplorer',

    # 功能103: 自动生成二进制文档中的API参考
    'APIDocumentationGenerator',

    # 功能104: 多线程竞争窗口自动扩大
    'RaceConditionAnalyzer',

    # 功能105: 基于执行快照的漏洞快速重现
    'ExecutionSnapshotManager',

    # 功能106: Windows PEB/TEB关键字段自动提取
    'PEBTEBAnalyzer',

    # 功能107: 基于符号执行的自动漏洞签名生成
    'VulnerabilitySignatureGenerator',

    # 功能108: 系统调用拦截与参数模糊化
    'SyscallInterceptor',

    # 功能109: 二进制差异热图
    'BinaryDiffHeatmap',

    # 功能110: 自动恢复C++的std::string等复杂类型操作
    'CppComplexTypeRestorer',

    # 功能111: 基于AI的栈帧变量用途推断
    'AIStackVariableAnalyzer',

    # 功能112: 反编译代码自动重排与简化
    'DecompiledCodeOptimizer',

    # 功能113: 异常处理函数中资源泄漏自动检测
    'ExceptionResourceLeakDetector',

    # 功能114: 基于GDB脚本的自动化调试信息收集
    'GDBInfoCollector',

    # 功能115: 二进制中的算法复杂度攻击面检测
    'AlgorithmComplexityAnalyzer',

    # 功能116: 多版本库共存环境模拟
    'MultiLibcEnvironmentSimulator',

    # 功能117: 自动提取二进制中用于反分析的加密配置解密逻辑
    'EncryptedConfigExtractor',

    # 功能118: 基于CTF比赛的漏洞利用知识库构建
    'CTFKnowledgeBaseBuilder',

    # 功能119: 二进制分析时间预估模型
    'AnalysisTimeEstimator',

    # 功能120: 基于符号执行的自动越权检测
    'PrivilegeEscalationDetector',
]

# 新增分析模块 (60个功能扩展)
from .indirect_jump_recovery import ()
    IndirectJumpRecovery,
    JumpTable,
    SwitchStructure,
    RecoveryResult,
    create_indirect_jump_recovery


from .cpp_exception_recovery import ()
    ExceptionRecovery,
    LSDARecord,
    TryBlock,
    CatchBlock,
    ExceptionFrame,
    RecoveryResult as ExceptionRecoveryResult,
    create_exception_recovery


from .library_tracing import ()
    LibraryTracer,
    LibraryFingerprintMatcher,
    LibraryFunction,
    FingerprintMatch,
    TracingResult,
    create_library_tracer


from .tls_callback_detector import ()
    TLSCallbackDetector,
    TLSCallback,
    DetectionResult,
    create_tls_detector


from .dead_code_analysis import ()
    DeadCodeAnalyzer,
    DeadCodeRegion,
    AnalysisResult as DeadCodeAnalysisResult,
    create_dead_code_analyzer


from .self_modifying_code import ()
    SMCExecutor,
    SMCRecord,
    ExecutionResult as SMCExecutionResult,
    create_smc_executor


from .blackbox_vm_reverse import ()
    BlackboxVMReverser,
    VirtualInstruction,
    VMReverseResult,
    create_blackbox_vm_reverser


from .recursive_devirtualization import ()
    RecursiveDevirtualizer,
    VirtualizationLayer,
    DevirtualizationResult,
    create_recursive_devirtualizer


from .protocol_state_inconsistency import ()
    ProtocolStateAnalyzer,
    StateTransition,
    InconsistencyResult,
    create_protocol_state_analyzer


from .privilege_race_learner import ()
    PrivilegeRaceLearner,
    PrivilegeEscalationPath,
    LearningResult,
    create_privilege_race_learner


from .fault_injection_fuzzer import ()
    FaultInjectionFuzzer,
    FaultInjectionPoint,
    FaultResult,
    create_fault_injection_fuzzer


from .fault_tolerance_analyzer import ()
    FaultToleranceAnalyzer,
    FaultToleranceVulnerability,
    AnalysisResult as FaultToleranceAnalysisResult,
    create_fault_tolerance_analyzer


from .database_extension_analyzer import ()
    DatabaseExtensionAnalyzer,
    SQLInjectionPoint,
    DBResult,
    create_database_extension_analyzer


from .microarch_side_channel_validator import ()
    MicroarchSideChannelValidator,
    SideChannelEvidence,
    VerificationResult,
    create_microarch_validator


from .attack_tree_generator import ()
    AttackTreeGenerator,
    AttackNode,
    AttackTreeResult,
    create_attack_tree_generator


from .memory_corruption_pathfinder import ()
    MemoryCorruptionPathfinder,
    ExploitStep,
    PathResult,
    create_memory_corruption_pathfinder


from .cache_side_channel_key_recovery import ()
    CacheSideChannelKeyRecovery,
    KeyRecoveryResult,
    create_cache_key_recovery


# 更新 __all__ 添加新模块导出
__all__.extend([)
    # 间接跳转表恢复
    'IndirectJumpRecovery',
    'JumpTable',
    'SwitchStructure',
    'RecoveryResult',
    'create_indirect_jump_recovery',
    
    # C++异常处理恢复
    'ExceptionRecovery',
    'LSDARecord',
    'TryBlock',
    'CatchBlock',
    'ExceptionFrame',
    'ExceptionRecoveryResult',
    'create_exception_recovery',
    
    # 第三方库函数级溯源
    'LibraryTracer',
    'LibraryFingerprintMatcher',
    'LibraryFunction',
    'FingerprintMatch',
    'TracingResult',
    'create_library_tracer',
    
    # TLS回调隐蔽入口发现
    'TLSCallbackDetector',
    'TLSCallback',
    'DetectionResult',
    'create_tls_detector',
    
    # 死代码可达性分析
    'DeadCodeAnalyzer',
    'DeadCodeRegion',
    'DeadCodeAnalysisResult',
    'create_dead_code_analyzer',
    
    # 自修改代码透明执行器
    'SMCExecutor',
    'SMCRecord',
    'SMCExecutionResult',
    'create_smc_executor',
    
    # 黑盒等价性VM逆向
    'BlackboxVMReverser',
    'VirtualInstruction',
    'VMReverseResult',
    'create_blackbox_vm_reverser',
    
    # 递归多虚拟化层拆解
    'RecursiveDevirtualizer',
    'VirtualizationLayer',
    'DevirtualizationResult',
    'create_recursive_devirtualizer',
    
    # 协议状态机不一致检测
    'ProtocolStateAnalyzer',
    'StateTransition',
    'InconsistencyResult',
    'create_protocol_state_analyzer',
    
    # 权限/资源竞争自动学习
    'PrivilegeRaceLearner',
    'PrivilegeEscalationPath',
    'LearningResult',
    'create_privilege_race_learner',
    
    # 故障注入漏洞挖掘
    'FaultInjectionFuzzer',
    'FaultInjectionPoint',
    'FaultResult',
    'create_fault_injection_fuzzer',
    
    # 容错机制漏洞分析
    'FaultToleranceAnalyzer',
    'FaultToleranceVulnerability',
    'FaultToleranceAnalysisResult',
    'create_fault_tolerance_analyzer',
    
    # 数据库扩展二进制漏洞分析
    'DatabaseExtensionAnalyzer',
    'SQLInjectionPoint',
    'DBResult',
    'create_database_extension_analyzer',
    
    # 微架构侧信道验证
    'MicroarchSideChannelValidator',
    'SideChannelEvidence',
    'VerificationResult',
    'create_microarch_validator',
    
    # 攻击树自动生成与量化
    'AttackTreeGenerator',
    'AttackNode',
    'AttackTreeResult',
    'create_attack_tree_generator',
    
    # 内存损坏到任意读写路径搜索
    'MemoryCorruptionPathfinder',
    'ExploitStep',
    'PathResult',
    'create_memory_corruption_pathfinder',
    
    # 缓存侧信道密钥恢复
    'CacheSideChannelKeyRecovery',
    'KeyRecoveryResult',
    'create_cache_key_recovery',
]

# 新增漏洞分析功能模块 (60个新功能)
from .exploitability_scorer import ()
    ExploitabilityScorer,
    ExploitabilityLevel,
    ProtectionMechanism,
    ProtectionStatus,
    VulnerabilityContext,
    ExploitabilityScore,
    calculate_exploitability_score


from .vulnerability_reporter import ()
    VulnerabilityReporter,
    ReportPlatform,
    ReportSeverity,
    VulnerabilityReport,
    SubmissionResult,
    create_vulnerability_report,
    export_report_to_file


from .fuzz_coverage_visualizer import ()
    FuzzCoverageVisualizer,
    CoverageType,
    CoverageData,
    HeatmapCell,
    CoverageVisualization,
    generate_coverage_heatmap_api


from .vuln_deduplicator import ()
    VulnDeduplicator,
    DeduplicationStrategy,
    ClusterSimilarity,
    VulnerabilitySignature,
    VulnerabilityCluster,
    DeduplicationResult,
    deduplicate_vulnerabilities


from .crash_classifier import ()
    CrashClassifier,
    CrashType,
    ExploitPrimitive,
    CrashAnalysisResult,
    ExploitPrototype,
    analyze_crash,
    generate_exploit_from_crash


from .semantic_diff_analyzer import ()
    SemanticDiffAnalyzer,
    ChangeType,
    SemanticChangeCategory,
    FunctionSignature,
    SemanticChange,
    SemanticDiffResult,
    analyze_semantic_diff


from .patch_quality_evaluator import ()
    PatchQualityEvaluator,
    PatchStatus,
    BypassRisk,
    PatchAssessment,
    evaluate_patch


from .sandbox_escape_detector import ()
    SandboxEscapeDetector,
    EscapeAttemptType,
    EscapeSeverity,
    EscapeAttempt,
    SandboxMonitoringResult,
    detect_sandbox_escape


from .kernel_integrity_monitor import ()
    KernelIntegrityMonitor,
    IntegrityStatus,
    TamperingType,
    IntegrityViolation,
    IntegrityCheckResult,
    monitor_kernel_integrity


from .distributed_vector_search import ()
    DistributedVectorSearch,
    IndexType,
    SearchResult,
    IndexStats,
    create_vector_search


from .unified_ir_converter import ()
    UnifiedIRConverter,
    Architecture,
    IROpcode,
    IRInstruction,
    IRFunction,
    IRModule,
    convert_to_ir


from .memory_primitive_extractor import ()
    MemoryPrimitiveExtractor,
    PrimitiveType,
    MemoryPrimitive,
    ExtractionResult,
    extract_memory_primitives


from .call_stack_reconstructor import ()
    CallStackReconstructor,
    FrameType,
    StackFrame,
    CallStack,
    reconstruct_call_stack


from .code_style_identifier import ()
    CodeStyleIdentifier,
    AuthorCategory,
    CodeStyle,
    StyleAnalysisResult,
    identify_code_style


from .anti_anti_debug import ()
    AntiAntiDebug,
    DebuggerType,
    AntiDebugTechnique,
    DetectionResult,
    AntiDebugResult,
    bypass_anti_debug


from .hardware_trace_analyzer import ()
    HardwareTraceAnalyzer,
    TraceType,
    TracePacket,
    ExecutionPath,
    TraceAnalysisResult,
    analyze_hardware_trace


from .cfi_integrity_analyzer import ()
    CFIIntegrityAnalyzer,
    CFIStatus,
    CFIType,
    CFIProtection,
    CFIViolation,
    CFIIntegrityResult,
    analyze_cfi_integrity


from .supply_chain_vulnerability_monitor import ()
    SupplyChainVulnerabilityMonitor,
    VulnerabilitySource,
    Severity,
    ComponentVulnerability,
    MonitorResult,
    monitor_supply_chain


from .syscall_dependency_graph import ()
    SyscallDependencyGraph,
    SyscallCategory,
    SyscallNode,
    DependencyGraph,
    build_syscall_dependency_graph


from .kernel_sync_detector import ()
    KernelSyncDetector,
    SyncIssueType,
    SyncIssue,
    SyncAnalysisResult,
    detect_kernel_sync_issues


from .gdb_script_generator import ()
    GdbScriptGenerator,
    ScriptType,
    GDBBreakpoint,
    GDBWatchpoint,
    GDBScript,
    generate_gdb_script


from .ebpf_dynamic_tracer import ()
    EbpfDynamicTracer,
    TracePoint,
    eBPFProgram,
    TraceData,
    TraceResult,
    create_ebpf_programs


from .container_vuln_locator import ()
    ContainerVulnLocator,
    VulnSource,
    LayerInfo,
    VulnLocation,
    ContainerScanResult,
    locate_container_vulnerabilities


from .opa_policy_generator import ()
    OPAPolicyGenerator,
    PolicyType,
    PolicyRule,
    OPAPolicy,
    generate_opa_policy


from .exploit_template_library import ()
    ExploitTemplateLibrary,
    TemplateType,
    ExploitTemplate,
    TemplateMatch,
    get_exploit_templates


from .gnn_vulnerability_detector import ()
    GNNVulnerabilityDetector,
    VulnerabilityPattern,
    GraphNode,
    GraphEdge,
    GNNResult,
    detect_vulnerabilities_with_gnn


from .function_behavior_classifier import ()
    FunctionBehaviorClassifier,
    BehaviorCategory,
    FunctionBehavior,
    ClassificationResult,
    classify_function_behavior


from .privacy_compliance_auditor import ()
    PrivacyComplianceAuditor,
    ComplianceFramework,
    DataCategory,
    DataFinding,
    ComplianceResult,
    audit_privacy_compliance


from .multi_dimension_stats_api import ()
    MultiDimensionStatsAPI,
    StatisticType,
    VulnerabilityDistribution,
    HighRiskFunction,
    SeverityTrend,
    AnalysisMetrics,
    APIResponse,
    get_statistics


from .zeroday_anomaly_detector import ()
    ZeroDayAnomalyDetector,
    AnomalySeverity,
    ChangeType,
    AnomalyFinding,
    ZeroDayResult,
    detect_zeroday_anomalies


from .dangerous_function_analyzer import ()
    DangerousFunctionAnalyzer,
    RiskLevel,
    DangerousFunction,
    ParameterAnalysis,
    FunctionAnalysis,
    AnalysisResult,
    analyze_dangerous_functions


from .memory_sensitive_op_detector import ()
    MemorySensitiveOpDetector,
    OperationType,
    RiskLevel as MemoryRiskLevel,
    SensitiveOperation,
    DetectionResult as MemoryDetectionResult,
    detect_memory_sensitive_operations


from .test_orchestrator import ()
    TestOrchestrator,
    TaskType,
    TaskStatus,
    TestTask,
    WorkflowResult,
    create_test_workflow


# 更新 __all__ 添加新模块导出
__all__.extend([)
    # 漏洞利用性评分模块
    'ExploitabilityScorer',
    'ExploitabilityLevel',
    'ProtectionMechanism',
    'ProtectionStatus',
    'VulnerabilityContext',
    'ExploitabilityScore',
    'calculate_exploitability_score',
    
    # 漏洞提交平台集成模块
    'VulnerabilityReporter',
    'ReportPlatform',
    'ReportSeverity',
    'VulnerabilityReport',
    'SubmissionResult',
    'create_vulnerability_report',
    'export_report_to_file',
    
    # 模糊测试覆盖率可视化模块
    'FuzzCoverageVisualizer',
    'CoverageType',
    'CoverageData',
    'HeatmapCell',
    'CoverageVisualization',
    'generate_coverage_heatmap_api',
    
    # 漏洞去重模块
    'VulnDeduplicator',
    'DeduplicationStrategy',
    'ClusterSimilarity',
    'VulnerabilitySignature',
    'VulnerabilityCluster',
    'DeduplicationResult',
    'deduplicate_vulnerabilities',
    
    # 崩溃分类与利用原型生成模块
    'CrashClassifier',
    'CrashType',
    'ExploitPrimitive',
    'CrashAnalysisResult',
    'ExploitPrototype',
    'analyze_crash',
    'generate_exploit_from_crash',
    
    # 二进制语义差异分析模块
    'SemanticDiffAnalyzer',
    'ChangeType',
    'SemanticChangeCategory',
    'FunctionSignature',
    'SemanticChange',
    'SemanticDiffResult',
    'analyze_semantic_diff',
    
    # 补丁质量评估模块
    'PatchQualityEvaluator',
    'PatchStatus',
    'BypassRisk',
    'PatchAssessment',
    'evaluate_patch',
    
    # 沙箱逃逸检测模块
    'SandboxEscapeDetector',
    'EscapeAttemptType',
    'EscapeSeverity',
    'EscapeAttempt',
    'SandboxMonitoringResult',
    'detect_sandbox_escape',
    
    # 内核完整性监控模块
    'KernelIntegrityMonitor',
    'IntegrityStatus',
    'TamperingType',
    'IntegrityViolation',
    'IntegrityCheckResult',
    'monitor_kernel_integrity',
    
    # 分布式向量搜索优化模块
    'DistributedVectorSearch',
    'IndexType',
    'SearchResult',
    'IndexStats',
    'create_vector_search',
    
    # 统一中间表示IR转换模块
    'UnifiedIRConverter',
    'Architecture',
    'IROpcode',
    'IRInstruction',
    'IRFunction',
    'IRModule',
    'convert_to_ir',
    
    # 内存原语自动提取模块
    'MemoryPrimitiveExtractor',
    'PrimitiveType',
    'MemoryPrimitive',
    'ExtractionResult',
    'extract_memory_primitives',
    
    # 调用栈回溯重建模块
    'CallStackReconstructor',
    'FrameType',
    'StackFrame',
    'CallStack',
    'reconstruct_call_stack',
    
    # 代码风格识别模块
    'CodeStyleIdentifier',
    'AuthorCategory',
    'CodeStyle',
    'StyleAnalysisResult',
    'identify_code_style',
    
    # 反反调试对抗模块
    'AntiAntiDebug',
    'DebuggerType',
    'AntiDebugTechnique',
    'DetectionResult',
    'AntiDebugResult',
    'bypass_anti_debug',
    
    # 硬件追踪分析模块
    'HardwareTraceAnalyzer',
    'TraceType',
    'TracePacket',
    'ExecutionPath',
    'TraceAnalysisResult',
    'analyze_hardware_trace',
    
    # CFI完整性分析模块
    'CFIIntegrityAnalyzer',
    'CFIStatus',
    'CFIType',
    'CFIProtection',
    'CFIViolation',
    'CFIIntegrityResult',
    'analyze_cfi_integrity',
    
    # 供应链漏洞监控模块
    'SupplyChainVulnerabilityMonitor',
    'VulnerabilitySource',
    'Severity',
    'ComponentVulnerability',
    'MonitorResult',
    'monitor_supply_chain',
    
    # 系统调用依赖图模块
    'SyscallDependencyGraph',
    'SyscallCategory',
    'SyscallNode',
    'DependencyGraph',
    'build_syscall_dependency_graph',
    
    # 内核同步检测模块
    'KernelSyncDetector',
    'SyncIssueType',
    'SyncIssue',
    'SyncAnalysisResult',
    'detect_kernel_sync_issues',
    
    # GDB调试脚本生成模块
    'GdbScriptGenerator',
    'ScriptType',
    'GDBBreakpoint',
    'GDBWatchpoint',
    'GDBScript',
    'generate_gdb_script',
    
    # eBPF动态追踪模块
    'EbpfDynamicTracer',
    'TracePoint',
    'eBPFProgram',
    'TraceData',
    'TraceResult',
    'create_ebpf_programs',
    
    # 容器漏洞定位模块
    'ContainerVulnLocator',
    'VulnSource',
    'LayerInfo',
    'VulnLocation',
    'ContainerScanResult',
    'locate_container_vulnerabilities',
    
    # OPA策略生成模块
    'OPAPolicyGenerator',
    'PolicyType',
    'PolicyRule',
    'OPAPolicy',
    'generate_opa_policy',
    
    # 漏洞利用模板库模块
    'ExploitTemplateLibrary',
    'TemplateType',
    'ExploitTemplate',
    'TemplateMatch',
    'get_exploit_templates',
    
    # GNN漏洞检测模块
    'GNNVulnerabilityDetector',
    'VulnerabilityPattern',
    'GraphNode',
    'GraphEdge',
    'GNNResult',
    'detect_vulnerabilities_with_gnn',
    
    # 函数行为分类模块
    'FunctionBehaviorClassifier',
    'BehaviorCategory',
    'FunctionBehavior',
    'ClassificationResult',
    'classify_function_behavior',
    
    # 隐私合规审计模块
    'PrivacyComplianceAuditor',
    'ComplianceFramework',
    'DataCategory',
    'DataFinding',
    'ComplianceResult',
    'audit_privacy_compliance',
    
    # 多维统计API模块
    'MultiDimensionStatsAPI',
    'StatisticType',
    'VulnerabilityDistribution',
    'HighRiskFunction',
    'SeverityTrend',
    'AnalysisMetrics',
    'APIResponse',
    'get_statistics',
    
    # 0-day差异预警模块
    'ZeroDayAnomalyDetector',
    'AnomalySeverity',
    'ChangeType',
    'AnomalyFinding',
    'ZeroDayResult',
    'detect_zeroday_anomalies',
    
    # 危险函数参数分析模块
    'DangerousFunctionAnalyzer',
    'RiskLevel',
    'DangerousFunction',
    'ParameterAnalysis',
    'FunctionAnalysis',
    'AnalysisResult',
    'analyze_dangerous_functions',
    
    # 内存敏感操作识别模块
    'MemorySensitiveOpDetector',
    'OperationType',
    'MemoryRiskLevel',
    'SensitiveOperation',
    'MemoryDetectionResult',
    'detect_memory_sensitive_operations',
    
    # 测试编排模块
    'TestOrchestrator',
    'TaskType',
    'TaskStatus',
    'TestTask',
    'WorkflowResult',
    'create_test_workflow',
]

# 保留旧版兼容性别名
ConfigMgr = ConfigManager
ResourceCtrl = ResourceController
ErrHandler = ErrorHandler
TaskSched = TaskScheduler