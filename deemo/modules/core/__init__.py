# 核心模块入口: 导出hooks接口, 按需延迟加载compat子模块
from modules.core.hooks import get_hook_manager, HookManager, HOOK_POINTS, run_hook

# 按名惰性解析: 首次访问时import对应子模块, 分摊初始化成本
_LAZY_EXPORTS = {
    'SubRegTaintState': ('modules.core.compat.subreg_taint', 'SubRegTaintState'),
    'propagate_subreg': ('modules.core.compat.subreg_taint', 'propagate_subreg'),
    'DriftCalibrator': ('modules.core.compat.drift_calibrator', 'DriftCalibrator'),
    'WeightImportanceTracker': ('modules.core.compat.drift_calibrator', 'WeightImportanceTracker'),
    'cfg_entropy_fingerprint': ('modules.core.compat.cfg_entropy_fingerprint', 'cfg_entropy_fingerprint'),
    'fingerprint_similarity': ('modules.core.compat.cfg_entropy_fingerprint', 'fingerprint_similarity'),
    # 溯源与预测增强
    'ContextVersionStore': ('modules.core.context_versioning', 'ContextVersionStore'),
    'ContextVersion': ('modules.core.context_versioning', 'ContextVersion'),
    'ProvenanceGraph': ('modules.core.provenance_tracker', 'ProvenanceGraph'),
    'ProvenanceScheduler': ('modules.core.provenance_tracker', 'ProvenanceScheduler'),
    'TaskPredictor': ('modules.core.task_predictor', 'TaskPredictor'),
    'PredictionGuidedScheduler': ('modules.core.task_predictor', 'PredictionGuidedScheduler'),
    'AdaptivePool': ('modules.core.adaptive_pool', 'AdaptivePool'),
    'ProbCondition': ('modules.core.prob_condition', 'ProbCondition'),
    'ProbConditionModel': ('modules.core.prob_condition', 'ProbConditionModel'),
    'RewardEstimator': ('modules.core.prob_condition', 'RewardEstimator'),
    # 漂移检测与优雅降级
    'StreamingSketch': ('modules.core.execution_sketch', 'StreamingSketch'),
    'MetricSketchGroup': ('modules.core.execution_sketch', 'MetricSketchGroup'),
    'DriftDetector': ('modules.core.drift_detector', 'DriftDetector'),
    'PipelineDriftMonitor': ('modules.core.drift_detector', 'PipelineDriftMonitor'),
    'DriftSeverity': ('modules.core.drift_detector', 'DriftSeverity'),
    'CriticalPathAnalyzer': ('modules.core.critical_path', 'CriticalPathAnalyzer'),
    'BackpressureSensor': ('modules.core.critical_path', 'BackpressureSensor'),
    'GracefulDegradationExecutor': ('modules.core.critical_path', 'GracefulDegradationExecutor'),
    # 异常检测 / 双模预测 / 层级收缩
    'PipelineAnomalyMonitor': ('modules.core.pipe_anomaly', 'PipelineAnomalyMonitor'),
    'HookAnomalyDetector': ('modules.core.pipe_anomaly', 'HookAnomalyDetector'),
    'BimodalPredictor': ('modules.core.bimodal_predictor', 'BimodalPredictor'),
    'EnsemblePredictor': ('modules.core.bimodal_predictor', 'EnsemblePredictor'),
    'ShrinkageEstimator': ('modules.core.hierarchical_belief', 'ShrinkageEstimator'),
    'HierarchicalProbCondition': ('modules.core.hierarchical_belief', 'HierarchicalProbCondition'),
    'ShrunkBelief': ('modules.core.hierarchical_belief', 'ShrunkBelief'),
    # 增量执行与断点续传
    'DiffExecutor': ('modules.core.diff_executor', 'DiffExecutor'),
    'IncrementalCacheStore': ('modules.core.diff_executor', 'IncrementalCacheStore'),
    'CheckpointManager': ('modules.core.checkpoint_manager', 'CheckpointManager'),
    'CheckpointManifest': ('modules.core.checkpoint_manager', 'CheckpointManifest'),
    # 模式推断与 DAG 验证
    'SchemaModel': ('modules.core.schema_inference', 'SchemaModel'),
    'DAGVerifier': ('modules.core.schema_inference', 'DAGVerifier'),
    'HookSignature': ('modules.core.schema_inference', 'HookSignature'),
    # 键生命周期管理
    'KeyLifetimeAnalyzer': ('modules.core.key_lifetime', 'KeyLifetimeAnalyzer'),
    'KeyEvictionManager': ('modules.core.key_lifetime', 'KeyEvictionManager'),
    'KeyLifetime': ('modules.core.key_lifetime', 'KeyLifetime'),
    # 时间预算执行
    'BudgetSelector': ('modules.core.time_budget', 'BudgetSelector'),
    'TimeBudgetExecutor': ('modules.core.time_budget', 'TimeBudgetExecutor'),
    'BudgetPlan': ('modules.core.time_budget', 'BudgetPlan'),
    # 多管道 DAG 融合
    'DAGFusionDetector': ('modules.core.dag_fusion', 'DAGFusionDetector'),
    'FusedExecutor': ('modules.core.dag_fusion', 'FusedExecutor'),
    'FusionPlan': ('modules.core.dag_fusion', 'FusionPlan'),
    # 管道自动合成
    'PipelineSynthesizer': ('modules.core.pipeline_synth', 'PipelineSynthesizer'),
    'SynthesizedPipeline': ('modules.core.pipeline_synth', 'SynthesizedPipeline'),
    # 钩子自适应重试
    'RetryPolicy': ('modules.core.hook_retry', 'RetryPolicy'),
    'HookRetryWrapper': ('modules.core.hook_retry', 'HookRetryWrapper'),
    'RetryScheduler': ('modules.core.hook_retry', 'RetryScheduler'),
    'FailurePatternDB': ('modules.core.hook_retry', 'FailurePatternDB'),
    'degrade_reduce_depth': ('modules.core.hook_retry', 'degrade_reduce_depth'),
    # 推测性分叉-汇合执行
    'SpecExecutor': ('modules.core.spec_exec', 'SpecExecutor'),
    'SpecPath': ('modules.core.spec_exec', 'SpecPath'),
    'QualityScorer': ('modules.core.spec_exec', 'QualityScorer'),
    # 贝叶斯优化参数调优
    'BayesOptimizer': ('modules.core.bayes_opt', 'BayesOptimizer'),
    'ParamDef': ('modules.core.bayes_opt', 'ParamDef'),
    'Trial': ('modules.core.bayes_opt', 'Trial'),
    # 智能管道入口
    'SmartPipeline': ('modules.core.smart_pipeline', 'SmartPipeline'),
    'BinaryProfile': ('modules.core.smart_pipeline', 'BinaryProfile'),
    'PipelineResult': ('modules.core.smart_pipeline', 'PipelineResult'),
    # 管道产出语义比对
    'PipelineDiffer': ('modules.core.output_diff', 'PipelineDiffer'),
    'BatchDiffer': ('modules.core.output_diff', 'BatchDiffer'),
    'DiffReport': ('modules.core.output_diff', 'DiffReport'),
    # Compat 模块自动发现与钩子注册
    'HookRegistry': ('modules.core.hook_registry', 'HookRegistry'),
    # 堆溢出误报压制
    'Interval': ('modules.core.compat.value_range', 'Interval'),
    'FalsePositiveFilter': ('modules.core.compat.fp_filter', 'FalsePositiveFilter'),
    'batch_filter_and_report': ('modules.core.compat.fp_filter', 'batch_filter_and_report'),
    # UAF 逃逸分析
    'UafEscapeResult': ('modules.core.compat.uaf_escape_analysis', 'UafEscapeResult'),
    'analyze_pointer_escape': ('modules.core.compat.uaf_escape_analysis', 'analyze_pointer_escape'),
    # 格式串状态机解析
    'parse_format_string': ('modules.core.compat.format_parser', 'parse_format_string'),
    'classify_format_risk': ('modules.core.compat.format_parser', 'classify_format_risk'),
    # 栈溢出严重度
    'grade_severity': ('modules.core.compat.stack_severity', 'grade_severity'),
    # 整数溢出
    'detect_overflow_ops': ('modules.core.compat.int_overflow_detector', 'detect_overflow_ops'),
    'IntOverflowCandidate': ('modules.core.compat.int_overflow_detector', 'IntOverflowCandidate'),
    'discover_compat_modules': ('modules.core.hook_registry', 'discover_compat_modules'),
}


def __getattr__(name):
    import importlib
    if name in _LAZY_EXPORTS:
        mod_path, attr = _LAZY_EXPORTS[name]
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
