# project module -- lazy-loading facade (Aug 2026 refactor)
__version__ = "1.8.0"
import sys as _sys, importlib as _il

__all__ = ['CIIntegration', 'CollaborationManager', 'ConfigManager', 'PluginManager', 'ProjectManager', 'RemoteAgent', 'ReportLocalizationEngine', 'ReportTemplateEngine', 'ResourceControl', 'SIEMIntegrator', 'TaskScheduler', 'WebAPI', 'AssetRegistry', 'ScanOrchestrator', 'EventBus', 'AuditTrail', 'CacheManager', 'MetricsRegistry', 'Counter', 'Gauge', 'Histogram', 'Summary', 'count_calls', 'track_inprogress',
           'BinaryDiffEngine', 'get_diff_engine', 'diff_binaries',
           'VulnerabilityGraphBuilder', 'CascadePredictor', 'CWECorrelationFinder',
           'build_vuln_graph_from_findings', 'assess_supply_chain_risk',
           'IncrementalAnalysisCache', 'IncrementalAnalysisScheduler',
           'AdaptiveThresholdDetector', 'MultiScaleResidualDetector',
           'MetricsAnomalyPipeline', 'BatchMetricAnalyzer',
           'EvidenceMapper', 'CrossStandardMapper', 'StandardLibrary',
           'assess_compliance',
           'AdaptiveScheduler', 'TaskProfiler', 'AdaptivePriorityLearner',
           'DataLineageTracker', 'PipelineLineageHook',
           'FindingEnrichmentPipeline', 'CVSSInferrer', 'CWERefiner', 'MITREAttackMapper',
           'ExploitabilityScorer', 'EPSSEstimator', 'TemporalDecayScorer']

_lazy = {
    'CIIntegration': ('ci_integration', 'CIIntegrator'), 'CollaborationManager': ('collaboration', 'CollaborationManager'),
    'ConfigManager': ('config_manager', 'ConfigManager'), 'PluginManager': ('plugin_manager', 'PluginManager'),
    'ProjectManager': ('project_manager', 'ProjectManager'), 'RemoteAgent': ('remote_agent', 'RemoteAgent'),
    'ReportLocalizationEngine': ('report_localization_engine', 'ReportLocalizationEngine'),
    'ReportTemplateEngine': ('report_template_engine', 'ReportTemplateEngine'),
    'ResourceControl': ('resource_control', 'ResourceController'), 'SIEMIntegrator': ('siem_integrator', 'SIEMIntegrator'),
    'TaskScheduler': ('task_scheduler', 'TaskScheduler'), 'WebAPI': ('web_api', 'start_server'),
    'AssetRegistry': ('asset_registry', 'AssetRegistry'), 'ScanOrchestrator': ('scan_orchestrator', 'ScanOrchestrator'),
    'EventBus': ('event_bus', 'EventBus'), 'AuditTrail': ('audit_trail', 'AuditTrail'),
    'CacheManager': ('cache_manager', 'CacheManager'),
    'MetricsRegistry': ('metrics_collector', 'MetricsRegistry'), 'Counter': ('metrics_collector', 'Counter'),
    'Gauge': ('metrics_collector', 'Gauge'), 'Histogram': ('metrics_collector', 'Histogram'),
    'Summary': ('metrics_collector', 'Summary'), 'count_calls': ('metrics_collector', 'count_calls'),
    'track_inprogress': ('metrics_collector', 'track_inprogress'),
    'BinaryDiffEngine': ('binary_diff_engine', 'BinaryDiffEngine'), 'get_diff_engine': ('binary_diff_engine', 'get_diff_engine'), 'diff_binaries': ('binary_diff_engine', 'diff_binaries'),
    'VulnerabilityGraphBuilder': ('vuln_knowledge_graph', 'VulnerabilityGraphBuilder'), 'CascadePredictor': ('vuln_knowledge_graph', 'CascadePredictor'), 'CWECorrelationFinder': ('vuln_knowledge_graph', 'CWECorrelationFinder'), 'build_vuln_graph_from_findings': ('vuln_knowledge_graph', 'build_vuln_graph_from_findings'), 'assess_supply_chain_risk': ('vuln_knowledge_graph', 'assess_supply_chain_risk'),
    'IncrementalAnalysisCache': ('incremental_cache', 'IncrementalAnalysisCache'), 'IncrementalAnalysisScheduler': ('incremental_cache', 'IncrementalAnalysisScheduler'),
    'AdaptiveThresholdDetector': ('metrics_anomaly', 'AdaptiveThresholdDetector'), 'MultiScaleResidualDetector': ('metrics_anomaly', 'MultiScaleResidualDetector'), 'MetricsAnomalyPipeline': ('metrics_anomaly', 'MetricsAnomalyPipeline'), 'BatchMetricAnalyzer': ('metrics_anomaly', 'BatchMetricAnalyzer'),
    'EvidenceMapper': ('compliance_mapper', 'EvidenceMapper'), 'CrossStandardMapper': ('compliance_mapper', 'CrossStandardMapper'), 'StandardLibrary': ('compliance_mapper', 'StandardLibrary'), 'assess_compliance': ('compliance_mapper', 'assess_compliance'),
    'AdaptiveScheduler': ('adaptive_scheduler', 'AdaptiveScheduler'), 'TaskProfiler': ('adaptive_scheduler', 'TaskProfiler'), 'AdaptivePriorityLearner': ('adaptive_scheduler', 'AdaptivePriorityLearner'),
    'DataLineageTracker': ('data_lineage', 'DataLineageTracker'), 'PipelineLineageHook': ('data_lineage', 'PipelineLineageHook'),
    'FindingEnrichmentPipeline': ('finding_enricher', 'FindingEnrichmentPipeline'), 'CVSSInferrer': ('finding_enricher', 'CVSSInferrer'), 'CWERefiner': ('finding_enricher', 'CWERefiner'), 'MITREAttackMapper': ('finding_enricher', 'MITREAttackMapper'),
    'ExploitabilityScorer': ('exploitability_scorer', 'ExploitabilityScorer'), 'EPSSEstimator': ('exploitability_scorer', 'EPSSEstimator'), 'TemporalDecayScorer': ('exploitability_scorer', 'TemporalDecayScorer'),
}

def __getattr__(name: str):
    if name in _lazy:
        mn, an = _lazy[name]; m = _il.import_module('.' + mn, package=__name__); a = getattr(m, an); setattr(_sys.modules[__name__], name, a); return a
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
