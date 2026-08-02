# project module -- lazy-loading facade (Aug 2026 refactor)
__version__ = "1.7.0"
import sys as _sys, importlib as _il

__all__ = ['CIIntegration', 'CollaborationManager', 'ConfigManager', 'PluginManager', 'ProjectManager', 'RemoteAgent', 'ReportLocalizationEngine', 'ReportTemplateEngine', 'ResourceControl', 'SIEMIntegrator', 'TaskScheduler', 'WebAPI', 'AssetRegistry', 'ScanOrchestrator', 'EventBus', 'AuditTrail', 'CacheManager', 'MetricsRegistry', 'Counter', 'Gauge', 'Histogram', 'Summary', 'count_calls', 'track_inprogress']

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
}

def __getattr__(name: str):
    if name in _lazy:
        mn, an = _lazy[name]; m = _il.import_module('.' + mn, package=__name__); a = getattr(m, an); setattr(_sys.modules[__name__], name, a); return a
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
