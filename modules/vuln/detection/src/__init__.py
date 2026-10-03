# vuln_detection/src包入口
# 子模块: logger, config, main, core/{confidence, taint_engine, plugin}

from deemo.modules.vuln.detection.src.logger import setup_logger, get_logger
from deemo.modules.vuln.detection.src.config import load_config, Config
from deemo.modules.vuln.detection.src.main import main
from deemo.modules.vuln.detection.src.core.confidence import BayesianConfidenceScorer, confidence_score
from deemo.modules.vuln.detection.src.core.taint_engine import TaintTracker, TaintSource, TaintSink
from deemo.modules.vuln.detection.src.core.plugin import PluginBase, PluginManager, discover_plugins

__all__ = [
    "setup_logger", "get_logger",
    "load_config", "Config",
    "main",
    "BayesianConfidenceScorer", "confidence_score",
    "TaintTracker", "TaintSource", "TaintSink",
    "PluginBase", "PluginManager", "discover_plugins",
]
