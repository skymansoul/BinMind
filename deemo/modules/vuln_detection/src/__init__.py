# 2026-07-30 — vuln_detection/src package init
# 子模块入口：logger, config, main, core/{confidence, taint_engine, plugin}

from vuln_detection.src.logger import setup_logger, get_logger
from vuln_detection.src.config import load_config, Config
from vuln_detection.src.main import main
from vuln_detection.src.core.confidence import BayesianConfidenceScorer, confidence_score
from vuln_detection.src.core.taint_engine import TaintTracker, TaintSource, TaintSink
from vuln_detection.src.core.plugin import PluginBase, PluginManager, discover_plugins

__all__ = [
    "setup_logger", "get_logger",
    "load_config", "Config",
    "main",
    "BayesianConfidenceScorer", "confidence_score",
    "TaintTracker", "TaintSource", "TaintSink",
    "PluginBase", "PluginManager", "discover_plugins",
]
