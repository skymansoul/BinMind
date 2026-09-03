import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import os
import importlib

logger = logging.getLogger(__name__)


class AnalyzerType(Enum):
    VULNERABILITY_DETECTOR = "vulnerability_detector"
    STATIC_ANALYZER = "static_analyzer"
    DYNAMIC_ANALYZER = "dynamic_analyzer"
    FUZZER = "fuzzer"
    DECOMPILER = "decompiler"
    GENERIC = "generic"


@dataclass
class AnalyzerMetadata:
    name: str = ""
    type: AnalyzerType = AnalyzerType.GENERIC
    version: str = "0.1.0"
    description: str = ""
    dependencies: List[str] = field(default_factory=list)
    supported_platforms: List[str] = field(default_factory=list)


class BaseAnalyzer(ABC):
    def __init__(self):
        self._initialized = False

    def initialize(self, config=None):
        self._initialized = True

    def finalize(self):
        pass

    @abstractmethod
    def analyze(self, **kwargs) -> Dict[str, Any]:
        ...

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata()


class PluginManager:
  def __init__(self):
    self._plugins: Dict[str, type] = {}
    self._instances: Dict[str, BaseAnalyzer] = {}
    self._search_paths: List[str] = []

  def register(self, name: str, plugin_cls: type):
    self._plugins[name] = plugin_cls

  def get(self, name: str) -> Optional[BaseAnalyzer]:
    if name in self._instances:
      return self._instances[name]
    if name in self._plugins:
      instance = self._plugins[name]()
      self._instances[name] = instance
      return instance
    return None

  def list_plugins(self) -> List[str]:
    return list(self._plugins.keys())

  def discover(self, search_dir: str):
    if not os.path.isdir(search_dir):
      return
    for item in os.listdir(search_dir):
      if item.endswith('_analyzer.py') and item != '__init__.py':
        mod_name = item[:-3]
        try:
          spec = importlib.util.spec_from_file_location(
            mod_name, os.path.join(search_dir, item)
          )
          if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for attr in dir(mod):
              obj = getattr(mod, attr)
              if isinstance(obj, type) and issubclass(obj, BaseAnalyzer) and obj is not BaseAnalyzer:
                self.register(attr, obj)
        except Exception:
          logger.debug(f"Failed to load plugin: {item}")

# 暂留 — 无core.plugin_manager环境下的回退插件基础设施
_PLUGIN_REGISTRY: Dict[str, Any] = {}

def _debug_print(msg: str) -> None:
  pass
