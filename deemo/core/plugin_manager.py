# 重导出模块 — 桥接 core.plugin_manager → modules.project.plugin_manager
# 22+ 个模块导入 from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
# 但 plugin_manager.py 实际位于 modules/project/plugin_manager.py。
# IAnalyzer 在此别名为 BaseAnalyzer 以匹配调用方的命名约定。

from modules.project.plugin_manager import (
    IAnalyzer as BaseAnalyzer,
    AnalyzerMetadata,
    AnalyzerType,
)
