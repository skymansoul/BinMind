# 重导出桥接 — 根目录 config 模块的兼容层, 供 from core.config import X 使用。
# 11+ 模块引用 core.config, 实际配置位于 deemo/ 根目录 config.py。
# 新增代码应直接使用 from config import X。

from config import *  # noqa: F401, F403
