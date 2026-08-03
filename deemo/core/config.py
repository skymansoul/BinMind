# 重导出模块 — from core.config import X 桥接到根 config 模块
# 11+ 个模块使用 from core.config import Config, 但 config.py 位于 deemo/ 根目录,
# 不在 deemo/core/ 下。创建此桥接文件避免批量修改所有调用方。
# 注：此仅为兼容性桥接, 新增代码应直接使用 from config import X。

from config import *  # noqa: F401, F403
