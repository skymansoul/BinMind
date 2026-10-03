# 桥接模块 — from core.logger import setup_logging
# firmware/src/main.py 使用了此导入路径。
# 实际日志初始化在 utils/logging_setup.py 中。

from utils.logging_setup import init_logging as setup_logging  # noqa: F401
