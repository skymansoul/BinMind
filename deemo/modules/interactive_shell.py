# 兼容入口：实现位于 core/compat/interactive_shell，此处聚合重导出。
from modules.core.compat.interactive_shell import (
    InteractiveShell,
    InteractiveReversingShell,
    BinaryState,
    ColorOutput,
    start_shell,
)

__all__ = [
    'InteractiveShell',
    'InteractiveReversingShell',
    'BinaryState',
    'ColorOutput',
    'start_shell',
]