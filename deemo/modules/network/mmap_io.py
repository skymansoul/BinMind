"""mmap IO——内存映射文件读写与池化管理

拆分自原单文件(441行)，保持全部公开API不变。
子模块: _mmap_types / _mmap_file / _mmap_manager / _mmap_reader
"""

import typing

from ._mmap_types import MmapMode, MmapAccess, MmapConfig, FileInfo
from ._mmap_file import MemoryMappedFile
from ._mmap_manager import MmapIOManager
from ._mmap_reader import MmapReader

__all__ = [
    "MmapMode",
    "MmapAccess",
    "MmapConfig",
    "FileInfo",
    "MemoryMappedFile",
    "MmapIOManager",
    "MmapReader",
    "get_mmap_manager",
    "open_mmap_file",
    "read_binary_mmap",
]


# 模块级单例与辅助

_global_manager: typing.Optional[MmapIOManager] = None


def get_mmap_manager() -> MmapIOManager:
    global _global_manager
    if _global_manager is None:
        _global_manager = MmapIOManager()
    return _global_manager


def open_mmap_file(file_path: str, **kwargs) -> MemoryMappedFile:
    manager = get_mmap_manager()
    config = MmapConfig()
    if 'mode' in kwargs:
        config.mode = MmapMode[kwargs['mode'].upper()]
    if 'access_pattern' in kwargs:
        config.access_pattern = MmapAccess[kwargs['access_pattern'].upper()]
    if 'prefetch_enabled' in kwargs:
        config.prefetch_enabled = kwargs['prefetch_enabled']
    if 'prefetch_size' in kwargs:
        config.prefetch_size = kwargs['prefetch_size']
    return manager.open_file(file_path, config)


def read_binary_mmap(file_path: str, offset: int, length: int) -> bytes:
    with open_mmap_file(file_path) as mf:
        return mf.read(offset, length)
