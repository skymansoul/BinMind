"""mmap IO 子模块——文件池管理（LRU回收+内存压力控制）"""

import os
import threading
import typing

from ._mmap_types import MmapConfig, FileInfo, _logger
from ._mmap_file import MemoryMappedFile


class MmapIOManager:

    def __init__(self):
        self._open_files: dict[str, MemoryMappedFile] = {}
        self._config = MmapConfig()
        self._max_open_files = 64
        self._lock = threading.RLock()
        self._total_mapped_bytes = 0
        self._pressure_threshold_mb = 512  # 映射总量超此阈值时回收

    def open_file(self, file_path: str,
                  config: typing.Optional[MmapConfig] = None) -> MemoryMappedFile:
        with self._lock:
            file_path = os.path.abspath(file_path)

            # 已打开 —— 返回缓存句柄
            if file_path in self._open_files:
                return self._open_files[file_path]

            # 硬限制: 打开文件数过多，回收LRU
            if len(self._open_files) >= self._max_open_files:
                self._evict_least_recently_used()

            # 内存压力: 映射字节超阈值，逐出至达标
            while (self._total_mapped_bytes > self._pressure_threshold_mb * 1024 * 1024
                   and len(self._open_files) > 1):
                self._evict_least_recently_used()

            mmap_file = MemoryMappedFile(file_path, config or self._config)
            mmap_file.open()
            self._open_files[file_path] = mmap_file
            self._total_mapped_bytes += mmap_file.get_file_size()

            return mmap_file

    def close_file(self, file_path: str) -> None:
        with self._lock:
            file_path = os.path.abspath(file_path)

            if file_path in self._open_files:
                mf = self._open_files[file_path]
                self._total_mapped_bytes -= mf.get_file_size()
                mf.close()
                del self._open_files[file_path]

    def close_all(self) -> None:
        with self._lock:
            for mf in self._open_files.values():
                try:
                    mf.close()
                except Exception as e:
                    _logger.warning(f"Error closing file: {e}")
            self._open_files.clear()
            self._total_mapped_bytes = 0

    def get_file_info(self, file_path: str) -> typing.Optional[FileInfo]:
        with self._lock:
            file_path = os.path.abspath(file_path)
            if file_path not in self._open_files:
                return None
            mf = self._open_files[file_path]
            return FileInfo(
                file_path=file_path,
                file_size=mf.get_file_size(),
                mmap_size=mf.get_file_size(),
                is_mapped=mf.is_open(),
                access_count=mf.get_access_count(),
                last_access_time=mf._last_access_time,
            )

    def list_open_files(self) -> list[FileInfo]:
        with self._lock:
            result = []
            for fp in self._open_files:
                info = self.get_file_info(fp)
                if info is not None:
                    result.append(info)
            return result

    def _evict_least_recently_used(self) -> None:
        if not self._open_files:
            return
        lru = min(self._open_files.items(),
                  key=lambda item: item[1]._last_access_time)
        _logger.debug(f"Evicting LRU file: {lru[0]}")
        self.close_file(lru[0])

    def set_config(self, config: MmapConfig) -> None:
        self._config = config

    def set_max_open_files(self, max_open: int) -> None:
        self._max_open_files = max_open

    @property
    def total_mapped_mb(self) -> float:
        return self._total_mapped_bytes / (1024 * 1024)
