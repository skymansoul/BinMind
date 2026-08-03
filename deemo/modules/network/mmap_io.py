from enum import StrEnum
import os
import mmap
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, List, BinaryIO
import typing

_logger = logging.getLogger(__name__)

class MmapMode(StrEnum):
    READ_ONLY = "r"
    READ_WRITE = "r+"
    COPY_ON_WRITE = "c"

class MmapAccess(StrEnum):
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    HYBRID = "hybrid"

@dataclass
class MmapConfig:
    mode: MmapMode = MmapMode.READ_ONLY
    access_pattern: MmapAccess = MmapAccess.SEQUENTIAL
    prefetch_enabled: bool = False
    prefetch_size: int = 64 * 1024
    buffer_size: int = 64 * 1024
    # 连续顺序读超出此字节数后向内核建议 MADV_SEQUENTIAL
    readahead_threshold: int = 256 * 1024

@dataclass
class FileInfo:
    file_path: str
    file_size: int
    mmap_size: int
    is_mapped: bool
    access_count: int
    last_access_time: float


class MemoryMappedFile:

    def __init__(self, file_path: str, config: typing.Optional[MmapConfig] = None):
        self._file_path = file_path
        self._config = config or MmapConfig()
        self._file_handle: typing.Optional[BinaryIO] = None
        self._mmap_obj: typing.Optional[mmap.mmap] = None
        self._is_open = False
        self._access_count = 0
        self._last_access_time = 0.0
        self._file_size = 0
        self._seq_bytes_read = 0
        self._last_read_offset = -1

    # ---- open / close ----

    def open(self) -> None:
        if self._is_open:
            return

        try:
            mode = self._get_file_mode()
            self._file_handle = open(self._file_path, mode)
            self._file_size = os.fstat(self._file_handle.fileno()).st_size

            if self._file_size == 0:
                _logger.warning(f"Zero-byte file: {self._file_path}")
                self._is_open = True
                return

            self._mmap_obj = mmap.mmap(
                fileno=self._file_handle.fileno(),
                length=0,
                flags=self._get_mmap_flags(),
                prot=self._get_mmap_protection(),
            )

            if self._config.prefetch_enabled and self._file_size > 0:
                self._prefetch_data()

            self._is_open = True
            _logger.info(f"Memory-mapped: {self._file_path} ({self._file_size} bytes)")

        except Exception as e:
            _logger.error(f"Failed to open memory-mapped file {self._file_path}: {e}")
            self.close()
            raise

    def close(self) -> None:
        if self._mmap_obj:
            try:
                self._mmap_obj.close()
            except Exception as e:
                _logger.warning(f"Error closing mmap: {e}")
            self._mmap_obj = None

        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception as e:
                _logger.warning(f"Error closing file: {e}")
            self._file_handle = None

        self._is_open = False

    # ---- read ops ----

    def read(self, offset: int, length: int) -> bytes:
        if not self._is_open or not self._mmap_obj:
            raise RuntimeError("File not open")
        if offset < 0 or offset >= self._file_size:
            raise ValueError(f"Invalid offset: {offset}")
        if length < 0:
            raise ValueError(f"Invalid length: {length}")

        end = min(offset + length, self._file_size)
        actual = end - offset
        if actual <= 0:
            return b""

        self._access_count += 1
        self._last_access_time = time.time()

        # readahead 启发式: 若顺序读取且累计足够字节，向内核提示
        if self._last_read_offset >= 0 and offset == self._last_read_offset:
            self._seq_bytes_read += actual
            if (self._seq_bytes_read >= self._config.readahead_threshold
                    and hasattr(self._mmap_obj, 'madvise')):
                try:
                    self._mmap_obj.madvise(mmap.MADV_SEQUENTIAL)
                except Exception:
                    pass  # 非Linux平台无madvise
        else:
            self._seq_bytes_read = actual

        self._last_read_offset = end
        return bytes(self._mmap_obj[offset:end])

    def read_byte(self, offset: int) -> int:
        if not self._is_open or not self._mmap_obj:
            raise RuntimeError("File not open")
        if offset < 0 or offset >= self._file_size:
            raise ValueError(f"Invalid offset: {offset}")

        self._access_count += 1
        self._last_access_time = time.time()
        return self._mmap_obj[offset]

    def read_int32(self, offset: int, little_endian: bool = True) -> int:
        chunk = self.read(offset, 4)
        if len(chunk) < 4:
            raise ValueError("Insufficient data")
        return int.from_bytes(chunk, 'little' if little_endian else 'big')

    def read_int64(self, offset: int, little_endian: bool = True) -> int:
        chunk = self.read(offset, 8)
        if len(chunk) < 8:
            raise ValueError("Insufficient data")
        return int.from_bytes(chunk, 'little' if little_endian else 'big')

    def read_string(self, offset: int, max_length: int = 1024) -> str:
        end = min(offset + max_length, self._file_size)
        blob = self.read(offset, end - offset)
        null_pos = blob.find(b'\x00')
        if null_pos != -1:
            blob = blob[:null_pos]
        return blob.decode('utf-8', errors='replace')

    # ---- write ----

    def write(self, offset: int, data: bytes) -> int:
        if self._config.mode == MmapMode.READ_ONLY:
            raise PermissionError("Cannot write to read-only file")
        if not self._is_open or not self._mmap_obj:
            raise RuntimeError("File not open")
        if offset < 0:
            raise ValueError(f"Invalid offset: {offset}")
        if offset + len(data) > self._file_size:
            raise ValueError("Write would exceed file size")

        self._mmap_obj[offset:offset + len(data)] = data
        self._access_count += 1
        self._last_access_time = time.time()
        return len(data)

    # ---- accessors ----

    def get_file_size(self) -> int:
        return self._file_size

    def is_open(self) -> bool:
        return self._is_open

    def get_access_count(self) -> int:
        return self._access_count

    # ---- 内部模式/保护/标志映射 ----

    def _get_file_mode(self) -> str:
        if self._config.mode == MmapMode.READ_ONLY:
            return 'rb'
        elif self._config.mode == MmapMode.READ_WRITE:
            return 'r+b'
        elif self._config.mode == MmapMode.COPY_ON_WRITE:
            return 'rb'
        return 'rb'

    def _get_mmap_protection(self) -> int:
        if self._config.mode == MmapMode.READ_ONLY:
            return mmap.PROT_READ
        elif self._config.mode == MmapMode.READ_WRITE:
            return mmap.PROT_READ | mmap.PROT_WRITE
        elif self._config.mode == MmapMode.COPY_ON_WRITE:
            return mmap.PROT_READ | mmap.PROT_WRITE
        return mmap.PROT_READ

    def _get_mmap_flags(self) -> int:
        if self._config.mode == MmapMode.COPY_ON_WRITE:
            return mmap.MAP_PRIVATE
        return mmap.MAP_SHARED

    def _prefetch_data(self) -> None:
        if self._file_size <= 0:
            return

        prefetch_size = min(self._config.prefetch_size, self._file_size)
        try:
            # 触发页面错误 — 内核将从此处异步预读
            _ = bytes(self._mmap_obj[:prefetch_size])
            _logger.debug(f"Prefetched {prefetch_size} bytes")
        except Exception as e:
            _logger.warning(f"Prefetch failed: {e}")

    def __enter__(self) -> 'MemoryMappedFile':
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ===========================================================================
class MmapIOManager:
    """mmap文件池管理——LRU回收+内存压力控制"""

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

    def list_open_files(self) -> List[FileInfo]:
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


# ===========================================================================
class MmapReader:
    """顺序读取器——封装MemoryMappedFile，游标驱动"""

    def __init__(self, mmap_file: MemoryMappedFile):
        self._mmap_file = mmap_file
        self._pos = 0

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > self._mmap_file.get_file_size():
            raise ValueError(f"Invalid offset: {offset}")
        self._pos = offset

    def tell(self) -> int:
        return self._pos

    def read(self, length: int) -> bytes:
        blob = self._mmap_file.read(self._pos, length)
        self._pos += len(blob)
        return blob

    def read_byte(self) -> int:
        b = self._mmap_file.read_byte(self._pos)
        self._pos += 1
        return b

    def read_int32(self, little_endian: bool = True) -> int:
        val = self._mmap_file.read_int32(self._pos, little_endian)
        self._pos += 4
        return val

    def read_int64(self, little_endian: bool = True) -> int:
        val = self._mmap_file.read_int64(self._pos, little_endian)
        self._pos += 8
        return val

    def read_string(self, max_length: int = 1024) -> str:
        s = self._mmap_file.read_string(self._pos, max_length)
        self._pos += len(s) + 1
        return s

    def read_until(self, delimiter: bytes) -> bytes:
        result = b""
        fsize = self._mmap_file.get_file_size()
        while self._pos < fsize:
            b = self._mmap_file.read_byte(self._pos)
            self._pos += 1
            if b == delimiter[0]:
                if len(delimiter) == 1:
                    break
                ok = True
                tmp = self._pos
                for i in range(1, len(delimiter)):
                    if tmp + i >= fsize:
                        ok = False
                        break
                    if self._mmap_file.read_byte(tmp + i) != delimiter[i]:
                        ok = False
                        break
                if ok:
                    self._pos = tmp + len(delimiter)
                    break
            result += bytes([b])
        return result

    def remaining(self) -> int:
        return max(0, self._mmap_file.get_file_size() - self._pos)


# ---- 模块级单例与辅助 ----

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
