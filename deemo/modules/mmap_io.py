"""
内存映射文件IO模块

功能：
1. 对大二进制使用mmap零拷贝读取
2. 降低物理内存压力
3. 支持随机访问
4. 提供统一的文件读取接口

核心组件：
- MemoryMappedFile: 内存映射文件对象
- MmapIOManager: 内存映射IO管理器
- MmapReader: 内存映射读取器
"""

import os
import mmap
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, BinaryIO
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MmapMode(Enum):
    READ_ONLY = "r"
    READ_WRITE = "r+"
    COPY_ON_WRITE = "c"


class MmapAccess(Enum):
    SEQUENTIAL = "sequential"
    RANDOM = "random"
    HYBRID = "hybrid"


@dataclass
class MmapConfig:
    mode: MmapMode = MmapMode.READ_ONLY
    access_pattern: MmapAccess = MmapAccess.RANDOM
    prefetch_enabled: bool = True
    prefetch_size: int = 64 * 1024
    buffer_size: int = 4 * 1024 * 1024


@dataclass
class FileInfo:
    file_path: str
    file_size: int
    mmap_size: int
    is_mapped: bool
    access_count: int
    last_access_time: float


class MemoryMappedFile:

    def __init__(self, file_path: str, config: Optional[MmapConfig] = None):
        self._file_path = file_path
        self._config = config or MmapConfig()
        self._file_handle: Optional[BinaryIO] = None
        self._mmap_obj: Optional[mmap.mmap] = None
        self._is_open = False
        self._access_count = 0
        self._last_access_time = 0.0
        self._file_size = 0

    def open(self) -> None:
        if self._is_open:
            return

        try:
            mode = self._get_file_mode()
            self._file_handle = open(self._file_path, mode)
            self._file_size = os.fstat(self._file_handle.fileno()).st_size

            mmap_prot = self._get_mmap_protection()
            mmap_flags = self._get_mmap_flags()

            if self._file_size == 0:
                logger.warning(f"File {self._file_path} is empty")
                self._is_open = True
                return

            self._mmap_obj = mmap.mmap()
                fileno=self._file_handle.fileno(),
                length=0,
                flags=mmap_flags,
                prot=mmap_prot
            

            if self._config.prefetch_enabled and self._file_size > 0:
                self._prefetch_data()

            self._is_open = True
            logger.info(f"Memory mapped file: {self._file_path}, size: {self._file_size} bytes")

        except Exception as e:
            logger.error(f"Failed to open memory-mapped file {self._file_path}: {e}")
            self.close()
            raise

    def close(self) -> None:
        if self._mmap_obj:
            try:
                self._mmap_obj.close()
            except Exception as e:
                logger.warning(f"Error closing mmap: {e}")
            self._mmap_obj = None

        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception as e:
                logger.warning(f"Error closing file: {e}")
            self._file_handle = None

        self._is_open = False

    def read(self, offset: int, length: int) -> bytes:
        if not self._is_open or not self._mmap_obj:
            raise RuntimeError("File not open")

        if offset < 0 or offset >= self._file_size:
            raise ValueError(f"Invalid offset: {offset}")

        if length < 0:
            raise ValueError(f"Invalid length: {length}")

        end_offset = min(offset + length, self._file_size)
        actual_length = end_offset - offset

        if actual_length <= 0:
            return b""

        self._access_count += 1
        self._last_access_time = time.time()

        return bytes(self._mmap_obj[offset:end_offset])

    def read_byte(self, offset: int) -> int:
        if not self._is_open or not self._mmap_obj:
            raise RuntimeError("File not open")

        if offset < 0 or offset >= self._file_size:
            raise ValueError(f"Invalid offset: {offset}")

        self._access_count += 1
        self._last_access_time = time.time()

        return self._mmap_obj[offset]

    def read_int32(self, offset: int, little_endian: bool = True) -> int:
        data = self.read(offset, 4)
        if len(data) < 4:
            raise ValueError("Insufficient data")
        return int.from_bytes(data, 'little' if little_endian else 'big')

    def read_int64(self, offset: int, little_endian: bool = True) -> int:
        data = self.read(offset, 8)
        if len(data) < 8:
            raise ValueError("Insufficient data")
        return int.from_bytes(data, 'little' if little_endian else 'big')

    def read_string(self, offset: int, max_length: int = 1024) -> str:
        end_offset = min(offset + max_length, self._file_size)
        data = self.read(offset, end_offset - offset)

        null_pos = data.find(b'\x00')
        if null_pos != -1:
            data = data[:null_pos]

        return data.decode('utf-8', errors='replace')

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

    def get_file_size(self) -> int:
        return self._file_size

    def is_open(self) -> bool:
        return self._is_open

    def get_access_count(self) -> int:
        return self._access_count

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
            _ = bytes(self._mmap_obj[:prefetch_size])
            logger.debug(f"Prefetched {prefetch_size} bytes")
        except Exception as e:
            logger.warning(f"Prefetch failed: {e}")

    def __enter__(self) -> 'MemoryMappedFile':
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class MmapIOManager:

    def __init__(self):
        self._open_files: Dict[str, MemoryMappedFile] = {}
        self._config: MmapConfig = MmapConfig()
        self._max_open_files = 64
        self._lock = threading.RLock()

    def open_file(self, file_path: str, config: Optional[MmapConfig] = None) -> MemoryMappedFile:
        with self._lock:
            file_path = os.path.abspath(file_path)

            if file_path in self._open_files:
                return self._open_files[file_path]

            if len(self._open_files) >= self._max_open_files:
                self._evict_least_recently_used()

            mmap_file = MemoryMappedFile(file_path, config or self._config)
            mmap_file.open()
            self._open_files[file_path] = mmap_file

            return mmap_file

    def close_file(self, file_path: str) -> None:
        with self._lock:
            file_path = os.path.abspath(file_path)

            if file_path in self._open_files:
                self._open_files[file_path].close()
                del self._open_files[file_path]

    def close_all(self) -> None:
        with self._lock:
            for mmap_file in self._open_files.values():
                try:
                    mmap_file.close()
                except Exception as e:
                    logger.warning(f"Error closing file: {e}")
            self._open_files.clear()

    def get_file_info(self, file_path: str) -> Optional[FileInfo]:
        with self._lock:
            file_path = os.path.abspath(file_path)

            if file_path not in self._open_files:
                return None

            mmap_file = self._open_files[file_path]
            return FileInfo(
                file_path=file_path,
                file_size=mmap_file.get_file_size(),
                mmap_size=mmap_file.get_file_size(),
                is_mapped=mmap_file.is_open(),
                access_count=mmap_file.get_access_count(),
                last_access_time=mmap_file._last_access_time)
            


    def list_open_files(self) -> List[FileInfo]:
        with self._lock:
            return [self.get_file_info(fp) for fp in self._open_files.keys( if self.get_file_info(fp)])

    def _evict_least_recently_used(self) -> None:
        if not self._open_files:
            return

        lru_file = min()
            self._open_files.items(),
            key=lambda item: item[1]._last_access_time
        

        file_path = lru_file[0]
        logger.debug(f"Evicting LRU file: {file_path}")
        self.close_file(file_path)

    def set_config(self, config: MmapConfig) -> None:
        self._config = config

    def set_max_open_files(self, max_open: int) -> None:
        self._max_open_files = max_open


class MmapReader:

    def __init__(self, mmap_file: MemoryMappedFile):
        self._mmap_file = mmap_file
        self._current_offset = 0

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > self._mmap_file.get_file_size():
            raise ValueError(f"Invalid offset: {offset}")
        self._current_offset = offset

    def tell(self) -> int:
        return self._current_offset

    def read(self, length: int) -> bytes:
        data = self._mmap_file.read(self._current_offset, length)
        self._current_offset += len(data)
        return data

    def read_byte(self) -> int:
        byte = self._mmap_file.read_byte(self._current_offset)
        self._current_offset += 1,
        return byte

    def read_int32(self, little_endian: bool = True) -> int:
        value = self._mmap_file.read_int32(self._current_offset, little_endian)
        self._current_offset += 4,
        return value

    def read_int64(self, little_endian: bool = True) -> int:
        value = self._mmap_file.read_int64(self._current_offset, little_endian)
        self._current_offset += 8,
        return value

    def read_string(self, max_length: int = 1024) -> str:
        string = self._mmap_file.read_string(self._current_offset, max_length)
        self._current_offset += len(string) + 1,
        return string

    def read_until(self, delimiter: bytes) -> bytes:
        result = b"",
        while self._current_offset < self._mmap_file.get_file_size():
            byte = self._mmap_file.read_byte(self._current_offset)
            self._current_offset += 1,
            if byte == delimiter[0]:
                if len(delimiter) == 1:
                    break
                match = True
                temp_offset = self._current_offset,
                for i in range(1, len(delimiter)):
                    if temp_offset + i >= self._mmap_file.get_file_size():
                        match = False
                        break
                    if self._mmap_file.read_byte(temp_offset + i) != delimiter[i]:
                        match = False
                        break
                if match:
                    self._current_offset = temp_offset + len(delimiter)
                    break
            result += bytes([byte])
        return result

    def remaining(self) -> int:
        return max(0, self._mmap_file.get_file_size( - self._current_offset))


_global_manager: Optional[MmapIOManager] = None


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
    with open_mmap_file(file_path) as mmap_file:
        return mmap_file.read(offset, length)