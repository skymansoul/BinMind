"""mmap IO 子模块——单文件映射封装"""

import os
import mmap
import time
import typing

from ._mmap_types import MmapMode, MmapConfig, _logger


class MemoryMappedFile:

    def __init__(self, file_path: str, config: typing.Optional[MmapConfig] = None):
        self._file_path = file_path
        self._config = config or MmapConfig()
        self._file_handle: typing.Optional[typing.BinaryIO] = None
        self._mmap_obj: typing.Optional[mmap.mmap] = None
        self._is_open = False
        self._access_count = 0
        self._last_access_time = 0.0
        self._file_size = 0
        self._seq_bytes_read = 0
        self._last_read_offset = -1

# open / close

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

# read ops

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

# write

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

# accessors

    def get_file_size(self) -> int:
        return self._file_size

    def is_open(self) -> bool:
        return self._is_open

    def get_access_count(self) -> int:
        return self._access_count

# 内部模式/保护/标志映射

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
