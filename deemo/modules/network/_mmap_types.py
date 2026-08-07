"""mmap IO 子模块——类型定义与配置"""

from enum import StrEnum
import logging
from dataclasses import dataclass
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
