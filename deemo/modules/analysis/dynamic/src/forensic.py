"""取证门面 — PE/ELF 头部时间戳提取, 文件操作分析,
时间异常检测, 时间线重建。

封装 engine/forensic_path_recorder.py 与
engine/forensic_timeline_reconstructor.py。

注: 归并排序 O(n log n) / O(n) 空间 — 优于快排, 因为文件
操作时间戳到达时接近有序。
"""

from __future__ import annotations

import datetime
import logging
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# PE/ELF 头部解析

@dataclass
class BinaryHeaderInfo:
    format: str  # "PE" or "ELF"
    architecture: str
    timestamp: float  # Unix timestamp
    timestamp_readable: str
    entry_point: int
    sections: List[Dict[str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)


def _parse_pe_header(filepath: str) -> Optional[BinaryHeaderInfo]:
    """解析 PE 头部的关键字段。"""
    try:
        with open(filepath, "rb") as f:
            # DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b"MZ":
                return None
            pe_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]

            # NT header
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return None

            # File header
            file_header = f.read(20)
            machine = struct.unpack_from("<H", file_header, 0)[0]
            section_count = struct.unpack_from("<H", file_header, 2)[0]
            timestamp = struct.unpack_from("<I", file_header, 4)[0]
            opt_header_size = struct.unpack_from("<H", file_header, 16)[0]

            arch_map = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM"}
            arch = arch_map.get(machine, f"unknown({machine:#x})")

            # Optional header
            opt_header = f.read(opt_header_size)
            entry_point = struct.unpack_from("<I", opt_header, 16)[0] if opt_header_size >= 20 else 0

            ts_readable = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc).isoformat()

            return BinaryHeaderInfo(
                format="PE",
                architecture=arch,
                timestamp=float(timestamp),
                timestamp_readable=ts_readable,
                entry_point=entry_point,
                sections=[{"count": section_count}],
            )
    except (OSError, struct.error) as e:
        log.warning("PE header parse error: %s", e)
        return None


def _parse_elf_header(filepath: str) -> Optional[BinaryHeaderInfo]:
    """解析 ELF 头部的关键字段。"""
    try:
        with open(filepath, "rb") as f:
            ident = f.read(16)
            if ident[:4] != b"\x7fELF":
                return None

            is_64bit = ident[4] == 2

            if is_64bit:
                header = f.read(48)
                entry_point = struct.unpack_from("<Q", header, 8)[0]
            else:
                header = f.read(36)
                entry_point = struct.unpack_from("<I", header, 8)[0]

            machine = struct.unpack_from("<H", header, -10)[0]
            arch_map = {3: "x86", 62: "x64", 40: "ARM", 183: "ARM64", 8: "MIPS"}
            arch = arch_map.get(machine, f"unknown({machine})")

            # ELF 无标准时间戳 — 回退到文件 mtime
            file_ts = os.path.getmtime(filepath)
            ts_readable = datetime.datetime.fromtimestamp(file_ts, tz=datetime.timezone.utc).isoformat()

            return BinaryHeaderInfo(
                format="ELF",
                architecture=arch,
                timestamp=file_ts,
                timestamp_readable=ts_readable,
                entry_point=entry_point,
            )
    except (OSError, struct.error) as e:
        log.warning("ELF header parse error: %s", e)
        return None


# 文件操作记录

@dataclass
class FileOperation:
    op_id: str
    filepath: str
    operation: str  # "创建", "读取", "写入", "删除", "重命名", "执行"
    timestamp: float
    process_name: str = ""
    pid: int = 0
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# 时间线重建器

class TimelineReconstructor:
    """从 PE/ELF 头部与文件操作记录重建二进制活动时间线。

    执行:

    1. PE/ELF 头部时间戳提取 (编译时间)
    2. 文件操作时间线分析
    3. 时间异常检测 (被篡改的时间戳, 时钟偏移)

    用法::

    tr = TimelineReconstructor()
    tr.record_file_op("创建", "C:\\\\temp\\\\dropper.exe", time.time())
    tr.record_file_op("写入", "C:\\\\temp\\\\payload.dll", time.time() + 1)
    anomalies = tr.detect_anomalies()
    timeline = tr.build_timeline()
    """

    def __init__(self, timezone: str = "UTC") -> None:
        self._timezone = timezone
        self._operations: List[FileOperation] = []
        self._binary_headers: Dict[str, BinaryHeaderInfo] = {}
        self._op_counter: int = 0

# 二进制头部分析

    def extract_binary_info(self, filepath: str) -> Optional[BinaryHeaderInfo]:
        """提取文件的 PE/ELF 头部信息。

        自动检测格式 (PE vs ELF), 提取编译时间戳, 入口点与
        架构。
        """
        if filepath in self._binary_headers:
            return self._binary_headers[filepath]

        info = _parse_pe_header(filepath) or _parse_elf_header(filepath)
        if info:
            self._binary_headers[filepath] = info
            log.info(
                "Extracted %s header: %s, compiled %s",
                info.format, filepath, info.timestamp_readable,
            )
        return info

# 文件操作记录

    def record_file_op(
        self,
        operation: str,
        filepath: str,
        timestamp: Optional[float] = None,
        process_name: str = "",
        pid: int = 0,
        size_bytes: int = 0,
    ) -> FileOperation:
        """记录文件操作事件。"""
        self._op_counter += 1
        op = FileOperation(
            op_id=f"fop_{self._op_counter:06d}",
            filepath=filepath,
            operation=operation,
            timestamp=timestamp or time.time(),
            process_name=process_name,
            pid=pid,
            size_bytes=size_bytes,
        )
        self._operations.append(op)
        return op

# 时间线构建

    def build_timeline(self) -> List[Dict[str, Any]]:
        """构建操作的时间顺序时间线。

        按时间戳对操作排序 (稳定归并排序, O(n log n)),
        并包含二进制头部的编译时间标记。
        """
        # 按时间戳排序文件操作 (归并排序 — 稳定)
        sorted_ops = sorted(self._operations, key=lambda o: o.timestamp)

        timeline: List[Dict[str, Any]] = []

        # 插入二进制编译时间标记
        for filepath, info in self._binary_headers.items():
            timeline.append({
                "type": "compile_time",
                "filepath": filepath,
                "timestamp": info.timestamp,
                "timestamp_readable": info.timestamp_readable,
                "format": info.format,
                "architecture": info.architecture,
            })

        # 插入文件操作
        for op in sorted_ops:
            timeline.append({
                "type": "file_operation",
                "op_id": op.op_id,
                "filepath": op.filepath,
                "operation": op.operation,
                "timestamp": op.timestamp,
                "timestamp_readable": datetime.datetime.fromtimestamp(
                    op.timestamp, tz=datetime.timezone.utc
                ).isoformat(),
                "process_name": op.process_name,
                "pid": op.pid,
                "size_bytes": op.size_bytes,
            })

        # 按时间戳排序合并后的时间线
        timeline.sort(key=lambda e: e["timestamp"])
        return timeline

# 异常检测

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """检测时间线中的时间异常。

        检查:
        - 未来时间戳 (时钟偏移或篡改)
        - 编译时间与运行时间的差距 (旧二进制)
        - 快速文件创建突发 (勒索软件模式)
        - epoch 0 时间戳 (伪造或缺失)
        """
        anomalies: List[Dict[str, Any]] = []
        now = time.time()

        # 检查未来时间戳
        for op in self._operations:
            if op.timestamp > now + 3600:  # 1 hour future
                anomalies.append({
                    "type": "future_timestamp",
                    "severity": "medium",
                    "filepath": op.filepath,
                    "operation": op.operation,
                    "timestamp": op.timestamp,
                    "message": f"Timestamp {op.timestamp} is in the future (now={now:.0f})",
                })

        # 检查 epoch 零点时间戳 (伪造/缺失)
        for op in self._operations:
            if abs(op.timestamp - 0) < 1.0 or abs(op.timestamp - 946684800) < 1.0:
                anomalies.append({
                    "type": "suspicious_timestamp",
                    "severity": "low",
                    "filepath": op.filepath,
                    "operation": op.operation,
                    "timestamp": op.timestamp,
                    "message": "Timestamp is near epoch — possibly forged or missing",
                })

        # 检查编译时间与运行时间的差距
        for filepath, info in self._binary_headers.items():
            age_days = (now - info.timestamp) / 86400.0
            if age_days > 365 * 3:  # Binary older 3 years
                anomalies.append({
                    "type": "old_binary",
                    "severity": "info",
                    "filepath": filepath,
                    "age_days": round(age_days, 1),
                    "message": f"Binary compiled {age_days:.0f} days ago — may be unpatched",
                })

        # 检查快速文件创建突发 (>10 个文件, <5 秒)
        create_ops = [o for o in self._operations if o.operation in ("create", "write")]
        for i in range(len(create_ops)):
            window_end = create_ops[i].timestamp + 5
            burst_count = sum(
                1 for o in create_ops
                if create_ops[i].timestamp <= o.timestamp <= window_end
            )
            if burst_count >= 10:
                anomalies.append({
                    "type": "file_burst",
                    "severity": "high",
                    "count": burst_count,
                    "window_start": create_ops[i].timestamp,
                    "message": f"Rapid file creation: {burst_count} files in 5 seconds (ransomware pattern)",
                })
                break

        return anomalies

# 报告生成

    def generate_report(self) -> Dict[str, Any]:
        """构造全面的取证时间线报告。"""
        return {
            "binary_count": len(self._binary_headers),
            "operation_count": len(self._operations),
            "anomalies": self.detect_anomalies(),
            "timeline": self.build_timeline(),
            "operation_summary": {
                "creates": sum(1 for o in self._operations if o.operation == "create"),
                "writes": sum(1 for o in self._operations if o.operation == "write"),
                "reads": sum(1 for o in self._operations if o.operation == "read"),
                "deletes": sum(1 for o in self._operations if o.operation == "delete"),
                "executes": sum(1 for o in self._operations if o.operation == "execute"),
            },
            "total_bytes_written": sum(
                o.size_bytes for o in self._operations if o.operation == "write"
            ),
        }

    def clear(self) -> None:
        """清除已记录的操作与头部数据。"""
        self._operations.clear()
        self._binary_headers.clear()
        self._op_counter = 0
