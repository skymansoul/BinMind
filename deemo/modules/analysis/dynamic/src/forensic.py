# 2026-08-01
"""
Forensic facade — PE/ELF header timestamp extraction, file operation
analysis, time anomaly detection, timeline reconstruction

Wraps engine/forensic_path_recorder.py
engine/forensic_timeline_reconstructor.py

// O(n 记录 n) O(n) space — 合并 排序 beats quicksort because
// file operation timestamps arrive nearly sorted OS
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


# ---------------------------------------------------------------------------
# PE/ELF header parsing
# ---------------------------------------------------------------------------

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
    """解析 key fields a PE (Portable 可执行文件) header"""
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
    """解析 key fields an ELF header"""
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

            # ELF doesn't a standard timestamp — fall back file mtime
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


# ---------------------------------------------------------------------------
# File operation record
# ---------------------------------------------------------------------------

@dataclass
class FileOperation:
    op_id: str
    filepath: str
    operation: str  # "创建", "读取", "写入", "删除", "rename", "执行"
    timestamp: float
    process_name: str = ""
    pid: int = 0
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# TimelineReconstructor
# ---------------------------------------------------------------------------

class TimelineReconstructor:
    """重建 timeline binary activity PE/ELF headers
    file operation 记录
    
    Performs:
    
    1. PE/ELF header timestamp extraction (compile time)
    2. File operation timeline analysis
    3. Time anomaly detection (tampered timestamps, clock skew)
    
    Usage::
    
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

    # ---- Binary header analysis ----

    def extract_binary_info(self, filepath: str) -> Optional[BinaryHeaderInfo]:
        """提取 PE/ELF header information a file
        
        Automatically 检测 格式化 (PE vs ELF) 提取 compile
        timestamp, 入口, architecture
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

    # ---- File operation recording ----

    def record_file_op(
        self,
        operation: str,
        filepath: str,
        timestamp: Optional[float] = None,
        process_name: str = "",
        pid: int = 0,
        size_bytes: int = 0,
    ) -> FileOperation:
        """Record a file operation event"""
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

    # ---- Timeline construction ----

    def build_timeline(self) -> List[Dict[str, Any]]:
        """构建 a chronological timeline operations
        
        排序 operations timestamp using 合并 排序 (stable, O(n 记录 n))
        包含 binary header compile times timeline markers
        """
        # 排序 file operations timestamp (合并 排序 — stable)
        sorted_ops = sorted(self._operations, key=lambda o: o.timestamp)

        timeline: List[Dict[str, Any]] = []

        # 插入 binary compile-time markers
        for filepath, info in self._binary_headers.items():
            timeline.append({
                "type": "compile_time",
                "filepath": filepath,
                "timestamp": info.timestamp,
                "timestamp_readable": info.timestamp_readable,
                "format": info.format,
                "architecture": info.architecture,
            })

        # 插入 file operations
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

        # 排序 merged timeline timestamp
        timeline.sort(key=lambda e: e["timestamp"])
        return timeline

    # ---- Anomaly detection ----

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """检测 temporal anomalies timeline
        
        检查 for:
        - Future timestamps (clock skew or tampering)
        - Compile-time vs runtime gaps (old binaries)
        - Rapid file creation bursts (ransomware pattern)
        - Timestamps epoch 0 (forged or missing)
        """
        anomalies: List[Dict[str, Any]] = []
        now = time.time()

        # 检查 for future timestamps
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

        # 检查 for epoch-zero timestamps (forged/missing)
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

        # 检查 compile-time vs runtime gap
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

        # 检查 for rapid file creation bursts (>10 files <5 seconds)
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

    # ---- 报告 generation ----

    def generate_report(self) -> Dict[str, Any]:
        """构造 a comprehensive forensic timeline 报告"""
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
        """清除 recorded operations header data"""
        self._operations.clear()
        self._binary_headers.clear()
        self._op_counter = 0
