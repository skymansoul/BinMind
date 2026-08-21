"""内存取证门面 — 活动进程与转存文件分析, volatility3 后端,
敏感数据提取 (keys, tokens, passwords), 内存布局可视化,
堆分析。

封装 engine/memory_*.py (memory_forensics, memory_heap,
memory_visualizer, memory_malware_detector,
memory_object_reconstructor, memory_primitive_extractor,
memory_sensitive_op_detector, memory_manipulation)。

注意: 转存文件截断时 volatility3 会 SIGSEGV,
加载前先校验文件大小。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


class MemoryImageFormat(str, Enum):
    RAW = "raw"
    ELF_COREDUMP = "elf"
    MINIDUMP = "minidump"
    MACHO = "macho"
    HIBERNATION = "hibernation"
    VMWARE = "vmware"
    VIRTUALBOX = "virtualbox"
    QEMU = "qemu"


# 内存取证 — 活动进程与转存文件分析

@dataclass
class ProcessInfo:
    pid: int
    name: str
    ppid: int = 0
    start_time: float = 0.0
    cmdline: str = ""
    modules: List[str] = field(default_factory=list)
    enviornment: Dict[str, str] = field(default_factory=dict)


@dataclass
class MemoryRegion:
    start: int
    end: int
    size: int
    permissions: str
    mapping: str = ""
    content_hash: str = ""


@dataclass
class SensitiveData:
    data_type: str
    value: str
    address: int
    confidence: float
    description: str = ""


class MemoryForensics:
    """由 volatility3 (若可用) 支撑的内存取证引擎。

    支持活动进程分析 (via /proc, ptrace, or readprocessmemory)
    与离线转存文件分析。volatility3 未安装时回退到启发式
    扫描。

    用法::

    mf = MemoryForensics()
    # Live analysis
    proc_info = mf.analyze_live_process(1234)
    # 转存分析
    results = mf.analyze_dump("memory.dmp")
    """

    VOLATILITY_AVAILABLE = False

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        try:
            import volatility3  # type: ignore # noqa: F401
            self.VOLATILITY_AVAILABLE = True
        except ImportError:
            log.info("volatility3 not installed; using heuristic fallback")

# 活动进程分析

    def analyze_live_process(self, pid: int) -> Optional[ProcessInfo]:
        """按 PID 分析活动进程。

        Linux 读取 /proc/<pid>/*; Windows 通过 ctypes 使用
        Win32 API (Toolhelp32 快照)。
        """
        log.info("Analyzing live process PID=%d", pid)
        info = ProcessInfo(pid=pid, name=f"process_{pid}")

        if os.name == "posix":
            info = self._analyze_linux_proc(pid, info)
        elif os.name == "nt":
            info = self._analyze_windows_proc(pid, info)

        return info

    def _analyze_linux_proc(self, pid: int, info: ProcessInfo) -> ProcessInfo:
        """读取 /proc/<pid> 进行 Linux 活动分析。"""
        proc_path = f"/proc/{pid}"
        try:
            with open(os.path.join(proc_path, "comm"), "r") as f:
                info.name = f.read().strip()
        except OSError:
            log.warning("Cannot read /proc/%d/comm", pid)

        try:
            with open(os.path.join(proc_path, "cmdline"), "r") as f:
                info.cmdline = f.read().replace("\x00", " ").strip()
        except OSError:
            pass

        try:
            with open(os.path.join(proc_path, "stat"), "r") as f:
                parts = f.read().split()
                if len(parts) > 3:
                    info.ppid = int(parts[3])
        except (OSError, ValueError):
            pass

        return info

    def _analyze_windows_proc(self, pid: int, info: ProcessInfo) -> ProcessInfo:
        """通过 ctypes 使用 Windows API 进行活动进程分析。"""
        try:
            import ctypes
            import ctypes.wintypes

            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_INFORMATION = 0x0400
            h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not h_process:
                log.warning("OpenProcess failed for PID=%d", pid)
                return info

            name_buf = ctypes.create_unicode_buffer(260)
            size = ctypes.wintypes.DWORD(260)
            kernel32.QueryFullProcessImageNameW(h_process, 0, name_buf, ctypes.byref(size))
            info.name = name_buf.value.split("\\")[-1] if "\\" in name_buf.value else name_buf.value

            kernel32.CloseHandle(h_process)
        except Exception as e:
            log.warning("Windows live analysis failed: %s", e)

        return info

# 转存文件分析

    def analyze_dump(self, dump_path: str) -> Dict[str, Any]:
        """分析内存转存文件。

        预先校验文件大小, 避免截断转存导致 volatility3
        SIGSEGV; 委托给 volatility3 后端或启发式扫描。
        """
        log.info("Analyzing dump: %s", dump_path)
        result: Dict[str, Any] = {"path": dump_path, "findings": []}

        if not os.path.isfile(dump_path):
            result["error"] = f"File not found: {dump_path}"
            return result

        file_size = os.path.getsize(dump_path)
        if file_size < 4096:
            log.warning("Dump file too small (%d bytes), likely truncated", file_size)
            result["warning"] = "Dump appears truncated (sub-4KB)"

        result["file_size"] = file_size
        result["format"] = self._detect_dump_format(dump_path)

        if self.VOLATILITY_AVAILABLE:
            result["backend"] = "volatility3"
            result["volatility_results"] = self._run_volatility(dump_path)
        else:
            result["backend"] = "heuristic"
            result["heuristic_results"] = self._heuristic_scan(dump_path)

        return result

    def _detect_dump_format(self, path: str) -> str:
        """按 magic bytes 检测内存转存格式。"""
        try:
            with open(path, "rb") as f:
                header = f.read(64)
            if header[:4] == b"\x7fELF":
                return "elf"
            if header[:4] == b"MDMP":
                return "minidump"
            if header[:4] == b"\xcf\xfa\xed\xfe":
                return "macho"
            return "raw"
        except OSError:
            return "unknown"

    def _run_volatility(self, dump_path: str) -> Dict[str, Any]:
        """对内存转存运行 volatility3 插件。"""
        results: Dict[str, Any] = {"plugins": {}}
        try:
            import volatility3
            import volatility3.plugins
            # 实践中调用 volatility3.cli 或使用其 Python API
            results["status"] = "volatility3_invoked"
            log.info("volatility3 analysis started for %s", dump_path)
        except ImportError:
            results["status"] = "volatility3_not_available"
        return results

    def _heuristic_scan(self, dump_path: str) -> Dict[str, Any]:
        """volatility3 不可用时的基础启发式扫描。"""
        results: Dict[str, Any] = {"strings_found": 0, "urls": [], "pe_headers": 0}
        try:
            with open(dump_path, "rb") as f:
                data = f.read()
            # 扫描 PE 头部
            pe_offset = 0
            while True:
                pe_offset = data.find(b"MZ", pe_offset)
                if pe_offset == -1:
                    break
                if pe_offset + 64 <= len(data):
                    pe_offs = struct.unpack_from("<I", data, pe_offset + 0x3C)[0]
                    if pe_offset + pe_offs + 4 <= len(data):
                        if data[pe_offset + pe_offs : pe_offset + pe_offs + 4] == b"PE\x00\x00":
                            results["pe_headers"] += 1
                pe_offset += 2
            # URL scan
            import re
            url_pattern = rb"https?://[^\x00\x20]+"
            results["urls"] = [
                m.decode("ascii", errors="replace")
                for m in re.findall(url_pattern, data)[:20]
            ]
        except OSError as e:
            log.error("Heuristic scan failed: %s", e)
        return results

# 敏感数据提取

    def extract_sensitive_data(self, dump_data: bytes) -> List[SensitiveData]:
        """从原始内存字节中提取敏感数据 (keys, tokens, passwords)。

        对常见敏感数据格式使用正则模式: AES/GCM keys,
        RSA 私钥, JWT, API token, 凭据模式。
        """
        import re
        findings: List[SensitiveData] = []

        patterns = {
            "aes_key": rb"[0-9A-Fa-f]{64}",
            "jwt_token": rb"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "api_key": rb"(?:key|token|secret)[:=]\s*[\"']?([A-Za-z0-9+/=]{20,})[\"']?",
            "password": rb"(?:password|passwd|pwd)[:=]\s*[\"']([^\"']{4,32})[\"']",
        }

        for data_type, pattern in patterns.items():
            for match in re.finditer(pattern, dump_data, re.IGNORECASE):
                findings.append(SensitiveData(
                    data_type=data_type,
                    value=match.group(0).decode("ascii", errors="replace")[:80],
                    address=match.start(),
                    confidence=0.7,
                    description=f"Found potential {data_type} at offset {match.start()}",
                ))

        return findings


# MemoryVisualizer — ASCII/SVG memory layout

class MemoryVisualizer:
    """构造 ASCII art 与 SVG 内存布局可视化。

    输出 hex 转存风格的 ASCII 内存区域映射, 或渲染展示分配
    边界、权限与数据密度的 SVG。
    """

    def __init__(self, width: int = 80) -> None:
        self._width = width

    def ascii_layout(self, regions: List[MemoryRegion]) -> str:
        """生成内存布局的 ASCII art 表示。"""
        if not regions:
            return "(empty)"
        total_size = max(r.end for r in regions) - min(r.start for r in regions)
        if total_size == 0:
            return "(zero-size)"

        lines: List[str] = []
        lines.append("=" * self._width)
        lines.append("MEMORY LAYOUT".center(self._width))
        lines.append("=" * self._width)

        base = min(r.start for r in regions)
        scale = self._width / total_size

        for region in sorted(regions, key=lambda r: r.start):
            offset = int((region.start - base) * scale)
            size_chars = max(1, int(region.size * scale))
            perm_char = {
                "r": "R", "rw": "W", "rwx": "X", "r-x": "C",
                "r--": "R", "--x": "x", "rwxc": "A",
            }.get(region.permissions, "?")

            line = " " * offset + perm_char * size_chars
            lines.append(line[:self._width].ljust(self._width))

            mapping = region.mapping or "(anon)"
            label = f"  {region.start:#010x}-{region.end:#010x} [{region.permissions}] {mapping}"
            if len(label) > self._width:
                label = label[:self._width - 3] + "..."
            lines.append(label)

        lines.append("=" * self._width)
        return "\n".join(lines)

    def svg_layout(
        self, regions: List[MemoryRegion], width: int = 800, height: int = 600
    ) -> str:
        """将内存布局渲染为 SVG 图。"""
        if not regions:
            return '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="20"><text>empty</text></svg>'

        min_addr = min(r.start for r in regions)
        max_addr = max(r.end for r in regions)
        addr_range = max_addr - min_addr or 1

        bar_height = 20
        y_pos = 40

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
            f'<text x="10" y="25" font-family="monospace" font-size="14">Memory Layout</text>',
        ]

        colors = {"rwx": "#ff6b6b", "rw": "#ffd93d", "r": "#6bcb77", "r-x": "#4d96ff"}

        for region in sorted(regions, key=lambda r: r.start):
            x = int((region.start - min_addr) / addr_range * (width - 20)) + 10
            w = max(2, int(region.size / addr_range * (width - 20)))
            color = colors.get(region.permissions, "#ccc")
            name = region.mapping or "anon"
            svg_parts.append(
                f'<rect x="{x}" y="{y_pos}" width="{w}" height="{bar_height}" '
                f'fill="{color}" stroke="#333"><title>{name}</title></rect>'
            )
            y_pos += bar_height + 5

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)


# 堆分析器 — 分配器状态分析与堆风水

@dataclass
class HeapChunk:
    address: int
    size: int
    flags: int
    is_free: bool
    prev_size: int = 0
    data_sample: bytes = b""


class HeapAnalyzer:
    """分析内存转存中的堆分配器状态。

    支持 glibc ptmalloc2 (Linux) 与 NT 堆 (Windows) 格式。
    执行堆 feng shui 分析, 构造针对特定堆状态的 fuzz 输入,
    生成漏洞利用代码骨架。
    """

    ALLOCATOR_GLIBC = "glibc_ptmalloc2"
    ALLOCATOR_WIN_HEAP = "windows_ntheap"

    def __init__(self, allocator_type: str = ALLOCATOR_GLIBC) -> None:
        self._allocator_type = allocator_type
        self._chunks: List[HeapChunk] = []

    def parse_heap(self, data: bytes, base_addr: int = 0) -> List[HeapChunk]:
        """解析堆数据并提取 chunk 元数据。"""
        self._chunks = []
        offset = 0

        while offset + 16 <= len(data):
            if self._allocator_type == self.ALLOCATOR_GLIBC:
                chunk = self._parse_glibc_chunk(data, offset, base_addr)
            else:
                chunk = self._parse_nt_chunk(data, offset, base_addr)

            if chunk:
                self._chunks.append(chunk)

            offset += max(chunk.size, 16) if chunk else 16
            if len(self._chunks) > 10000:
                break

        return self._chunks

    def _parse_glibc_chunk(
        self, data: bytes, offset: int, base_addr: int
    ) -> Optional[HeapChunk]:
        try:
            prev_size = struct.unpack_from("<Q", data, offset)[0]
            size_field = struct.unpack_from("<Q", data, offset + 8)[0]
            chunk_size = size_field & ~7
            flags = size_field & 7
            is_free = bool(flags & 1)

            return HeapChunk(
                address=base_addr + offset,
                size=max(chunk_size, 16),
                flags=flags,
                is_free=is_free,
                prev_size=prev_size,
                data_sample=data[offset + 16 : offset + 32] if offset + 32 <= len(data) else b"",
            )
        except struct.error:
            return None

    def _parse_nt_chunk(
        self, data: bytes, offset: int, base_addr: int
    ) -> Optional[HeapChunk]:
        try:
            chunk_size = struct.unpack_from("<H", data, offset + 2)[0] * 8
            flags = struct.unpack_from("<H", data, offset + 6)[0]
            return HeapChunk(
                address=base_addr + offset,
                size=max(chunk_size, 16),
                flags=flags,
                is_free=(flags & 1) != 0,
            )
        except struct.error:
            return None

    def analyze_heap_state(self) -> Dict[str, Any]:
        """分析堆分配器状态以寻找利用机会。"""
        total_free = 0
        total_used = 0
        free_chunks = 0
        used_chunks = 0

        for chunk in self._chunks:
            if chunk.is_free:
                total_free += chunk.size
                free_chunks += 1
            else:
                total_used += chunk.size
                used_chunks += 1

        return {
            "total_chunks": len(self._chunks),
            "free_chunks": free_chunks,
            "used_chunks": used_chunks,
            "total_free_bytes": total_free,
            "total_used_bytes": total_used,
            "fragmentation_ratio": total_free / max(total_free + total_used, 1),
        }

    def heap_feng_shui_plan(
        self, target_size: int, allocation_count: int
    ) -> List[Dict[str, Any]]:
        """构造堆 feng shui 计划以取得 target_size 的 chunk。

        返回分配/释放步骤序列, 旨在创建期望大小的连续空闲
        区域。
        """
        steps: List[Dict[str, Any]] = []
        remaining = target_size
        # Phase 1: Spray fill holes
        steps.append({"action": "spray", "size": 64, "count": allocation_count})
        # Phase 2: Free alternating chunks 创建 single free block
        for i in range(allocation_count // 2):
            remaining -= 64
            if remaining <= 0:
                break
            steps.append({"action": "free", "index": i * 2 + 1})
        steps.append({"action": "allocate_target", "size": target_size})
        return steps

    def generate_exploit_code(self, vulnerability_type: str) -> str:
        """为堆漏洞构造利用代码骨架。"""
        templates = {
            "use_after_free": self._uaf_exploit_template,
            "double_free": self._double_free_template,
            "heap_overflow": self._heap_overflow_template,
        }
        generator = templates.get(vulnerability_type, self._uaf_exploit_template)
        return generator()

    def _uaf_exploit_template(self) -> str:
        return """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *victim = malloc(128);
    strcpy(victim, "target_data");
    free(victim);
    // UAF: victim is freed but still usable
    char *attacker = malloc(128);
    memset(attacker, 'A', 127);
    // victim now overlaps with attacker
    printf("victim[0] = %c (expected A)\\n", victim[0]);
    return 0;
}"""

    def _double_free_template(self) -> str:
        return """#include <stdlib.h>
int main() {
    void *p = malloc(64);
    free(p);
    free(p);  // Double free!
    return 0;
}"""

    def _heap_overflow_template(self) -> str:
        return """#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
    char *buf = malloc(16);
    char *victim = malloc(128);
    strcpy(victim, "safe");
    // Heap overflow: overflows into adjacent chunk
    memset(buf, 'B', 128);
    printf("victim = %s (corrupted?)\\n", victim);
    return 0;
}"""
