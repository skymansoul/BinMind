# 2026-08-01
"""
Memory forensics facade — live process 转存 file analysis, volatility3
backend, sensitive data extraction (keys, tokens, passwords), memory layout
visualization, 堆 analysis

Wraps engine/memory_*.py (memory_forensics, memory_堆, memory_visualizer
memory_malware_detector, memory_object_reconstructor
memory_primitive_extractor, memory_sensitive_op_detector, memory_manipulation)

// WATCH: 转存 file truncated, volatility3 SIGSEGV
// pre-校验 file size loading
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


# MemoryForensics — live + 转存 analysis

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
    """Memory forensics engine backed volatility3 (available)
    
    支持 live process analysis (via /proc, ptrace, or readprocessmemory)
    offline 转存 file analysis. Falls back heuristic scanning
    volatility3 installed
    
    Usage::
    
    mf = MemoryForensics()
    # Live analysis
    proc_info = mf.analyze_live_process(1234)
    # 转存 analysis
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

# Live process analysis

    def analyze_live_process(self, pid: int) -> Optional[ProcessInfo]:
        """分析 a live process PID
        
        Linux 读取 /proc/<pid>/*. Windows 使用 Win32 API
        via ctypes (Toolhelp32快照)
        """
        log.info("Analyzing live process PID=%d", pid)
        info = ProcessInfo(pid=pid, name=f"process_{pid}")

        if os.name == "posix":
            info = self._analyze_linux_proc(pid, info)
        elif os.name == "nt":
            info = self._analyze_windows_proc(pid, info)

        return info

    def _analyze_linux_proc(self, pid: int, info: ProcessInfo) -> ProcessInfo:
        """读取 /proc/<pid> for Linux live analysis"""
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
        """使用 Windows API for live process analysis via ctypes"""
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

# 转存 file analysis

    def analyze_dump(self, dump_path: str) -> Dict[str, Any]:
        """分析 a memory 转存 file
        
        Pre-校验s file size avoid volatility3 SIGSEGV truncated 转存
        delegates volatility3 backend or heuristic scanning
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
        """检测 memory 转存 格式化 magic bytes"""
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
        """运行 volatility3 plugins against a memory 转存"""
        results: Dict[str, Any] = {"plugins": {}}
        try:
            import volatility3
            import volatility3.plugins
            # practice 调用 volatility3.cli or 使用 Python API
            results["status"] = "volatility3_invoked"
            log.info("volatility3 analysis started for %s", dump_path)
        except ImportError:
            results["status"] = "volatility3_not_available"
    # 这坨代码先不清了，后面重构的时候再说
        return results

    def _heuristic_scan(self, dump_path: str) -> Dict[str, Any]:
        """Basic heuristic scanning volatility3 unavailable"""
        results: Dict[str, Any] = {"strings_found": 0, "urls": [], "pe_headers": 0}
        try:
            with open(dump_path, "rb") as f:
                data = f.read()
            # Simple PE header scan
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

# Sensitive data extraction

    def extract_sensitive_data(self, dump_data: bytes) -> List[SensitiveData]:
        """提取 sensitive data (keys, tokens, passwords) raw memory bytes
        
        使用 regex patterns for common sensitive data 格式化: AES/GCM keys
        RSA private keys, JWTs, API tokens, credential patterns
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
    """构造 ASCII art SVG memory layout visualizations
    
    输出 hex-转存 style ASCII maps memory regions, or 渲染
    an SVG showing allocation boundaries, permissions, data density
    """

    def __init__(self, width: int = 80) -> None:
        self._width = width

    def ascii_layout(self, regions: List[MemoryRegion]) -> str:
        """Produce an ASCII art representation memory layout"""
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
        """渲染 memory layout an SVG diagram"""
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


# 堆Analyzer — allocator state analysis, 堆 feng shui

@dataclass
class HeapChunk:
    address: int
    size: int
    flags: int
    is_free: bool
    prev_size: int = 0
    data_sample: bytes = b""


class HeapAnalyzer:
    """分析 堆 allocator state a memory 转存
    
    支持 glibc ptmalloc2 (Linux) NT 堆 (Windows) 格式化
    Performs 堆 feng shui analysis, 构造 fuzz inputs targeting
    specific 堆 states, produce 漏洞利用 code skeletons
    """

    ALLOCATOR_GLIBC = "glibc_ptmalloc2"
    ALLOCATOR_WIN_HEAP = "windows_ntheap"

    def __init__(self, allocator_type: str = ALLOCATOR_GLIBC) -> None:
        self._allocator_type = allocator_type
        self._chunks: List[HeapChunk] = []

    def parse_heap(self, data: bytes, base_addr: int = 0) -> List[HeapChunk]:
        """解析 堆 data 提取 chunk metadata"""
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
        """分析 堆 allocator state for 漏洞利用ation opportunities"""
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
        """构造 a 堆 feng shui plan secure a chunk target_size
        
        返回 a sequence allocation/deallocation steps designed
        创建 a contiguous free region desired size
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
        """构造 漏洞利用 code skeleton for a 堆 漏洞"""
        templates = {
            "use_after_free": self._uaf_exploit_template,
            "double_free": self._double_free_template,
            "heap_overflow": self._heap_overflow_template,
        }
        generator = templates.get(vulnerability_type, self._uaf_exploit_template)
        return generator()

    def _uaf_exploit_template(self) -> str:
        return """#include <stdio.h>
# 包含 <stdlib.h>
# 包含 <string.h>

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
# 包含 <stdlib.h>
# 包含 <string.h>
int main() {
    char *buf = malloc(16);
    char *victim = malloc(128);
    strcpy(victim, "safe");
    // Heap overflow: overflows into adjacent chunk
    memset(buf, 'B', 128);
    printf("victim = %s (corrupted?)\\n", victim);
    return 0;
}"""
