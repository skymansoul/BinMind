# 多技术进程内存转储 - Linux (gcore, /proc/pid/mem) + Windows (procdump, MiniDumpWriteDump via ctypes)
# 设计思路：按可用方法顺序尝试，失败则回退到次选方案
# ProcessScanner 提供跨平台的进程枚举能力

import os
import sys
import struct
import shutil
import logging
import platform
import tempfile
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable
from pathlib import Path

import subprocess

_log = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")


# 枚举与数据类

class DumpMethod(str, Enum):
    GCORE = "gcore"          # Linux gcore
    PROC_MEM = "proc_mem"    # Linux /proc/pid/mem
    MINIDUMP = "minidump"    # Windows MiniDumpWriteDump
    PROCDUMP = "procdump"    # Sysinternals procdump
    CUSTOM = "custom"        # 自定义方法


@dataclass
class MemoryRegion:
    start: int = 0
    end: int = 0
    size: int = 0
    permissions: str = "---"
    path: str = ""
    offset: int = 0

    @property
    def is_readable(self) -> bool:
        return "r" in self.permissions

    @property
    def is_writable(self) -> bool:
        return "w" in self.permissions

    @property
    def is_executable(self) -> bool:
        return "x" in self.permissions


@dataclass
class DumpResult:
    success: bool = False
    method: str = ""
    output_path: str = ""
    pid: Optional[int] = None
    message: str = ""
    regions_dumped: int = 0


# 进程扫描器

class ProcessScanner:
    """跨平台进程枚举与信息获取"""

    # 获取单个进程详细信息
    def get_process_info(self, pid: int) -> Dict[str, Any]:
        if IS_LINUX:
            return self._info_linux(pid)
        elif IS_WINDOWS:
            return self._info_windows(pid)
        return {"pid": pid, "error": "unsupported platform"}

    def _info_linux(self, pid: int) -> Dict[str, Any]:
        info: Dict[str, Any] = {"pid": pid}
        # /proc/pid/status
        try:
            with open(f"/proc/{pid}/status", "r") as fh:
                for line in fh:
                    if line.startswith("Name:"):
                        info["name"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Threads:"):
                        info["threads"] = int(line.split(":", 1)[1].strip())
        except (IOError, OSError):
            info["name"] = "unknown"

        # /proc/pid/cmdline
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                raw = fh.read()
                info["cmdline"] = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (IOError, OSError):
            info["cmdline"] = ""

        # /proc/pid/exe
        try:
            info["path"] = os.readlink(f"/proc/{pid}/exe")
        except (IOError, OSError):
            info["path"] = ""

        # /proc/pid/maps → memory_regions
        regions = self._parse_maps(pid)
        info["memory_regions"] = [{"start": r.start, "end": r.end,
                                    "size": r.size, "permissions": r.permissions,
                                    "path": r.path, "offset": r.offset}
                                  for r in regions[:100]]
        info["region_count"] = len(regions)
        return info

    def _parse_maps(self, pid: int) -> List[MemoryRegion]:
        regions: List[MemoryRegion] = []
        try:
            with open(f"/proc/{pid}/maps", "r") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) < 2:
                        continue
                    addr_range = parts[0].split("-")
                    perms = parts[1]
                    offset = int(parts[2], 16) if len(parts) > 2 else 0
                    path = parts[-1] if len(parts) > 5 else ""
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    regions.append(MemoryRegion(
                        start=start, end=end, size=end-start,
                        permissions=perms, path=path, offset=offset
                    ))
        except (IOError, OSError):
            pass
        return regions

    def _info_windows(self, pid: int) -> Dict[str, Any]:
        info: Dict[str, Any] = {"pid": pid, "platform": "windows"}
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32

            TH32CS_SNAPPROCESS = 0x00000002
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            class PROCESSENTRY32W(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260),
                ]

            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if snap == INVALID_HANDLE_VALUE:
                return info
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
                while True:
                    if pe.th32ProcessID == pid:
                        info["name"] = pe.szExeFile
                        info["threads"] = pe.cntThreads
                        break
                    if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                        break
            kernel32.CloseHandle(snap)
            info["cmdline"] = ""
            info["path"] = info.get("name", "")
            info["memory_regions"] = []
            info["region_count"] = 0
        except Exception:
            pass
        return info

    # 按名称查找进程
    def find_process(self, name: str) -> List[Tuple[int, Dict[str, Any]]]:
        results: List[Tuple[int, Dict[str, Any]]] = []
        for proc in self.list_processes():
            proc_name = proc.get("name", "").lower()
            if name.lower() in proc_name:
                results.append((proc["pid"], proc))
        return results

    # 枚举所有进程
    def list_processes(self) -> List[Dict[str, Any]]:
        procs: List[Dict[str, Any]] = []
        if IS_LINUX:
            for entry in Path("/proc").iterdir():
                if entry.is_dir():
                    try:
                        pid = int(entry.name)
                        info = self.get_process_info(pid)
                        procs.append({"pid": pid, "name": info.get("name", "")})
                    except (ValueError, OSError):
                        continue
        elif IS_WINDOWS:
            try:
                import ctypes
                from ctypes import wintypes
                kernel32 = ctypes.windll.kernel32

                TH32CS_SNAPPROCESS = 0x00000002
                INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

                class PROCESSENTRY32W(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
                        ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", wintypes.LONG),
                        ("dwFlags", wintypes.DWORD),
                        ("szExeFile", wintypes.WCHAR * 260),
                    ]

                snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                if snap != INVALID_HANDLE_VALUE:
                    pe = PROCESSENTRY32W()
                    pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
                    if kernel32.Process32FirstW(snap, ctypes.byref(pe)):
                        while True:
                            procs.append({"pid": pe.th32ProcessID, "name": pe.szExeFile})
                            if not kernel32.Process32NextW(snap, ctypes.byref(pe)):
                                break
                    kernel32.CloseHandle(snap)
            except Exception:
                pass
        return procs


# 进程转储器

class ProcessDumper:
    """
    多技术进程内存转储
    自动检测平台并选择可用方法
    """

    def __init__(self, pid: Optional[int] = None, process_name: Optional[str] = None):
        self.pid = pid
        self.process_name = process_name
        self._scanner = ProcessScanner()
        if not pid and process_name:
            found = self._scanner.find_process(process_name)
            if found:
                self.pid = found[0][0]

    def list_methods(self) -> List[str]:
        """列出当前平台可用的转储方法名。"""
        if IS_LINUX:
            return [m.value for m in (DumpMethod.GCORE, DumpMethod.PROC_MEM)]
        if IS_WINDOWS:
            return [m.value for m in (DumpMethod.PROCDUMP, DumpMethod.MINIDUMP)]
        return []

    # Linux 技术

    def _dump_via_gcore(self, output_path: str) -> bool:
        if not IS_LINUX or not self.pid:
            return False
        if not shutil.which("gcore"):
            _log.warning("gcore 不可用")
            return False
        try:
            subprocess.run(["gcore", "-o", output_path, str(self.pid)],
                          capture_output=True, check=True, timeout=30)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            _log.exception("gcore 转储失败")
            return False

    def _dump_via_proc_mem(self, output_path: str, start: Optional[int] = None,
                           size: Optional[int] = None) -> bool:
        """通过 /proc/pid/mem 读取内存"""
        if not IS_LINUX or not self.pid:
            return False
        try:
            mem_path = f"/proc/{self.pid}/mem"
            regions = self._scanner._parse_maps(self.pid)
            readable = [r for r in regions if r.is_readable]
            if not readable:
                return False
            with open(output_path, "wb") as out:
                with open(mem_path, "rb") as mem:
                    for region in readable:
                        if start is not None and region.start < start:
                            continue
                        actual_size = min(region.size, size) if size is not None else region.size
                        try:
                            mem.seek(region.start)
                            data = mem.read(actual_size)
                            out.write(data)
                        except (IOError, OSError):
                            continue
            return os.path.getsize(output_path) > 0
        except Exception:
            _log.exception("/proc/mem 读取失败")
            return False

    # Windows 技术

    def _dump_via_procdump(self, output_path: str) -> bool:
        if not IS_WINDOWS:
            return False
        procdump_path = shutil.which("procdump.exe") or shutil.which("procdump64.exe")
        if not procdump_path:
            _log.warning("procdump 不可用")
            return False
        try:
            subprocess.run([procdump_path, "-ma", str(self.pid), output_path],
                          capture_output=True, check=True, timeout=60)
            return True
        except Exception:
            _log.exception("procdump 转储失败")
            return False

    def _dump_via_minidump(self, output_path: str) -> bool:
        """
        通过 ctypes 调用 MiniDumpWriteDump
        需要 PROCESS_ALL_ACCESS, 通常需要 SeDebugPrivilege
        """
        if not IS_WINDOWS or not self.pid:
            return False
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            dbghelp = ctypes.windll.dbghelp

            PROCESS_ALL_ACCESS = 0x001F0FFF
            MiniDumpNormal = 0x00000000
            MiniDumpWithFullMemory = 0x00000002
            MiniDumpWithHandleData = 0x00000004
            MiniDumpWithFullMemoryInfo = 0x00000800
            MiniDumpWithThreadInfo = 0x00001000

            dump_type = (MiniDumpNormal | MiniDumpWithFullMemory |
                        MiniDumpWithHandleData | MiniDumpWithFullMemoryInfo |
                        MiniDumpWithThreadInfo)

            hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
            if not hProcess:
                _log.error("OpenProcess 失败 (pid=%d), 可能需要管理员权限", self.pid)
                return False

            hFile = kernel32.CreateFileW(
                output_path,
                0x40000000,  # GENERIC_WRITE
                0, None,
                2,  # CREATE_ALWAYS
                0x80,  # FILE_ATTRIBUTE_NORMAL
                None
            )
            if hFile == ctypes.c_void_p(-1).value:
                kernel32.CloseHandle(hProcess)
                _log.error("CreateFileW 失败: %s", output_path)
                return False

            result = dbghelp.MiniDumpWriteDump(
                hProcess, self.pid, hFile,
                dump_type,
                None, None, None
            )

            kernel32.CloseHandle(hFile)
            kernel32.CloseHandle(hProcess)
            return bool(result)
        except Exception:
            _log.exception("MiniDumpWriteDump 失败")
            return False

    # 公开 API

    def dump_full(self, output_path: str) -> Optional[str]:
        """
        完整内存转储
        依次尝试可用方法，返回成功使用的输出路径
        """
        methods: List[Tuple[str, Callable]] = []
        if IS_LINUX:
            methods = [
                ("gcore", lambda p: self._dump_via_gcore(p)),
                ("proc_mem", lambda p: self._dump_via_proc_mem(p)),
            ]
        elif IS_WINDOWS:
            methods = [
                ("procdump", lambda p: self._dump_via_procdump(p)),
                ("minidump", lambda p: self._dump_via_minidump(p)),
            ]

        for name, fn in methods:
            _log.info("尝试 %s 转储...", name)
            final_path = output_path
            if name == "gcore":
                final_path = output_path + f".{self.pid}"
            try:
                if fn(final_path):
                    _log.info("转储成功: %s → %s", name, final_path)
                    return final_path
            except Exception:
                _log.exception("%s 异常，尝试下一个方法", name)
        return None

    def dump_sections(self, output_dir: str,
                      sections: List[str] = None) -> Dict[str, str]:
        """
        按段名选择性转储
        返回 section_name → file_path 映射
        """
        if sections is None:
            sections = ["text", "data", "rodata"]
        result: Dict[str, str] = {}
        if not IS_LINUX or not self.pid:
            return result
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(f"/proc/{self.pid}/mem", "rb") as mem:
                regions = self._scanner._parse_maps(self.pid)
                for section in sections:
                    matched = [r for r in regions
                              if section in r.path or section in r.permissions]
                    if not matched:
                        continue
                    out_file = os.path.join(output_dir, f"{section}.bin")
                    with open(out_file, "wb") as out:
                        for region in matched:
                            try:
                                mem.seek(region.start)
                                out.write(mem.read(region.size))
                            except (IOError, OSError):
                                continue
                    result[section] = out_file
        except Exception:
            _log.exception("分节转储失败")
        return result

    def dump_range(self, output_path: str, start: int, size: int) -> Optional[str]:
        """指定地址范围转储"""
        if IS_LINUX and self.pid:
            ok = self._dump_via_proc_mem(output_path, start, size)
            return output_path if ok else None
        return None
