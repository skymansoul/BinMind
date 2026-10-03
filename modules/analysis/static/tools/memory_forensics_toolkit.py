import struct
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    base_addr: int = 0
    size: int = 0
    num_threads: int = 0
    create_time: int = 0
    is_suspicious: bool = False
    suspicions: List[str] = field(default_factory=list)


@dataclass
class Driver:
    name: str
    base_addr: int = 0
    size: int = 0
    path: str = ""
    is_signed: bool = False
    is_suspicious: bool = False


@dataclass
class SSDTEntry:
    index: int
    service_name: str
    current_addr: int
    expected_addr: int
    is_hooked: bool = False


LIME_MAGIC = b"EMiL"
MZ_SIGNATURE = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

# _EPROCESS offsets (64-bit Windows, approximate)
EP_NAME   = 0x450   # ImageFileName
EP_PID    = 0x2E0   # UniqueProcessId
EP_LINKS  = 0x2F0   # ActiveProcessLinks
EP_PPID   = 0x340   # InheritedFromUniqueProcessId
EP_THREADS= 0x3C8   # ActiveThreads
EP_CTIME  = 0x2E8   # CreateTime
EP_SECTION= 0x3C0   # SectionBaseAddress

KERNEL_BASES = [
    0xFFFFF80000000000, 0xFFFFFFFF80000000,
    0xFFFFF80100000000, 0xFFFFF80200000000, 0xFFFFF80300000000,
]

REFLECTIVE_PATTERNS = [
    b"\x50\xC3",                # push rax; ret
    b"\xE8\x00\x00\x00\x00\x5B",# call $+5; pop rbx
    b"\x53\x56\x57",            # push rbx; push rsi; push rdi
]


class MemoryForensicsToolkit:
    """内存取证分析引擎: 进程枚举, 注入检测, rootkit狩猎, 隐藏模块扫描"""

    def __init__(self, dump_path: str, platform: Optional[str] = None) -> None:
        with open(dump_path, "rb") as fh:
            self._data = fh.read()
        self.platform = platform or self.detect_platform(self._data)
        self._word_size = 8
        if self.platform == "windows":
            self._kernel_base = self._find_kernel_base(self._data)
        elif self.platform == "linux":
            self._kernel_base = 0
        else:
            self._kernel_base = 0

# platform detection

    @staticmethod
    def detect_platform(data: bytes) -> str:
        """检查 MZ+PE first (Windows), LiME magic (Linux)"""
        for off in range(0, min(len(data), 32 * 1024 * 1024), 0x1000):
            if off + 2 > len(data):
                break
            if data[off:off + 2] == MZ_SIGNATURE:
                pe_rva = struct.unpack_from("<I", data, off + 0x3C)[0]
                if (off + pe_rva + 4 <= len(data)
                        and data[off + pe_rva:off + pe_rva + 4] == PE_SIGNATURE):
                    return "windows"
        if data.find(LIME_MAGIC) != -1:
            return "linux"
        return "unknown"

# Windows 进程枚举

    def parse_windows_processes(self, data: Optional[bytes] = None) -> List[Process]:
        """EPROCESS chain walk: PsActiveProcessHead -> ActiveProcessLinks"""
        if data is None:
            data = self._data
        procs: Dict[int, Process] = {}

        # Scan for EPROCESS-like structures ImageFileName heuristics
        stop = min(len(data), 128 * 1024 * 1024)
        i = 0
        while i < stop - EP_NAME - 16:
            if i + EP_NAME + 16 > stop:
                break
            name = self._read_str(data, i + EP_NAME, 16)
            if self._is_win_name(name) and len(name) >= 3:
                try:
                    pid = struct.unpack_from("<I", data, i + EP_PID)[0]
                    if pid == 0 or pid > 0xFFFF:
                        i += 1; continue
                    procs[pid] = Process(
                        pid=pid,
                        ppid=struct.unpack_from("<I", data, i + EP_PPID)[0],
                        name=name,
                        base_addr=struct.unpack_from("<Q", data, i + EP_SECTION)[0],
                        num_threads=struct.unpack_from("<I", data, i + EP_THREADS)[0],
                        create_time=struct.unpack_from("<Q", data, i + EP_CTIME)[0],
                    )
                    i += 0x80
                except struct.error:
                    i += 1
            else:
                i += 1

        # Walk ActiveProcessLinks doubly-linked list
        if self._kernel_base:
            linked = self._walk_links(data, EP_LINKS, EP_NAME, EP_PID, EP_PPID)
            for p in linked:
                procs[p.pid] = p

        return sorted(procs.values(), key=lambda p: p.pid)

    def _walk_links(self, data: bytes, links_off: int, name_off: int,
                    pid_off: int, ppid_off: int) -> List[Process]:
        procs: List[Process] = []
        visited: set = set()
        cand = self._scan_eprocess(data)
        if not cand:
            return procs
        start = cand[len(cand) // 2] + links_off
        flink = start
        for _ in range(1024):
            if flink in visited:
                break
            visited.add(flink)
            ep = flink - links_off
            if ep + 0x800 > len(data):
                break
            try:
                name = self._read_str(data, ep + name_off, 16)
                if not self._is_win_name(name):
                    flink = self._read_ptr(data, flink); continue
                procs.append(Process(
                    pid=struct.unpack_from("<I", data, ep + pid_off)[0],
                    ppid=struct.unpack_from("<I", data, ep + ppid_off)[0],
                    name=name,
                ))
            except struct.error:
                break
            nxt = self._read_ptr(data, flink)
            if nxt == start or nxt == 0:
                break
            flink = nxt
        return procs

    def _scan_eprocess(self, data: bytes) -> List[int]:
        cand: List[int] = []
        stop = min(len(data), 128 * 1024 * 1024)
        i = 0
        while i < stop - EP_NAME - 16:
            name = self._read_str(data, i + EP_NAME, 16)
            if self._is_win_name(name) and len(name) >= 3:
                cand.append(i); i += 0x80
            else:
                i += 1
        return cand

    @staticmethod
    def _is_win_name(name: str) -> bool:
        if not name or not all(c.isprintable() and not c.isspace() for c in name):
            return False
        return (name.endswith((".exe", ".dll", ".sys"))
                or name in ("System", "Idle")
                or any(name.startswith(p) for p in ("svchost", "csrss", "winlogon", "lsass")))

# Linux (LiME) process enumeration

    def parse_linux_processes(self, data: Optional[bytes] = None) -> List[Process]:
        """Walk task_struct list via LiME header"""
        if data is None:
            data = self._data
        lime = data.find(LIME_MAGIC)
        if lime == -1:
            return []
        try:
            _, start_addr, end_addr, _ = struct.unpack_from("<IQQQ", data, lime + 4)
        except struct.error:
            return []
        start = lime + 28 if start_addr < lime else 0
        return self._scan_tasks(data, start)

    def _scan_tasks(self, data: bytes, start: int) -> List[Process]:
        procs: List[Process] = []
        stop = min(len(data), start + 512 * 1024 * 1024)
        seen: set = set()
        comm_offs = [0x6E0, 0x6E8, 0x6D0, 0x6F0, 0x540, 0x548]

        i = start
        while i < stop - 0x800:
            found = False
            for co in comm_offs:
                p = i + co
                if p + 16 > stop:
                    continue
                name = self._read_str(data, p, 16)
                if name and len(name) >= 2 and all(32 <= ord(c) < 127 for c in name):
                    try:
                        pid = struct.unpack_from("<I", data, p - 4)[0]
                        tid = struct.unpack_from("<I", data, p - 8)[0]
                    except struct.error:
                        pid = tid = 0
                    pv = pid if 0 < pid < 0x800000 else tid
                    if 0 < pv < 0x800000 and pv not in seen:
                        seen.add(pv)
                        procs.append(Process(pid=pv, ppid=0, name=name, base_addr=i))
                        found = True; break
            i += (0x400 if found else 1)
        return procs

# 注入检测

    def detect_injection(self, data: Optional[bytes] = None,
                         processes: Optional[List[Process]] = None) -> List[Dict[str, Any]]:
        """检测 reflective DLL stubs, process hollowing, RWX regions"""
        if data is None:
            data = self._data
        if processes is None:
            processes = []
        findings: List[Dict[str, Any]] = []

        for pat in REFLECTIVE_PATTERNS:
            for pos in self._scan(data, pat)[:10]:
                findings.append({
                    "type": "reflective_loader_stub",
                    "process": None,
                    "evidence": f"Pattern {pat.hex()} at 0x{pos:X}",
                    "confidence": 0.45,
                })

        for proc in processes:
            if proc.base_addr == 0:
                continue
            s = proc.base_addr + max(proc.size, 0x1000)
            e = min(s + 16 * 1024 * 1024, len(data))
            if e > s and self._scan(data, b"MZ\x00", start=s):
                findings.append({
                    "type": "process_hollowing",
                    "process": proc.name,
                    "evidence": f"MZ after base of {proc.name}",
                    "confidence": 0.65,
                })

        for va in self._find_rwx(data):
            findings.append({
                "type": "rwx_memory_region",
                "process": None,
                "evidence": f"RWX section at VA 0x{va:X}",
                "confidence": 0.55,
            })
        return findings

    def _find_rwx(self, data: bytes) -> List[int]:
        sections: List[int] = []
        for mz in self._scan(data, b"MZ")[:200]:
            try:
                pr = struct.unpack_from("<I", data, mz + 0x3C)[0]
                pe = mz + pr
                if data[pe:pe + 4] != PE_SIGNATURE:
                    continue
                ns = struct.unpack_from("<H", data, pe + 6)[0]
                oh = struct.unpack_from("<H", data, pe + 20)[0]
                st = pe + 24 + oh
                for s in range(ns):
                    sb = st + s * 40
                    ch = struct.unpack_from("<I", data, sb + 36)[0]
                    if (ch & 0xA0000000) == 0xA0000000:  # W^X
                        sections.append(struct.unpack_from("<I", data, sb + 12)[0])
            except struct.error:
                continue
        return sections

# Rootkit 检测

    def hunt_rootkits(self, data: Optional[bytes] = None,
                      processes: Optional[List[Process]] = None) -> List[Dict[str, Any]]:
        """SSDT 钩子s + IDT 检查 + DKOM hidden process detection"""
        if data is None:
            data = self._data
        if processes is None:
            processes = []
        findings: List[Dict[str, Any]] = []
        findings.extend(self._check_ssdt(data))
        findings.extend(self._check_idt(data))
        findings.extend(self._detect_dkom(data, processes))
        return findings

    def _check_ssdt(self, data: bytes) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self._kernel_base == 0:
            return findings
        found = self._scan(data, b"\x4C\x8D\x15", start=self._kernel_base)
        for m in found:
            try:
                disp = struct.unpack_from("<i", data, m + 3)[0]
                ksdt = m + 7 + disp
                sst = self._read_ptr(data, ksdt)
                cnt = struct.unpack_from("<I", data, ksdt + 8)[0]
                if cnt == 0 or cnt > 10000 or sst < self._kernel_base:
                    continue
                for idx in range(min(cnt, 2000)):
                    ea = sst + idx * 4
                    if ea + 4 > len(data):
                        break
                    enc = struct.unpack_from("<I", data, ea)[0]
                    if enc == 0:
                        continue
                    handler = (sst & 0xFFFFFFFF00000000) | (enc >> 4)
                    if not (self._kernel_base <= handler < self._kernel_base + 0x1000000):
                        findings.append({
                            "type": "ssdt_hook",
                            "process": None,
                            "evidence": f"SSDT[{idx}] -> 0x{handler:X} (outside ntoskrnl)",
                            "confidence": 0.85,
                        })
            except struct.error:
                continue
        return findings

    def _check_idt(self, data: bytes) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if self._kernel_base == 0:
            return findings
        for idt in range(0xFFFFF80000000000, min(len(data), 0xFFFFF90000000000), 0x1000):
            if idt + 256 * 16 > len(data):
                break
            handlers: List[int] = []
            for i in range(256):
                off = idt + i * 16
                try:
                    lo = struct.unpack_from("<H", data, off)[0]
                    hi = struct.unpack_from("<H", data, off + 6)[0]
                    mid = struct.unpack_from("<I", data, off + 8)[0]
                except struct.error:
                    break
                if not (data[off + 5] & 0x80):  # present bit
                    handlers.append(0)
                else:
                    handlers.append((hi << 48) | (mid << 16) | lo)
            if len([h for h in handlers if h != 0]) >= 64:
                for idx, h in enumerate(handlers):
                    if h and not (self._kernel_base <= h < self._kernel_base + 0x1000000):
                        findings.append({
                            "type": "idt_hook",
                            "process": None,
                            "evidence": f"IDT[{idx}] -> 0x{h:X} outside kernel",
                            "confidence": 0.80,
                        })
                break
        return findings

    def _detect_dkom(self, data: bytes, processes: List[Process]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not processes:
            return findings
        owners: Dict[int, int] = {}
        for toff in self._scan(data, b"\x54\x68\x72\x65\x61\x64")[:500]:  # "Thread"
            try:
                o = struct.unpack_from("<Q", data, toff + 0x380)[0]
                if o:
                    owners[o] = owners.get(o, 0) + 1
            except struct.error:
                continue
        known = {p.base_addr for p in processes}
        for ep, tc in owners.items():
            if ep not in known and tc > 0:
                findings.append({
                    "type": "dkom_hidden_process",
                    "process": None,
                    "evidence": f"EPROCESS 0x{ep:X} has {tc} threads, not in process list",
                    "confidence": 0.70,
                })
        return findings

# 隐藏模块扫描

    def scan_hidden_modules(self, data: Optional[bytes] = None) -> List[Dict[str, Any]]:
        """比较 驱动 strings against PE export names 查找 unlinked modules"""
        if data is None:
            data = self._data
        findings: List[Dict[str, Any]] = []
        if self._kernel_base == 0:
            return findings

        known: Dict[str, int] = {}
        for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{3,20}\.sys\x00", data):
            name = m.group().rstrip(b"\x00").decode("ascii", errors="ignore")
            known[name] = m.start()

        for mz in self._scan(data, b"MZ")[:200]:
            try:
                pr = struct.unpack_from("<I", data, mz + 0x3C)[0]
                pe = mz + pr
                if data[pe:pe + 4] != PE_SIGNATURE:
                    continue
                exp = struct.unpack_from("<I", data, pe + 0x70)[0]
                if exp == 0:
                    continue
                mod = self._read_str(data, mz + exp + 24, 64)
                if mod.endswith((".sys", ".dll")):
                    known.pop(mod, None)
            except (struct.error, IndexError):
                continue

        for name, addr in known.items():
            findings.append({
                "type": "hidden_driver",
                "name": name,
                "evidence": f"\"{name}\" at 0x{addr:X} unlinked from module list",
                "confidence": 0.60,
            })
        return findings

# 辅助函数

    def _read_ptr(self, data: bytes, addr: int) -> int:
        if addr < 0 or addr + 8 > len(data):
            return 0
        try:
            return struct.unpack_from("<Q", data, addr)[0]
        except struct.error:
            return 0

    def _read_str(self, data: bytes, addr: int, max_len: int = 256) -> str:
        if addr < 0 or addr >= len(data):
            return ""
        chunk = data[addr:min(addr + max_len, len(data))]
        null = chunk.find(b"\x00")
        raw = chunk if null == -1 else chunk[:null]
        return raw.decode("ascii", errors="replace").strip()

    def _scan(self, data: bytes, pattern: bytes, start: int = 0) -> List[int]:
        """Byte scan; 0xCC pattern = wildcard (byte)"""
        results: List[int] = []
        pl = len(pattern)
        dl = len(data)
        if pl == 0 or start >= dl:
            return results
        pos = start
        while pos <= dl - pl:
            if all(pattern[j] in (0xCC, data[pos + j]) for j in range(pl)):
                results.append(pos)
            pos += 1
        return results

    def _find_kernel_base(self, data: bytes) -> int:
        for base in KERNEL_BASES:
            for delta in range(0, 0x2000000, 0x1000):
                addr = base + delta
                if addr + 2 > len(data):
                    break
                fo = addr & 0x1FFFFFFF
                if fo + 0x400 > len(data):
                    continue
                if data[fo:fo + 2] == MZ_SIGNATURE:
                    pr = struct.unpack_from("<I", data, fo + 0x3C)[0]
                    so = fo + pr
                    if so + 4 <= len(data) and data[so:so + 4] == PE_SIGNATURE:
                        return addr
        return 0

    @staticmethod
    def _section_entropy(data_section: bytes) -> float:
        if not data_section:
            return 0.0
        n = len(data_section)
        counts = Counter(data_section)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

# 统一分析

    def analyze(self) -> Dict[str, Any]:
        processes = (
            self.parse_windows_processes() if self.platform == "windows"
            else self.parse_linux_processes() if self.platform == "linux"
            else []
        )
        injection = self.detect_injection(processes=processes)
        rootkits = self.hunt_rootkits(processes=processes)
        hidden = self.scan_hidden_modules()

        return {
            "platform": self.platform,
            "kernel_base": hex(self._kernel_base) if self._kernel_base else None,
            "process_count": len(processes),
            "processes": [{
                "pid": p.pid, "ppid": p.ppid, "name": p.name,
                "base_addr": hex(p.base_addr) if p.base_addr else None,
                "num_threads": p.num_threads,
                "is_suspicious": p.is_suspicious,
                "suspicions": p.suspicions,
            } for p in processes],
            "injection_findings": injection,
            "rootkit_findings": rootkits,
            "hidden_modules": hidden,
            "total_alerts": len(injection) + len(rootkits) + len(hidden),
        }
