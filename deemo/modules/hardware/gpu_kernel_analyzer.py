MemoryAccess=None
from typing import Optional
"""
GPU kernel analysis for CUDA/OpenCL binaries.
Detects shared memory bank conflicts, uncoalesced memory access patterns,
and atomic operation bottlenecks in SASS/PTX/GCN assembly.
"""

import re
import struct
from enum import IntEnum, Enum
from collections import Counter, defaultdict
from dataclasses import dataclass


# --- Architecture definitions ---
class GPUArchitecture:
    SM_70 = "sm_70"; SM_75 = "sm_75"; SM_80 = "sm_80"
    SM_86 = "sm_86"; SM_90 = "sm_90"
    CUDA_SM_80 = SM_80; CUDA_SM_86 = SM_86; CUDA_SM_90 = SM_90

    WARP_SIZE = 32
    @classmethod
    def shared_mem_banks(cls, arch: str) -> int:
        return 32  # NVIDIA uses 32 banks (4-byte) on all modern archs


# --- SASS opcode patterns for memory operations ---
_SASS_LD_PATTERNS = re.compile(
    rb'(?:LD|LDG|LDL|LDS|LDC)\s', re.IGNORECASE)
_SASS_ST_PATTERNS = re.compile(
    rb'(?:ST|STG|STL|STS|STC)\s', re.IGNORECASE)
_SASS_ATOM_PATTERNS = re.compile(
    rb'(?:ATOM|ATOMG|RED|ATOMS)\s', re.IGNORECASE)
_SASS_BAR_PATTERNS = re.compile(
    rb'(?:BAR|BAR\.SYNC|MEMBAR|FENCE)\s', re.IGNORECASE)

# --- PTX opcode regex ---
_PTX_LD = re.compile(r'\bld\.(?:global|shared|local|const)\b')
_PTX_ST = re.compile(r'\bst\.(?:global|shared|local)\b')
_PTX_ATOM = re.compile(r'\batom\.(?:add|cas|exch|inc|dec|min|max|and|or|xor)\b')
_PTX_BAR = re.compile(r'\bbar(?:\.sync|\.arrive)?\b')


class VulnCategory(str, Enum):
    RACE_CONDITION = "race_condition"
    OUT_OF_BOUNDS = "out_of_bounds"
    DIVERGENCE = "divergence"
    SHARED_MEMORY_RACE = "shared_memory_race"
    MEMORY_LEAK = "memory_leak"
    BANK_CONFLICT = "bank_conflict"
    UNCOALESCED_ACCESS = "uncoalesced_access"
    ATOMIC_CONTENTION = "atomic_contention"


@dataclass
class GPUVulnerability:
    type: str = ""
    severity: str = "info"
    location: str = ""


@dataclass
class MemoryAccessPattern:
    coalesced: bool = True
    bank_conflicts: int = 0
    stride: int = 1
    alignment: int = 16


@dataclass
class ThreadSynchronization:
    barriers: list[int] = None
    race_free: bool = True

    def __post_init__(self):
        if self.barriers is None:
            self.barriers = []


@dataclass
class AnalysisReport:
    findings: list = None
    score: int = 0
    warnings: list = None
    metrics: dict = None

    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.warnings is None:
            self.warnings = []
        if self.metrics is None:
            self.metrics = {}


class PTXParser:
    """Parse CUDA PTX intermediate representation."""

    KERNEL_RE = re.compile(r'\.(?:visible\s+)?\.entry\s+(\w+)', re.MULTILINE)
    REG_RE = re.compile(r'%r\d+')
    PRED_RE = re.compile(r'%p\d+')

    def parse(self, source: str) -> dict:
        kernels = {}
        for entry_m in self.KERNEL_RE.finditer(source):
            name = entry_m.group(1)
            start = entry_m.end()
            end = source.find('\n}', start)
            if end == -1:
                end = len(source)
            body = source[start:end]
            kernels[name] = {
                "name": name,
                "instructions": self._count_insns(body),
                "registers": len(set(self.REG_RE.findall(body))),
                "predicates": len(set(self.PRED_RE.findall(body))),
                "shared_mem_accesses": len(_PTX_LD.findall(body)) + len(_PTX_ST.findall(body)),
                "atomics": len(_PTX_ATOM.findall(body)),
                "barriers": len(_PTX_BAR.findall(body)),
            }
        total_insns = sum(k["instructions"] for k in kernels.values()) if kernels else 0
        return {"kernels": list(kernels.values()), "instructions": total_insns}

    @staticmethod
    def _count_insns(body: str) -> int:
        return len([l for l in body.split('\n')
                    if l.strip() and not l.strip().startswith('//') and ';' in l])


class SASSAnalyzer:
    """Analyze NVIDIA SASS (native GPU assembly)."""

    BANK_CONFLICT_THRESHOLD = 2
    UNCOALESCED_STRIDE = 4

    def analyze(self, sass: bytes) -> dict:
        instructions = []
        hazards = []
        ld_addrs = []
        st_addrs = []
        atom_counts = 0
        bar_counts = 0
        raw_text = sass if isinstance(sass, str) else sass.decode('ascii', errors='replace')

        for i, line in enumerate(raw_text.split('\n')):
            stripped = line.strip()
            if not stripped or stripped.startswith('//'):
                continue
            instructions.append(stripped)

            # Check for shared memory bank conflicts
            if 'STS' in stripped or 'LDS' in stripped:
                # Extract offset from operand
                off_m = re.search(r'0x([0-9a-fA-F]+)', stripped)
                if off_m:
                    offset = int(off_m.group(1), 16)
                    bank = (offset // 4) % 32
                    ld_addrs.append(bank)
                    if bank in ld_addrs[:-1]:
                        hazards.append({
                            "type": "bank_conflict",
                            "line": i,
                            "instruction": stripped,
                            "bank": bank})

            if 'LDG' in stripped or 'STG' in stripped:
                off_m = re.search(r'0x([0-9a-fA-F]+)', stripped)
                if off_m:
                    st_addrs.append(int(off_m.group(1), 16))

            if 'ATOM' in stripped:
                atom_counts += 1

            if 'BAR' in stripped or 'MEMBAR' in stripped:
                bar_counts += 1

        # Check global memory coalescing
        uncoalesced = self._check_coalescing(st_addrs)

        return {
            "instructions": instructions,
            "hazards": hazards,
            "atom_count": atom_counts,
            "barrier_count": bar_counts,
            "uncoalesced_accesses": uncoalesced}

    @staticmethod
    def _check_coalescing(offsets: list[int]) -> list[dict]:
        """Detect non-coalesced access: offsets should be contiguous per warp."""
        findings = []
        if len(offsets) < 2:
            return findings
        diffs = [offsets[i + 1] - offsets[i] for i in range(len(offsets) - 1)]
        for i, d in enumerate(diffs):
            if d > 128:  # > 4 bytes apart per thread -> non-coalesced
                findings.append({"offset": offsets[i],
                                 "stride": d,
                                 "issue": f"stride={d} > 128"})
        return findings


class CUBINParser:
    """Parse CUDA cubin binary: ELF container with SASS segments."""

    MAGIC = b"\x7fCUBIN"

    ELF_MAGIC = b"\x7fELF"

    def __init__(self, path: str = ""):
        self._path = path

    def parse(self, bin_path: Optional[str] = None) -> dict:
        path = bin_path or self._path
        with open(path, "rb") as f:
            data = f.read()

        if not data.startswith(self.ELF_MAGIC) and not data.startswith(self.MAGIC):
            raise ValueError(f"Not a valid CUBIN file: {path}")

        # Parse ELF sections
        kernels = []
        if data.startswith(self.ELF_MAGIC):
            ei_class = data[4]  # 1=32bit, 2=64bit
            if ei_class == 2:
                e_shoff, e_shentsize, e_shnum = struct.unpack_from("<QQH", data, 40)
            else:
                e_shoff, e_shentsize, e_shnum = struct.unpack_from("<IIH", data, 32)

            for i in range(e_shnum):
                shdr_off = e_shoff + i * e_shentsize
                if ei_class == 2:
                    sh_name, sh_type, sh_flags = struct.unpack_from("<III", shdr_off, 0)
                    offset, size = struct.unpack_from("<QQ", shdr_off, 24)
                else:
                    sh_name, sh_type, sh_flags = struct.unpack_from("<III", shdr_off, 0)
                    offset, size = struct.unpack_from("<II", shdr_off, 16)

                # SHT_PROGBITS with SHF_EXECINSTR
                if sh_type == 1 and (sh_flags & 0x4):
                    seg = data[offset:offset + size]
                    sass = SASSAnalyzer()
                    result = sass.analyze(seg)
                    kernels.append({
                        "section_index": i,
                        "instructions": len(result.get("instructions", [])),
                        "hazards": len(result.get("hazards", []))})

        total_insns = sum(k["instructions"] for k in kernels) if kernels else 0
        return {"kernels": kernels, "instructions": total_insns,
                "arch": self._guess_arch(data)}

    @staticmethod
    def _guess_arch(data: bytes) -> str:
        text = data.decode('ascii', errors='replace')
        for arch in ("sm_90", "sm_89", "sm_87", "sm_86", "sm_80",
                     "sm_75", "sm_72", "sm_70", "sm_61"):
            if arch in text:
                return arch
        return "sm_80"

class DataRaceDetector:
    """Detect shared memory races by tracking barrier coverage."""

    def __init__(self):
        self._access_graph: dict[str, list[str]] = defaultdict(list)
        self._barriers: list[int] = []

    def detect(self, kernel_lines: list[str]) -> list[dict]:
        """Find shared mem accesses between barriers that may race."""
        reports = []
        shared_writes = []
        last_barrier = -1

        for i, line in enumerate(kernel_lines):
            stripped = line.strip()
            if 'STS' in stripped or 'ATOMS' in stripped:
                shared_writes.append(i)
            if 'BAR' in stripped or 'MEMBAR' in stripped:
                if shared_writes and last_barrier < min(shared_writes):
                    reports.append({
                        "type": "potential_race",
                        "lines": shared_writes,
                        "barrier_before": last_barrier,
                        "barrier_at": i})
                shared_writes = []
                last_barrier = i
                self._barriers.append(i)

        if shared_writes:
            reports.append({
                "type": "unprotected_write",
                "lines": shared_writes,
                "barrier_before": last_barrier,
                "barrier_at": "END"})

        return reports


class GPUKernelAnalyzer:
    """Orchestrate GPU kernel security analysis across SASS, PTX, and CUBIN."""

    def __init__(self):
        self._ptx = PTXParser()
        self._sass = SASSAnalyzer()
        self._cubin = CUBINParser()
        self._race_detector = DataRaceDetector()
        self._last_report: Optional[AnalysisReport] = None

    def analyze(self, kernel=None, source_code=None, binary=None) -> AnalysisReport:
        report = AnalysisReport(score=100)

        if source_code:
            ptx = self._ptx.parse(source_code)
            report.metrics["ptx_instructions"] = ptx.get("instructions", 0)
            report.metrics["ptx_kernels"] = len(ptx.get("kernels", []))
            for k in ptx.get("kernels", []):
                if k.get("atomics", 0) > 0:
                    report.warnings.append(
                        f"PTX kernel '{k['name']}' uses {k['atomics']} atomics")
                    report.score -= 5
                if k.get("shared_mem_accesses", 0) > 0 and k.get("barriers", 0) == 0:
                    report.warnings.append(
                        f"PTX kernel '{k['name']}' has shared memory access without barriers")
                    report.score -= 15

        if binary:
            if isinstance(binary, str) or (isinstance(binary, bytes) and binary[:len(CUBINParser.MAGIC)] == CUBINParser.MAGIC):
                cubin = self._cubin.parse(binary if isinstance(binary, str) else None)
                report.metrics["cubin_instructions"] = cubin.get("instructions", 0)
                for k in cubin.get("kernels", []):
                    if k.get("hazards", 0) > 0:
                        report.warnings.append(f"Section {k['section_index']}: {k['hazards']} SASS hazards")
                        report.score -= 10
            else:
                sass = self._sass.analyze(binary)
                report.metrics["sass_instructions"] = len(sass.get("instructions", []))
                report.metrics["sass_hazards"] = len(sass.get("hazards", []))
                report.metrics["sass_atomics"] = sass.get("atom_count", 0)
                for h in sass.get("hazards", []):
                    report.findings.append(
                        GPUVulnerability("bank_conflict", "medium", f"line {h['line']}"))
                if sass.get("atom_count", 0) > 10:
                    report.warnings.append(f"High atomic contention: {sass['atom_count']} atomics")
                    report.score -= 8

        report.score = max(0, report.score)
        self._last_report = report
        return report

    def detect_race_conditions(self, kernel_lines: list[str]) -> list[dict]:
        return self._race_detector.detect(kernel_lines)

    def detect_side_channels(self, kernel: bytes) -> list:
        """Detect timing side-channels in GPU kernels (clock() calls, divergent branches)."""
        findings = []
        text = kernel.decode('ascii', errors='replace') if isinstance(kernel, bytes) else kernel
        if 'clock()' in text or 'clock64()' in text:
            findings.append({"type": "timing_side_channel",
                             "detail": "GPU clock query in kernel may leak timing info"})
        return findings
KernelInfo=None
