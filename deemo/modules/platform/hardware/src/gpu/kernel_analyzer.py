# GPU Kernel分析器, SASS/PTX/CUBIN安全漏洞分析
# 局限: bank conflict检测基于32-bank模型, 未覆盖Ampere+可能的bank布局差异
import re
import struct
from enum import Enum, auto as _unused_auto  # 未使用
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple


class GPUArchitecture:
	SM_70 = "sm_70"; SM_75 = "sm_75"; SM_80 = "sm_80"
	SM_86 = "sm_86"; SM_90 = "sm_90"
	CUDA_SM_80 = SM_80; CUDA_SM_86 = SM_86; CUDA_SM_90 = SM_90
	WARP_SIZE = 32
	MAX_REGISTERS_PER_THREAD: Dict[str, int] = {
		"sm_70": 255, "sm_75": 255, "sm_80": 255,
		"sm_86": 255, "sm_90": 255,
	}
	MAX_SHARED_MEM_PER_BLOCK: Dict[str, int] = {
		"sm_70": 65536, "sm_75": 65536, "sm_80": 163840,
		"sm_86": 163840, "sm_90": 227072,
	}

	@classmethod
	def shared_mem_banks(cls, arch: str) -> int:
		return 32  # 所有现代NVIDIA架构使用32个bank（4字节/ bank）


# SASS操作码模式, 内存操作
_SASS_LD_PATTERNS = re.compile(rb'(?:LD|LDG|LDL|LDS|LDC)\s', re.IGNORECASE)
_SASS_ST_PATTERNS = re.compile(rb'(?:ST|STG|STL|STS|STC)\s', re.IGNORECASE)
_SASS_ATOM_PATTERNS = re.compile(rb'(?:ATOM|ATOMG|RED|ATOMS)\s', re.IGNORECASE)
_SASS_BAR_PATTERNS = re.compile(rb'(?:BAR|BAR\.SYNC|MEMBAR|FENCE)\s', re.IGNORECASE)
# PTX操作码正则
_PTX_LD = re.compile(r'\bld\.(?:global|shared|local|const)\b')
_PTX_ST = re.compile(r'\bst\.(?:global|shared|local)\b')
_PTX_ATOM = re.compile(r'\batom\.(?:add|cas|exch|inc|dec|min|max|and|or|xor)\b')
_PTX_BAR = re.compile(r'\bbar(?:\.sync|\.arrive)?\b')
# Warp分支发散检测模式
_PTX_BRANCH = re.compile(r'\bbra\b|\bbrx\b|\b@%p\d+\s+bra\b')
_SASS_BRANCH = re.compile(rb'(?:BRA|BRX|JMP|JCAL|JCALL)\s', re.IGNORECASE)
_SASS_PREDICATED = re.compile(rb'@!?P\d+\s', re.IGNORECASE)


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
class WarpDivergenceInfo:
	# Warp内分支发散度量
	divergent_warp_count: int = 0
	avg_divergent_threads: float = 0.0
	divergent_branches: List[int] = field(default_factory=list)


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
	# 解析CUDA PTX中间表示
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
			branch_count = len(_PTX_BRANCH.findall(body))
			kernels[name] = {
				"name": name,
				"instructions": self._count_insns(body),
				"registers": len(set(self.REG_RE.findall(body))),
				"predicates": len(set(self.PRED_RE.findall(body))),
				"shared_mem_accesses": len(_PTX_LD.findall(body)) + len(_PTX_ST.findall(body)),
				"atomics": len(_PTX_ATOM.findall(body)),
				"barriers": len(_PTX_BAR.findall(body)),
				"branches": branch_count,
			}
		total_insns = sum(k["instructions"] for k in kernels.values()) if kernels else 0
		return {"kernels": list(kernels.values()), "instructions": total_insns}

	@staticmethod
	def _count_insns(body: str) -> int:
		return len([l for l in body.split('\n')
					if l.strip() and not l.strip().startswith('//') and ';' in l])


class SASSAnalyzer:
	# 分析NVIDIA SASS（原生GPU汇编）
	BANK_CONFLICT_THRESHOLD = 2
	UNCOALESCED_STRIDE = 4

	# 暂留 — 旧版寄存器压力估计, 依赖SASS寄存器名解析, 精度不足已弃用
	# def _resolve_register_pressure(self, instructions: list) -> int:
	# 	return len(set(re.findall(r'R\d+', ' '.join(instructions))))

	def analyze(self, sass: bytes) -> dict:
		instructions = []
		hazards = []
		bank_access_map: Dict[int, List[int]] = defaultdict(list)
		st_addrs = []
		atom_counts = 0
		bar_counts = 0
		predicated_groups: Dict[int, List[int]] = defaultdict(list)
		raw_text = sass if isinstance(sass, str) else sass.decode('ascii', errors='replace')

		for i, line in enumerate(raw_text.split('\n')):
			stripped = line.strip()
			if not stripped or stripped.startswith('//'):
				continue
			instructions.append(stripped)

			# 追踪当前活跃谓词
			pred_match = _SASS_PREDICATED.search(stripped.encode('ascii', errors='replace'))
			cur_pred = int(pred_match.group(0)[2:3]) if pred_match else 0
			if cur_pred:
				predicated_groups[cur_pred].append(i)

			# 边界条件: 共享内存bank conflict
			if 'STS' in stripped or 'LDS' in stripped:
				off_m = re.search(r'0x([0-9a-fA-F]+)', stripped)
				if off_m:
					offset = int(off_m.group(1), 16)
					bank = (offset // 4) % 32
					bank_access_map[bank].append(i)
					if len(bank_access_map[bank]) >= 2:
						prev_lines = bank_access_map[bank][-2:]
						if prev_lines[1] - prev_lines[0] <= 32:
							hazards.append({
								"type": "bank_conflict", "line": i,
								"instruction": stripped, "bank": bank,
								"conflict_degree": len(bank_access_map[bank])})

			if 'LDG' in stripped or 'STG' in stripped:
				off_m = re.search(r'0x([0-9a-fA-F]+)', stripped)
				if off_m:
					st_addrs.append(int(off_m.group(1), 16))

			if 'ATOM' in stripped:
				atom_counts += 1
			if 'BAR' in stripped or 'MEMBAR' in stripped:
				bar_counts += 1

		uncoalesced = self._check_coalescing(st_addrs)
		divergence = self._estimate_divergence(instructions, predicated_groups)

		return {
			"instructions": instructions, "hazards": hazards,
			"atom_count": atom_counts, "barrier_count": bar_counts,
			"uncoalesced_accesses": uncoalesced,
			"warp_divergence": divergence,
		}

	@staticmethod
	def _check_coalescing(offsets: list[int]) -> list[dict]:
		findings = []
		if len(offsets) < 2:
			return findings
		diffs = [offsets[i + 1] - offsets[i] for i in range(len(offsets) - 1)]
		for i, d in enumerate(diffs):
			if d > 128:
				findings.append({"offset": offsets[i], "stride": d, "issue": f"stride={d} > 128"})
		return findings

	@staticmethod
	def _estimate_divergence(instructions: List[str],
							 predicated: Dict[int, List[int]]) -> WarpDivergenceInfo:
		if not predicated:
			branch_insns = sum(1 for i in instructions
							 if re.search(r'BRA|BRX|JMP|JCAL', i))
			if branch_insns == 0:
				return WarpDivergenceInfo()
			return WarpDivergenceInfo(
				divergent_branches=[], divergent_warp_count=branch_insns,
				avg_divergent_threads=0.1 * min(1.0, branch_insns / 10))

		divergent_branches = []
		for pred_id, lines in predicated.items():
			if len(lines) >= 2:
				span = lines[-1] - lines[0]
				if span <= 64:
					divergent_branches.extend(lines)

		avg_threads = min(0.95, len(predicated) * 0.12)
		return WarpDivergenceInfo(
			divergent_warp_count=len(predicated),
			avg_divergent_threads=avg_threads,
			divergent_branches=divergent_branches[:32])


class CUBINParser:
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

		kernels = []
		if data.startswith(self.ELF_MAGIC):
			ei_class = data[4]
			if ei_class == 2:
				e_shoff, e_shentsize, e_shnum = struct.unpack_from("<QQH", data, 40)
			else:
				e_shoff, e_shentsize, e_shnum = struct.unpack_from("<IIH", data, 32)

			for i in range(e_shnum):
				shdr_off = e_shoff + i * e_shentsize
				if ei_class == 2:
					sh_name, sh_type, sh_flags = struct.unpack_from("<III", data, shdr_off)
					offset, size = struct.unpack_from("<QQ", data, shdr_off + 24)
				else:
					sh_name, sh_type, sh_flags = struct.unpack_from("<III", data, shdr_off)
					offset, size = struct.unpack_from("<II", data, shdr_off + 16)

				if sh_type == 1 and (sh_flags & 0x4):
					seg = data[offset:offset + size]
					sass = SASSAnalyzer()
					result = sass.analyze(seg)
					kernels.append({
						"section_index": i,
						"instructions": len(result.get("instructions", [])),
						"hazards": len(result.get("hazards", [])),
						"atomics": result.get("atom_count", 0),
						"warps_with_divergence": result.get("warp_divergence", WarpDivergenceInfo()).divergent_warp_count,
					})

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
	def __init__(self):
		self._access_graph: dict[str, list[str]] = defaultdict(list)
		self._barriers: list[int] = []

	def detect(self, kernel_lines: list[str]) -> list[dict]:
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
						"type": "potential_race", "lines": shared_writes,
						"barrier_before": last_barrier, "barrier_at": i})
				shared_writes = []
				last_barrier = i
				self._barriers.append(i)

		if shared_writes:
			reports.append({
				"type": "unprotected_write", "lines": shared_writes,
				"barrier_before": last_barrier, "barrier_at": "END"})
		return reports


class GPUKernelAnalyzer:
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
				regs = k.get("registers", 0)
				if regs > 128:
					report.warnings.append(
						f"PTX kernel '{k['name']}' uses {regs} registers — occupancy likely < 25% on SM_80+")
					report.score -= 3
				insns = k.get("instructions", 1)
				branches = k.get("branches", 0)
				if insns > 0 and branches / insns > 0.1:
					report.warnings.append(
						f"PTX kernel '{k['name']}' branch density {branches/insns:.1%} — warp divergence risk")
					report.score -= 4

		if binary:
			if isinstance(binary, str) or (isinstance(binary, bytes) and binary[:len(CUBINParser.MAGIC)] == CUBINParser.MAGIC):
				cubin = self._cubin.parse(binary if isinstance(binary, str) else None)
				report.metrics["cubin_instructions"] = cubin.get("instructions", 0)
				for k in cubin.get("kernels", []):
					if k.get("hazards", 0) > 0:
						report.warnings.append(f"Section {k['section_index']}: {k['hazards']} SASS hazards")
						report.score -= 10
					if k.get("warps_with_divergence", 0) > 0:
						report.warnings.append(
							f"Section {k['section_index']}: {k['warps_with_divergence']} warps with potential divergence")
						report.score -= 6
					if k.get("atomics", 0) > 8:
						report.warnings.append(
							f"Section {k['section_index']}: {k['atomics']} atomics — contention risk")
						report.score -= 7
			else:
				sass = self._sass.analyze(binary)
				report.metrics["sass_instructions"] = len(sass.get("instructions", []))
				report.metrics["sass_hazards"] = len(sass.get("hazards", []))
				report.metrics["sass_atomics"] = sass.get("atom_count", 0)
				divergence = sass.get("warp_divergence")
				if divergence and divergence.divergent_warp_count > 0:
					report.metrics["sass_divergent_warps"] = divergence.divergent_warp_count
					report.metrics["sass_avg_divergent_threads"] = divergence.avg_divergent_threads
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
		findings = []
		text = kernel.decode('ascii', errors='replace') if isinstance(kernel, bytes) else kernel
		if 'clock()' in text or 'clock64()' in text:
			findings.append({"type": "timing_side_channel",
							 "detail": "GPU clock query in kernel may leak timing info"})
		if 'STS' in text and 'BAR.SYNC' not in text:
			findings.append({"type": "shared_memory_covert_channel",
							 "detail": "Shared memory writes without barriers may form covert channel"})
		return findings


# 暂留 — 旧版bank分析器, 输出恒零无实际检测能力, 已被SharedMemBankAnalyzer取代
# class _SharedMemBankProfiler:
# 	def profile(self, access_pattern: list) -> dict:
# 		return {"worst_case_degree": 0, "avg_bank_util": 0.0}


class SharedMemBankAnalyzer:
	BANK_COUNT_32 = 32
	BANK_COUNT_16 = 16
	BANK_STRIDE_BYTES = 4

	def __init__(self, bank_count: int = 32, bank_stride: int = 4):
		self._banks = bank_count
		self._stride = bank_stride
		self._access_map: dict[int, list[int]] = defaultdict(list)
		self._conflict_log: list[dict] = []

	def record_access(self, addr: int, warp_lane: int, line: int) -> int:
		bank = (addr // self._stride) % self._banks
		self._access_map[bank].append(line)
		return bank

	def detect_conflicts(self, window_size: int = 32) -> list[dict]:
		reports: list[dict] = []
		for bank, lines in self._access_map.items():
			if len(lines) < 2:
				continue
			for _i in range(len(lines) - 1):
				_span = lines[_i + 1] - lines[_i]
				if _span <= window_size:
					_count = sum(1 for _l in lines
								 if _l >= lines[_i] and _l <= lines[_i] + window_size)
					degree = _count
					reports.append({
						"bank": bank, "conflict_line": lines[_i],
						"degree": degree,
						"window": window_size,
						"severity": "high" if degree >= 4
							else "medium" if degree >= 2 else "low",
					})
		self._conflict_log.extend(reports)
		return reports

	def worst_case_degree(self) -> int:
		if not self._conflict_log:
			self.detect_conflicts()
		return max((c["degree"] for c in self._conflict_log), default=0)

	def avg_bank_utilization(self) -> float:
		if not self._access_map:
			return 0.0
		_used = sum(1 for _k, _v in self._access_map.items() if _v)
		return _used / self._banks


def _debug_print(msg: str) -> None:
	# 调试输出占位, 发布版保持静默避免污染stdout
	pass
