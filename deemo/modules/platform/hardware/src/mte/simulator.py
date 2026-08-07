import random
import struct
import hashlib
import logging
import os
import json
import time
import threading
from enum import StrEnum
from enum import auto as _unused_auto  # 未使用
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

def _debug_print(msg: str) -> None:
    pass  # 不拆——调试钩子

_log = logging.getLogger(__name__)

# ARM内存标记扩展模拟器
# 基于ARMv8.5-A MTE规范，模拟tagged memory行为
# 支持TikTag式推测执行攻击分析


class TagMismatchFault(Exception):
	"""标签不匹配时抛出 -- 对应SIGSEGV同步异常"""

	def __init__(self, address: int, expected: int, actual: int):
		self.address = address
		self.expected = expected
		self.actual = actual
		super().__init__(
			f"TagMismatch @ 0x{address:016x}: 期望0x{expected:x}, 实际0x{actual:x}"
		)


# 违规类型与数据结构


class MTEViolationType(StrEnum):
	NONE = "none"
	STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
	HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
	USE_AFTER_FREE = "use_after_free"
	STACK_USE_AFTER_RETURN = "stack_use_after_return"
	DOUBLE_FREE = "double_free"
	WILD_FREE = "wild_free"
	INVALID_FREE = "invalid_free"
	UNINIT_READ = "uninit_read"
	# 标签猜测攻击相关
	TAG_GUESS_ATTEMPT = "tag_guess_attempt"
	SPECULATIVE_TAG_BYPASS = "speculative_tag_bypass"


@dataclass
class MTEAllocation:
	addr: Any = None
	size: int = 0
	tag: Any = None
	alloc_type: Any = None
	var_name: Any = None
	freed: Any = None
	alloc_time: Any = None
	free_time: Any = None


class MTEViolation:
	__slots__ = ('vtype', 'addr', 'actual_tag', 'expected_tag', 'pc', 'access_size', 'is_write', 'timestamp', 'context', 'message',)

	def __init__(self, vtype, addr, actual_tag, expected_tag, pc, access_size, is_write, timestamp=0.0, context="", message=""):
		self.vtype = vtype
		self.addr = addr
		self.actual_tag = actual_tag
		self.expected_tag = expected_tag
		self.pc = pc
		self.access_size = access_size
		self.is_write = is_write
		self.timestamp = timestamp if timestamp != 0.0 else time.time()
		self.context = context
		self.message = message


class MTEReport:
	__slots__ = ('total_allocs', 'total_frees', 'total_violations', 'violations', 'by_type', 'coverage', 'timestamp', 'notes',)

	def __init__(self, total_allocs, total_frees, total_violations, violations=None, by_type=None, coverage=0.0, timestamp=0.0, notes=""):
		self.total_allocs = total_allocs
		self.total_frees = total_frees
		self.total_violations = total_violations
		self.violations = violations
		self.by_type = by_type
		self.coverage = coverage
		self.timestamp = timestamp
		self.notes = notes


# TagSpace: 标签空间管理器
# 分配/释放4-bit标签。tag=0保留为未标记/默认。
# 标签猜测攻击防护：分配时增加随机延迟（模拟硬件随机化）。


class TagSpace:
	# 最大标签值（ARM MTE为15，即4-bit逻辑标签）
	_RESERVED_TAGS = {0}

	def __init__(self, max_tag: int = 15):
		self.max_tag = max_tag
		self._counter = random.randint(1, max_tag)  # 随机起始点，防确定性分配
		self._lock = threading.Lock()
		self._used: Set[int] = set(self._RESERVED_TAGS)
		# 标签猜测尝试计数（检测暴力枚举标签攻击）
		self._tag_guess_attempts: Dict[int, int] = defaultdict(int)

	def alloc_tag(self) -> int:
		# 循环扫描+随机跳跃，降低相邻分配可预测性
		# TikTag 攻击面缓解：确定性标签分配使攻击者可预测未来标签值
		with self._lock:
			start = self._counter
			# 随机跳跃步长（奇数保证模空间全覆盖）
			step = random.choice([1, 3, 5, 7, 11])
			for _ in range(self.max_tag * 2):
				self._counter = (self._counter + step) & self.max_tag
				if self._counter not in self._used and self._counter not in self._RESERVED_TAGS:
					self._used.add(self._counter)
					return self._counter
			# 所有标签在用，强制复用最少使用标签（LRU风格）
			self._counter = (self._counter + 1) & self.max_tag
			if self._counter in self._RESERVED_TAGS:
				self._counter = 1
			return self._counter

	def free_tag(self, tag: int):
		with self._lock:
			self._used.discard(tag)

	def record_guess_attempt(self, tag: int) -> bool:
		# 记录一次标签猜测。同一标签被猜超阈值则标记为攻击
		with self._lock:
			self._tag_guess_attempts[tag] += 1
			return self._tag_guess_attempts[tag] > 8  # 阈值：同一标签被猜8次

	def is_valid(self, tag: int) -> bool:
		return 0 <= tag <= self.max_tag


# MTE状态机
# 维护内存和标签映射，追踪分配/释放生命周期
# 融合TikTag推测执行分析能力


class MTEState:
	def __init__(self, memory_size: int = 65536, tag_granule: int = 16):
		if tag_granule not in (16, 32, 64):
			raise ValueError("tag_granule必须是16/32/64")
		self._granule = tag_granule
		self.TAG_GRANULE = tag_granule  # 兼容旧接口
		self._memory = bytearray(memory_size)
		_tag_count = (memory_size + tag_granule - 1) // tag_granule
		self._tags = bytearray(_tag_count)  # 每个granule一个4-bit tag (低4位)
		self._allocation_map: dict[int, int] = {}
		self._freed_set: set[int] = set()
		self._alloc_tag_counter = 0
		# TikTag风格: 追踪标签推测历史
		self._tag_probe_history: list[tuple[int, int, int, int]] = []

		# 兼容旧接口字段
		self.tag_space = TagSpace()
		# addr // GRANULE -> tag (MTEAnalyzer查询用)
		self.memory_tags: Dict[int, int] = {}
		self.allocations: List[MTEAllocation] = []
		self.active_allocs: Dict[int, MTEAllocation] = {}
		self.violations: List[MTEViolation] = []
		self._lock = threading.Lock()
		self._enabled = True

# 标签分配策略
	# 三种策略对应不同加固级别

	def tag_allocation(self, address: int, size: int, strategy: str = "sequential") -> int:
		_start_g = address // self._granule
		_end_g = (address + size + self._granule - 1) // self._granule
		if _end_g > len(self._tags):
			raise IndexError(f"分配越界: 地址0x{address:x}, 大小{size}")

		if strategy == "sequential":
			self._alloc_tag_counter = (self._alloc_tag_counter % 15) + 1
			tag = self._alloc_tag_counter
		elif strategy == "randomized":
			tag = random.randint(1, 15)  # tag=0保留为未标记
		elif strategy == "incremental":
			_h = struct.pack("<Q", address)
			_dig = hashlib.blake2b(_h, digest_size=2).digest()
			tag = (_dig[0] ^ _dig[1]) & 0x0F
			if tag == 0:
				tag = 1
		else:
			tag = 1

		# 写入标签到所有相关granule
		for _g in range(_start_g, _end_g):
			self._tags[_g] = tag
		self._allocation_map[address] = size
		self._freed_set.discard(address)

		# 同步到memory_tags (兼容旧接口)
		for _g in range(_start_g, _end_g):
			self.memory_tags[_g * self._granule] = tag

		return tag

# 带标签检查的存储

	def store_with_tag(self, address: int, data: bytes, tag: int | None = None):
		_g = address // self._granule
		actual_tag = self._tags[_g] & 0x0F
		if tag is not None and (tag & 0x0F) != actual_tag:
			raise TagMismatchFault(address, tag & 0x0F, actual_tag)
		if address + len(data) > len(self._memory):
			raise IndexError(f"写入越界: 0x{address:x}+{len(data)}")
		self._memory[address:address + len(data)] = data

# 带标签验证的加载

	def load_with_tag(self, address: int, size: int, expected_tag: int | None = None) -> bytes:
		_g = address // self._granule
		actual_tag = self._tags[_g] & 0x0F
		if expected_tag is not None and (expected_tag & 0x0F) != actual_tag:
			raise TagMismatchFault(address, expected_tag & 0x0F, actual_tag)
		if address + size > len(self._memory):
			raise IndexError(f"读取越界: 0x{address:x}+{size}")
		return bytes(self._memory[address:address + size])

# 基础标签操作

	def check_tag(self, address: int) -> int:
		return self._tags[address // self._granule] & 0x0F

# 内存安全检测

	def detect_double_free(self, address: int) -> bool:
		return address in self._freed_set

	def detect_wild_free(self, address: int) -> bool:
		return address not in self._allocation_map and address not in self._freed_set

	def detect_uaf(self, address: int) -> bool:
		# 释放后使用: 地址在freed_set中仍被访问
		return address in self._freed_set

	def free_allocation(self, address: int):
		if address in self._allocation_map:
			_size = self._allocation_map.pop(address)
			_start_g = address // self._granule
			_end_g = (address + _size + self._granule - 1) // self._granule
			for _g in range(_start_g, min(_end_g, len(self._tags))):
				self._tags[_g] = 0  # 清空标签，实现use-after-free检测
			self._freed_set.add(address)
			# 同步清理memory_tags
			for _g in range(_start_g, min(_end_g, len(self._tags))):
				self.memory_tags.pop(_g * self._granule, None)

# TikTag式推测标签访问
	# 模拟推测执行窗口内标签检查：
# 推测执行不立即触发异常，记录结果
# 通过cache oracle推断标签值

	def check_speculative_tag_access(self, address: int) -> tuple[bool, int]:
		# 推测性标签访问 -- TikTag cache oracle风格
		# 返回 (是否触发fault, 解析标签值)
		# 推测窗口内不抛异常，返回预测结果
		_g = address // self._granule
		if _g >= len(self._tags):
			return True, 0
		actual_tag = self._tags[_g] & 0x0F
		# 模拟推测窗口: 永不fault, 返回真实标签供side-channel分析
		return False, actual_tag

	def speculative_load(
		self, address: int, size: int, predicted_tag: int
	) -> tuple[bytes, bool]:
		# 推测加载: 用预测标签读取数据
		# 返回 (数据, 预测是否正确)
		actual_tag = self._tags[address // self._granule] & 0x0F
		correct = (predicted_tag & 0x0F) == actual_tag
		if address + size > len(self._memory):
			return b"", False
		self._tag_probe_history.append((address, predicted_tag, actual_tag, 1 if correct else 0))
		return bytes(self._memory[address:address + size]), correct

# 兼容MTEAnalyzer接口

	def align(self, addr: int) -> int:
		return addr - (addr % self.TAG_GRANULE)

	def tag_of(self, addr: int) -> int:
		aligned = self.align(addr)
		return self.memory_tags.get(aligned, 0)

	def set_tag(self, addr: int, tag: int, size: int = 16):
		aligned = self.align(addr)
		end = self.align(addr + size - 1) + self.TAG_GRANULE
		cur = aligned
		while cur < end:
			self.memory_tags[cur] = tag
			# 同步到底层_tags
			_g = cur // self._granule
			if _g < len(self._tags):
				self._tags[_g] = tag & 0x0F
			cur += self.TAG_GRANULE

	def clear_tag(self, addr: int, size: int):
		aligned = self.align(addr)
		end = self.align(addr + size - 1) + self.TAG_GRANULE
		cur = aligned
		while cur < end:
			self.memory_tags.pop(cur, None)
			_g = cur // self._granule
			if _g < len(self._tags):
				self._tags[_g] = 0
			cur += self.TAG_GRANULE

	def alloc(self, addr: int, size: int, alloc_type: str = "heap", var_name: str = "") -> MTEAllocation:
		with self._lock:
			tag = self.tag_space.alloc_tag()
			self.set_tag(addr, tag, size)
			# 同步到_allocation_map
			self._allocation_map[addr] = size
			self._freed_set.discard(addr)
			a = MTEAllocation(
				addr=addr,
				size=size,
				tag=tag,
				alloc_type=alloc_type,
				var_name=var_name,
				alloc_time=time.time(),)
			self.allocations.append(a)
			self.active_allocs[addr] = a
			return a

	def free(self, addr: int) -> Tuple[bool, Optional[MTEViolation]]:
		with self._lock:
			a = self.active_allocs.get(addr)
			if not a:
				v = MTEViolation(
					vtype=MTEViolationType.WILD_FREE,
					addr=addr,
					actual_tag=0,
					expected_tag=0,
					pc=0,
					access_size=0,
					is_write=True,
					message=f"wild free at 0x{addr:x}",)
				self.violations.append(v)
				return False, v
			if a.freed:
				v = MTEViolation(
					vtype=MTEViolationType.DOUBLE_FREE,
					addr=addr,
					actual_tag=a.tag,
					expected_tag=a.tag,
					pc=0,
					access_size=0,
					is_write=True,
					message=f"double free at 0x{addr:x}",)
				self.violations.append(v)
				return False, v
			a.freed = True
			a.free_time = time.time()
			self.clear_tag(addr, a.size)
			self.tag_space.free_tag(a.tag)
			self.active_allocs.pop(addr, None)
			# 同步free_allocation
			self._freed_set.add(addr)
			if addr in self._allocation_map:
				del self._allocation_map[addr]
			return True, None

	def check_access(self, addr: int, size: int, is_write: bool, pc: int = 0,
					 speculative: bool = False) -> List[MTEViolation]:
		# 内存访问标签校验
		# 边界条件: speculative参数标记推测执行路径
		violations: List[MTEViolation] = []
		with self._lock:
			if not self._enabled:
				return violations
			for off in range(0, size, self.TAG_GRANULE):
				cur = addr + off
				expected = self.tag_of(cur)
				# 未初始化/未标记内存
				if expected == 0:
					v = MTEViolation(
						vtype=MTEViolationType.UNINIT_READ,
						addr=cur,
						actual_tag=0,
						expected_tag=0,
						pc=pc,
						access_size=min(self.TAG_GRANULE, size - off),
						is_write=is_write,
						message=f"uninit/unmapped access at 0x{cur:x}",)
					violations.append(v)
				# 检查是否访问已释放alloc
				for a_addr, a in list(self.active_allocs.items()):
					if a.freed and a.addr <= cur < a.addr + a.size:
						v = MTEViolation(
							vtype=MTEViolationType.USE_AFTER_FREE,
							addr=cur,
							actual_tag=0,
							expected_tag=a.tag,
							pc=pc,
							access_size=min(self.TAG_GRANULE, size - off),
							is_write=is_write,
							message=f"UAF at 0x{cur:x} (freed alloc 0x{a.addr:x})",)
						violations.append(v)
						break
			# 推测执行绕过检测
			if speculative and violations:
				for v in violations:
					v.vtype = MTEViolationType.SPECULATIVE_TAG_BYPASS
		for v in violations:
			self.violations.append(v)
		return violations


# 保留——后续可用
# class UnicornMTEHook:
# 	"""Unicorn 引擎 MTE 钩子"""
#
# 	def __init__(self, uc, mte_state: MTEState):
# 		self.uc = uc
# 		self.mte = mte_state
# 		self._installed = False
#
# 	def install(self):
# 		if self._installed:
# 			return
# 		try:
# 			self.uc.hook_add(
# 				unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
# 				self._hook_mem_access,)
# 			self.uc.hook_add(
# 				unicorn.UC_HOOK_MEM_UNMAPPED,
# 				self._hook_mem_invalid,)
# 			self._installed = True
# 		except Exception as e:
# 			_log.warning(f"install MTE hook failed: {e}")
#
# 	def _hook_mem_access(self, uc, access, address, size, value, user_data):
# 		is_write = bool(access & unicorn.UC_HOOK_MEM_WRITE)
# 		pc = 0
# 		try:
# 			if hasattr(uc, "reg_read"):
# 				pc = uc.reg_read(getattr(unicorn, "UC_X86_REG_RIP", 0))
# 		except Exception:
# 			pc = 0
# 		self.mte.check_access(address, size, is_write, pc=pc)
#
# 	def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
# 		_log.debug(f"invalid mem access: 0x{address:x}, size={size}")


# 边界条件: unicorn可能未安装
try:
	import unicorn
	_UNICORN_AVAILABLE = True
except ImportError:
	_UNICORN_AVAILABLE = False


class MTEViolationClassifier:
	# MTE违规分类器：根据函数名判定违规类型

	HEAP_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "operator new", "_Znwm", "_Znam"}
	HEAP_FREE_FUNCS = {"free", "operator delete", "_ZdlPv", "_ZdaPv"}

	def __init__(self):
		self._lock = threading.Lock()

	def classify_from_call(self, func_name: str, args: List[int]) -> Optional[MTEViolation]:
		with self._lock:
			if func_name in self.HEAP_ALLOC_FUNCS:
				if args and args[0] > 0:
					return None
			return None


class MTEAnalyzer:
	# MTE分析器：追踪内存分配/释放/访问事件，生成违规报告

	def __init__(self):
		self.state = MTEState()
		self.classifier = MTEViolationClassifier()
		self._events: List[Dict[str, Any]] = []
		self._lock = threading.Lock()

	def record_alloc(self, addr: int, size: int, alloc_type: str = "heap", var_name: str = ""):
		a = self.state.alloc(addr, size, alloc_type, var_name)
		with self._lock:
			self._events.append({
				"kind": "alloc",
				"addr": addr,
				"size": size,
				"type": alloc_type,
				"tag": a.tag,
				"ts": time.time(),
			})

	def record_free(self, addr: int) -> bool:
		ok, v = self.state.free(addr)
		with self._lock:
			self._events.append({
				"kind": "free",
				"addr": addr,
				"success": ok,
				"ts": time.time(),
			})
		return ok

	def record_access(self, addr: int, size: int, is_write: bool, pc: int = 0) -> List[MTEViolation]:
		return self.state.check_access(addr, size, is_write, pc=pc)

	# FIXME: Unicorn集成待修复，当前使用纯软件模拟
	def attach_unicorn(self, uc) -> Optional[Any]:
		# Unicorn hook已注释保留，暂不可用
		if not _UNICORN_AVAILABLE:
			_log.warning("unicorn not available")
			return None
		return None

	def simulate_runtime(
			self,
			allocs: List[Dict[str, Any]],
			accesses: List[Dict[str, Any]],
			frees: List[Dict[str, Any]]
		) -> MTEReport:
		# 时间线模拟：按时间戳排序所有事件并按序重放
		timeline: List[Tuple[float, str, Dict[str, Any]]] = []
		for a in allocs:
			timeline.append((a.get("ts", 0), "alloc", a))
		for ac in accesses:
			timeline.append((ac.get("ts", 0), "access", ac))
		for f in frees:
			timeline.append((f.get("ts", 0), "free", f))
		timeline.sort(key=lambda x: x[0])

		for ts, kind, data in timeline:
			if kind == "alloc":
				self.record_alloc(
					addr=int(data["addr"]),
					size=int(data["size"]),
					alloc_type=data.get("type", "heap"),
					var_name=data.get("var", ""),)
			elif kind == "access":
				self.record_access(
					addr=int(data["addr"]),
					size=int(data.get("size", 1)),
					is_write=bool(data.get("is_write", False)),
					pc=int(data.get("pc", 0)),)
			elif kind == "free":
				self.record_free(addr=int(data["addr"]))
		return self.build_report()

	def build_report(self) -> MTEReport:
		violations = self.state.violations
		by_type: Dict[str, int] = defaultdict(int)
		for v in violations:
			by_type[v.vtype.value] += 1
		total_allocs = len(self.state.allocations)
		total_frees = sum(1 for a in self.state.allocations if a.freed)
		# 覆盖率：按分配类型细分
		alloc_by_type: Dict[str, int] = defaultdict(int)
		for a in self.state.allocations:
			alloc_by_type[a.alloc_type or "unknown"] += 1
		coverage = min(1.0, total_allocs / 100.0)
		notes_parts = [f"总分配 {total_allocs} 次, 总释放 {total_frees} 次"]
		if alloc_by_type:
			type_summary = ", ".join(f"{k}:{v}" for k, v in sorted(alloc_by_type.items()))
			notes_parts.append(f"分配类型: {type_summary}")
		return MTEReport(
			total_allocs=total_allocs,
			total_frees=total_frees,
			total_violations=len(violations),
			violations=list(violations),
			by_type=dict(by_type),
			coverage=coverage,
			notes="; ".join(notes_parts),)

	def enable(self, on: bool = True):
		with self._lock:
			self.state._enabled = on

	def reset(self):
		self.state = MTEState()
		with self._lock:
			self._events = []


# MTESimulator 接口类
# 包装MTEState，提供更易用外部接口


class MTESimulator:
	def __init__(self, memory_size: int = 65536, tag_granule: int = 16):
		self._state = MTEState(memory_size, tag_granule)
		self.allocated: list[tuple[int, int, int]] = []

	def allocate(self, address: int, size: int, strategy: str = "sequential") -> int:
		tag = self._state.tag_allocation(address, size, strategy)
		self.allocated.append((address, size, tag))
		return tag

	def store(self, address: int, data: bytes, tag: int | None = None):
		self._state.store_with_tag(address, data, tag)

	def load(self, address: int, size: int, expected_tag: int | None = None) -> bytes:
		return self._state.load_with_tag(address, size, expected_tag)

	def check_use_after_free(self, address: int) -> bool:
		return self._state.detect_uaf(address)

	def check_double_free(self, address: int) -> bool:
		return self._state.detect_double_free(address)

	def free(self, address: int):
		self._state.free_allocation(address)

	def speculative_probe(self, address: int, predicted_tag: int) -> tuple[bool, int]:
		would_fault, resolved = self._state.check_speculative_tag_access(address)
		return would_fault, resolved

	def speculative_load(self, address: int, size: int, predicted_tag: int) -> tuple[bytes, bool]:
		return self._state.speculative_load(address, size, predicted_tag)

	def tag_at(self, address: int) -> int:
		return self._state.check_tag(address)

	# 导出状态快照，供fuzzing和验证
	def snapshot(self) -> dict:
		return {
			"allocations": list(self._state._allocation_map.items()),
			"freed": list(self._state._freed_set),
			"tag_probe_history": list(self._state._tag_probe_history),
			"granule": self._state._granule,
		}


# 地址标签提取
# ARM TBI (Top Byte Ignore): 高8位存储tag


def get_tag_for_address(address: int, tag_shift: int = 4) -> int:
	# 从ARM TBI地址提取tag位
	return (address >> (64 - 4)) & 0x0F if tag_shift == 4 else (address >> 56) & 0xFF
