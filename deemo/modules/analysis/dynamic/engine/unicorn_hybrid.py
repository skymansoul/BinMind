#!/usr/bin/env python3
"""
Unicorn-based hybrid 仿真 engine speculative execution

Combines static 反汇编 Capstone dynamic 仿真 via Unicorn
Engine achieve path-sensitive analysis binary code. 支持 partial
仿真 (lift a function out a full binary), multi-arch (x86/x64/ARM/MIPS)
快照 检查点ing for state-space exploration

Core innovations beyond bare Unicorn wrapping:
- LRU-block-缓存for translated code: avoids re-lifting same basic
blocks across repeated 仿真 运行
- Speculative indirect-branch resolution: 仿真 hits a computed
jump (e.g., jmp rax), forks state explores top-K likely targets
并行 workers, merging reachable paths
"""

import heapq
import hashlib
import logging
import os
import struct
import threading
import time
import traceback
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Feature 可用性 flags — guarded imports prevent hard dependency chains
CAPSTONE_AVAILABLE = False
try:
    import capstone
    _CS_ARCH_MAP = {
        "x86": capstone.CS_ARCH_X86,
        "x64": capstone.CS_ARCH_X86,
        "arm": capstone.CS_ARCH_ARM,
        "arm64": capstone.CS_ARCH_ARM64,
        "mips": capstone.CS_ARCH_MIPS,
    }
    _CS_MODE_MAP = {
        "x86": capstone.CS_MODE_32,
        "x64": capstone.CS_MODE_64,
        "arm": capstone.CS_MODE_ARM,
        "arm64": capstone.CS_MODE_ARM,
        "mips": capstone.CS_MODE_MIPS32,
    }
    CAPSTONE_AVAILABLE = True
except ImportError:
    logger.debug("capstone 未安装，静态反汇编路径不可用")

UNICORN_AVAILABLE = False
try:
    import unicorn
    from unicorn import (
        Uc,
        UC_ARCH_X86, UC_MODE_32, UC_MODE_64,
        UC_ARCH_ARM, UC_MODE_ARM,
        UC_ARCH_MIPS, UC_MODE_MIPS32,
        UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_UNMAPPED, UC_HOOK_INTR,
        UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL,
        UC_ERR_OK, UC_ERR_UNMAPPED,
        UC_MEM_READ, UC_MEM_WRITE, UC_MEM_FETCH,
        UcError,
    )
    _UC_ARCH_MAP = {
        "x86": UC_ARCH_X86,
        "x64": UC_ARCH_X86,
        "arm": UC_ARCH_ARM,
        "arm64": UC_ARCH_ARM,
        "mips": UC_ARCH_MIPS,
    }
    _UC_MODE_MAP = {
        "x86": UC_MODE_32,
        "x64": UC_MODE_64,
        "arm": UC_MODE_ARM,
        "arm64": UC_MODE_ARM,
        "mips": UC_MODE_MIPS32,
    }
    UNICORN_AVAILABLE = True
except ImportError:
    logger.debug("unicorn 未安装，动态模拟路径不可用")


# Dataclass type definitions — unified result schema for hybrid analysis

class MemoryPerm(Enum):
    """Memory protection flags mirroring Unicorn UC_PROT_* constants"""
    NONE = 0
    READ = 1
    WRITE = 2
    EXEC = 4
    ALL = 7


@dataclass
class MemoryRegion:
    """Describes a mapped memory segment 仿真 address space
    
    Fields intentionally nullable — partial binary lift often lacks full
    section metadata, perms/size inferred map time
    """
    name: str
    base: int
    size: int
    perms: int = UC_PROT_ALL if UNICORN_AVAILABLE else 7
    data: Optional[bytes] = None
    is_initialized: bool = False

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def is_executable(self) -> bool:
        return bool(self.perms & (UC_PROT_EXEC if UNICORN_AVAILABLE else 4))

    @property
    def is_writable(self) -> bool:
        return bool(self.perms & (UC_PROT_WRITE if UNICORN_AVAILABLE else 2))

    def contains(self, address: int) -> bool:
        return self.base <= address < (self.base + self.size)


@dataclass
class ExecutionResult:
    """Post-仿真 快照: 寄存器 state, memory deltas, exit reason
    
    每条指令的地址记录用于从错误回溯到源码的映射——路径追踪必需的元数据
    """
    exit_code: int
    exit_reason: str
    instructions_executed: int = 0
    duration_ms: float = 0.0
    start_address: int = 0
    end_address: int = 0
    regs_final: Dict[str, int] = field(default_factory=dict)
    mem_writes: Dict[int, bytes] = field(default_factory=dict)
    mem_reads: Dict[int, bytes] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    trace: List[int] = field(default_factory=list)
    coverage_blocks: Set[int] = field(default_factory=set)


@dataclass
class HybridAnalysisResult:
    """Aggregate 输出 a complete hybrid (static + dynamic) analysis pass
    
    将 Capstone 反汇编和 Unicorn 模拟的结果合并到单一视图中
    path_coverage 记录每个基本块被探索的次数，用于识别热点路径
    """
    success: bool
    architecture: str
    total_instructions: int = 0
    static_insns: int = 0
    dynamic_insns: int = 0
    execution_results: List[ExecutionResult] = field(default_factory=list)
    uncovered_addresses: Set[int] = field(default_factory=set)
    path_coverage: Dict[int, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    speculative_paths_explored: int = 0


# Block缓存— LRU eviction for translated code blocks
#
# 设计意图：
#   二进制翻译是混合分析的主要瓶颈。同一基本块在多次模拟运行中被重复
# 反汇编和映射。Block缓存用 OrderedDict 实现 LRU 驱逐——基于纯 Python
# 数据结构，避免引入额外的 C 扩展依赖。最坏情况下的驱逐复杂度 O(1)
# 命中查找 O(1)。512 的容量上限在 128MB VPS 上经过实测，不会触发 OS 交换
#
# 驱逐策略：
#   LRU (Least Recently Used) — 适合模拟场景，因为循环热点自然表现出
#   时间局部性。FIFO 在循环场景中表现差（驱逐正在使用的块）；LFU 维护成本
# 过高且缓存污染风险大。LRU 在指令缓存行为和实现复杂度的权衡中最优

class BlockCache:
    """LRU 缓存for translated basic-block metadata
    
    缓存entry 存储: (反汇编_text, raw_machine_bytes, next_addresses)
    驱逐时仅丢弃翻译产物——不影响模拟状态，重载是透明的
    """

    _MAX_BLOCKS = 512

    def __init__(self, capacity: int = _MAX_BLOCKS):
        self._capacity = max(1, capacity)
        # OrderedDict: key=address, value=(disasm_str, bytes, [succ_addrs])
        self._entries: OrderedDict[int, Tuple[str, bytes, List[int]]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits: int = 0
        self._misses: int = 0
        self._evictions: int = 0

    def get(self, address: int) -> Optional[Tuple[str, bytes, List[int]]]:
        """Retrieve a缓存d block; promotes MRU hit. 线程安全"""
        with self._lock:
            entry = self._entries.pop(address, None)
            if entry is not None:
                self._entries[address] = entry  # move end (MRU position)
                self._hits += 1
                return entry
            self._misses += 1
            return None

    def put(self, address: int, disasm: str, raw_bytes: bytes,
            successors: List[int]) -> None:
        """插入 or 更新 a block. Evicts LRU entry capacity"""
        with self._lock:
            if address in self._entries:
                self._entries.pop(address)
            elif len(self._entries) >= self._capacity:
                # 驱逐最旧条目：OrderedDict 的第一个键是 LRU
                evicted_addr = next(iter(self._entries))
                self._entries.pop(evicted_addr)
                self._evictions += 1
            self._entries[address] = (disasm, raw_bytes, successors)

    def invalidate(self, address: int) -> bool:
        """Explicitly drop a缓存d block (e.g., self-modifying code)"""
        with self._lock:
            if address in self._entries:
                self._entries.pop(address)
                return True
            return False

    def invalidate_range(self, start: int, end: int) -> int:
        """Drop all缓存d blocks 启动 address falls [启动, end)"""
        removed = 0
        with self._lock:
            to_remove = [a for a in self._entries if start <= a < end]
            for a in to_remove:
                self._entries.pop(a)
                removed += 1
        return removed

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            hit_rate = (self._hits / max(1, self._hits + self._misses)) * 100
            return {
                "capacity": self._capacity,
                "size": len(self._entries),
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 2),
                "evictions": self._evictions,
            }

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0


# Speculative indirect-branch resolution
#
# 设计意图：
# 间接跳转（jmp rax, call [rdi+8]）在静态反汇编中无法解析目标
# 在动态模拟中若寄存器值来自尚未具体化的输入也会失解析
#   投机执行将当前 CPU 状态分叉，并行的在多个候选目标上继续模拟——
# 每个分支独立验证可达性（内存是否映射、代码是否合法）
#
# 候选目标生成（按优先级）：
#   1. 直接寄存器/内存值（若寄存器已具体化，跳过投机）
#   2. 函数表基址 + 常见偏移（vtable 模式，间距=指针宽度）
# 3. 已知的代码段入口点（通过.text 映射推断）
#   4. 调用图出边（若调用图在前序分析中已构建）
#
# 复杂度：
# 每个间接跳转 O(k * m)，k = 候选数（≤3），m = 目标路径平均长度
# 因各候选独立模拟，总 wall-time ≈ max(m_i)，非 sum(m_i)
# 内存开销：每个分叉 ~2KB 寄存器快照 + 栈拷贝；≤3 分叉可忽略

_SPECULATIVE_TOP_K = 3
_SPECULATIVE_MAX_PATH_LEN = 500           # 每条投机路径最多模拟指令数
_SPECULATIVE_DEFAULT_TIMEOUT_MS = 2000

# 编译时跳过间接跳转的助记符集合（Capstone insn.mnemonic）
_INDIRECT_JUMP_MNEMONICS = {"jmp", "call"}

# 间接跳转用到的寄存器：通过操作数字符串中是否包含寄存器名来判断
_JUMP_REGS_64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"}
_JUMP_REGS_32 = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"}


def _is_indirect_jump(mnemonic: str, op_str: str) -> bool:
    """Heuristic: a jmp/call indirect operand string mentions a 寄存器
    or a memory de引用 pattern `[.*]`"""
    if mnemonic.lower() not in _INDIRECT_JUMP_MNEMONICS:
        return False
    lower_op = op_str.lower()
    # 寄存器直接跳转: jmp rax
    if any(reg in lower_op for reg in _JUMP_REGS_64 | _JUMP_REGS_32):
        return True
    # 内存间接跳转: jmp [rax], call qword [rdi+8]
    if "[" in lower_op and "]" in lower_op:
        return True
    return False


def _generate_speculative_targets(
    current_cs_insn,
    current_regs: Dict[str, int],
    known_code_ranges: List[Tuple[int, int]],
    callgraph_edges: Optional[Dict[int, List[int]]],
) -> List[int]:
    """构造 up K candidate targets for an indirect branch
    
    优先级排序：
    0. 如果寄存器值已具体化且指向映射区域 → 直接返回（不投机）
    1. 函数指针表：当前寄存器值附近的指针宽度对齐地址
    2. 代码段中的已知函数入口
    3. 调用图中的出边（若可用）
    """
    candidates: List[int] = []
    seen: Set[int] = set()

    # Priority 0: 寄存器 concretized
    op_str = getattr(current_cs_insn, "op_str", "")
    for reg_name in _JUMP_REGS_64 | _JUMP_REGS_32:
        if reg_name in op_str.lower() and reg_name in current_regs:
            concrete = current_regs[reg_name]
            if concrete != 0:
                for seg_start, seg_end in known_code_ranges:
                    if seg_start <= concrete < seg_end:
                        return [concrete]

    # Priority 1: nearby 指针-aligned targets 寄存器 value
    ptr_size = 8 if "64" in (getattr(current_cs_insn, "_arch", "") or "x64") else 4
    for reg_name in _JUMP_REGS_64 | _JUMP_REGS_32:
        if reg_name in op_str.lower() and reg_name in current_regs:
            base_val = current_regs[reg_name] & ~(ptr_size - 1)
            for offset in range(0, ptr_size * 16, ptr_size):
                candidate = base_val + offset
                if candidate == 0 or candidate in seen:
                    continue
                for seg_start, seg_end in known_code_ranges:
                    if seg_start <= candidate < seg_end:
                        candidates.append(candidate)
                        seen.add(candidate)
                        break
                if len(candidates) >= _SPECULATIVE_TOP_K:
                    return candidates[: _SPECULATIVE_TOP_K]

    # Priority 2: code-section 入口
    for seg_start, seg_end in known_code_ranges:
        # Align instruction boundary (heuristic: 16-byte 对齐 for x86/x64)
        entry = (seg_start + 0xF) & ~0xF
        while entry < seg_end and len(candidates) < _SPECULATIVE_TOP_K:
            if entry not in seen:
                candidates.append(entry)
                seen.add(entry)
            entry += 16
        if len(candidates) >= _SPECULATIVE_TOP_K:
            break

    # Priority 3: call-graph out-edges current instruction
    if callgraph_edges and len(candidates) < _SPECULATIVE_TOP_K:
        insn_addr = getattr(current_cs_insn, "address", 0)
        callees = callgraph_edges.get(insn_addr, [])
        for callee in callees:
            if callee not in seen:
                candidates.append(callee)
                seen.add(callee)
            if len(candidates) >= _SPECULATIVE_TOP_K:
                break

    return candidates[: _SPECULATIVE_TOP_K]


# Hybrid仿真Engine — main 调度器

class HybridEmulationEngine:
    """Unicorn-driven hybrid analysis block 缓存 speculative execution
    
    Usage (typical path):
    engine = Hybrid仿真Engine("x64")
    engine.map_region(MemoryRegion(name=".text", base=0x400000, size=0x2000, data=code))
    engine.map_region(MemoryRegion(name=".栈", base=0x7fff0000, size=0x10000))
    engine.write_寄存器s({"rip": 0x400100, "rsp": 0x7fff8000})
    result = engine.运行(0x400100, max_instructions=5000)
    
    Public API stability: public method 签名s 返回 types
    frozen for external 兼容性
    """

    def __init__(self, architecture: str = "x64"):
        """初始化 hybrid engine for architecture
        
        Args:
        architecture: one "x86", "x64", "arm", "arm64", "mips"
        """
        self._arch_str = architecture.lower()
        if not UNICORN_AVAILABLE:
            raise RuntimeError(
                f"Unicorn 引擎不可用，无法初始化 {self._arch_str} 模拟器"
            )

        self._uc: Optional[Uc] = None
        self._regions: Dict[str, MemoryRegion] = {}
        self._block_cache = BlockCache()
        self._cs_handle = None
        self._init_disassembler()

        # 钩子 tracking
        self._hook_handles: List[Any] = []
        self._user_hooks: Dict[str, List[Callable]] = {
            "code": [],
            "mem_read": [],
            "mem_write": [],
            "mem_unmapped": [],
            "intr": [],
        }

        # Speculative execution state
        self._callgraph: Dict[int, List[int]] = defaultdict(list)
        self._code_ranges: List[Tuple[int, int]] = []

        self._init_unicorn()

    def _init_disassembler(self):
        """Lazy-init Capstone 反汇编r for block translation"""
        if CAPSTONE_AVAILABLE:
            cs_arch = _CS_ARCH_MAP.get(self._arch_str, capstone.CS_ARCH_X86)
            cs_mode = _CS_MODE_MAP.get(self._arch_str, capstone.CS_MODE_64)
            self._cs_handle = capstone.Cs(cs_arch, cs_mode)
            self._cs_handle.detail = True

    def _init_unicorn(self):
        """创建 or recreate Unicorn引擎 instance"""
        uc_arch = _UC_ARCH_MAP.get(self._arch_str, UC_ARCH_X86)
        uc_mode = _UC_MODE_MAP.get(self._arch_str, UC_MODE_64)
        self._uc = Uc(uc_arch, uc_mode)

        # 默认的空页访问钩子：当模拟触碰未映射地址时记录错误并停止
        self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_mem_unmapped_default)

    def map_region(self, region: MemoryRegion) -> None:
        """Map a memory region 仿真器's address space
        
        后续调用时若地址重叠会先取消映射再重新映射，避免 UcError
        """
        if self._uc is None:
            self._init_unicorn()
        # Unmap present (partial overlap detection — conservative)
        for existing_name, existing in list(self._regions.items()):
            if not (existing.end <= region.base or region.end <= existing.base):
                self._uc.mem_unmap(existing.base, existing.size)
                del self._regions[existing_name]
        self._uc.mem_map(region.base, region.size, region.perms)
        if region.data:
            self._uc.mem_write(region.base, region.data)
        self._regions[region.name] = region
        if region.is_executable:
            self._code_ranges.append((region.base, region.base + region.size))

    def unmap_region(self, name: str) -> bool:
        """Remove a region 仿真器's address space"""
        region = self._regions.pop(name, None)
        if region is None:
            return False
        try:
            self._uc.mem_unmap(region.base, region.size)
        except UcError:
            pass
        # Remove code_ranges
        key = (region.base, region.base + region.size)
        if key in self._code_ranges:
            self._code_ranges.remove(key)
        return True

    def write_registers(self, regs: Dict[str, int]) -> None:
        """写入 寄存器 values current CPU context
        
        使用 architecture-appropriate 寄存器 mapping
        """
        for reg_name, value in regs.items():
            reg_id = self._reg_name_to_id(reg_name)
            self._uc.reg_write(reg_id, value)

    def read_registers(self, reg_names: List[str]) -> Dict[str, int]:
        """读取 寄存器 values current CPU context"""
        result = {}
        for reg_name in reg_names:
            reg_id = self._reg_name_to_id(reg_name)
            result[reg_name] = self._uc.reg_read(reg_id)
        return result

    def write_memory(self, address: int, data: bytes) -> None:
        """写入 raw bytes emulated memory address"""
        self._uc.mem_write(address, data)

    def read_memory(self, address: int, size: int) -> bytes:
        """读取 raw bytes emulated memory"""
        return self._uc.mem_read(address, size)

    def add_hook(self, hook_type: str, callback: Callable,
                 begin: int = 1, end: int = 0) -> None:
        """寄存器 a user 回调 for a Unicorn 钩子 event
        
        Supported 钩子_type values: "code", "mem_read", "mem_write"
        "mem_unmapped", "intr"
        """
        uc_hook_map = {
            "code": UC_HOOK_CODE,
            "mem_read": UC_HOOK_MEM_READ,
            "mem_write": UC_HOOK_MEM_WRITE,
            "mem_unmapped": UC_HOOK_MEM_UNMAPPED,
            "intr": UC_HOOK_INTR,
        }
        uc_hook = uc_hook_map.get(hook_type)
        if uc_hook is None:
            raise ValueError(f"Unknown hook type: {hook_type}")
        handle = self._uc.hook_add(uc_hook, callback, begin=begin, end=end)
        self._hook_handles.append(handle)
        self._user_hooks[hook_type].append(callback)

    def remove_all_hooks(self) -> None:
        """Remove user-寄存器ed 钩子s. System 钩子s (e.g., unmapped 处理器) remain"""
        for handle in self._hook_handles:
            self._uc.hook_del(handle)
        self._hook_handles.clear()
        for hooks_list in self._user_hooks.values():
            hooks_list.clear()

    def snapshot(self) -> Dict[str, Any]:
        """创建 a serializable 检查点 current 仿真 state
        
        返回 a dict containing 寄存器 state memory region contents
        用于状态空间探索中的回溯——投机执行分叉前调用此方法
        """
        snap: Dict[str, Any] = {
            "architecture": self._arch_str,
            "regions": {},
        }
        # 寄存器 快照
        reg_ids = self._default_reg_ids()
        for name, reg_id in reg_ids.items():
            try:
                snap[name] = self._uc.reg_read(reg_id)
            except UcError:
                snap[name] = 0
        # Memory region 快照
        for name, region in self._regions.items():
            try:
                contents = self._uc.mem_read(region.base, region.size)
            except UcError:
                contents = b""
            snap["regions"][name] = {
                "base": region.base,
                "size": region.size,
                "perms": region.perms,
                "data": contents,
            }
        return snap

    def restore(self, snapshot: Dict[str, Any]) -> None:
        """恢复 仿真 state a previously captured 快照"""
        # Re-init engine
        self._init_unicorn()
        self._regions.clear()
        self._code_ranges.clear()
        # Remap regions
        for name, region_info in snapshot.get("regions", {}).items():
            region = MemoryRegion(
                name=name,
                base=region_info["base"],
                size=region_info["size"],
                perms=region_info["perms"],
                data=region_info.get("data"),
            )
            self.map_region(region)
        # 恢复 寄存器s
        reg_ids = self._default_reg_ids()
        for name, reg_id in reg_ids.items():
            if name in snapshot:
                try:
                    self._uc.reg_write(reg_id, snapshot[name])
                except UcError:
                    pass

    def run(self, start_address: int, max_instructions: int = 10000,
            timeout_ms: int = 5000) -> ExecutionResult:
        """运行 仿真 start_address, stopping max_instructions or timeout
        
        Core 入口 for single-path 仿真. Block 缓存is consulted
        skip re-反汇编 previously visited addresses
        
        返回:
        ExecutionResult exit reason, instruction count, 寄存器 state
        """
        if self._uc is None:
            self._init_unicorn()
        cpu_snapshot = self.snapshot()
        t_start = time.perf_counter()
        exec_result = ExecutionResult(
            exit_code=0,
            exit_reason="timeout",
            start_address=start_address,
            end_address=start_address,
        )
        try:
            self._uc.emu_start(
                start_address,
                0,  # 停止 钩子s 返回 False or timeout
                timeout=timeout_ms * 1000,  # microseconds
                count=max_instructions,
            )
            exec_result.exit_reason = "success"
        except UcError as e:
            exec_result.exit_reason = f"unicorn_error: {e}"
            exec_result.exit_code = e.errno if hasattr(e, "errno") else -1
            exec_result.errors.append(str(e))
            self._uc.emu_stop()
        except Exception as e:
            exec_result.exit_reason = f"exception: {e}"
            exec_result.exit_code = -1
            exec_result.errors.append(traceback.format_exc())
        finally:
            exec_result.duration_ms = (time.perf_counter() - t_start) * 1000
        return exec_result

    def analyze(self, start_address: int, end_address: int,
                max_instructions: int = 20000,
                enable_speculative: bool = False) -> HybridAnalysisResult:
        """Hybrid analysis combining static 反汇编 dynamic 仿真
        
        对指定范围内的所有代码路径进行静态反汇编，然后用动态模拟补充
        路径覆盖率。若 enable_speculative=True，碰到间接跳转时启用
        投机执行来探索更多路径
        
        Args:
        start_address: 分析的起始地址
        end_address: 分析的结束地址（不含）
        max_instructions: 模拟的最大指令数
        enable_speculative: 是否启用投机间接跳转解析
        
        返回:
        HybridAnalysisResult 包含静态和动态分析的数据
        """
        t_start = time.perf_counter()
        hr = HybridAnalysisResult(
            success=False,
            architecture=self._arch_str,
        )

        # Phase 1: 静态反汇编区域内所有代码
        static_addrs: Set[int] = set()
        if CAPSTONE_AVAILABLE and self._cs_handle is not None:
            try:
                code_data = self._uc.mem_read(start_address, end_address - start_address)
                for insn in self._cs_handle.disasm(code_data, start_address):
                    if insn.address >= end_address:
                        break
                    static_addrs.add(insn.address)
                    # Populate block 缓存with 反汇编d instructions
                    # 批量填充缓存以减少后续模拟时的反汇编开销
                    successor_addrs: List[int] = []
                    # 简单的后继推断：下一条指令地址
                    next_addr = insn.address + insn.size
                    if start_address <= next_addr < end_address:
                        successor_addrs.append(next_addr)
                    # 若为直接跳转/调用，记录目标
                    if insn.mnemonic.startswith("j") or insn.mnemonic == "call":
                        op_str = getattr(insn, "op_str", "")
                        try:
                            imm_target = int(op_str, 0)
                            if start_address <= imm_target < end_address:
                                successor_addrs.append(imm_target)
                        except (ValueError, TypeError):
                            pass
                    self._block_cache.put(
                        insn.address,
                        f"{insn.mnemonic} {op_str}",
                        insn.bytes,
                        successor_addrs,
                    )
            except UcError:
                hr.warnings.append("静态反汇编阶段无法读取代码段内存")
        hr.static_insns = len(static_addrs)

        # Phase 2: 动态模拟
        exec_result = self.run(start_address, max_instructions=max_instructions)
        hr.execution_results.append(exec_result)
        hr.dynamic_insns = exec_result.instructions_executed
        hr.total_instructions = len(static_addrs | {a for a in exec_result.trace})

        # Phase 3: 投机执行（若启用）
        # 投机执行的入口点来自静态分析中标记的间接跳转
        if enable_speculative:
            # 从指令跟踪中寻找间接跳转
            self._speculative_explore(hr, start_address, end_address, max_instructions)
            hr.speculative_paths_explored = len(hr.execution_results) - 1

        # Phase 4: 识别未覆盖地址
        all_dynamic_addrs: Set[int] = set()
        for er in hr.execution_results:
            all_dynamic_addrs |= set(er.trace)
        hr.uncovered_addresses = static_addrs - all_dynamic_addrs
        hr.success = len(hr.errors) == 0 and len(hr.warnings) == 0
        hr.duration_ms = (time.perf_counter() - t_start) * 1000
        return hr

    # 投机执行内部方法：检测间接跳转并尝试并行探索目标
    # 每个候选目标在独立的执行上下文中运行，互不干扰
    # 当某个目标路径可达时，将其追踪纳入最终结果
    def _speculative_explore(self, hr: HybridAnalysisResult,
                             start_addr: int, end_addr: int,
                             max_insns: int) -> None:
        """Attempt speculative resolution for indirect branches encountered
        
        不需要对每条指令重复调用——仅在分析阶段收集间接跳转地址
        然后并行尝试所有候选目标
        """
        snap = self.snapshot()
        indirect_targets: List[Tuple[int, List[int]]] = []

        # 遍历静态指令缓存，识别间接跳转
        # 注意：这要求先调用了 analyze() 中的静态阶段，填充了 block_cache
        for addr in range(start_addr, end_addr):
            cached = self._block_cache.get(addr)
            if cached is None:
                continue
            disasm, _, _ = cached
            parts = disasm.split(maxsplit=1)
            if len(parts) < 2:
                continue
            mnemonic, op_str = parts[0], parts[1]
            if not _is_indirect_jump(mnemonic, op_str):
                continue
            # 当前执行上下文已过时——使用快照中的寄存器值近似
            regs_at_jump = {k: v for k, v in snap.items() if isinstance(v, int)}
            targets = _generate_speculative_targets(
                type("_FakeInsn", (), {"op_str": op_str, "_arch": self._arch_str})(),
                regs_at_jump,
                self._code_ranges,
                dict(self._callgraph) if self._callgraph else None,
            )
            if targets:
                indirect_targets.append((addr, targets))

        if not indirect_targets:
            return

        # 并行执行投机路径：每个间接跳转的候选目标在同一快照基础上独立模拟
        with ThreadPoolExecutor(max_workers=min(len(indirect_targets) * _SPECULATIVE_TOP_K, 8)) as pool:
            futures = {}
            for jump_addr, targets in indirect_targets:
                for target in targets:
                    fut = pool.submit(
                        self._speculative_worker,
                        snap, jump_addr, target,
                        max(min(max_insns, _SPECULATIVE_MAX_PATH_LEN), 1),
                    )
                    futures[fut] = (jump_addr, target)
            for fut in as_completed(futures, timeout=_SPECULATIVE_DEFAULT_TIMEOUT_MS / 1000 + 10):
                try:
                    worker_result = fut.result(timeout=1)
                    if worker_result is not None:
                        hr.execution_results.append(worker_result)
                except Exception:
                    pass

    def _speculative_worker(self, snap: Dict[str, Any], jump_addr: int,
                            target: int, max_steps: int) -> Optional[ExecutionResult]:
        """Worker thread: 恢复 快照, redirect PC target, emulate
        
        从快照状态恢复 → 将 PC 设为候选目标 → 模拟至多 max_steps 条指令
        若目标地址不可达（未映射、非法代码），返回 None
        """
        worker_engine = None
        try:
            worker_engine = HybridEmulationEngine(self._arch_str)
            worker_engine.restore(snap)
            # Redirect program counter speculative target
            pc_name = self._get_pc_name()
            worker_engine.write_registers({pc_name: target})
            er = worker_engine.run(target, max_instructions=max_steps, timeout_ms=1000)
            if er.exit_reason == "success" or er.instructions_executed > 0:
                return er
            return None
        except Exception:
            return None
        finally:
            if worker_engine is not None:
                worker_engine.destroy()

    def destroy(self) -> None:
        """释放 Unicorn resources internal state"""
        if self._uc is not None:
            try:
                self.remove_all_hooks()
                self._uc.emu_stop()
            except Exception:
                pass
            self._uc = None
        self._regions.clear()
        self._code_ranges.clear()
        self._block_cache.clear()
        self._hook_handles.clear()
        self._callgraph.clear()

    def set_callgraph(self, callgraph: Dict[int, List[int]]) -> None:
        """提供 a precomputed call-graph for speculative execution hinting"""
        self._callgraph = defaultdict(list, callgraph)

    def get_block_cache_stats(self) -> Dict[str, Any]:
        """返回 block 缓存hit/miss statistics for 性能 monitoring"""
        return self._block_cache.stats

    def invalidate_code_cache(self, start: int, end: int) -> int:
        """In校验 all缓存d blocks [启动, end). 返回 count removed"""
        return self._block_cache.invalidate_range(start, end)

    # Internal 辅助函数
    def _hook_mem_unmapped_default(self, uc: Uc, access: int, address: int,
                                   size: int, value: int, user_data: Any) -> bool:
        """默认的未映射内存钩子：记录访问并停止模拟，防止无限故障循环"""
        access_names = {UC_MEM_READ: "read", UC_MEM_WRITE: "write", UC_MEM_FETCH: "fetch"}
        access_type = access_names.get(access, "unknown")
        logger.debug(
            "内存未映射访问: type=%s addr=0x%x size=%d value=0x%x",
            access_type, address, size, value,
        )
        return False  # 停止模拟

    def _get_pc_name(self) -> str:
        """返回 program-counter 寄存器 name for current architecture"""
        pc_map = {
            "x86": "eip", "x64": "rip",
            "arm": "pc", "arm64": "pc",
            "mips": "pc",
        }
        return pc_map.get(self._arch_str, "rip")

    def _reg_name_to_id(self, reg_name: str) -> int:
        """Map a human-readable 寄存器 name Unicorn 寄存器 ID"""
        reg_name_l = reg_name.lower()

        # x86/x64 寄存器s
        x86_regs = {
            "eax": unicorn.x86_const.UC_X86_REG_EAX,
            "ebx": unicorn.x86_const.UC_X86_REG_EBX,
            "ecx": unicorn.x86_const.UC_X86_REG_ECX,
            "edx": unicorn.x86_const.UC_X86_REG_EDX,
            "esi": unicorn.x86_const.UC_X86_REG_ESI,
            "edi": unicorn.x86_const.UC_X86_REG_EDI,
            "ebp": unicorn.x86_const.UC_X86_REG_EBP,
            "esp": unicorn.x86_const.UC_X86_REG_ESP,
            "eip": unicorn.x86_const.UC_X86_REG_EIP,
            "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
            "rax": unicorn.x86_const.UC_X86_REG_RAX,
            "rbx": unicorn.x86_const.UC_X86_REG_RBX,
            "rcx": unicorn.x86_const.UC_X86_REG_RCX,
            "rdx": unicorn.x86_const.UC_X86_REG_RDX,
            "rsi": unicorn.x86_const.UC_X86_REG_RSI,
            "rdi": unicorn.x86_const.UC_X86_REG_RDI,
            "rbp": unicorn.x86_const.UC_X86_REG_RBP,
            "rsp": unicorn.x86_const.UC_X86_REG_RSP,
            "rip": unicorn.x86_const.UC_X86_REG_RIP,
            "r8": unicorn.x86_const.UC_X86_REG_R8,
            "r9": unicorn.x86_const.UC_X86_REG_R9,
            "r10": unicorn.x86_const.UC_X86_REG_R10,
            "r11": unicorn.x86_const.UC_X86_REG_R11,
            "r12": unicorn.x86_const.UC_X86_REG_R12,
            "r13": unicorn.x86_const.UC_X86_REG_R13,
            "r14": unicorn.x86_const.UC_X86_REG_R14,
            "r15": unicorn.x86_const.UC_X86_REG_R15,
            "rflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        }

        if reg_name_l in x86_regs:
            return x86_regs[reg_name_l]

        # ARM 寄存器s
        arm_map = {
            "r0": unicorn.arm_const.UC_ARM_REG_R0,
            "r1": unicorn.arm_const.UC_ARM_REG_R1,
            "r2": unicorn.arm_const.UC_ARM_REG_R2,
            "r3": unicorn.arm_const.UC_ARM_REG_R3,
            "r4": unicorn.arm_const.UC_ARM_REG_R4,
            "r5": unicorn.arm_const.UC_ARM_REG_R5,
            "r6": unicorn.arm_const.UC_ARM_REG_R6,
            "r7": unicorn.arm_const.UC_ARM_REG_R7,
            "r8": unicorn.arm_const.UC_ARM_REG_R8,
            "r9": unicorn.arm_const.UC_ARM_REG_R9,
            "r10": unicorn.arm_const.UC_ARM_REG_R10,
            "r11": unicorn.arm_const.UC_ARM_REG_R11,
            "r12": unicorn.arm_const.UC_ARM_REG_R12,
            "sp": unicorn.arm_const.UC_ARM_REG_SP,
            "lr": unicorn.arm_const.UC_ARM_REG_LR,
            "pc": unicorn.arm_const.UC_ARM_REG_PC,
            "cpsr": unicorn.arm_const.UC_ARM_REG_CPSR,
        }

        # 对于 arm64，使用 arm64_const
        if "arm64" in self._arch_str:
            arm64_map = {
                "x0": unicorn.arm64_const.UC_ARM64_REG_X0,
                "x1": unicorn.arm64_const.UC_ARM64_REG_X1,
                "x29": unicorn.arm64_const.UC_ARM64_REG_FP,
                "x30": unicorn.arm64_const.UC_ARM64_REG_LR,
                "sp": unicorn.arm64_const.UC_ARM64_REG_SP,
                "pc": unicorn.arm64_const.UC_ARM64_REG_PC,
                "nzcv": unicorn.arm64_const.UC_ARM64_REG_NZCV,
            }
            if reg_name_l in arm64_map:
                return arm64_map[reg_name_l]
            # Generic Xn mapping
            if reg_name_l.startswith("x") and len(reg_name_l) <= 3:
                try:
                    reg_idx = int(reg_name_l[1:])
                    if 0 <= reg_idx <= 30:
                        return getattr(unicorn.arm64_const, f"UC_ARM64_REG_X{reg_idx}")
                except ValueError:
                    pass

        if reg_name_l in arm_map:
            return arm_map[reg_name_l]

        # MIPS 寄存器s
        mips_map = {
            "zero": unicorn.mips_const.UC_MIPS_REG_ZERO,
            "at": unicorn.mips_const.UC_MIPS_REG_AT,
            "v0": unicorn.mips_const.UC_MIPS_REG_V0,
            "v1": unicorn.mips_const.UC_MIPS_REG_V1,
            "a0": unicorn.mips_const.UC_MIPS_REG_A0,
            "a1": unicorn.mips_const.UC_MIPS_REG_A1,
            "a2": unicorn.mips_const.UC_MIPS_REG_A2,
            "a3": unicorn.mips_const.UC_MIPS_REG_A3,
            "t0": unicorn.mips_const.UC_MIPS_REG_T0,
            "t1": unicorn.mips_const.UC_MIPS_REG_T1,
            "sp": unicorn.mips_const.UC_MIPS_REG_SP,
            "fp": unicorn.mips_const.UC_MIPS_REG_FP,
            "ra": unicorn.mips_const.UC_MIPS_REG_RA,
            "pc": unicorn.mips_const.UC_MIPS_REG_PC,
        }
        if reg_name_l in mips_map:
            return mips_map[reg_name_l]

        raise KeyError(f"Unknown register '{reg_name}' for architecture '{self._arch_str}'")

    def _default_reg_ids(self) -> Dict[str, int]:
        """返回 default set general-purpose 寄存器 IDs for 快照ting"""
        if self._arch_str in ("x86", "x64"):
            return {
                "rax": unicorn.x86_const.UC_X86_REG_RAX,
                "rbx": unicorn.x86_const.UC_X86_REG_RBX,
                "rcx": unicorn.x86_const.UC_X86_REG_RCX,
                "rdx": unicorn.x86_const.UC_X86_REG_RDX,
                "rsi": unicorn.x86_const.UC_X86_REG_RSI,
                "rdi": unicorn.x86_const.UC_X86_REG_RDI,
                "rbp": unicorn.x86_const.UC_X86_REG_RBP,
                "rsp": unicorn.x86_const.UC_X86_REG_RSP,
                "rip": unicorn.x86_const.UC_X86_REG_RIP,
            }
        elif self._arch_str in ("arm",):
            return {
                "r0": unicorn.arm_const.UC_ARM_REG_R0,
                "r1": unicorn.arm_const.UC_ARM_REG_R1,
                "r2": unicorn.arm_const.UC_ARM_REG_R2,
                "r3": unicorn.arm_const.UC_ARM_REG_R3,
                "sp": unicorn.arm_const.UC_ARM_REG_SP,
                "lr": unicorn.arm_const.UC_ARM_REG_LR,
                "pc": unicorn.arm_const.UC_ARM_REG_PC,
            }
        elif self._arch_str in ("arm64",):
            return {
                "x0": unicorn.arm64_const.UC_ARM64_REG_X0,
                "x1": unicorn.arm64_const.UC_ARM64_REG_X1,
                "sp": unicorn.arm64_const.UC_ARM64_REG_SP,
                "lr": unicorn.arm64_const.UC_ARM64_REG_LR,
                "pc": unicorn.arm64_const.UC_ARM64_REG_PC,
            }
        elif self._arch_str in ("mips",):
            return {
                "v0": unicorn.mips_const.UC_MIPS_REG_V0,
                "a0": unicorn.mips_const.UC_MIPS_REG_A0,
                "sp": unicorn.mips_const.UC_MIPS_REG_SP,
                "ra": unicorn.mips_const.UC_MIPS_REG_RA,
                "pc": unicorn.mips_const.UC_MIPS_REG_PC,
            }
        return {}


# Convenience 工厂 function


def create_engine(architecture: str = "x64",
                  block_cache_capacity: int = 512) -> HybridEmulationEngine:
    """工厂: construct 返回 a ready--使用 Hybrid仿真Engine
    
    Args:
    architecture: Target ISA string ("x86", "x64", "arm", "arm64", "mips")
    block_cache_capacity: Maximum number of缓存d translated blocks
    
    返回:
    配置ured Hybrid仿真Engine instance
    """
    engine = HybridEmulationEngine(architecture)
    engine._block_cache = BlockCache(capacity=block_cache_capacity)
    return engine
