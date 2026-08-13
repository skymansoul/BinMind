from enum import StrEnum
import logging
import os
import json
import time
import random
import struct
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


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


class TagSpace:
    """??????"""

    def __init__(self, max_tag: int = 15):
        self.max_tag = max_tag
        self._counter = 0
        self._lock = threading.Lock()
        # tag 0 ?????/????
        self._used: Set[int] = {0}
        # 标签猜测计数：tag -> 连续猜测次数
        self._guess_counts: Dict[int, int] = {}

    def alloc_tag(self) -> int:
        with self._lock:
            for _ in range(self.max_tag * 2):
                self._counter = (self._counter + 1) & self.max_tag
                if self._counter == 0:
                    self._counter = 1
                if self._counter not in self._used:
                    self._used.add(self._counter)
                    return self._counter
            # ????, ????
            self._counter = (self._counter + 1) & self.max_tag
            if self._counter == 0:
                self._counter = 1
            return self._counter

    def free_tag(self, tag: int):
        with self._lock:
            self._used.discard(tag)

    def is_valid(self, tag: int) -> bool:
        return 0 <= tag <= self.max_tag

    # 猜测攻击检测：同一标签被猜超过阈值标记为攻击。
    # 4 位标签空间含 16 个值，暴力猜测尝试次数是现实攻击模型的近似。
    GUESS_THRESHOLD = 8

    def record_guess_attempt(self, tag: int) -> bool:
        """记录一次对指定标签的猜测，超过阈值返回 True（攻击）。"""
        with self._lock:
            count = self._guess_counts.get(tag, 0) + 1
            self._guess_counts[tag] = count
            return count > self.GUESS_THRESHOLD


class MTEState:
    """MTE ??"""

    TAG_GRANULE = 16  # ? 16 ??????

    def __init__(self):
        self.tag_space = TagSpace()
        # addr // GRANULE -> tag
        self.memory_tags: Dict[int, int] = {}
        self.allocations: List[MTEAllocation] = []
        self.active_allocs: Dict[int, MTEAllocation] = {}
        self.violations: List[MTEViolation] = []
        self._lock = threading.Lock()
        self._enabled = True

    def align(self, addr: int) -> int:
        return addr - (addr % self.TAG_GRANULE)

    def tag_of(self, addr: int) -> int:
        aligned = self.align(addr)
        return self.memory_tags.get(aligned, 0)

    def set_tag(self, addr: int, tag: int, size: int = TAG_GRANULE):
        aligned = self.align(addr)
        end = self.align(addr + size - 1) + self.TAG_GRANULE
        cur = aligned
        while cur < end:
            self.memory_tags[cur] = tag
            cur += self.TAG_GRANULE

    def clear_tag(self, addr: int, size: int):
        aligned = self.align(addr)
        end = self.align(addr + size - 1) + self.TAG_GRANULE
        cur = aligned
        while cur < end:
            self.memory_tags.pop(cur, None)
            cur += self.TAG_GRANULE

    def alloc(self, addr: int, size: int, alloc_type: str = "heap", var_name: str = "") -> MTEAllocation:
        with self._lock:
            tag = self.tag_space.alloc_tag()
            self.set_tag(addr, tag, size)
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
                # active_allocs 中无记录：区分从未分配与已释放两种情况。
                # 已释放的分配保留在 allocations 历史列表中，供二次释放检测。
                freed_alloc = next(
                    (x for x in reversed(self.allocations)
                     if x.addr == addr and x.freed),
                    None,
                )
                if freed_alloc is not None:
                    v = MTEViolation(
                        vtype=MTEViolationType.DOUBLE_FREE,
                        addr=addr,
                        actual_tag=freed_alloc.tag,
                        expected_tag=freed_alloc.tag,
                        pc=0,
                        access_size=0,
                        is_write=True,
                        message=f"重复释放 0x{addr:x}",)
                    self.violations.append(v)
                    return False, v
                v = MTEViolation(
                    vtype=MTEViolationType.WILD_FREE,
                    addr=addr,
                    actual_tag=0,
                    expected_tag=0,
                    pc=0,
                    access_size=0,
                    is_write=True,
                    message=f"释放未分配地址 0x{addr:x}",)
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
                    message=f"重复释放 0x{addr:x}",)
                self.violations.append(v)
                return False, v
            a.freed = True
            a.free_time = time.time()
            self.clear_tag(addr, a.size)
            self.tag_space.free_tag(a.tag)
            self.active_allocs.pop(addr, None)
            return True, None

    def check_access(self, addr: int, size: int, is_write: bool, pc: int = 0,
                     speculative: bool = False) -> List[MTEViolation]:
        """检查内存访问是否违反 MTE 标签约束。

        speculative=True 时，推测执行导致的标签失配降级为
        SPECULATIVE_TAG_BYPASS，不作为确定性违规上报。
        """
        violations: List[MTEViolation] = []
        with self._lock:
            if not self._enabled:
                return violations
            for off in range(0, size, self.TAG_GRANULE):
                cur = addr + off
                expected = self.tag_of(cur)
                # 已释放分配上的访问判定为 UAF；freed 记录保留在 allocations 历史中。
                # 该分支优先于 UNINIT_READ：释放后标签被清除，但语义上是悬垂访问。
                freed_alloc = next(
                    (a for a in self.allocations
                     if a.freed and a.addr <= cur < a.addr + a.size),
                    None,
                )
                if freed_alloc is not None:
                    vtype = (MTEViolationType.SPECULATIVE_TAG_BYPASS
                             if speculative else MTEViolationType.USE_AFTER_FREE)
                    v = MTEViolation(
                        vtype=vtype,
                        addr=cur,
                        actual_tag=0,
                        expected_tag=freed_alloc.tag,
                        pc=pc,
                        access_size=min(self.TAG_GRANULE, size - off),
                        is_write=is_write,
                        message=f"UAF 访问 0x{cur:x} (释放于 0x{freed_alloc.addr:x})",)
                    violations.append(v)
                    continue
                # 未初始化/未分配
                if expected == 0:
                    v = MTEViolation(
                        vtype=MTEViolationType.UNINIT_READ,
                        addr=cur,
                        actual_tag=0,
                        expected_tag=0,
                        pc=pc,
                        access_size=min(self.TAG_GRANULE, size - off),
                        is_write=is_write,
                        message=f"未初始化/未分配 0x{cur:x}",)
                    if speculative:
                        v.vtype = MTEViolationType.SPECULATIVE_TAG_BYPASS
                    violations.append(v)
        for v in violations:
            self.violations.append(v)
        return violations


class UnicornMTEHook:
    """Unicorn ?? MTE ??"""

    def __init__(self, uc, mte_state: MTEState):
        self.uc = uc
        self.mte = mte_state
        self._installed = False

    def install(self):
        """??? Unicorn ??"""
        if self._installed:
            return
        try:
            self.uc.hook_add(
                unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
                self._hook_mem_access,)
            self.uc.hook_add(
                unicorn.UC_HOOK_MEM_UNMAPPED,
                self._hook_mem_invalid,)
            self._installed = True
        except Exception as e:
            logger.warning(f"?? MTE ????: {e}")

    def _hook_mem_access(self, uc, access, address, size, value, user_data):
        is_write = bool(access & unicorn.UC_HOOK_MEM_WRITE)
        pc = 0
        try:
            if hasattr(uc, "reg_read"):
                pc = uc.reg_read(getattr(unicorn, "UC_X86_REG_RIP", 0))
        except Exception:
            pc = 0
        self.mte.check_access(address, size, is_write, pc=pc)

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        logger.debug(f"???????: 0x{address:x}, size={size}")


try:
    import unicorn
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False


class MTEViolationClassifier:
    """MTE ?????"""

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
    """MTE ??? (???)"""

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

    def attach_unicorn(self, uc) -> Optional[UnicornMTEHook]:
        """??? Unicorn ??"""
        if not _UNICORN_AVAILABLE:
            logger.warning("unicorn ???")
            return None
        hook = UnicornMTEHook(uc, self.state)
        hook.install()
        return hook

    def simulate_runtime(
            self,
            allocs: List[Dict[str, Any]],
            accesses: List[Dict[str, Any]],
            frees: List[Dict[str, Any]]
        ) -> MTEReport:
        """?????"""
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
        return MTEReport(
            total_allocs=total_allocs,
            total_frees=total_frees,
            total_violations=len(violations),
            violations=list(violations),
            by_type=dict(by_type),
            coverage=min(1.0, total_allocs / 100.0),
            notes=f"??? {total_allocs} ?, ??? {total_frees} ?",)

    def enable(self, on: bool = True):
        with self._lock:
            self.state._enabled = on

    def reset(self):
        self.state = MTEState()
        with self._lock:
            self._events = []
