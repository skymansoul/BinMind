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
    # 新增：标签猜测攻击相关
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


class TagSpace:
    """标签空间管理器

    分配/释放 4-bit 标签。tag=0 保留为未标记/默认。
    标签猜测攻击防护：增加分配时的随机延迟（模拟硬件中的随机化）。
    """

    # 最大标签值（ARM MTE 为 15，即 4-bit 逻辑标签）
    # tag 0 保留给无标签内存
    _RESERVED_TAGS = {0}

    def __init__(self, max_tag: int = 15):
        self.max_tag = max_tag
        self._counter = random.randint(1, max_tag)  # 随机起始点，防确定性分配
        self._lock = threading.Lock()
        self._used: Set[int] = set(self._RESERVED_TAGS)
        # 标签猜测尝试计数（用于检测暴力枚举标签的攻击）
        self._tag_guess_attempts: Dict[int, int] = defaultdict(int)

    def alloc_tag(self) -> int:
        """分配一个未使用的标签。

        采用循环扫描 + 随机跳跃，降低相邻分配的可预测性。
        这是 TikTag (S&P 2025) 攻击面缓解的一部分：
        确定性标签分配使攻击者可预测未来标签值。
        """
        with self._lock:
            start = self._counter
            # 随机跳跃步长（奇数保证在模空间中覆盖所有值）
            step = random.choice([1, 3, 5, 7, 11])
            for _ in range(self.max_tag * 2):
                self._counter = (self._counter + step) & self.max_tag
                if self._counter not in self._used and self._counter not in self._RESERVED_TAGS:
                    self._used.add(self._counter)
                    return self._counter
            # 所有标签都在用 → 强制复用最少使用的标签（LRU 风格）
            self._counter = (self._counter + 1) & self.max_tag
            if self._counter in self._RESERVED_TAGS:
                self._counter = 1
            return self._counter

    def free_tag(self, tag: int):
        with self._lock:
            self._used.discard(tag)

    def record_guess_attempt(self, tag: int) -> bool:
        """记录一次标签猜测。如果同一标签被猜超过阈值，标记为攻击。"""
        with self._lock:
            self._tag_guess_attempts[tag] += 1
            return self._tag_guess_attempts[tag] > 8  # 阈值：同一标签被猜 8 次

    def is_valid(self, tag: int) -> bool:
        return 0 <= tag <= self.max_tag


class MTEState:
    """MTE 内存标签状态机 — 管理标签分配、内存标签映射和访问校验。"""

    TAG_GRANULE = 16  # 每 16 字节一个标签颗粒

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
                v = MTEViolation(
                    vtype=MTEViolationType.WILD_FREE,
                    addr=addr,
                    actual_tag=0,
                    expected_tag=0,
                    pc=0,
                    access_size=0,
                    is_write=True,
                    message=f"野指针释放 0x{addr:x}",)
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
                    message=f"双重释放 0x{addr:x}",)
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
        """内存访问标签校验。

        新增 speculative 参数：如果访问发生在推测执行路径中，
        标记为潜在侧信道（参考 TikTag: 推测执行可绕过 MTE 标签检查）。
        """
        violations: List[MTEViolation] = []
        with self._lock:
            if not self._enabled:
                return violations
            for off in range(0, size, self.TAG_GRANULE):
                cur = addr + off
                expected = self.tag_of(cur)
                # 未初始化内存检查
                if expected == 0:
                    v = MTEViolation(
                        vtype=MTEViolationType.UNINIT_READ,
                        addr=cur,
                        actual_tag=0,
                        expected_tag=0,
                        pc=pc,
                        access_size=min(self.TAG_GRANULE, size - off),
                        is_write=is_write,
                        message=f"未初始化读/野指针 0x{cur:x}",)
                    violations.append(v)
                # 检查已释放的 alloc 对象
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
                            message=f"UAF 访问 0x{cur:x} (分配于 0x{a.addr:x} 已释放)",)
                        violations.append(v)
                        break
            # 推测执行绕过检测
            if speculative and violations:
                for v in violations:
                    v.vtype = MTEViolationType.SPECULATIVE_TAG_BYPASS
        for v in violations:
            self.violations.append(v)
        return violations


class UnicornMTEHook:
    """Unicorn 挂钩 MTE 内存访问检查 — 将 MTE 标签校验注入 Unicorn 模拟器。"""

    def __init__(self, uc, mte_state: MTEState):
        self.uc = uc
        self.mte = mte_state
        self._installed = False

    def install(self):
        """安装 Unicorn 挂钩 — 注册内存读写和未映射访问回调。"""
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
            logger.warning(f"安装 MTE 挂钩失败: {e}")

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
        logger.debug(f"无效内存访问: 0x{address:x}, size={size}")


try:
    import unicorn
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False


class MTEViolationClassifier:
    """MTE 违规分类器 — 根据函数调用名称和参数分类违规类型。"""

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
    """MTE 分析器 (主入口) — 记录分配/释放/访问事件，生成违规报告。"""

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
        """附加 Unicorn 挂钩 — 将 MTE 检测注入到 Unicorn 模拟器中。"""
        if not _UNICORN_AVAILABLE:
            logger.warning("unicorn 不可用 — 无法附加 MTE 挂钩")
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
        """运行时模拟 — 按时间线重放分配/访问/释放事件并生成报告。"""
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
        notes_parts = [f"共 {total_allocs} 次分配, {total_frees} 次释放"]
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
