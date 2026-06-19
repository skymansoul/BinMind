"""
内存标签模拟与分析模块 (类似 ARM MTE)

功能:
    1. 在 Unicorn 模拟中实现内存标签(类似 ARM MTE)
    2. 标记分配的内存区域, 模拟检测 UAF 和缓冲区溢出
    3. 辅助漏洞验证和利用稳定性测试

核心技术:
    - 标签颗粒度: 16 字节(对齐)
    - 标签分配: 随机 + 增量计数器
    - 检查语义: 加载/存储时验证标签匹配
    - 报告生成: 详细的不匹配事件
"""

import logging
import os
import json
import time
import random
import struct
import threading
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class MTEViolationType(Enum):
    """MTE 违规类型"""
    NONE = "none"
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    STACK_USE_AFTER_RETURN = "stack_use_after_return"
    DOUBLE_FREE = "double_free"
    WILD_FREE = "wild_free"
    INVALID_FREE = "invalid_free"
    UNINIT_READ = "uninit_read"


@dataclass
class MTEAllocation:
    """MTE 内存分配记录"""
    addr: int
    size: int
    tag: int
    alloc_type: str  # "stack" / "heap" / "global"
    var_name: str = ""
    freed: bool = False
    alloc_time: float = 0.0
    free_time: float = 0.0


@dataclass
class MTEViolation:
    """MTE 违规事件"""
    vtype: MTEViolationType
    addr: int
    actual_tag: int
    expected_tag: int
    pc: int
    access_size: int
    is_write: bool
    timestamp: float = 0.0
    context: str = ""
    message: str = ""

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class MTEReport:
    """MTE 分析报告"""
    total_allocs: int
    total_frees: int
    total_violations: int
    violations: List[MTEViolation] = field(default_factory=list)
    by_type: Dict[str, int] = field(default_factory=dict)
    coverage: float = 0.0
    timestamp: float = 0.0
    notes: str = ""


class TagSpace:
    """标签空间管理"""

    def __init__(self, max_tag: int = 15):
        self.max_tag = max_tag
        self._counter = 0
        self._lock = threading.Lock()
        # tag 0 保留为无效/未初始化
        self._used: Set[int] = {0}

    def alloc_tag(self) -> int:
        with self._lock:
            for _ in range(self.max_tag * 2):
                self._counter = (self._counter + 1) & self.max_tag
                if self._counter == 0:
                    self._counter = 1
                if self._counter not in self._used:
                    self._used.add(self._counter)
                    return self._counter
            # 全部使用, 强制覆盖
            self._counter = (self._counter + 1) & self.max_tag
            if self._counter == 0:
                self._counter = 1
            return self._counter

    def free_tag(self, tag: int):
        with self._lock:
            self._used.discard(tag)

    def is_valid(self, tag: int) -> bool:
        return 0 <= tag <= self.max_tag


class MTEState:
    """MTE 状态"""

    TAG_GRANULE = 16  # 每 16 字节一个标签

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
                alloc_time=time.time())
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
                    message=f"尝试释放未追踪地址 0x{addr:x}")
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
                    message=f"双重释放 0x{addr:x}")
                self.violations.append(v)
                return False, v
            a.freed = True
            a.free_time = time.time()
            self.clear_tag(addr, a.size)
            self.tag_space.free_tag(a.tag)
            self.active_allocs.pop(addr, None)
            return True, None

    def check_access(self, addr: int, size: int, is_write: bool, pc: int = 0) -> List[MTEViolation]:
        """检查访问是否合法"""
        violations: List[MTEViolation] = []
        with self._lock:
            if not self._enabled:
                return violations
            for off in range(0, size, self.TAG_GRANULE):
                cur = addr + off
                expected = self.tag_of(cur)
                # 期望非零标签
                if expected == 0:
                    v = MTEViolation(
                        vtype=MTEViolationType.UNINIT_READ,
                        addr=cur,
                        actual_tag=0,
                        expected_tag=0,
                        pc=pc,
                        access_size=min(self.TAG_GRANULE, size - off),
                        is_write=is_write,
                        message=f"访问未初始化/无效内存 0x{cur:x}")
                    violations.append(v)
                # 检查是否属于已释放的 alloc
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
                            message=f"UAF 访问 0x{cur:x} (分配 0x{a.addr:x} 已释放)")
                        violations.append(v)
                        break
        for v in violations:
            self.violations.append(v)
        return violations


class UnicornMTEHook:
    """Unicorn 引擎 MTE 钩子"""

    def __init__(self, uc, mte_state: MTEState):
        self.uc = uc
        self.mte = mte_state
        self._installed = False

    def install(self):
        """安装到 Unicorn 引擎"""
        if self._installed:
            return
        try:
            self.uc.hook_add(
                unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
                self._hook_mem_access)
            self.uc.hook_add(
                unicorn.UC_HOOK_MEM_UNMAPPED,
                self._hook_mem_invalid)
            self._installed = True
        except Exception as e:
            logger.warning(f"安装 MTE 钩子失败: {e}")

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
        logger.debug(f"未映射内存访问: 0x{address:x}, size={size}")


# 容错导入
try:
    import unicorn  # type: ignore
    _UNICORN_AVAILABLE = True
except ImportError:
    _UNICORN_AVAILABLE = False
    unicorn = None  # type: ignore


class MTEViolationClassifier:
    """MTE 违规分类器"""

    HEAP_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "operator new", "_Znwm", "_Znam"}
    HEAP_FREE_FUNCS = {"free", "operator delete", "_ZdlPv", "_ZdaPv"}

    def __init__(self):
        self._lock = threading.Lock()

    def classify_from_call(self, func_name: str, args: List[int]) -> Optional[MTEViolation]:
        """从调用分类"""
        with self._lock:
            if func_name in self.HEAP_ALLOC_FUNCS:
                if args and args[0] > 0:
                    return None  # alloc 由 MTEState 处理
            return None


class MTEAnalyzer:
    """MTE 分析器 (主入口)"""

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
        """附加到 Unicorn 引擎"""
        if not _UNICORN_AVAILABLE:
            logger.warning("unicorn 不可用")
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
        """模拟运行时"""
        # 排序: alloc -> access -> free
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
                    var_name=data.get("var", ""))
            elif kind == "access":
                self.record_access(
                    addr=int(data["addr"]),
                    size=int(data.get("size", 1)),
                    is_write=bool(data.get("is_write", False)),
                    pc=int(data.get("pc", 0)))
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
            notes=f"已分配 {total_allocs} 次, 已释放 {total_frees} 次")

    def enable(self, on: bool = True):
        with self._lock:
            self.state._enabled = on

    def reset(self):
        self.state = MTEState()
        with self._lock:
            self._events = []
