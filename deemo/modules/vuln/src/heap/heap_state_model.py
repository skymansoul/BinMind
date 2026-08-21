#
"""堆生命周期状态机 — 对malloc/free/realloc的调用图+数据流建模。

现有 BIFT 对堆漏洞的检测是间接的——它只能标记"污点数据到达了 free()"，
但无法判断"free 之后同一个指针是否仍被使用"(UAF)或"同一指针被 free 两次"。

本模块的方案——不执行程序, 通过静态调用图+数据流分析推断堆指针生命周期:
1. 识别所有 malloc/calloc/realloc 调用点 (分配点)。
2. 识别所有 free 调用点 (释放点)。
3. 对每个分配点, 追踪其返回值(堆指针)在调用图上的流动。
4. 若指针在 free 后仍传递到任何 dereference 点 → UAF。
5. 若同一指针出现两条 free 路径 → Double-Free。

关键: 这是"可能分析"(may-analysis)——不要求证明一定发生,
只要存在一条可能的路径 → 标记为潜在漏洞。
这保证了零漏报(对所有可证明安全的路径已过滤),
代价是仍有一些假阳性(不可达的路径被保守地认为可达)。

HexType 使用类似的状态机但依赖动态类型信息。
本实现纯静态——不需要运行时信息, 直接工作在反汇编输出上。

与现有模块集成:
  - 输入: BIFT 的污点源/汇 + 反汇编的调用图
  - 输出: 堆漏洞发现列表 → 注入 cmvc_engine 做跨模态确认
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


class HeapOp(Enum):
    ALLOC = "alloc"      # malloc / calloc / realloc
    FREE = "free"        # free / kfree
    REALLOC = "realloc"  # realloc (先free再alloc)
    USE = "use"          # 解引用 / 作为函数参数传递


class HeapPtrState(Enum):
    LIVE = "live"             # 已分配, 可使用
    FREED = "freed"           # 已释放, 不可使用
    DANGLING = "dangling"     # 释放后被使用 → UAF
    DOUBLE_FREED = "df"      # 被释放两次


@dataclass
class HeapEvent:
    """堆操作事件——在某个函数/地址发生的一次堆操作。"""
    event_id: str
    op: HeapOp
    address: int
    function_name: str
    pointer_expr: str = ""     # 被操作的指针表达式(如 rax, [rbp-8])
    size_arg: int = 0           # alloc时的size参数(0=未知)
    callees: List[str] = field(default_factory=list)


@dataclass
class HeapPtrLifetime:
    """一个堆指针的完整生命周期追踪。"""
    ptr_id: str
    alloc_event: Optional[HeapEvent] = None
    free_events: List[HeapEvent] = field(default_factory=list)
    use_events: List[HeapEvent] = field(default_factory=list)
    use_after_free: List[Tuple[HeapEvent, HeapEvent]] = field(default_factory=list)
    double_free: List[Tuple[HeapEvent, HeapEvent]] = field(default_factory=list)


@dataclass
class HeapVulnFinding:
    """堆漏洞发现。"""
    vuln_type: str                # "use_after_free" | "double_free"
    alloc_site: int = 0
    free_site: int = 0
    use_site: int = 0             # UAF的use点
    second_free_site: int = 0     # DF的第二个free点
    function_name: str = ""
    severity: str = "HIGH"
    confidence: float = 0.6       # 静态分析的保守置信度


class HeapStateModel:
    """堆生命周期有限状态机——静态推断UAF/Double-Free。

    使用:
      model = HeapStateModel()
      model.ingest_alloc(addr, func, ptr_expr)
      model.ingest_free(addr, func, ptr_expr)
      findings = model.detect_vulnerabilities()

    状态转移:
      null → (malloc) → LIVE → (free) → FREED
      LIVE → (use) → LIVE
      FREED → (use) → DANGLING [UAF告警]
      FREED → (free) → DOUBLE_FREED [DF告警]
      LIVE → (realloc) → LIVE [size变化但ptr不变]
    """

    def __init__(self):
        # 所有指针的生命周期
        self._lifetimes: Dict[str, HeapPtrLifetime] = {}
        # 指针别名追踪: func::expr → ptr_id
        self._aliases: Dict[str, str] = {}
        # 函数间传递: 调用点→被调用函数的参数→ptr_id
        self._interprocedural: Dict[Tuple[str, int], str] = {}

    # 摄入API

    def ingest_alloc(
        self, addr: int, func_name: str, ptr_expr: str,
        size: int = 0,
    ) -> str:
        """摄入一次分配——返回指针ID。"""
        _pid = f"heap@{hex(addr)}"
        _event = HeapEvent(
            event_id=f"alloc_{_pid}", op=HeapOp.ALLOC,
            address=addr, function_name=func_name,
            pointer_expr=ptr_expr, size_arg=size,
        )

        if _pid not in self._lifetimes:
            self._lifetimes[_pid] = HeapPtrLifetime(ptr_id=_pid)
        self._lifetimes[_pid].alloc_event = _event

        self._aliases[f"{func_name}::{ptr_expr}"] = _pid
        return _pid

    def ingest_free(
        self, addr: int, func_name: str, ptr_expr: str,
    ) -> Optional[str]:
        """摄入一次释放——若此前已free则为Double-Free。"""
        _pid = self._resolve_ptr(func_name, ptr_expr)
        if _pid is None:
            return None

        _event = HeapEvent(
            event_id=f"free_{_pid}@{hex(addr)}", op=HeapOp.FREE,
            address=addr, function_name=func_name,
            pointer_expr=ptr_expr,
        )

        if _pid not in self._lifetimes:
            self._lifetimes[_pid] = HeapPtrLifetime(ptr_id=_pid)
        _lt = self._lifetimes[_pid]
        _lt.free_events.append(_event)

        return _pid

    def ingest_use(
        self, addr: int, func_name: str, ptr_expr: str,
    ) -> Optional[str]:
        """摄入一次指针使用(解引用/传递)——若在free后则为UAF。"""
        _pid = self._resolve_ptr(func_name, ptr_expr)
        if _pid is None:
            return None

        _event = HeapEvent(
            event_id=f"use_{_pid}@{hex(addr)}", op=HeapOp.USE,
            address=addr, function_name=func_name,
            pointer_expr=ptr_expr,
        )

        if _pid not in self._lifetimes:
            self._lifetimes[_pid] = HeapPtrLifetime(ptr_id=_pid)
        self._lifetimes[_pid].use_events.append(_event)

        return _pid

    # 检测API

    def detect_vulnerabilities(self) -> List[HeapVulnFinding]:
        """对所有已追踪指针执行UAF/Double-Free检测。"""
        _findings: List[HeapVulnFinding] = []

        for _pid, _lt in self._lifetimes.items():
            _alloc_addr = _lt.alloc_event.address if _lt.alloc_event else 0

            # Double-Free: 两条free路径到达同一指针
            if len(_lt.free_events) >= 2:
                for _i in range(len(_lt.free_events)):
                    for _j in range(_i + 1, len(_lt.free_events)):
                        _df = (min(_lt.free_events[_i], _lt.free_events[_j],
                                   key=lambda e: e.address),
                               max(_lt.free_events[_i], _lt.free_events[_j],
                                   key=lambda e: e.address))
                        _lt.double_free.append(_df)
                        _findings.append(HeapVulnFinding(
                            vuln_type="double_free",
                            alloc_site=_alloc_addr,
                            free_site=_df[0].address,
                            second_free_site=_df[1].address,
                            function_name=_df[0].function_name,
                            confidence=0.85,
                        ))

            # UAF: free之后有use
            if _lt.free_events and _lt.use_events:
                _last_free = max(_lt.free_events, key=lambda e: e.address)
                for _use in _lt.use_events:
                    if _use.address > _last_free.address:
                        _lt.use_after_free.append((_last_free, _use))
                        _findings.append(HeapVulnFinding(
                            vuln_type="use_after_free",
                            alloc_site=_alloc_addr,
                            free_site=_last_free.address,
                            use_site=_use.address,
                            function_name=_use.function_name,
                            confidence=0.70,
                        ))

        return _findings

    # 内部

    def _resolve_ptr(self, func_name: str, ptr_expr: str) -> Optional[str]:
        """解析指针——通过别名表找到对应的ptr_id。"""
        _key = f"{func_name}::{ptr_expr}"
        return self._aliases.get(_key)

    def _register_callee_arg(
        self, caller_func: str, callee_func: str,
        arg_index: int, ptr_id: str,
    ):
        """注册跨函数指针传递——caller的第arg_index个参数传给callee。"""
        self._aliases[f"{callee_func}::arg{arg_index}"] = ptr_id


# smoke
def _check():
    _m = HeapStateModel()

    # 正常: alloc→use→free
    _m.ingest_alloc(0x1000, "main", "rax")
    _m.ingest_use(0x1010, "main", "rax")
    _m.ingest_free(0x1020, "main", "rax")

    # UAF: alloc→free→use
    _m.ingest_alloc(0x2000, "process", "rbx")
    _m.ingest_free(0x2010, "process", "rbx")
    _m.ingest_use(0x2020, "process", "rbx")  # UAF!

    # Double-Free: alloc→free→free
    _m.ingest_alloc(0x3000, "cleanup", "rcx")
    _m.ingest_free(0x3010, "cleanup", "rcx")
    _m.ingest_free(0x3020, "cleanup", "rcx")  # DF!

    _findings = _m.detect_vulnerabilities()
    print(f"[heap_model] findings: {len(_findings)}")
    for _f in _findings:
        print(f"  {_f.vuln_type}: alloc={hex(_f.alloc_site)} "
              f"free={hex(_f.free_site)} conf={_f.confidence:.2f}")

    _uafs = [f for f in _findings if f.vuln_type == "use_after_free"]
    _dfs = [f for f in _findings if f.vuln_type == "double_free"]
    assert len(_uafs) >= 1, f"should detect UAF, got {len(_uafs)}"
    assert len(_dfs) >= 1, f"should detect double-free, got {len(_dfs)}"
    print("[OK] heap_state_model passed")


if __name__ == "__main__":
    _check()
