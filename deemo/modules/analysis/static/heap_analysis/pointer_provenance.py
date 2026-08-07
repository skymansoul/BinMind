"""指针溯源追踪器 — 基于 def-use 链的轻量级指针来源追踪.

每个 malloc 返回值被赋予唯一 Provenance ID (alloc@0xADDR),
通过 mov/lea/add/sub/load/store 追踪其在寄存器/栈/内存中的传播路径.
在堆访问点查询 ptr 的 Provenance 是否匹配预期的分配点:
不匹配 → 该访问针对不同的 malloc 对象 → 过滤误报.

与 VSA 互补: VSA 回答"值是多少", 本模块回答"指针来自哪里".

设计决策:
  - 不做完整指针分析: strip 二进制不可靠.
    采用保守溯源 — 不确定时保留告警.
  - 不用 SSA: 二进制 IR 构造 phi 函数对多架构不一致.
    def-use 链传播更简单、架构无关.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple


class ProvenanceType(Enum):
    """溯源类型的分类."""
    MALLOC = auto()         # 直接来自 malloc 返回值
    CALLOC = auto()         # 来自 calloc
    REALLOC = auto()        # 来自 realloc
    STACK = auto()          # 栈变量地址 (lea rbp-XX)
    GLOBAL = auto()         # 全局/静态变量地址
    PARAMETER = auto()      # 函数参数传入
    DERIVED = auto()        # 通过算术从其他指针派生
    UNKNOWN = auto()        # 无法确定来源 — 保守标记


@dataclass
class Provenance:
    """一个指针的溯源信息."""
    prov_id: str                        # 唯一溯源ID (格式: alloc@ADDR)
    prov_type: ProvenanceType
    origin_addr: int                    # 原始分配/定义的指令地址
    origin_func: str                    # 原始分配/定义所在函数
    base_prov_id: Optional[str] = None  # 若为 DERIVED, 指向基指针的溯源ID
    offset_from_base: int = 0           # 若为 DERIVED, 偏移量
    confidence: float = 1.0             # 溯源置信度 [0,1]

    def __hash__(self):
        return hash(self.prov_id)

    def is_heap_alloc(self) -> bool:
        return self.prov_type in (
            ProvenanceType.MALLOC, ProvenanceType.CALLOC, ProvenanceType.REALLOC)


@dataclass
class DefUseChain:
    """一条 def-use 链 — 追踪一个值的传播路径."""
    def_addr: int                       # 定义地址
    def_operand: str                    # 被定义的寄存器/变量
    use_addrs: List[int] = field(default_factory=list)  # 所有使用该定义的地址
    propagated_to: List[str] = field(default_factory=list)  # 传播到的寄存器


class PointerProvenanceTracker:
    """基于 def-use 链的指针溯源追踪器.

    使用方式:
      tracker = PointerProvenanceTracker()
      tracker.register_malloc(0x401000, "main", "rax", 256)
      tracker.track_assign(0x401010, "rbx", "rax")      # rbx ← rax
      tracker.track_arithmetic(0x401020, "rcx", "rbx", 8) # rcx ← rbx+8
      prov = tracker.query(0x401020, "rcx")
      # → prov.prov_id = "alloc@0x401000", offset_from_base = 8
    """

    def __init__(self):
        # 所有注册的溯源: prov_id → Provenance
        self._provenances: Dict[str, Provenance] = {}
        # 寄存器→当前溯源映射 (单函数内有效): reg_name → (prov_id, offset)
        self._reg_provenance: Dict[str, Tuple[str, int]] = {}
        # 内存地址→溯源: addr → prov_id (用于追踪从内存加载的指针)
        self._mem_provenance: Dict[int, str] = {}
        # 栈偏移→溯源 (用于追踪栈上保存的指针)
        self._stack_provenance: Dict[int, Tuple[str, int]] = {}
        # def-use 链记录
        self._def_use_chains: Dict[Tuple[int, str], DefUseChain] = {}
        # 统计
        self._query_count = 0
        self._resolved_count = 0

    # 注册 API

    def register_malloc(self, addr: int, func: str, ptr_reg: str,
                        alloc_size: int = 0, is_calloc: bool = False) -> str:
        """注册一个 malloc/calloc 调用点, 返回溯源ID."""
        prov_id = f"alloc@{hex(addr)}"
        prov_type = ProvenanceType.CALLOC if is_calloc else ProvenanceType.MALLOC
        self._provenances[prov_id] = Provenance(
            prov_id=prov_id, prov_type=prov_type,
            origin_addr=addr, origin_func=func)
        self._reg_provenance[ptr_reg] = (prov_id, 0)
        return prov_id

    def register_realloc(self, addr: int, func: str, ptr_reg: str,
                         old_prov_id: Optional[str] = None) -> str:
        """注册 realloc — 保持旧溯源但更新地址."""
        prov_id = f"realloc@{hex(addr)}"
        self._provenances[prov_id] = Provenance(
            prov_id=prov_id, prov_type=ProvenanceType.REALLOC,
            origin_addr=addr, origin_func=func,
            base_prov_id=old_prov_id)
        self._reg_provenance[ptr_reg] = (prov_id, 0)
        return prov_id

    def register_stack_var(self, addr: int, func: str, ptr_reg: str,
                           var_name: str = "") -> str:
        """注册栈变量地址 (lea rbp-XX → reg)."""
        prov_id = f"stack@{hex(addr)}_{var_name or ptr_reg}"
        self._provenances[prov_id] = Provenance(
            prov_id=prov_id, prov_type=ProvenanceType.STACK,
            origin_addr=addr, origin_func=func)
        self._reg_provenance[ptr_reg] = (prov_id, 0)
        return prov_id

    def register_global(self, addr: int, func: str, ptr_reg: str,
                        symbol: str = "") -> str:
        """注册全局变量地址加载."""
        prov_id = f"global@{hex(addr)}_{symbol or ptr_reg}"
        self._provenances[prov_id] = Provenance(
            prov_id=prov_id, prov_type=ProvenanceType.GLOBAL,
            origin_addr=addr, origin_func=func)
        self._reg_provenance[ptr_reg] = (prov_id, 0)
        return prov_id

    def register_parameter(self, addr: int, func: str, ptr_reg: str,
                           param_index: int = 0) -> str:
        """注册函数参数 (来自调用方, 溯源未知)."""
        prov_id = f"param@{hex(addr)}_{ptr_reg}"
        self._provenances[prov_id] = Provenance(
            prov_id=prov_id, prov_type=ProvenanceType.PARAMETER,
            origin_addr=addr, origin_func=func, confidence=0.5)
        self._reg_provenance[ptr_reg] = (prov_id, 0)
        return prov_id

    # 追踪 API

    def track_assign(self, addr: int, dst_reg: str, src_reg: str):
        """dst ← src (mov/lea)."""
        if src_reg in self._reg_provenance:
            prov_id, offset = self._reg_provenance[src_reg]
            self._reg_provenance[dst_reg] = (prov_id, offset)
            self._record_def_use(addr, dst_reg, src_reg)
            # 若dst也是派生类型, 注册DERIVED溯源
            if offset != 0:
                derived_id = f"derived@{hex(addr)}_{dst_reg}"
                base_prov = self._provenances.get(prov_id)
                self._provenances[derived_id] = Provenance(
                    prov_id=derived_id, prov_type=ProvenanceType.DERIVED,
                    origin_addr=addr, origin_func=(base_prov.origin_func if base_prov else ""),
                    base_prov_id=prov_id, offset_from_base=offset)

    def track_arithmetic(self, addr: int, dst_reg: str,
                         base_reg: str, constant_offset: int):
        """dst ← base_reg + constant_offset (add/lea)."""
        if base_reg in self._reg_provenance:
            prov_id, base_offset = self._reg_provenance[base_reg]
            new_offset = base_offset + constant_offset
            self._reg_provenance[dst_reg] = (prov_id, new_offset)
            self._record_def_use(addr, dst_reg, base_reg)
            # 注册派生溯源
            derived_id = f"derived@{hex(addr)}_{dst_reg}"
            base_prov = self._provenances.get(prov_id)
            self._provenances[derived_id] = Provenance(
                prov_id=derived_id, prov_type=ProvenanceType.DERIVED,
                origin_addr=addr,
                origin_func=(base_prov.origin_func if base_prov else ""),
                base_prov_id=prov_id, offset_from_base=new_offset)

    def track_store(self, addr: int, mem_expr: str, src_reg: str):
        """将寄存器值存储到内存 (mov [mem], reg)."""
        if src_reg in self._reg_provenance:
            # 简化: 用地址做键
            self._mem_provenance[addr] = self._reg_provenance[src_reg][0]

    def track_load(self, addr: int, dst_reg: str, src_addr: int):
        """从内存加载到寄存器 (mov reg, [mem])."""
        if src_addr in self._mem_provenance:
            prov_id = self._mem_provenance[src_addr]
            self._reg_provenance[dst_reg] = (prov_id, 0)

    def track_stack_save(self, stack_offset: int, src_reg: str):
        """保存寄存器到栈."""
        if src_reg in self._reg_provenance:
            self._stack_provenance[stack_offset] = self._reg_provenance[src_reg]

    def track_stack_restore(self, stack_offset: int, dst_reg: str):
        """从栈恢复寄存器."""
        if stack_offset in self._stack_provenance:
            self._reg_provenance[dst_reg] = self._stack_provenance[stack_offset]

    def track_call(self, addr: int, callee: str,
                   arg_regs: List[str], ret_reg: str = "rax"):
        """追踪函数调用 — 保守地传播溯源到返回值.

        若被调用函数可能返回堆指针 (如 malloc 包装器), 则对返回值保守标记.
        """
        # 若任一参数是堆指针, 保守地标记返回值也是堆指针
        for arg_reg in arg_regs:
            if arg_reg in self._reg_provenance:
                prov_id, offset = self._reg_provenance[arg_reg]
                # realloc 模式: free(ptr) 后又返回新ptr
                if callee in ("realloc", "g_realloc", "_Znam", "reallocarray"):
                    new_id = self.register_realloc(addr, callee, ret_reg, prov_id)
                else:
                    # 通用包装: 保守传播
                    self._reg_provenance[ret_reg] = (
                        prov_id, offset)
                return

    # 查询 API

    def query(self, addr: int, reg: str) -> Optional[Provenance]:
        """查询某地址处寄存器的指针溯源."""
        self._query_count += 1
        if reg in self._reg_provenance:
            prov_id, offset = self._reg_provenance[reg]
            prov = self._provenances.get(prov_id)
            if prov:
                self._resolved_count += 1
                # 返回带偏移的溯源信息
                if offset != 0:
                    return Provenance(
                        prov_id=prov.prov_id, prov_type=prov.prov_type,
                        origin_addr=prov.origin_addr,
                        origin_func=prov.origin_func,
                        base_prov_id=prov.base_prov_id,
                        offset_from_base=offset,
                        confidence=prov.confidence)
                return prov
        return None

    def query_offset(self, addr: int, reg: str) -> int:
        """查询指针相对于其基址的偏移量."""
        if reg in self._reg_provenance:
            _, offset = self._reg_provenance[reg]
            return offset
        return 0

    def is_same_provenance(self, reg_a: str, reg_b: str) -> bool:
        """两寄存器是否来自同一溯源."""
        if reg_a in self._reg_provenance and reg_b in self._reg_provenance:
            return (self._reg_provenance[reg_a][0]
                    == self._reg_provenance[reg_b][0])
        return False

    # 内部

    def _record_def_use(self, addr: int, dst: str, src: str):
        """记录一次 def-use 关系."""
        key = (addr, dst)
        if key not in self._def_use_chains:
            self._def_use_chains[key] = DefUseChain(
                def_addr=addr, def_operand=dst)
        self._def_use_chains[key].propagated_to.append(src)

    # 统计/管理

    @property
    def resolution_rate(self) -> float:
        return self._resolved_count / max(1, self._query_count)

    def active_provenances(self) -> Set[str]:
        """当前活跃的溯源集合."""
        return {pid for pid, prov in self._provenances.items()
                if prov.is_heap_alloc()}

    def stats(self) -> dict:
        return {
            "total_provenances": len(self._provenances),
            "heap_provenances": len([p for p in self._provenances.values()
                                     if p.is_heap_alloc()]),
            "registers_tracked": len(self._reg_provenance),
            "memory_entries": len(self._mem_provenance),
            "stack_entries": len(self._stack_provenance),
            "queries": self._query_count,
            "resolved": self._resolved_count,
            "resolution_rate": round(self.resolution_rate, 3),
        }

    def reset(self):
        self._provenances.clear()
        self._reg_provenance.clear()
        self._mem_provenance.clear()
        self._stack_provenance.clear()
        self._def_use_chains.clear()
        self._query_count = 0
        self._resolved_count = 0
