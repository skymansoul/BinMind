# 指针溯源追踪器: 追踪指针从分配点到使用的完整生命周期
# 技术问题: 二进制中指针值经过寄存器、栈、全局内存传播,
#   丢失了"这个指针是从哪个malloc调用返回的"这个关键信息.
#   需要在指令级追踪指针的mov/load/store/arithmetic以维护溯源链
# 解决手段: 基于抽象位置的指针溯源:
#   - 抽象寄存器: rax@0x401020 → alloc_site_3
#   - 抽象栈槽: [rsp+0x20] → alloc_site_3 (从rax stored)
#   - 抽象堆槽: [rax+0x10] → 这是alloc_site_3的内部偏移
#   当指针经过算术运算 (add/sub) 时, 传播溯源信息
#   当指针被另一指针覆写时, 更新溯源链
#
#   Balakrishnan & Reps "Analyzing Memory Accesses in x86 Executables"
#     (CC 2004) — a-loc (abstract location) 概念,
#     本项目借鉴其抽象位置思想但简化用于堆指针溯源
#   SPA (Static Pointer Analysis, LLVM) — 指针分析的andersen/steensgaard
#     本项目使用更简单的流敏感追踪, 因为二进制中指针分析精度有限
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .allocation_tracker import AllocationSite, AllocationTracker


@dataclass
class PointerOrigin:
    """指针的溯源信息: 记录指针来源和偏移."""
    alloc_site_id: str          # 来自哪个分配点
    offset_in_alloc: int = 0    # 相对于分配基址的偏移
    propagation_path: List[str] = field(default_factory=list)  # 传播路径
    is_live: bool = True        # 是否仍活跃
    confidence: float = 1.0     # 溯源置信度


@dataclass
class AbstractLocation:
    """抽象位置: (kind, identifier, offset).

    kind: 'reg'(寄存器), 'stack'(栈), 'heap'(堆), 'global'(全局数据)
    """
    kind: str
    identifier: str             # 寄存器名或基址的字符串表示
    offset: int = 0

    def __hash__(self):
        return hash((self.kind, self.identifier, self.offset))

    def __eq__(self, other):
        return (isinstance(other, AbstractLocation) and
                self.kind == other.kind and
                self.identifier == other.identifier and
                self.offset == other.offset)

    def __repr__(self):
        return f"{self.kind}:{self.identifier}+{self.offset:#x}"


class PointerProvenanceTracker:
    """指针溯源追踪器.

    维护 抽象位置 → PointerOrigin 的映射.
    对每条指令更新映射:
      - mov rax, rdi: rax继承rdi的溯源
      - lea rax, [rbx+8]: rax获得rbx的溯源, 偏移+8
      - mov [rsp+0x20], rax: [stack:rsp+0x20]继承rax的溯源
      - add rax, 0x10: rax溯源保留, offset+0x10
    """

    def __init__(self):
        # 抽象位置 → 溯源信息
        self._provenance: Dict[AbstractLocation, PointerOrigin] = {}
        # 快速查找: 寄存器名 → 溯源信息列表 (不同偏移可能有不同溯源)
        self._reg_index: Dict[str, List[AbstractLocation]] = {}

    def record_alloc_return(self, reg: str, site: AllocationSite,
                            call_addr: int, context: str = ""):
        """记录分配函数的返回值: rax ← new AllocSite."""
        loc = AbstractLocation('reg', reg)
        origin = PointerOrigin(
            alloc_site_id=site.site_id,
            offset_in_alloc=0,
            propagation_path=[f"call {site.alloc_func}@{call_addr:#x}"],
            is_live=True, confidence=1.0)
        self._provenance[loc] = origin
        self._index_reg(reg, loc)

    def propagate_reg_to_reg(self, dst_reg: str, src_abstract: str,
                             context: str = ""):
        """mov dst, src — 寄存器间传播溯源."""
        src_loc = self._resolve_reg(src_abstract)
        if src_loc and src_loc in self._provenance:
            dst_loc = AbstractLocation('reg', dst_reg)
            origin = self._provenance[src_loc]
            new_path = list(origin.propagation_path)
            if context:
                new_path.append(f"mov {dst_reg}←{src_abstract}@{context}")
            self._provenance[dst_loc] = PointerOrigin(
                alloc_site_id=origin.alloc_site_id,
                offset_in_alloc=origin.offset_in_alloc,
                propagation_path=new_path,
                is_live=origin.is_live,
                confidence=origin.confidence * 0.99)
            self._index_reg(dst_reg, dst_loc)

    def propagate_reg_to_stack(self, base_reg: str, offset: int,
                               src_reg: str, context: str = ""):
        """mov [base+offset], src — 寄存器→栈."""
        src_loc = self._resolve_reg(src_reg)
        if src_loc and src_loc in self._provenance:
            dst_loc = AbstractLocation('stack', base_reg, offset)
            origin = self._provenance[src_loc]
            new_path = list(origin.propagation_path)
            if context:
                new_path.append(f"store [{base_reg}+{offset:#x}]@{context}")
            self._provenance[dst_loc] = PointerOrigin(
                alloc_site_id=origin.alloc_site_id,
                offset_in_alloc=origin.offset_in_alloc,
                propagation_path=new_path,
                is_live=origin.is_live,
                confidence=origin.confidence * 0.98)

    def propagate_stack_to_reg(self, dst_reg: str, base_reg: str,
                               offset: int, context: str = ""):
        """mov dst, [base+offset] — 栈→寄存器."""
        src_loc = AbstractLocation('stack', base_reg, offset)
        if src_loc in self._provenance:
            dst_loc = AbstractLocation('reg', dst_reg)
            origin = self._provenance[src_loc]
            new_path = list(origin.propagation_path)
            if context:
                new_path.append(f"load {dst_reg}←[{base_reg}+{offset:#x}]@{context}")
            self._provenance[dst_loc] = PointerOrigin(
                alloc_site_id=origin.alloc_site_id,
                offset_in_alloc=origin.offset_in_alloc,
                propagation_path=new_path,
                is_live=origin.is_live,
                confidence=origin.confidence * 0.97)
            self._index_reg(dst_reg, dst_loc)

    def apply_pointer_arith(self, dst_reg: str, src_reg: str,
                            added_offset: int, context: str = ""):
        """指针算术: add/sub dst, imm — 保留溯源但调整偏移."""
        src_loc = self._resolve_reg(src_reg)
        if src_loc and src_loc in self._provenance:
            dst_loc = AbstractLocation('reg', dst_reg)
            origin = self._provenance[src_loc]
            new_path = list(origin.propagation_path)
            if context:
                new_path.append(f"ptr+{added_offset}@{context}")
            self._provenance[dst_loc] = PointerOrigin(
                alloc_site_id=origin.alloc_site_id,
                offset_in_alloc=origin.offset_in_alloc + added_offset,
                propagation_path=new_path,
                is_live=origin.is_live,
                confidence=origin.confidence * 0.99)
            self._index_reg(dst_reg, dst_loc)

    def apply_lea(self, dst_reg: str, base_reg: str, offset: int,
                  index_reg: str = "", scale: int = 1, context: str = ""):
        """lea dst, [base + index*scale + offset]."""
        src_loc = self._resolve_reg(base_reg)
        if src_loc and src_loc in self._provenance:
            dst_loc = AbstractLocation('reg', dst_reg)
            origin = self._provenance[src_loc]
            total_offset = offset
            if index_reg:
                idx_loc = self._resolve_reg(index_reg)
                if idx_loc and idx_loc in self._provenance:
                    idx_origin = self._provenance[idx_loc]
                    # 若index寄存器有不同溯源, 合并置信度降低
                    if idx_origin.alloc_site_id != origin.alloc_site_id:
                        origin = PointerOrigin(
                            alloc_site_id=origin.alloc_site_id,
                            offset_in_alloc=origin.offset_in_alloc,
                            propagation_path=origin.propagation_path,
                            confidence=origin.confidence * 0.5)
            total_offset = origin.offset_in_alloc + offset
            new_path = list(origin.propagation_path) + [f"lea +{offset}"]
            self._provenance[dst_loc] = PointerOrigin(
                alloc_site_id=origin.alloc_site_id,
                offset_in_alloc=total_offset,
                propagation_path=new_path,
                is_live=origin.is_live,
                confidence=origin.confidence * 0.95)
            self._index_reg(dst_reg, dst_loc)

    def get_origin(self, reg: str, offset: int = 0) -> Optional[PointerOrigin]:
        """查询寄存器的溯源信息."""
        loc = self._resolve_reg(reg)
        if loc:
            result = self._provenance.get(loc)
            if result and offset:
                result = PointerOrigin(
                    alloc_site_id=result.alloc_site_id,
                    offset_in_alloc=result.offset_in_alloc + offset,
                    propagation_path=result.propagation_path,
                    is_live=result.is_live,
                    confidence=result.confidence)
            return result
        return None

    def get_or_create_origin(self, reg: str) -> PointerOrigin:
        """获取溯源信息, 若无则创建未知溯源."""
        origin = self.get_origin(reg)
        if origin:
            return origin
        return PointerOrigin(alloc_site_id="unknown")

    def mark_dead(self, reg: str):
        """标记寄存器中的指针溯源为已无效 (例如被free后)."""
        loc = self._resolve_reg(reg)
        if loc and loc in self._provenance:
            self._provenance[loc].is_live = False

    def clear_register(self, reg: str):
        """清除寄存器的溯源 (被覆写为非指针值)."""
        loc = AbstractLocation('reg', reg)
        self._provenance.pop(loc, None)
        if reg in self._reg_index:
            self._reg_index[reg] = [l for l in self._reg_index[reg]
                                   if l != loc]

    def clear_all_registers(self):
        """清除所有寄存器溯源 — 跨函数边界时调用.

        决策理由: 线性分析管道中, CRT启动代码的malloc调用
        会在寄存器中留下溯源信息, 进入用户函数后这些信息
        仍然存在, 导致用户函数的写入操作被错误关联到CRT的分配点.
        在函数边界清空寄存器溯源可消除此类跨函数污染.
        """
        reg_locs = [loc for loc in list(self._provenance.keys())
                    if loc.kind == 'reg']
        for loc in reg_locs:
            del self._provenance[loc]
        self._reg_index.clear()

    def clear_stack_slots(self):
        """清除所有栈槽位溯源 — 跨函数边界时调用.

        每个函数有自己的栈帧, rbp+0x10在函数A中的含义完全不同于
        函数B. 不清栈槽位会导致: duplicate_ppstrings的malloc指针
        存入[rbp+0x10], fill_buffer在相同偏移处读取参数时,
        错误获得duplicate_ppstrings的溯源而非main的溯源.
        """
        stack_locs = [loc for loc in list(self._provenance.keys())
                      if loc.kind == 'stack']
        for loc in stack_locs:
            del self._provenance[loc]

    def _resolve_reg(self, reg: str) -> Optional[AbstractLocation]:
        """将寄存器名解析为抽象位置."""
        loc = AbstractLocation('reg', reg)
        if loc in self._provenance:
            return loc
        # 查找最近的匹配
        if reg in self._reg_index:
            locs = self._reg_index[reg]
            if locs:
                return locs[-1]  # 返回最近绑定的
        return None

    def _index_reg(self, reg: str, loc: AbstractLocation):
        if reg not in self._reg_index:
            self._reg_index[reg] = []
        # 替换同一寄存器的旧位置
        self._reg_index[reg] = [l for l in self._reg_index[reg]
                               if l.offset != loc.offset]
        self._reg_index[reg].append(loc)

    def all_provenances(self) -> Dict[AbstractLocation, PointerOrigin]:
        return dict(self._provenance)

    def summary(self) -> Dict:
        active = sum(1 for o in self._provenance.values() if o.is_live)
        return {
            "total_locations": len(self._provenance),
            "active_origins": active,
            "tracked_regs": len(self._reg_index),
            "avg_confidence": (
                sum(o.confidence for o in self._provenance.values()) /
                max(len(self._provenance), 1)),
        }
