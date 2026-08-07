# 悬挂指针追踪器: free后指针状态的寄存器级+栈槽级管理
# 技术问题: free(ptr)后, ptr的值仍然存在于寄存器和栈槽中,
#   后续通过同一值或别名访问堆内存即构成UAF.
#   需要在指令级追踪悬挂指针的传播 (mov/lea/load/store)
# 解决手段: 双层悬挂状态 (寄存器级 + 栈槽级):
#   - 寄存器级: rax → DanglingInfo (free时的溯源信息)
#   - 栈槽级: stack:rbp:-8 → DanglingInfo (悬挂指针存入栈后)
# 设计原则: 与PointerProvenanceTracker正交 —
#   provenance回答"指针从哪来",
#   dangling回答"指针是否已释放"
# 理论来源:
#   Caballero et al. "Undangle" (ISSTA 2012) — 悬挂指针检测的动态方法
#   Gens et al. "K-Miner" (NDSS 2018) — 内核UAF静态检测
#   Gu et al. "DangSan" (EuroSys 2017) — 悬挂指针清零
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .pointer_provenance import PointerOrigin


@dataclass
class DanglingInfo:
    """悬挂指针追踪记录."""
    ptr_reg: str = ""
    origin: Optional[PointerOrigin] = None
    freed_at_idx: int = 0
    freed_by: str = ""
    alloc_site_id: str = ""
    alias_chain: List[Tuple[int, str, str]] = field(default_factory=list)


class DanglingPtrTracker:
    """悬挂指针追踪器: free后的指针状态管理.

    维护两个层级的悬挂状态:
      1. 寄存器级: reg → DanglingInfo (free时的寄存器/别名)
      2. 栈槽级: stack:base:offset → DanglingInfo (悬指存入栈后)
    """

    def __init__(self):
        self._dangling: Dict[str, DanglingInfo] = {}
        self._stack_slots: Dict[str, DanglingInfo] = {}  # "stack:rbp:-N"

    @staticmethod
    def _stack_key(base: str, offset: int) -> str:
        return f"stack:{base}:{offset}"

    def mark_freed(self, reg: str, origin: Optional[PointerOrigin],
                   free_idx: int, free_func: str, alloc_site_id: str = ""):
        info = DanglingInfo(ptr_reg=reg, origin=origin,
                           freed_at_idx=free_idx, freed_by=free_func,
                           alloc_site_id=alloc_site_id,
                           alias_chain=[(free_idx, reg, "FREE_SOURCE")])
        self._dangling[reg] = info

    def mark_stack_dangling(self, base: str, offset: int,
                            info: DanglingInfo, at_idx: int):
        """标记栈槽为悬挂状态."""
        key = self._stack_key(base, offset)
        new_info = DanglingInfo(
            ptr_reg=f"[{base}{offset:+d}]", origin=info.origin,
            freed_at_idx=info.freed_at_idx, freed_by=info.freed_by,
            alloc_site_id=info.alloc_site_id,
            alias_chain=info.alias_chain + [
                (at_idx, f"[{base}{offset:+d}]", "STACK_STORE")])
        self._stack_slots[key] = new_info

    def load_from_stack(self, base: str, offset: int,
                        dst_reg: str, at_idx: int) -> bool:
        """从栈槽加载: 若栈槽是悬挂的, 传播悬挂到dst_reg. 返回是否悬挂."""
        key = self._stack_key(base, offset)
        if key in self._stack_slots:
            src = self._stack_slots[key]
            info = DanglingInfo(
                ptr_reg=dst_reg, origin=src.origin,
                freed_at_idx=src.freed_at_idx, freed_by=src.freed_by,
                alloc_site_id=src.alloc_site_id,
                alias_chain=src.alias_chain + [
                    (at_idx, dst_reg, f"LOAD_FROM_[{base}{offset:+d}]")])
            self._dangling[dst_reg] = info
            return True
        return False

    def clear_stack_slot(self, base: str, offset: int):
        """清除栈槽的悬挂状态 (被非悬挂值覆写)."""
        key = self._stack_key(base, offset)
        self._stack_slots.pop(key, None)

    def propagate_alias(self, src_reg: str, dst_reg: str, at_idx: int):
        if src_reg not in self._dangling:
            return
        src = self._dangling[src_reg]
        info = DanglingInfo(
            ptr_reg=dst_reg, origin=src.origin,
            freed_at_idx=src.freed_at_idx, freed_by=src.freed_by,
            alloc_site_id=src.alloc_site_id,
            alias_chain=src.alias_chain + [
                (at_idx, dst_reg, f"ALIAS_FROM_{src_reg}")])
        self._dangling[dst_reg] = info

    def is_dangling(self, reg: str) -> bool:
        return reg in self._dangling

    def get_info(self, reg: str) -> Optional[DanglingInfo]:
        return self._dangling.get(reg)

    def clear_reg(self, reg: str):
        self._dangling.pop(reg, None)

    def clear_all(self):
        self._dangling.clear()
        self._stack_slots.clear()
