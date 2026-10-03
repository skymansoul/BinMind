# 堆分配点追踪器: malloc/calloc/realloc调用点建模
# 技术问题: 堆溢出检测的核心难点在于不知道每个堆指针关联的分配大小.
#   静态分析需要还原 "在地址0x401000调用了malloc(0x80)" 这个事实,
#   然后追踪返回的指针如何传播, 最终在写入点验证写入量vs分配量
# 解决手段: 分配点建模:
#   1. 识别所有malloc/calloc/realloc调用点及大小参数
#   2. 对大小参数进行值域推导 (从ValueRangeDomain获取)
#   3. 将分配点信息绑定到返回的指针追踪链上
#   4. 处理特殊分配: realloc调整大小, calloc清零
#
#   ISSTA 2024 "Precise Compositional Buffer Overflow Detection via
#     Heap Disjointness" — 堆不相交性分析, 本项目借鉴其分配点→指针
#     的追踪链路, 但扩展到无源码的二进制分析场景
#   CodeAlchemist (USENIX 2023) — 堆分配语义建模
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from .value_range import ValueRange

# malloc-like: 返回新分配的堆内存指针
_ALLOC_FUNCTIONS = {"malloc", "calloc", "_malloc", "__malloc", "operator_new",
                    "HeapAlloc", "g_malloc", "g_malloc0", "g_try_malloc",
                    "kmalloc", "kzalloc", "vmalloc", "malloc_debug"}
# realloc-like: 可能调整大小, 可能移动
_REALLOC_FUNCTIONS = {"realloc", "_realloc", "__realloc", "g_realloc",
                      "HeapReAlloc", "krealloc"}
# free-like
_FREE_FUNCTIONS = {"free", "_free", "__free", "g_free", "HeapFree", "kfree", "vfree"}


@dataclass
class AllocationSite:
    """一个堆分配调用点的建模结果.

    核心字段:
      alloc_size_range: malloc参数的值域 (例如 [0x80, 0x80])
      alloc_func: 分配函数名
      return_reg: 分配返回值的存放寄存器 (通常是rax)
      is_array: 是否为数组分配 (n * sizeof(T))
      element_count: 若为数组, 元素数量的值域
      element_size: 元素大小
    """
    site_id: str                    # 唯一标识: func_addr:func_name
    alloc_func: str                 # malloc / calloc / realloc
    alloc_size_range: ValueRange    # 分配大小的值域
    return_reg: str = "rax"
    is_array: bool = False
    element_count: Optional[ValueRange] = None
    element_size: int = 1
    call_address: int = 0           # 调用指令的相对虚拟地址
    in_loop: bool = False           # 是否在循环中 (影响重复分配建模)
    loop_bound_range: Optional[ValueRange] = None
    alignment: int = 16             # 堆分配的对齐要求
    is_fallback: bool = False       # 是否使用默认值域 (size_vr为TOP时的兜底)
    # realloc特有
    old_ptr_reg: Optional[str] = None  # realloc的第一个参数 (原指针)
    is_realloc_resize: bool = False    # realloc是否只是调整大小

    def min_allocation(self) -> int:
        """分配的保守下界."""
        if self.alloc_size_range.is_top or self.alloc_size_range.is_bottom:
            return 0
        return max(self.alloc_size_range.umin, 0)

    def max_allocation(self) -> int:
        """分配的上界 (用于判断是否可能溢出)."""
        if self.alloc_size_range.is_top:
            return 0xFFFFFFFFFFFFFFFF
        if self.alloc_size_range.is_bottom:
            return 0
        return self.alloc_size_range.umax

    def definitely_larger_than(self, size: int) -> bool:
        """分配大小是否确定大于给定值."""
        if self.alloc_size_range.is_top:
            return False
        if self.alloc_size_range.is_bottom:
            return False
        return self.alloc_size_range.umin > size


@dataclass
class FreeSite:
    """一个free调用点."""
    site_id: str
    free_func: str
    ptr_reg: str                # 被释放指针所在的寄存器
    call_address: int = 0


class AllocationTracker:
    """堆分配追踪器.

    核心职责:
      1. 从指令序列中识别分配/释放调用
      2. 建立分配大小与返回指针之间的绑定
      3. 维护活跃分配点集合 (未free的分配)
      4. 处理realloc的指针更新逻辑
    与PointerProvenanceTracker配合使用:
      AllocationTracker记录"哪里分配了什么大小",
      PointerProvenanceTracker追踪"这个指针流向了哪些内存操作"
    """

    def __init__(self):
        self._alloc_sites: Dict[str, AllocationSite] = {}  # site_id → site
        self._free_sites: Dict[str, FreeSite] = {}
        self._active_allocs: Set[str] = set()  # 当前活跃的分配点ID
        self._ptr_to_alloc: Dict[str, str] = {}  # 追踪寄存器→分配点映射
        self._addr_to_alloc: Dict[int, str] = {}  # 抽象地址→分配点映射

    def register_alloc(self, site: AllocationSite) -> str:
        """注册一个新的分配点, 返回site_id."""
        sid = site.site_id
        self._alloc_sites[sid] = site
        self._active_allocs.add(sid)
        return sid

    def register_free(self, site: FreeSite):
        self._free_sites[site.site_id] = site
        # 标记对应的释放: 尝试断开指针→分配点的映射
        ptr_key = f"{site.call_address}:{site.ptr_reg}"
        if ptr_key in self._ptr_to_alloc:
            alloc_sid = self._ptr_to_alloc.pop(ptr_key)
            # 若所有指针引用都已移除, 标记分配为已释放
            if alloc_sid not in self._ptr_to_alloc.values():
                self._active_allocs.discard(alloc_sid)

    def bind_ptr_to_alloc(self, ptr_location: str, alloc_site_id: str):
        """建立指针位置到分配点的映射."""
        self._ptr_to_alloc[ptr_location] = alloc_site_id

    def get_alloc_by_ptr(self, ptr_reg: str, call_context: int = 0) -> Optional[AllocationSite]:
        """根据寄存器名查找对应的分配点."""
        key = f"{call_context}:{ptr_reg}"
        sid = self._ptr_to_alloc.get(key, self._ptr_to_alloc.get(ptr_reg))
        if sid:
            return self._alloc_sites.get(sid)
        return None

    def get_alloc_size_range(self, ptr_reg: str, call_context: int = 0) -> ValueRange:
        """获取指针关联的分配大小值域."""
        site = self.get_alloc_by_ptr(ptr_reg, call_context)
        if site:
            return site.alloc_size_range
        return ValueRange.top()

    def is_active(self, alloc_site_id: str) -> bool:
        """检查分配是否未被释放."""
        return alloc_site_id in self._active_allocs

    def model_malloc_call(self, site_id: str, size_reg: str,
                          result_reg: str, call_addr: int,
                          size_range: ValueRange,
                          in_loop: bool = False) -> AllocationSite:
        """为一处malloc调用建模.

        size_range: malloc参数的值域 (从ValueRangeDomain推断)
        返回创建的AllocationSite.
        """
        site = AllocationSite(
            site_id=site_id,
            alloc_func="malloc",
            alloc_size_range=size_range,
            return_reg=result_reg,
            call_address=call_addr,
            in_loop=in_loop,
            alignment=16)
        self.register_alloc(site)
        self.bind_ptr_to_alloc(f"{call_addr}:{result_reg}", site_id)
        return site

    def model_calloc_call(self, site_id: str, count_range: ValueRange,
                          elem_size: int, result_reg: str,
                          call_addr: int) -> AllocationSite:
        """为一处calloc调用建模."""
        total_range = count_range.mul(ValueRange.constant(elem_size))
        site = AllocationSite(
            site_id=site_id,
            alloc_func="calloc",
            alloc_size_range=total_range,
            return_reg=result_reg,
            call_address=call_addr,
            is_array=True,
            element_count=count_range,
            element_size=elem_size,
            alignment=16)
        self.register_alloc(site)
        self.bind_ptr_to_alloc(f"{call_addr}:{result_reg}", site_id)
        return site

    def model_realloc_call(self, site_id: str, old_ptr_reg: str,
                           new_size_range: ValueRange,
                           result_reg: str, call_addr: int) -> AllocationSite:
        """realloc调用建模: 更新原指针的分配大小."""
        old_alloc_id = self._ptr_to_alloc.get(old_ptr_reg)
        old_site = self._alloc_sites.get(old_alloc_id or "")
        site = AllocationSite(
            site_id=site_id,
            alloc_func="realloc",
            alloc_size_range=new_size_range,
            return_reg=result_reg,
            call_address=call_addr,
            old_ptr_reg=old_ptr_reg,
            is_realloc_resize=(old_site is not None))
        self.register_alloc(site)
        self.bind_ptr_to_alloc(f"{call_addr}:{result_reg}", site_id)
        # 断开旧指针绑定
        if old_ptr_reg in self._ptr_to_alloc:
            self._ptr_to_alloc.pop(old_ptr_reg, None)
        return site

    def all_sites(self) -> Dict[str, AllocationSite]:
        return dict(self._alloc_sites)

    def active_sites(self) -> Dict[str, AllocationSite]:
        return {sid: s for sid, s in self._alloc_sites.items()
                if sid in self._active_allocs}

    def summary(self) -> Dict:
        return {
            "total_alloc_sites": len(self._alloc_sites),
            "active_alloc_sites": len(self._active_allocs),
            "total_free_sites": len(self._free_sites),
            "pointer_bindings": len(self._ptr_to_alloc),
        }
