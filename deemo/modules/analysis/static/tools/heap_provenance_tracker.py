# 指针来源追踪引擎, 确定每个寄存器中的堆指针来自哪个 malloc 调用
# 方法论依据: Heap Disjointness, 堆对象区分是误报控制的核心
# 本模块将 symbolic heap location 的概念适配为 binary-level 的寄存器追踪

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class HeapProvenance:
    """堆指针的来源信息"""
    alloc_site: int            # malloc 调用地址
    alloc_size: int            # 分配时的参数值 (-1=未知)
    ptr_register: str          # 指针当前所在的寄存器
    propagated_to: Set[str] = field(default_factory=set)  # 传播到的其他寄存器
    escaped: bool = False      # 指针是否逃逸到内存/全局变量

class HeapProvenanceTracker:
    """追踪堆指针的来源, 确定每个写操作的目标是哪个 malloc 分配的缓冲区

    核心思路: 静态检测的误报主因是堆对象混淆
    malloc(64) 和 memcpy(128) 若操作不同的缓冲区→不是漏洞
    只有 memcpy 的目标确实来自那个 64 字节的 malloc→才是堆溢出

    本模块追踪每条指令的寄存器数据流:
    - call malloc → rax 持有新堆指针, 记录来源
    - mov rdi, rax → rdi 继承了 rax 的来源
    - mov [mem], rax → 指针逃逸到内存, 标记为可能跨函数
    - call free(rdi) → 清除 rdi 的来源标记
    """

    _REG_ALIASES = {
        'rdi': {'rdi','edi','di','dil'}, 'rsi': {'rsi','esi','si','sil'},
        'rdx': {'rdx','edx','dx','dl'}, 'rcx': {'rcx','ecx','cx','cl'},
        'r8': {'r8','r8d','r8w','r8b'}, 'r9': {'r9','r9d','r9w','r9b'},
        'rax': {'rax','eax','ax','al'}, 'rbx': {'rbx','ebx','bx','bl'},
        'r10':{'r10','r10d','r10w','r10b'},'r11':{'r11','r11d','r11w','r11b'},
        'r12':{'r12','r12d'},'r13':{'r13','r13d'},'r14':{'r14','r14d'},
        'r15':{'r15','r15d'},'rbp':{'rbp','ebp','bp'},'rsp':{'rsp','esp','sp'},
    }

    def __init__(self):
        self._provenance: Dict[int, HeapProvenance] = {}  # alloc_site → provenance
        self._reg_origin: Dict[str, int] = {}  # canonical_register → alloc_site

    def _canonical(self, reg: str) -> str:
        for canon, aliases in self._REG_ALIASES.items():
            if reg in aliases:
                return canon
        return reg

    def track_alloc(self, call_addr: int, size: int) -> None:
        """记录一次 malloc 调用, malloc 返回后 rax 持有新堆指针"""
        prov = HeapProvenance(
            alloc_site=call_addr, alloc_size=size, ptr_register='rax',
            propagated_to={'rax'},
        )
        self._provenance[call_addr] = prov
        self._reg_origin['rax'] = call_addr

    def track_free(self, freed_reg: str) -> None:
        """记录 free 调用, 清除被释放指针的来源标记"""
        canon = self._canonical(freed_reg)
        origin = self._reg_origin.pop(canon, None)
        if origin and origin in self._provenance:
            self._provenance[origin].propagated_to.discard(canon)

    def track_move(self, dst_reg: str, src_reg: str, is_memory_store: bool = False) -> None:
        """记录数据移动 (mov/lea), 传播来源标记"""
        d_canon = self._canonical(dst_reg)
        s_canon = self._canonical(src_reg)
        origin = self._reg_origin.get(s_canon)
        if origin is None:
            return
        self._reg_origin[d_canon] = origin
        if origin in self._provenance:
            self._provenance[origin].propagated_to.add(d_canon)
            if is_memory_store:
                self._provenance[origin].escaped = True

    def get_origin(self, reg: str) -> Optional[HeapProvenance]:
        """查询寄存器中堆指针的来源"""
        canon = self._canonical(reg)
        origin = self._reg_origin.get(canon)
        return self._provenance.get(origin) if origin else None

    def same_allocation(self, reg_a: str, reg_b: str) -> bool:
        """判断两个寄存器是否指向同一个 malloc 分配"""
        oa = self.get_origin(reg_a)
        ob = self.get_origin(reg_b)
        return oa is not None and ob is not None and oa.alloc_site == ob.alloc_site
