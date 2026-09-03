"""DRIFT 堆对象身份追踪 — 每个堆对象分配后获得唯一身份, 通过寄存器/栈槽传递.

方法: 分配点→对象ID→寄存器赋值链→free时的对象匹配→use时的对象验证.
与旧版PointerLifecycleTracker的区别: 旧版追踪"rax持有某指针", 新版追踪
"rax持有malloc@0x401000返回的对象#3". 身份粒度从"某指针"提升到"具体对象".

创建: 2025-03-28
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re


@dataclass
class ObjectIdentity:
    """堆对象的唯一身份 — (分配地址, 分配函数, 序号)."""
    alloc_addr: int        # 分配指令地址
    alloc_func: str        # malloc/calloc/realloc
    seq: int               # 此函数内第几个分配
    size_hint: int = 0     # 分配大小 (已知时)

    def __hash__(self):
        return hash((self.alloc_addr, self.seq))

    def __eq__(self, other):
        if not isinstance(other, ObjectIdentity):
            return False
        return self.alloc_addr == other.alloc_addr and self.seq == other.seq

    def label(self) -> str:
        return f"obj#{self.seq}@{self.alloc_addr:x}"


@dataclass
class HeapObject:
    """一个跟踪中的堆对象."""
    oid: ObjectIdentity
    alloc_line: int = -1          # 分配指令行号
    freed_at: int = -1           # free指令地址, -1=未释放
    freed_line: int = -1         # free所在行号
    double_freed: bool = False   # 同一对象被free两次
    use_after_free: List[int] = field(default_factory=list)  # free后的use行号
    # 条件释放标记: free 位于条件分支内, 仅标记 maybe_freed 而非 freed_at
    maybe_freed: bool = False


# 指令解析模式

_ALLOC_FUNCS = re.compile(
    r'\b(?:call|jmp)\s+(?:[0-9a-f]+\s+)?<?(malloc|calloc|realloc|_Znwm|_Znam'
    r'|kmalloc|kzalloc|vmalloc)(?:@plt)?>?\b', re.I)
_FREE_FUNCS = re.compile(
    r'\b(?:call|jmp)\s+(?:[0-9a-f]+\s+)?<?(free|kfree|vfree|delete|_ZdlPv'
    r'|_ZdaPv)(?:@plt)?>?\b', re.I)
_DEREF_PAT = re.compile(
    r'\b(mov|movzx|movsx|add|sub|cmp|test|and|or|xor)\s+'
    r'(\w+),\s*(?:(?:qword|dword|word|byte)(?:\s+ptr)?\s+)?'
    r'\[(\w+)([+\-]\s*(?:0x[0-9a-f]+|\d+))?\]', re.I)
# write to memory through pointer: mov [reg], val
_MEM_WRITE_PAT = re.compile(
    r'\bmov\s+(?:(?:qword|dword|word|byte)(?:\s+ptr)?\s+)?'
    r'\[(\w+)([+\-]\s*(?:0x[0-9a-f]+|\d+))?\],\s*(\w+)', re.I)
# mov dst_reg, src_reg or mov dst_reg, [rbp+N]
_MOV_REG = re.compile(
    r'\bmov\s+(\w+),\s*(\w+)\s*$', re.I)
_MOV_STACK_LOAD = re.compile(
    r'\bmov\s+(\w+),\s*(?:qword\s+ptr\s+)?\[(?:rbp|rsp)\s*([+\-])\s*'
    r'(0x[0-9a-f]+|\d+)\]', re.I)
_MOV_STACK_STORE = re.compile(
    r'\bmov\s+(?:qword\s+ptr\s+)?\[(?:rbp|rsp)\s*([+\-])\s*'
    r'(0x[0-9a-f]+|\d+)\],\s*(\w+)', re.I)
_LEA_PAT = re.compile(
    r'\blea\s+(\w+),\s*\[(\w+)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', re.I)
_XOR_ZERO = re.compile(r'\bxor\s+(\w+),\s*\1\b', re.I)
# RIP相对寻址的LOAD: mov reg, [rip+off]
_RIP_LOAD_PAT = re.compile(
    r'\bmov\s+(\w+),\s*(?:qword\s+ptr\s+)?\[rip\s*([+\-])\s*'
    r'(0x[0-9a-f]+|\d+)\]', re.I)


def _canon_reg(r: str) -> str:
    """寄存器名规范化为64位形式."""
    r = r.lower().strip()
    _map = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
            'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
            'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'}
    return _map.get(r, r)


def _parse_int(s: str) -> Optional[int]:
    try: return int(s, 16 if s.lower().startswith('0x') else 10)
    except ValueError: return None


class ObjIdTracker:
    """堆对象身份追踪器 — 寄存器/栈槽/堆字段→对象身份的映射.

    核心数据结构:
      reg_obj: Dict[str, ObjectIdentity]  — 每个寄存器当前持有的对象
      stack_obj: Dict[int, ObjectIdentity] — 每个栈槽(rbp偏移)存储的对象
      _heap_fields: Dict[Tuple[int,int,int], ObjectIdentity] — 堆上struct字段
        key = (base_obj_alloc_addr, base_obj_seq, field_offset)
        value = stored object identity
      objects: Dict[ObjectIdentity, HeapObject] — 所有已知对象的状态
    """

    def __init__(self):
        self.reg_obj: Dict[str, ObjectIdentity] = {}
        self.stack_obj: Dict[int, ObjectIdentity] = {}
        self._heap_fields: Dict[Tuple[int, int, int], ObjectIdentity] = {}
        self._global_vars: Dict[int, ObjectIdentity] = {}  # rip偏移→对象身份
        self.objects: Dict[ObjectIdentity, HeapObject] = {}
        self._seq_counter: int = 0
        # 指令地址→行号映射 (用于报告)
        self._addr_to_line: Dict[int, int] = {}
        # call-ret配对栈: 每次call push当前reg_obj, ret时pop恢复
        # 解决: 函数A的ret不应清除函数B中rax持有的对象身份
        # 栈元素: (reg_obj_snapshot, stack_obj_snapshot)
        # stack_obj也需要保存/恢复: 不同函数使用相同栈偏移会碰撞
        self._call_stack: List[Tuple[Dict[str, ObjectIdentity],
                                     Dict[int, ObjectIdentity]]] = []

    def next_seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    def track_alloc(self, alloc_addr: int, alloc_func: str,
                    line_idx: int, size_hint: int = 0) -> ObjectIdentity:
        """记录一次堆分配 — 创建对象身份, 标记rax持有此对象."""
        oid = ObjectIdentity(
            alloc_addr=alloc_addr, alloc_func=alloc_func,
            seq=self.next_seq(), size_hint=size_hint)
        # rax(及eax)持有新对象身份 — kill旧身份
        self.reg_obj['rax'] = oid
        self.reg_obj['eax'] = oid
        self.objects[oid] = HeapObject(oid=oid, alloc_line=line_idx)
        self._addr_to_line[alloc_addr] = line_idx
        return oid

    def track_free(self, free_addr: int, line_idx: int,
                   freed_reg: str,
                   conditional: bool = False) -> Optional[ObjectIdentity]:
        """记录一次free调用 — 查找被释放的对象身份.

        设计决策:
          - conditional=True 时 free 位于条件分支内, 仅设置 maybe_freed
            而非 freed_at, 避免对条件性 free 报确定性 UAF.
        """
        reg = _canon_reg(freed_reg)
        oid = self.reg_obj.get(reg)
        if oid is None:
            return None
        obj = self.objects.get(oid)
        if obj is None:
            return None
        if conditional:
            # 条件释放: 不设置 freed_at, 仅标记 maybe_freed
            obj.maybe_freed = True
        else:
            if obj.freed_at >= 0:
                # 已被释放过 → double free (不更新freed_line, 保留首次free行号)
                obj.double_freed = True
            else:
                obj.freed_at = free_addr
                obj.freed_line = line_idx
        self._addr_to_line[free_addr] = line_idx
        return oid

    def check_use(self, line_idx: int, used_reg: str
                  ) -> Optional[HeapObject]:
        """检查一次指针解引用 — 若对象已释放则记录UAF.

        设计决策:
          - freed_at >= 0 → 确定性 UAF, 直接记录.
          - maybe_freed=True → 条件释放, 仍返回 obj 但不记录 use_after_free,
            供调用方降低置信度而非确定性报 UAF.
        """
        reg = _canon_reg(used_reg)
        oid = self.reg_obj.get(reg)
        if oid is None:
            return None
        obj = self.objects.get(oid)
        if obj is None:
            return None
        if obj.freed_at >= 0:
            obj.use_after_free.append(line_idx)
            return obj
        if obj.maybe_freed:
            # 条件释放: 返回对象供调用方降低置信度, 不记录确定性 UAF
            return obj
        return None

    def track_mov_reg(self, dst_reg: str, src_reg: str) -> None:
        """追踪寄存器间移动: mov dst, src — 对象身份随值传递."""
        d = _canon_reg(dst_reg)
        s = _canon_reg(src_reg)
        if d in ('rbp', 'rsp', 'rip'):
            return
        if s in self.reg_obj:
            self.reg_obj[d] = self.reg_obj[s]
        else:
            # src无身份 → dst也失去身份 (kill)
            self.reg_obj.pop(d, None)

    def track_mov_imm(self, dst_reg: str) -> None:
        """mov dst, imm — dst寄存器失去对象身份 (kill)."""
        d = _canon_reg(dst_reg)
        if d not in ('rbp', 'rsp', 'rip'):
            self.reg_obj.pop(d, None)
            # 同时kill 32位变体
            for variant in self._subreg_variants(d):
                self.reg_obj.pop(variant, None)

    def track_stack_store(self, offset: int, src_reg: str) -> None:
        """mov [rbp+N], reg — 对象身份存入栈槽."""
        s = _canon_reg(src_reg)
        if s in self.reg_obj:
            self.stack_obj[offset] = self.reg_obj[s]

    def track_stack_load(self, dst_reg: str, offset: int) -> None:
        """mov reg, [rbp+N] — 从栈槽恢复对象身份."""
        d = _canon_reg(dst_reg)
        if d in ('rbp', 'rsp', 'rip'):
            return
        if offset in self.stack_obj:
            self.reg_obj[d] = self.stack_obj[offset]
        else:
            self.reg_obj.pop(d, None)

    def track_xor_zero(self, dst_reg: str) -> None:
        """xor reg, reg — 寄存器清零, 对象身份清除."""
        d = _canon_reg(dst_reg)
        self.reg_obj.pop(d, None)
        for variant in self._subreg_variants(d):
            self.reg_obj.pop(variant, None)

    def track_lea(self, dst_reg: str, base_reg: str, offset: int) -> None:
        """lea dst, [base+offset] — 派生指针仍指向同一对象.

        对栈指针(rbp/rsp), 若offset处有已知对象身份, 传播给dst.
        关键: main中 &struct_on_stack 通过参数传递给被调者,
        被调者解引用后恢复对象身份→UAF检测.
        """
        d = _canon_reg(dst_reg)
        b = _canon_reg(base_reg)
        if d in ('rbp', 'rsp', 'rip'):
            return
        if b in self.reg_obj:
            # 派生指针仍然指向同一对象 (只是偏移不同)
            self.reg_obj[d] = self.reg_obj[b]
        elif b in ('rbp', 'rsp') and offset in self.stack_obj:
            # lea rax, [rbp+N] — 取栈槽的地址, 栈槽内存储了对象身份
            # → 传播: rax"指向"该对象 (当被调者解引用此地址时恢复身份)
            self.reg_obj[d] = self.stack_obj[offset]
        else:
            self.reg_obj.pop(d, None)

    def track_heap_store(self, base_reg: str, offset: int,
                         value_reg: str) -> None:
        """mov [base_reg+off], value_reg — 对象身份存入堆上struct字段.

        例: t->ctx = malloc(128) 编译为 mov [rax], rdx
        base_reg=rax持有struct对象, value_reg=rdx持有新分配的子对象.
        记录: heap[(struct_obj, offset)] = child_obj
        """
        b = _canon_reg(base_reg)
        v = _canon_reg(value_reg)
        base_oid = self.reg_obj.get(b)
        val_oid = self.reg_obj.get(v)
        if base_oid is not None and val_oid is not None:
            key = (base_oid.alloc_addr, base_oid.seq, offset)
            self._heap_fields[key] = val_oid

    def track_global_store(self, rip_offset: int, src_reg: str) -> None:
        """mov [rip+off], reg — 对象身份存入全局变量."""
        s = _canon_reg(src_reg)
        if s in self.reg_obj:
            self._global_vars[rip_offset] = self.reg_obj[s]

    def track_global_load(self, dst_reg: str, rip_offset: int) -> None:
        """mov reg, [rip+off] — 从全局变量恢复对象身份."""
        d = _canon_reg(dst_reg)
        if d in ('rbp', 'rsp', 'rip'):
            return
        if rip_offset in self._global_vars:
            self.reg_obj[d] = self._global_vars[rip_offset]
        else:
            self.reg_obj.pop(d, None)

    def track_heap_load(self, dst_reg: str, base_reg: str,
                        offset: int) -> None:
        """mov dst_reg, [base_reg+off] — 从堆struct字段恢复对象身份.

        例: t->ctx 编译为 mov rax, [rax]
        base_reg=rax持有struct对象, 从heap_fields查找子对象身份→dst_reg.

        特殊: self-deref at offset 0 (mov rax, [rax]) 且字段未存储时,
        保留base的对象身份. 涵盖:
          - 栈地址解引用: [&stack_slot] → 堆对象 (via lea rbp propagation)
          - 数组基址读取: arr[0] → 值 (保守保留, temporal_verifier可过滤FP)
        """
        d = _canon_reg(dst_reg)
        b = _canon_reg(base_reg)
        if d in ('rbp', 'rsp', 'rip'):
            return
        base_oid = self.reg_obj.get(b)
        if base_oid is not None:
            key = (base_oid.alloc_addr, base_oid.seq, offset)
            if key in self._heap_fields:
                self.reg_obj[d] = self._heap_fields[key]
                return
            # self-deref at offset 0: 身份传递 (栈解引用/首字段)
            if offset == 0 and d == b:
                self.reg_obj[d] = base_oid
                return
        self.reg_obj.pop(d, None)

    def track_ret(self) -> None:
        """ret指令 — 函数返回, 恢复调用者的reg_obj+stack_obj状态.

        call-ret配对: 从_call_stack弹出调用前保存的状态,
        保留当前rax (可能持有被调函数返回的堆对象).
        若_call_stack为空, 保守不处理.

        maybe_freed 传播: 被调函数中条件释放的对象, 若其身份仍存在于
        恢复后的 reg_obj 中, 则保留 maybe_freed 标记传递给调用者.
        """
        if self._call_stack:
            saved_reg, saved_stack = self._call_stack.pop()
            # 保留被调函数返回的rax中的对象身份
            returned_rax = self.reg_obj.get('rax')
            returned_eax = self.reg_obj.get('eax')
            # 收集被调函数中标记 maybe_freed 的对象身份
            maybe_freed_oids = {oid for oid, obj in self.objects.items()
                                if obj.maybe_freed}
            self.reg_obj = saved_reg
            self.stack_obj = saved_stack
            if returned_rax is not None:
                self.reg_obj['rax'] = returned_rax
            if returned_eax is not None:
                self.reg_obj['eax'] = returned_eax
            # 恢复后, 仍存活于调用者寄存器/栈槽中的 maybe_freed 对象保留标记
            live_oids = set(self.reg_obj.values()) | set(self.stack_obj.values())
            for oid in maybe_freed_oids:
                if oid in live_oids:
                    obj = self.objects.get(oid)
                    if obj is not None:
                        obj.maybe_freed = True

    def track_func_entry(self) -> None:
        """函数入口 — 新函数上下文, 只清除栈槽对象身份.

        寄存器保留 (函数参数通过寄存器传递):
          call_clobber已在调用点杀死了易失寄存器(rcx,rdx,r8-r11),
          被调函数的前几条指令通常是参数栈保存(mov [rbp+N], rcx),
          保留reg_obj允许从调用者的寄存器状态中识别参数对象身份.
        栈槽清除: 新函数有自己的栈帧.
        """
        self.stack_obj.clear()

    def track_call_clobber(self) -> None:
        """call指令 — 保存当前状态到call_stack, 不杀参数寄存器.

        调用前push当前reg_obj+stack_obj状态, ret时pop恢复.
        不再清除rcx/rdx/r8-r11: 被调函数需要这些寄存器中的对象身份
        来处理参数保存 (mov [rbp+N], rcx). callee自身的指令会自然
        覆盖寄存器; track_ret恢复调用前状态.
        stack_obj也保存: 不同函数的栈帧偏移可能碰撞.
        """
        self._call_stack.append((dict(self.reg_obj), dict(self.stack_obj)))

    def get_live_objects(self) -> List[HeapObject]:
        """获取所有仍存活 (已分配未释放) 的对象."""
        return [o for o in self.objects.values() if o.freed_at < 0]

    def get_uaf_objects(self) -> List[HeapObject]:
        """获取所有存在UAF的对象."""
        return [o for o in self.objects.values()
                if o.freed_at >= 0 and o.use_after_free]

    def get_double_free_objects(self) -> List[HeapObject]:
        """获取所有double free的对象."""
        return [o for o in self.objects.values() if o.double_freed]

    def stats(self) -> dict:
        uaf = self.get_uaf_objects()
        df = self.get_double_free_objects()
        total_uses = sum(len(o.use_after_free) for o in uaf)
        return {
            'total_objects': len(self.objects),
            'total_freed': sum(1 for o in self.objects.values() if o.freed_at >= 0),
            'uaf_objects': len(uaf),
            'total_uaf_uses': total_uses,
            'double_free_objects': len(df),
            'live_objects': len(self.get_live_objects()),
            'reg_tracked': len(self.reg_obj),
            'stack_tracked': len(self.stack_obj),
        }

    @staticmethod
    def _subreg_variants(reg64: str) -> List[str]:
        """返回64位寄存器的32/16/8位变体名."""
        _map = {'rax': ['eax', 'ax', 'al'], 'rbx': ['ebx', 'bx', 'bl'],
                'rcx': ['ecx', 'cx', 'cl'], 'rdx': ['edx', 'dx', 'dl'],
                'rsi': ['esi', 'si', 'sil'], 'rdi': ['edi', 'di', 'dil'],
                'rbp': ['ebp', 'bp', 'bpl'], 'rsp': ['esp', 'sp', 'spl']}
        return _map.get(reg64, [])
