# 值流大小耦合追踪器 (Size Identity Tracker)
# 技术问题: 堆溢出检测的最大误报源是"分配-写入同源 idiom":
#   size_t n = parse_input(); p = malloc(n); memcpy(p, src, n);
#   通用工具分别推断 malloc 参数与 memcpy 参数, 各自对 n 取最坏假设,
#   得到 "分配=任意大, 写入=任意大 → 无法证明安全" 的误报结论.
#   实际上同一个值 n 同时约束分配与写入, 写入量不可能超过分配量.
# 解决手段: 符号化大小变量的流敏感同一性追踪 (value-flow coupling):
#   为每个寄存器/栈槽维护一个符号身份 SizeIdentity = (chain_id, scale, offset),
#   语义: 值 = scale * base_chain + offset.
#   当 memcpy 的 size 与 malloc 的 size 解析到同一 chain 时,
#   约束验证可符号化证明 write_size ≤ alloc_size, 消除该类误报.
# 与污点分析的区别: taint 标记"值是否受输入控制", 不区分同一来源的两个副本;
#   identity 标记"值是否由同一个抽象变量推导", 这是耦合判定的基础.
# 保守性决策:
#   1. 易失寄存器在 call 后被清为 unknown (Win64: rax/rcx/rdx/r8-r11)
#   2. 非易失寄存器跨 call 保留 (ABI 保证 callee 保存)
#   3. 栈槽 identity 仅在 [rbp/rsp±off] 形式下追踪, 索引寻址不追踪
#   4. 乘/除/移位破坏 chain (scale 仅通过常数乘传播)
# TODO: 建模 callee 经指针改写 caller 栈槽的场景, 目前依赖同函数距离限制
# 已知近似: 不建模 callee 通过指针改写 caller 栈槽的场景,
#   由同函数+指令距离限制缓解 (耦合判定仅在同一函数内进行).
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

_U64_MAX = 0xFFFFFFFFFFFFFFFF

# Win64 调用约定易失寄存器 (call 后被破坏)
_VOLATILE_REGS = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
# 栈基寄存器: 仅这些基址的槽位参与 identity 内存传播
_STACK_BASES = {"rbp", "rsp"}


@dataclass(frozen=True)
class SizeIdentity:
    """符号大小身份: 值 = scale * chain_base + offset.

    kind:
      'chain'  — 来自同一个抽象源变量 (chain_id 相同即同源)
      'const'  — 编译期常数
      'unknown'— 无法追踪 (不参与耦合判定)
    scale: 源变量的倍数 (如 calloc(n,4) 的分配大小为 4n)
    offset: 相对源变量的常数额外量 (如 malloc(n+1) 的分配大小为 n+1)
    """
    kind: str = 'unknown'
    chain_id: int = 0
    scale: int = 1
    offset: int = 0
    const_value: int = 0

    @staticmethod
    def unknown() -> 'SizeIdentity':
        return SizeIdentity(kind='unknown')

    @staticmethod
    def const(val: int) -> 'SizeIdentity':
        return SizeIdentity(kind='const', const_value=val & _U64_MAX)

    @staticmethod
    def chain(cid: int, scale: int = 1, offset: int = 0) -> 'SizeIdentity':
        return SizeIdentity(kind='chain', chain_id=cid,
                            scale=scale, offset=offset)

    @property
    def is_unknown(self) -> bool:
        return self.kind == 'unknown'

    @property
    def is_const(self) -> bool:
        return self.kind == 'const'

    @property
    def is_chain(self) -> bool:
        return self.kind == 'chain'

    def add_constant(self, delta: int) -> 'SizeIdentity':
        """加常数: 仅对 scale=1 的 chain 与 const 保持精确, 否则退化."""
        if self.is_const:
            return SizeIdentity.const(self.const_value + delta)
        if self.is_chain and self.scale == 1:
            return SizeIdentity.chain(self.chain_id, 1, self.offset + delta)
        return SizeIdentity.unknown()

    def mul_constant(self, factor: int) -> 'SizeIdentity':
        """乘常数: scale 与 offset 同乘 (精确)."""
        if self.is_const:
            return SizeIdentity.const(self.const_value * factor)
        if self.is_chain:
            return SizeIdentity.chain(self.chain_id,
                                      self.scale * factor,
                                      self.offset * factor)
        return SizeIdentity.unknown()

    def with_offset(self, delta: int) -> 'SizeIdentity':
        """lea 等指针/大小运算: chain 平移 (scale 不变)."""
        if self.is_chain:
            return SizeIdentity.chain(self.chain_id, self.scale,
                                      self.offset + delta)
        return self

    def write_le_alloc(self, alloc: 'SizeIdentity',
                       pointer_offset: int = 0) -> bool:
        """耦合判定: 本 identity (写入量) 是否符号化 ≤ 分配量.

        约束: 写入总量 = scale_w * base + offset_w + pointer_offset
              分配总量 = scale_a * base + offset_a
        同 chain 下: 对任意 base ≥ 0 成立 ⟺ scale_w ≤ scale_a 且
                    offset_w + pointer_offset ≤ offset_a.
        常数情形退化为精确整数比较.
        """
        if self.is_unknown or alloc.is_unknown:
            return False
        if self.is_const and alloc.is_const:
            return (self.const_value + pointer_offset) <= alloc.const_value
        if self.is_const or alloc.is_const:
            return False
        if self.chain_id != alloc.chain_id:
            return False
        if self.scale > alloc.scale:
            return False
        return (self.offset + pointer_offset) <= alloc.offset

    def same_chain(self, other: 'SizeIdentity') -> bool:
        return (self.is_chain and other.is_chain
                and self.chain_id == other.chain_id)

    def summarize(self) -> str:
        if self.is_unknown:
            return "?"
        if self.is_const:
            return f"#{self.const_value:#x}"
        s = f"c{self.chain_id}"
        if self.scale != 1:
            s += f"*{self.scale}"
        if self.offset != 0:
            s += f"{self.offset:+d}"
        return s


class SizeIdentityTracker:
    """值流大小身份追踪器.

    与 PointerProvenanceTracker 平行维护, 由 PropagationCoordinator
    在同一指令循环中驱动, 保证身份状态与检测管道一致.
    """

    def __init__(self):
        self._next_chain = 1
        self._regs: Dict[str, SizeIdentity] = {}
        self._mem: Dict[Tuple[str, int], SizeIdentity] = {}
        self._alloc_sizes: Dict[str, SizeIdentity] = {}
        self._sink_sizes: Dict[str, SizeIdentity] = {}
        self._cmp_snapshots: Dict[int, SizeIdentity] = {}
        self._n_cleared = 0

# 传播转移

    def mov_reg(self, dst: str, src: str):
        """mov dst, src — 寄存器复制."""
        self._set_reg(dst, self._regs.get(src, SizeIdentity.unknown()))

    def mov_const(self, dst: str, val: int):
        """mov dst, imm — 常数覆写."""
        self._set_reg(dst, SizeIdentity.const(val))

    def mov_mem_to_reg(self, dst: str, base: str, off: int):
        """mov dst, [base+off] — 栈槽加载."""
        key = (base, off)
        self._set_reg(dst, self._mem.get(key, SizeIdentity.unknown()))

    def mov_reg_to_mem(self, base: str, off: int, src: str):
        """mov [base+off], src — 栈槽存储."""
        key = (base, off)
        self._mem[key] = self._regs.get(src, SizeIdentity.unknown())

    def mov_const_to_mem(self, base: str, off: int, val: int):
        """mov [base+off], imm — 常数存储.

        路径相关性检测: 槽位先前持链/未知值, 又被常数覆盖 →
        该常数仅代表部分路径 (钳位模式), 线性扫描无法区分
        路径, 槽位 identity 退化 unknown 以防误耦合 (cve18 回归根因).
        """
        key = (base, off)
        prev = self._mem.get(key)
        if (prev is not None
                and (prev.is_chain or prev.is_unknown
                     or (prev.is_const and prev.const_value != val))):
            self._mem[key] = SizeIdentity.unknown()
            return
        self._mem[key] = SizeIdentity.const(val)

    def arith(self, op: str, reg: str, delta: int):
        """add/sub reg, imm — chain 平移或常数增减."""
        cur = self._regs.get(reg, SizeIdentity.unknown())
        if op == 'add':
            self._set_reg(reg, cur.add_constant(delta))
        elif op == 'sub':
            self._set_reg(reg, cur.add_constant(-delta))

    def lea(self, reg: str, base: str, off: int):
        """lea reg, [base+off] — 继承 base 的 identity 并平移."""
        self._set_reg(reg, self._regs.get(base, SizeIdentity.unknown())
                      .with_offset(off))

    def mul(self, reg: str, factor: int):
        """imul reg, imm — 倍率传播 (calloc 大小计算)."""
        self._set_reg(reg, self._regs.get(reg, SizeIdentity.unknown())
                      .mul_constant(factor))

    def zero(self, reg: str):
        """xor reg, reg — 清零."""
        self._set_reg(reg, SizeIdentity.const(0))

    def mark_unknown(self, reg: str):
        """保守退化 (非平凡算术/移位/未知源)."""
        self._set_reg(reg, SizeIdentity.unknown())

    def on_call(self):
        """call 指令: 清空易失寄存器 identity, rax 赋新符号链.

        ABI 决策: Win64 中 rcx/rdx/r8-r11 被 callee 任意改写, 其携带的
        chain 在 call 后不可信, 必须清空.
        rax 为返回值寄存器: 持有 callee 产出的新值 (如 atoi 的结果),
        分配新的抽象 chain — 返回值是大小耦合链的重要源头.
        """
        for reg in _VOLATILE_REGS - {"rax"}:
            self._regs.pop(reg, None)
        self._regs['rax'] = SizeIdentity.chain(self._next_chain, 1, 0)
        self._next_chain += 1
        self._n_cleared += 1

# 调用点绑定

    def bind_alloc(self, site_id: str, size_reg: str, scale: int = 1):
        """记录 malloc/calloc/realloc 调用点的 size identity.

        scale: calloc 的元素大小 (分配量 = count × elem_size).
        """
        ident = self._regs.get(size_reg, SizeIdentity.unknown())
        if scale > 1 and ident.is_chain:
            ident = SizeIdentity.chain(ident.chain_id,
                                       ident.scale * scale,
                                       ident.offset * scale)
        self._alloc_sizes[site_id] = ident

    def bind_sink(self, access_id: str, size_reg: str):
        """记录 memcpy 等写入 sink 的 size identity."""
        self._sink_sizes[access_id] = self._regs.get(
            size_reg, SizeIdentity.unknown())

    def snapshot_cmp(self, idx: int, loc: tuple, ident: 'SizeIdentity'):
        """记录 cmp 指令操作数的 identity 快照 (循环耦合用).

        loc: ('reg', reg64) 或 ('mem', slot).
        同一 idx 可记录左右两个操作数, 供循环分析器按位置取用.
        """
        snap = self._cmp_snapshots.setdefault(idx, {})
        snap[loc] = ident

    def get_cmp_snapshot(self, idx: int, loc: Optional[tuple] = None
                         ) -> Optional['SizeIdentity']:
        """读取 cmp 快照; 不指定位置时返回任一非 unknown 快照."""
        snap = self._cmp_snapshots.get(idx)
        if not snap:
            return None
        if loc is not None:
            return snap.get(loc)
        for ident in snap.values():
            if not ident.is_unknown:
                return ident
        return None

    def get_alloc_size_id(self, site_id: str) -> Optional[SizeIdentity]:
        return self._alloc_sizes.get(site_id)

    def get_sink_size_id(self, access_id: str) -> Optional[SizeIdentity]:
        return self._sink_sizes.get(access_id)

    def get_identity(self, reg: str) -> SizeIdentity:
        return self._regs.get(reg, SizeIdentity.unknown())

    def get_mem_identity(self, base: str, off: int) -> SizeIdentity:
        return self._mem.get((base, off), SizeIdentity.unknown())

# 生命周期

    def clear_all_registers(self):
        """跨函数边界: 清空所有寄存器 identity."""
        self._regs.clear()

    def clear_stack_slots(self):
        """跨函数边界: 清空栈槽 identity."""
        self._mem.clear()

    def _set_reg(self, reg: str, ident: SizeIdentity):
        self._regs[reg] = ident

    def summary(self) -> Dict:
        return {
            "tracked_regs": len(self._regs),
            "tracked_mem": len(self._mem),
            "alloc_size_bindings": len(self._alloc_sizes),
            "sink_size_bindings": len(self._sink_sizes),
            "call_clears": self._n_cleared,
        }
