# coding: utf-8
# 创建: 2026-04-22  |  反向定值链解析——size 参数的值域重建
#
"""
反向定值链 (backward def-use chain) 值域解析器。

问题: 现有实现只提取 call 前紧邻的 `mov reg, imm`, 遇到
  `mov r8, rax; sub r8, 8; call memcpy`
即返回 0, 保守保留候选 → 误报。

方法: 从 call 点反向扫描, 沿寄存器定值链逐跳重建值域 Region:
  mov r, imm        → CONSTANT [imm, imm]
  mov r, s          → 递归解析 s 的值域
  lea r, [s+imm]    → 解析 s 后平移 imm
  add/sub r, imm    → 平移
  imul r, imm       → 缩放
  movzx/movsx       → 宽度收窄/符号扩展
  xor r, r          → CONSTANT 0
  mov r, [rbp+imm]  → PARAMETER (正偏移=函数参数) / STACK (负偏移)
  其他/未知         → UNKNOWN [0, +inf)

约束:
  - 扫描窗口默认 40 条指令, 跳数上限 12, 防循环与开销爆炸
  - 扫描遇 call 且目标寄存器为 caller-saved → UNKNOWN (值来自未知调用)
  - 解析失败保守返回 UNKNOWN (不误删真实漏洞, 只增误报空间给后续过滤器)
"""

import dataclasses
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .insn import Instruction, normalize_reg, callee_name
from .memop import _imm_val, _mem_off, _plain_reg_token, _dest_reg
from .region import (
    Region, KIND_CONSTANT, KIND_COMPUTED, KIND_PARAMETER,
    KIND_STACK, KIND_MEMORY, KIND_UNKNOWN, NEG_INF, POS_INF,
)

_WINDOW = 40
_MAX_HOPS = 12

# caller-saved 寄存器——跨 call 视为被污染
_CALLER_SAVED = frozenset({
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
})


class DefUseResolver:
    """反向定值链值域解析器."""

    def __init__(self, window: int = _WINDOW, max_hops: int = _MAX_HOPS):
        self._window = window
        self._max_hops = max_hops
        self._stats = {"resolved": 0, "unresolved": 0}

# 对外入口

    def resolve(self, insns: List[Instruction], call_idx: int,
                cand_regs: List[str]) -> Region:
        """解析 call_idx 前 cand_regs 中任一寄存器的值域.

        返回首个存在真实定值的候选值域; 全部无定值返回 UNKNOWN.
        """
        fallback: Optional[Region] = None
        for reg in cand_regs:
            reg64 = normalize_reg(reg)
            region, def_found = self._walk(insns, call_idx - 1, reg64,
                                           self._max_hops)
            if def_found:
                self._stats["resolved"] += 1
                return region
            if fallback is None:
                fallback = region
        self._stats["unresolved"] += 1
        if fallback is not None and not fallback.is_top:
            return fallback
        return Region.unbounded(KIND_UNKNOWN, source_id="unknown")

# 核心回溯

    def _walk(self, insns: List[Instruction], start: int, reg: str,
              hops: int) -> Tuple[Region, bool]:
        """从 start 反向查找 reg 的定义, 递归解析.

        返回 (Region, def_found); def_found=False 表示未找到真实定值,
        仅返回参数/未知回退值域。
        """
        if hops <= 0 or start < 0:
            return Region.unbounded(KIND_UNKNOWN, source_id=reg), False

        for j in range(start, max(-1, start - self._window), -1):
            insn = insns[j]

            if insn.mnem == "call":
                # 遇 call: caller-saved 寄存器值未知。
                # 例外: alloc 调用按被调函数保留寄存器建模 (与编译器
                # 代码生成一致), 其返回前的寄存器值链可跨越分配点。
                from .abi import find_alloc
                if reg in _CALLER_SAVED and not find_alloc(callee_name(insn)):
                    return Region.unbounded(KIND_UNKNOWN,
                                            source_id="call"), False
                continue

            if insn.mnem == "ret":
                break

            dst = _dest_reg(insn)
            if not dst or normalize_reg(dst) != reg:
                continue

            region = self._apply_def(insn, insns, j, reg, hops)
            # 根键分配: 复制链继承来源根键 (来源无根时以本定值点为根);
            # 立即数/内存加载重置为本定值点; 算术派生重置为 op 定值点
            if insn.mnem == "mov":
                src = _plain_reg_token(insn.op(1)) if len(insn.ops) > 1 else ""
                is_copy = bool(src) and _imm_val(insn.op(1)) is None
                if is_copy and region.root_key:
                    pass  # 继承来源根键
                else:
                    region = dataclasses.replace(
                        region, root_key=f"def@{j}:{reg}")
            else:
                region = dataclasses.replace(
                    region, root_key=f"op@{j}:{reg}")
            return region, True

        # 未找到定义: 若为参数寄存器 → PARAMETER (函数入口传入)
        if reg in ("rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10"):
            return Region.param(source_id=f"param:{reg}"), False
        return Region.unbounded(KIND_UNKNOWN, source_id=reg), False

    def _apply_def(self, insn: Instruction, insns: List[Instruction],
                   idx: int, reg: str, hops: int) -> Region:
        """按助记符将定值指令转换为值域."""
        mnem = insn.mnem
        ops = insn.ops
        src = _plain_reg_token(ops[1]) if len(ops) > 1 else ""

        def _rw(start: int, target: str, h: int) -> Region:
            r, _ = self._walk(insns, start, target, h)
            return r

        if mnem == "mov":
            if len(ops) < 2:
                return Region.unbounded(KIND_UNKNOWN, source_id=reg)
            # 立即数
            if _imm_val(ops[1]) is not None:
                return Region.constant(_imm_val(ops[1]))
            # 寄存器→寄存器
            if src:
                return _rw(idx - 1, normalize_reg(src), hops - 1)
            # 内存加载
            mem_ops = [o for o in ops if "[" in o]
            if mem_ops:
                return self._load_mem(mem_ops[0], reg)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "lea":
            mem_ops = [o for o in ops if "[" in o]
            if not mem_ops:
                return Region.unbounded(KIND_UNKNOWN, source_id=reg)
            base, off = _mem_off(mem_ops[0])
            if base is None:
                return Region.unbounded(KIND_UNKNOWN, source_id=reg)
            if base == "rip":
                return Region.unbounded(KIND_MEMORY, source_id="rip")
            if off is not None:
                base_reg = normalize_reg(base)
                sub = _rw(idx - 1, base_reg, hops - 1)
                if sub.is_bottom:
                    return sub
                return sub.shift_add(off)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "add":
            imm = _imm_val(ops[1]) if len(ops) > 1 else None
            if imm is not None:
                return _rw(idx - 1, reg, hops - 1).shift_add(imm)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "sub":
            imm = _imm_val(ops[1]) if len(ops) > 1 else None
            if imm is not None:
                return _rw(idx - 1, reg, hops - 1).shift_sub(imm)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "imul":
            if len(ops) >= 2 and _imm_val(ops[-1]) is not None:
                factor = _imm_val(ops[-1])
                if len(ops) >= 3:
                    s = _plain_reg_token(ops[1])
                    base = _rw(idx - 1, normalize_reg(s), hops - 1) if s \
                        else Region.unbounded()
                else:
                    base = _rw(idx - 1, reg, hops - 1)
                return base.scale(factor)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "xor":
            if len(ops) > 1 and normalize_reg(ops[1]) == reg:
                return Region.constant(0)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem == "and":
            imm = _imm_val(ops[1]) if len(ops) > 1 else None
            if imm is not None:
                return _rw(idx - 1, reg, hops - 1).bit_and_mask(imm)
            return Region.unbounded(KIND_UNKNOWN, source_id=reg)

        if mnem in ("movzx", "movsx"):
            base = _rw(idx - 1, src, hops - 1) if src \
                else Region.unbounded()
            if mnem == "movzx":
                return base.widen32()
            return base.sign_extend32()

        if mnem == "inc":
            return _rw(idx - 1, reg, hops - 1).shift_add(1)
        if mnem == "dec":
            return _rw(idx - 1, reg, hops - 1).shift_sub(1)

        if mnem == "pop":
            # pop rxx — 栈恢复, 视为 UNKNOWN
            return Region.unbounded(KIND_STACK, source_id=reg)

        return Region.unbounded(KIND_UNKNOWN, source_id=reg)

    def _load_mem(self, mem_op: str, reg: str) -> Region:
        """内存加载 → PARAMETER/STACK/MEMORY 分类."""
        base, off = _mem_off(mem_op)
        if base is None:
            return Region.unbounded(KIND_MEMORY, source_id=reg)
        if base == "rbp":
            if off is not None and off > 0:
                return Region.param(source_id=f"param:{base}+{off:#x}")
            return Region.unbounded(KIND_STACK,
                                    source_id=f"stk:{base}{off:+d}")
        if base == "rsp":
            # Win64 阴影空间之上为正偏移, 可能是参数
            if off is not None and off >= 0x20:
                return Region.param(source_id=f"param:{base}+{off:#x}")
            return Region.unbounded(KIND_STACK,
                                    source_id=f"stk:{base}{off:+d}")
        return Region.unbounded(KIND_MEMORY, source_id=reg)

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["DefUseResolver", "_dest_reg", "_imm_val"]
