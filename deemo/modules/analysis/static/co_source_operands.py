# AWSC 操作数解析 mixin — 指令反推与内存操作数解析
#
# 职责:
#   - 单步反推 (step_reg / step_slot): 从寄存器/栈槽反推其 def 来源
#   - 内存操作数解析: [rbp-0x20], [rax+0x10], [rbx*4+off] (scaled index)
# 立即数按寄存器宽度符号扩展 (0xffffff80 → -128)
# 寄存器/函数名归一化
#
# 设计: 反推状态机由 trace_size_root 驱动, 本 mixin 只做单步决策,
# 返回统一元组 (kind, payload, coeff, const) 或 Root.
# 创建: 2026-04-27

import re
from typing import Dict, List, Optional, Tuple

from .co_source_core import ROOT_UNKNOWN, _CALLER_SAVED, Root


class CoSourceOperandMixin:
    """操作数反推与解析方法, 由 AWSCEngine 继承."""

    _W32_TO_W64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx",
                   "edx": "rdx", "esi": "rsi", "edi": "rdi",
                   "r8d": "r8", "r9d": "r9", "r10d": "r10",
                   "r11d": "r11", "r12d": "r12", "r13d": "r13",
                   "r14d": "r14", "r15d": "r15"}

    def _step_reg(self, ins: dict, current: str, coeff: int, const: int):
        """寄存器态反推: 找出对 current 的最后一次定义.

        返回: Root | None (无相关定义) | (kind, payload, coeff, const).
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if not ops:
            return None

        dst = self._norm(ops[0]) if len(ops) >= 1 else ""

        # mov/lea 族: dst ← src
        if mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            if dst != current:
                return None
            src = ops[1].strip()
            if self._is_imm(src):
                v = self._parse_imm_signed(src, ops[0])
                if v is None:
                    return ("imm", 0, coeff, const)
                return ("imm", v * coeff + const, 1, 0)
            if "[" in src.lower():
                slot = self._slot_of(src)
                if slot:
                    return ("slot", slot, coeff, const)
                return Root(ROOT_UNKNOWN, 0)
            return ("reg", self._norm(src), coeff, const)

        if mnem == "lea" and len(ops) >= 2:
            if dst != current:
                return None
            base, off, scale = self._parse_mem_full(ops[1])
            if base is None:
                return Root(ROOT_UNKNOWN, 0)
            if scale not in (0, 1):
                # lea rcx, [rbx*4+0] → rcx = 4*rbx → 系数缩放
                return ("reg", self._norm(base), coeff * scale,
                        const + off * coeff)
            return ("reg", self._norm(base), coeff, const + off * coeff)

        # 常量算术: add/sub current, imm|reg
        if mnem in ("add", "sub") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                delta = v if mnem == "add" else -v
                return ("reg", current, coeff, const + delta * coeff)
            # add/sub current, reg: dst_new = dst_old ± src.
            # 主数据流是 dst_old (current 自身), src 通常为次要偏移或
            # 循环变量. 追根应回到 dst_old, 否则误追到 src 导致同源
            # 判定失效. 与 lea rcx,[rcx+rdx] 的语义保持一致.
            return ("reg", current, coeff, const)

        # and current, imm — 位掩码收窄宽度, 不改变根来源与系数
        if mnem == "and" and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                return ("reg", current, coeff, const)
            return None

        # shl/shr current, imm → 系数缩放
        if mnem in ("shl", "shr") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                return ("reg", current, coeff * (1 << v), const)
            return Root(ROOT_UNKNOWN, 0)

        # imul/mul: 非常量乘数使写入量非线性, 单变量线性根无法表达.
        # 若乘数为立即数 → 系数缩放; 否则根来源无法归约 (避免
        # count*elem 与 count 被误判同源而漏报).
        if mnem in ("imul", "mul") and len(ops) >= 2:
            if dst != current:
                return None
            if self._is_imm(ops[1]):
                v = self._parse_imm_signed(ops[1], ops[0])
                if v is None:
                    return None
                return ("reg", current, coeff * v, const)
            return Root(ROOT_UNKNOWN, 0)

        # call: 返回值(rax)或 clobber caller-saved
        if mnem == "call":
            if current == "rax":
                func = self._extract_func(ops[0])
                return Root("callret", func, coeff, const)
            if current in _CALLER_SAVED:
                return Root(ROOT_UNKNOWN, 0)
            return None

        return None

    def _step_slot(self, ins: dict, slot_key: str, coeff: int, const: int):
        """栈槽态反推: 找出对 slot_key 的最后一次写入.

        返回: Root | None | (kind, payload, coeff, const).
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if not ops or mnem != "mov":
            return None

        dst = ops[0].strip()
        if "[" not in dst.lower():
            return None
        dst_slot = self._slot_of(dst)
        if dst_slot is None or dst_slot != slot_key:
            return None
        if len(ops) < 2:
            return Root(ROOT_UNKNOWN, 0)

        src = ops[1].strip()
        if self._is_imm(src):
            v = self._parse_imm_signed(src, dst)
            if v is None:
                return ("imm", 0, coeff, const)
            return ("imm", v * coeff + const, 1, 0)
        if "[" in src.lower():
            s2 = self._slot_of(src)
            if s2:
                return ("slot", s2, coeff, const)
            return Root(ROOT_UNKNOWN, 0)
        return ("reg", self._norm(src), coeff, const)

    @staticmethod
    def _slot_of(op: str) -> Optional[str]:
        m = re.search(r'\[(r[bs]p[+-]0x[0-9a-f]+)\]', op.lower())
        if m:
            return m.group(1)
        m = re.search(r'\[(r[bs]p)\]', op.lower())
        if m:
            return m.group(1)
        return None

    @staticmethod
    def _parse_mem_full(op: str) -> Tuple[Optional[str], int, int]:
        """解析内存操作数, 返回 (基址寄存器, 偏移, scale系数).

        支持 [rbp-0x20], [rax+0x10], [rbx*4+0x0] (scaled index),
        [rax+rax*1] (base 与 index 同寄存器 → 系数=1+scale).
        """
        op = op.lower().replace(" ", "")
        m = re.search(r'\[(r[bs]p[+-]0x[0-9a-f]+)\]', op)
        if m:
            base = m.group(1)
            sign = -1 if "-" in base else 1
            try:
                off = sign * int(base.split(("+" if sign > 0 else "-"))[1], 16)
            except (IndexError, ValueError):
                off = 0
            base_reg = "rbp" if "rbp" in base else "rsp"
            return base_reg, off, 1
        m = re.search(r'\[([a-z][a-z0-9]*)(?:\*([0-9]+))?'
                      r'(?:\+([a-z][a-z0-9]*)(?:\*([0-9]+))?)?'
                      r'([+-]0x[0-9a-f]+)?\]', op)
        if m:
            base_reg = m.group(1) or ""
            base_scale = int(m.group(2) or 1)
            idx_reg = m.group(3) or ""
            idx_scale = int(m.group(4) or 1)
            off_str = m.group(5) or ""
            off = 0
            if off_str:
                try:
                    off = int(off_str, 16) if "+" in off_str \
                        else -int(off_str[1:], 16)
                except ValueError:
                    off = 0
            # base 与 index 同寄存器: [rax+rax*2] → 系数 = 1 + 2 = 3
            if idx_reg and idx_reg == base_reg:
                return base_reg, off, base_scale + idx_scale
            if idx_reg:
                return base_reg, off, 1
            if base_reg:
                return base_reg, off, base_scale
        return None, 0, 1

    @staticmethod
    def _parse_mem(op: str) -> Tuple[Optional[str], int]:
        base, off, _ = CoSourceOperandMixin._parse_mem_full(op)
        return base, off

    def _norm(self, reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        if "#" in r:
            r = r.split("#")[0].strip()
        if "[" in r:
            return r
        return self._W32_TO_W64.get(r, r)

    @staticmethod
    def _is_imm(op: str) -> bool:
        s = op.strip().lower().lstrip("$").split("#")[0].strip()
        return (s.startswith("0x") or s.isdigit()
                or (s.startswith("-") and s[1:].isdigit()))

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    def _parse_imm_signed(self, op: str, reg: str = "") -> Optional[int]:
        """按目标寄存器宽度符号扩展 (0xffffff80 → -128)."""
        v = self._parse_imm(op)
        if v is None or v < 0:
            return v
        r = reg.strip().lower().lstrip("%")
        if "[" in r or not r:
            return v
        if r in self._W32_TO_W64 or r.endswith("d"):
            if v >= 0x80000000:
                return v - 0x100000000
        return v

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        m = re.search(r"<([^>]+)>", t)
        if m:
            t = m.group(1)
        return t.split("@")[0].split("(")[0].split(".")[-1]


__all__ = ["CoSourceOperandMixin"]
