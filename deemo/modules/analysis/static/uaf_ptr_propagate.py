# 指针传播器.
# 职责: mov/lea/movzx 等指令中的指针别名传播 + 内存操作数目标解析
# 创建: 2026-07-17

from typing import Optional

from .disasm_util import norm_reg, extract_stack_slot, resolve_rip_relative
from .uaf_operand_utils import is_indexed_access
from .uaf_global_array import (
    resolve_global_array_base, match_global_array_elem, extract_base_reg
)


class PointerPropagator:
    """mov/lea 指令的指针别名传播: 寄存器/栈槽/全局变量/全局数组."""

    def __init__(self, detector):
        self._det = detector

    def propagate(self, ins: dict, dst_op: str, src_op: str, addr: int):
        dst_raw, src_raw = dst_op.strip(), src_op.strip()
        dst_reg, src_reg = norm_reg(dst_raw), norm_reg(src_raw)
        if not ("[" in dst_raw.lower() or "[" in src_raw.lower()):
            oid = self._det._reg_to_obj.get(src_reg)
            if oid is not None: self._det._reg_to_obj[dst_reg] = oid
            return
        if "[" in dst_raw.lower():
            if self._handle_store(dst_raw, src_reg, ins, addr):
                return
        if "[" in src_raw.lower():
            if self._handle_load(dst_reg, src_raw, ins, addr):
                return
            self._det._reg_to_obj.pop(dst_reg, None)

    def _handle_store(self, dst_raw: str, src_reg: Optional[str],
                      ins: dict, addr: int) -> bool:
        """dst 侧内存操作数: RIP相对/栈槽/indexed全局数组 store. 返回True=已处理."""
        abs_addr = resolve_rip_relative(ins, dst_raw, addr)
        if abs_addr is not None:
            oid = self._det._reg_to_obj.get(src_reg)
            if oid is not None: self._det._addr_to_obj[abs_addr] = oid
            return True
        if self._det._is_user_code(addr):
            slot = extract_stack_slot(dst_raw)
            if slot is not None:
                oid = self._det._reg_to_obj.get(src_reg)
                if oid is not None:
                    self._det._stack_to_obj[slot] = oid
                else:
                    # 源为0/常量/未知: 槽不再指向堆对象, 清除旧映射,
                    # 否则置空后的读取被误判为UAF.
                    self._det._stack_to_obj.pop(slot, None)
                return True
            if is_indexed_access(dst_raw):
                gbase = resolve_global_array_base(
                    dst_raw, self._det._ins_snapshot, self._det._current_addr)
                if gbase is not None:
                    oid = self._det._reg_to_obj.get(src_reg)
                    if oid is not None: self._det._addr_to_obj[gbase] = oid
                    return True
        return False

    def _handle_load(self, dst_reg: str, src_raw: str,
                     ins: dict, addr: int) -> bool:
        """src 侧内存操作数: RIP相对/栈槽/单寄存器/indexed全局数组 load. 返回True=已处理."""
        abs_addr = resolve_rip_relative(ins, src_raw, addr)
        if abs_addr is not None:
            self._det._reg_to_global[dst_reg] = abs_addr
            oid = self._det._addr_to_obj.get(abs_addr)
            if oid is not None:
                self._det._reg_to_obj[dst_reg] = oid
                return True
            oid = match_global_array_elem(ins, src_raw, addr,
                                          self._det._addr_to_obj)
            if oid is not None:
                self._det._reg_to_obj[dst_reg] = oid
                return True
        if self._det._is_user_code(addr):
            slot = extract_stack_slot(src_raw)
            if slot is not None:
                oid = self._det._stack_to_obj.get(slot)
                if oid is not None:
                    self._det._reg_to_obj[dst_reg] = oid
                    return True
            base_reg = extract_base_reg(src_raw)
            if base_reg is not None:
                gbase = self._det._reg_to_global.get(base_reg)
                if gbase is not None:
                    oid = self._det._addr_to_obj.get(gbase)
                    if oid is not None:
                        self._det._reg_to_obj[dst_reg] = oid
                        return True
        if is_indexed_access(src_raw):
            gbase = resolve_global_array_base(
                src_raw, self._det._ins_snapshot, self._det._current_addr)
            if gbase is not None:
                oid = self._det._addr_to_obj.get(gbase)
                if oid is not None:
                    self._det._reg_to_obj[dst_reg] = oid
                    return True
            # 字段/下标解引用未解析到已知对象: 目标寄存器不再指向
            # 原堆对象基址, 必须清除旧映射, 否则 free(obj->field) 被
            # 误判为 free(obj) → double_free 误报.
            self._det._reg_to_obj.pop(dst_reg, None)
            return True
        return False


__all__ = ["PointerPropagator"]
