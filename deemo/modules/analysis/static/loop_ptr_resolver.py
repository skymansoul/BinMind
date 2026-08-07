# 循环指针解析器 (Loop Pointer Resolver)
#
# 核心决策:
#   循环累加写入追踪需要在循环所属函数范围内重建指针→分配映射,
#   避免全局ptr_map被CRT函数的栈帧复用污染.
#   本模块模拟函数内mov/lea指令传播堆指针, 并反向解析call目标寄存器.
#
# 创建: 2026-04-20

from typing import Optional
from .disasm_util import norm_reg, extract_func_name, extract_stack_slot
from .heap_constraint import HeapConstraintTracker


class LoopPtrResolver:
    """在函数范围内重建并解析指针→分配映射."""

    def find_func_start(self, instructions: list,
                        addr: int) -> int:
        """从循环header向前找到函数入口 (push rbp)."""
        target_idx = None
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == addr:
                target_idx = i
                break
        if target_idx is None:
            return 0
        for j in range(target_idx, -1, -1):
            mnem = instructions[j].get("mnemonic", "").lower()
            ops = instructions[j].get("operands", [""])
            if mnem == "push" and ops and "rbp" in ops[0].lower():
                return j
        return max(0, target_idx - 50)

    def find_func_end(self, instructions: list,
                      addr: int) -> int:
        """从循环back_edge向后找到函数结尾 (ret)."""
        target_idx = None
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) == addr:
                target_idx = i
                break
        if target_idx is None:
            return len(instructions) - 1
        for j in range(target_idx, len(instructions)):
            if instructions[j].get("mnemonic", "").lower() == "ret":
                return j
        return min(len(instructions) - 1, target_idx + 50)

    def build_ptr_map(self, instructions: list,
                      start_idx: int, end_idx: int,
                      alloc_tracker: HeapConstraintTracker) -> dict:
        """在函数范围内重建指针→分配映射.

        模拟mov/lea传播堆指针, 不受全局ptr_map污染.
        """
        ptr_map: dict = {}
        for i in range(start_idx, min(end_idx + 1, len(instructions))):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call" and ops:
                func = extract_func_name(ops[0])
                if func in ("malloc", "calloc", "realloc", "_Znwm", "_Znam"):
                    call_addr = ins.get("address", 0)
                    if call_addr in alloc_tracker._allocations:
                        ptr_map["rax"] = call_addr
            elif mnem == "mov" and len(ops) >= 2:
                dst = ops[0].strip()
                dst_reg = norm_reg(dst)
                src = ops[1].strip()
                src_reg = norm_reg(src)
                if src_reg in ptr_map and "[" not in dst.lower():
                    ptr_map[dst_reg] = ptr_map[src_reg]
                elif src_reg in ptr_map and "[rbp" in dst.lower():
                    slot = extract_stack_slot(dst)
                    if slot:
                        ptr_map[f"stack:{slot}"] = ptr_map[src_reg]
                elif "[rbp" in src.lower():
                    slot = extract_stack_slot(src)
                    if slot:
                        sk = f"stack:{slot}"
                        if sk in ptr_map:
                            ptr_map[dst_reg] = ptr_map[sk]
                        else:
                            ptr_map.pop(dst_reg, None)
                elif "[" not in dst.lower() and "[" not in src.lower():
                    if src_reg in ptr_map:
                        ptr_map[dst_reg] = ptr_map[src_reg]
                    else:
                        ptr_map.pop(dst_reg, None)
            elif mnem == "lea" and len(ops) >= 2:
                src_op = ops[1].strip().lower()
                base = src_op.lstrip("[").split("+")[0].split("*")[0].strip()
                if base in ptr_map:
                    ptr_map[norm_reg(ops[0])] = ptr_map[base]
            elif mnem in ("add", "sub") and ops:
                # add reg, imm: 指针在分配块内移动, 不清除映射.
                # O2/Os: rbx=buf; add rbx, 0x40 → rbx仍指向同一alloc.
                # add reg, reg: 若src持有堆指针, dst继承映射(i+buf → buf的alloc)
                # add reg, reg (均非堆指针): 清除dst映射
                if len(ops) >= 2:
                    imm = self._try_parse_imm(ops[1])
                    if imm is not None:
                        continue  # add reg, imm → 保持映射
                    src_reg = norm_reg(ops[1])
                    dst_r = norm_reg(ops[0])
                    if src_reg in ptr_map:
                        ptr_map[dst_r] = ptr_map[src_reg]
                    elif dst_r in ptr_map:
                        pass  # dst已持有映射, add不改变alloc归属
                    else:
                        ptr_map.pop(dst_r, None)
        return ptr_map

    @staticmethod
    def _try_parse_imm(op: str) -> Optional[int]:
        """尝试将操作数解析为立即数, 失败返回None."""
        s = op.strip().lower().lstrip("%").replace("$", "").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    def resolve_ptr_for_call(self, instructions: list,
                              call_idx: int, dst_reg: str,
                              ptr_map: dict) -> Optional[int]:
        """从call前反向扫描, 解析目标指针寄存器对应的alloc_addr.

        处理: mov arg_reg, tmp_reg; mov tmp_reg, [rbp-N] 等中转.
        """
        first_src = None
        for j in range(call_idx - 1, max(-1, call_idx - 20), -1):
            jins = instructions[j]
            jmnem = jins.get("mnemonic", "").lower()
            jops = jins.get("operands", [])
            if jmnem == "mov" and len(jops) >= 2:
                if norm_reg(jops[0]) == dst_reg:
                    first_src = jops[1]
                    break
        if first_src is None:
            return ptr_map.get(dst_reg)
        src_reg = norm_reg(first_src)
        if src_reg in ptr_map:
            return ptr_map[src_reg]
        if "[rbp" in first_src.lower():
            slot = extract_stack_slot(first_src)
            if slot:
                return ptr_map.get(f"stack:{slot}")
        for j in range(call_idx - 1, max(-1, call_idx - 20), -1):
            jins = instructions[j]
            jmnem = jins.get("mnemonic", "").lower()
            jops = jins.get("operands", [])
            if jmnem == "mov" and len(jops) >= 2:
                if norm_reg(jops[0]) == src_reg:
                    src2 = jops[1]
                    if "[rbp" in src2.lower():
                        slot = extract_stack_slot(src2)
                        if slot:
                            val = ptr_map.get(f"stack:{slot}")
                            if val is not None:
                                return val
                    src2_reg = norm_reg(src2)
                    if src2_reg in ptr_map:
                        return ptr_map[src2_reg]
                    break
        return ptr_map.get(dst_reg)


__all__ = ["LoopPtrResolver"]
