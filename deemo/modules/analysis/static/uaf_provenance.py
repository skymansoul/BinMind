# ULPR — UAF Lifetime Provenance Re-verification (生命周期来源复核).
#
# 决策逻辑:
#   UAF前向追踪按对象ID维护寄存器/栈槽→释放对象的映射. 误报源于映射
#   在以下场景失真:
#     - 指针经 call 返回值复活 (p = get_ptr(); 检测器不清除 rax 旧映射)
#     - 寄存器被中间调用冲刷后未重新定义 (rdi/rsi 跨函数残留)
#     - 内存槽被非释放来源重写后经槽加载回寄存器
#   本模块对 finalize 产出的每条候选做后向定义链复核:
#     - 在 freed_at 与 deref 之间, 扫描 deref 寄存器的一切重定义.
#     - 重定义为立即数/新对象 → 指针已复活 → BENIGN.
#     - 重定义源自 call 返回值或不可解析内存加载 → 无法确认仍指向
#       释放对象 → SUSPECTED (降级, 不计入确认).
#     - 无重定义且定义链回溯至释放对象 → CONFIRMED.
#   仅 CONFIRMED 计入检出, 与堆检测的 PcWBI 三级判定保持同一机制.
#
# 创建: 2023-08-12

from typing import Dict, List, Optional, Tuple

from .disasm_util import norm_reg, extract_stack_slot, extract_func_name


class UafVerdict:
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    BENIGN = "benign"


# caller-saved 寄存器: 中间 call 会冲刷其值.
_CALLER_SAVED = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11",
                 "eax", "ecx", "edx", "r8d", "r9d", "r10d", "r11d"}


class UAFProvenanceFilter:
    """UAF 生命周期来源复核过滤器."""

    def __init__(self, alloc_funcs=None, free_funcs=None):
        self._alloc = alloc_funcs or {"malloc", "calloc", "realloc", "_Znwm",
                                      "_Znam", "g_malloc", "ExAllocatePool"}
        self._free = free_funcs or {"free", "_ZdlPv", "_ZdaPv", "g_free",
                                    "ExFreePool"}
        self._stats = {"confirmed": 0, "suspected": 0, "benign": 0}

    def filter(self, findings: List[dict],
               instructions: List[dict]) -> Tuple[List[dict], List[dict], List[dict]]:
        """对候选 findings 执行来源复核.

        返回 (confirmed, suspected, benign).
        """
        confirmed, suspected, benign = [], [], []
        for f in findings:
            verdict, reason = self._verify(f, instructions)
            f["ulp_verdict"] = verdict
            f["ulp_reason"] = reason
            f["ulp_filtered"] = verdict != UafVerdict.CONFIRMED
            self._stats[verdict] += 1
            if verdict == UafVerdict.CONFIRMED:
                confirmed.append(f)
            elif verdict == UafVerdict.SUSPECTED:
                suspected.append(f)
            else:
                benign.append(f)
        return confirmed, suspected, benign

    def _verify(self, f: dict, instructions: List[dict]) -> Tuple[str, str]:
        """单条候选的复核."""
        freed_at = f.get("freed_at", 0)
        deref_addr = f.get("address", 0)
        reg = f.get("reg") or self._extract_deref_reg(f)
        if not reg:
            return UafVerdict.CONFIRMED, "no register to verify"
        if deref_addr <= freed_at:
            return UafVerdict.CONFIRMED, "free after deref order anomaly"

        idx_map = {ins.get("address", i): i for i, ins in enumerate(instructions)}
        if deref_addr not in idx_map or freed_at not in idx_map:
            return UafVerdict.CONFIRMED, "address not in instruction stream"
        lo = idx_map[freed_at]
        hi = idx_map[deref_addr]
        if hi - lo > 400:
            return UafVerdict.SUSPECTED, "free->use window too large to verify"

        # 后向定义链追踪: 从 deref 处 reg 的最后定义回溯.
        chain, reason = self._trace_def_chain(
            instructions, hi, reg, freed_at, obj_id=f.get("obj_id"))
        if chain == "reborn_const":
            return UafVerdict.BENIGN, "pointer redefined to constant"
        if chain == "reborn_call":
            return UafVerdict.SUSPECTED, "pointer redefined via call return"
        if chain == "reborn_mem":
            return UafVerdict.SUSPECTED, "pointer reloaded from unverified memory"
        if chain == "confirmed":
            return UafVerdict.CONFIRMED, f"def chain intact ({reason})"
        if chain == "reborn_obj":
            return UafVerdict.BENIGN, "pointer rebound to different allocation"
        return UafVerdict.SUSPECTED, "chain not resolvable"

    def _trace_def_chain(self, instructions: List[dict], hi: int,
                         reg: str, freed_at: int,
                         obj_id: Optional[int]) -> Tuple[str, str]:
        """从指令索引 hi 处 reg 的定义回溯, 判定其是否仍指向释放对象.

        返回 (状态, 依据), 状态 ∈ confirmed|reborn_const|reborn_call|
        reborn_mem|reborn_obj|unknown.
        """
        cur_reg = norm_reg(reg)
        # 从 deref 指令的前一条开始回溯, deref 调用自身不视为冲刷其参数.
        for i in range(hi - 1, -1, -1):
            ins = instructions[i]
            addr = ins.get("address", 0)
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])

            if mnem == "call":
                if cur_reg in _CALLER_SAVED or cur_reg == "rax":
                    # call 冲刷 caller-saved; 若随后无重定义则值已丢失.
                    if not ops:
                        return "reborn_call", f"clobbered by call@{addr:x}"
                    fn = extract_func_name(ops[0])
                    if fn in self._alloc and cur_reg in ("rax", "eax"):
                        return "reborn_obj", f"new alloc@{addr:x}"
                    return "reborn_call", f"clobbered by call@{addr:x}"
                continue

            if len(ops) < 2:
                continue
            dst = norm_reg(ops[0])
            if dst != cur_reg:
                continue

            src = ops[1].strip()
            imm = self._parse_imm(src)
            if imm is not None:
                if mnem in ("mov", "movabs", "xor"):
                    # 真正的常量重定义 (mov/xor 清空指针) → 安全.
                    if imm == 0:
                        return "reborn_const", f"nulled@{addr:x}"
                    return "reborn_const", f"constant@{addr:x}"
                # add/sub/shl 等为指针算术: 基址不变, 继续回溯.
                continue

            if mnem == "lea":
                # 地址计算非解引用: 基址寄存器继续.
                base = self._mem_base_reg(src)
                if base:
                    cur_reg = base
                continue

            if "[" in src.lower():
                # 内存加载: 回溯该槽的最后写入.
                return self._trace_slot_load(
                    instructions, i, src, freed_at, obj_id)

            src_reg = norm_reg(src)
            if src_reg:
                if src_reg in ("rax", "eax") and i > 0 and \
                        instructions[i - 1].get("mnemonic", "").lower() == "call":
                    fn = self._call_name(instructions[i - 1])
                    if fn in self._alloc:
                        # 分配调用是释放对象的出生点, 定义链到达分配即确认.
                        a = instructions[i - 1].get("address", 0)
                        return "confirmed", f"chain reaches alloc@{a:x}"
                    return "reborn_call", f"rax from call@{addr:x}"
                cur_reg = src_reg
                continue

        return "confirmed", f"chain reaches function entry for {reg}"

    def _trace_slot_load(self, instructions: List[dict], load_idx: int,
                         mem_operand: str, freed_at: int,
                         obj_id: Optional[int]) -> Tuple[str, str]:
        """内存加载的来源判定: 找该槽最后一次写入, 按其相对 free 的时序判定.

        最后一次写入早于 free → 槽仍持释放前对象 → confirmed.
        写入晚于 free   → 槽已被非释放来源重写 (指针复活) → reborn_mem.
        """
        slot = extract_stack_slot(mem_operand)
        base = self._mem_base(mem_operand)
        for j in range(load_idx - 1, -1, -1):
            ins = instructions[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            # 仅 mov 写内存才更新槽; cmp/test 等只读不写.
            if mnem != "mov":
                continue
            dst = ops[0].strip()
            if "[" not in dst.lower():
                continue
            if (slot and slot == extract_stack_slot(dst)) or \
                    (base and base == self._mem_base(dst)):
                return self._judge_slot_write(instructions, j, freed_at)
        return "reborn_mem", "slot write not found in window"

    @staticmethod
    def _judge_slot_write(instructions: List[dict], write_idx: int,
                          freed_at: int) -> Tuple[str, str]:
        """按槽写入的地址与来源判定."""
        write_addr = instructions[write_idx].get("address", 0)
        ops = instructions[write_idx].get("operands", [""])
        src = ops[1].strip() if len(ops) > 1 else ""
        imm = UAFProvenanceFilter._parse_imm(src)
        if imm is not None:
            if imm == 0:
                return "reborn_const", f"slot nulled@{write_addr:x}"
            return "reborn_const", f"slot constant@{write_addr:x}"
        if write_addr > freed_at:
            return "reborn_mem", f"slot rewritten after free@{write_addr:x}"
        return "confirmed", f"slot holds pre-free object@{write_addr:x}"

    @staticmethod
    def _call_name(ins: dict) -> str:
        ops = ins.get("operands", [""])
        return extract_func_name(ops[0]) if ops and ops[0] else ""

    @staticmethod
    def _mem_base(operand: str) -> Optional[str]:
        """提取内存操作数基址寄存器."""
        op = operand.strip().lower()
        if "[" not in op:
            return None
        inner = op[op.find("[") + 1:op.rfind("]")]
        return norm_reg(inner.split("+")[0].split("-")[0].split("*")[0].strip())

    @staticmethod
    def _mem_base_reg(operand: str) -> str:
        """从 [rbx+0x4] 提取基址寄存器."""
        o = operand.strip().lower()
        inner = o.split("[", 1)[-1].split("]", 1)[0]
        base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
        return norm_reg(base) if base else ""

    @staticmethod
    def _extract_deref_reg(f: dict) -> str:
        reg = f.get("deref_reg", "")
        if reg:
            return norm_reg(reg.split("[")[1].split("]")[0].split("+")[0]
                            .split("-")[0].strip()
                            if "[" in reg else reg)
        return ""

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lower().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    @property
    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["UAFProvenanceFilter", "UafVerdict"]
