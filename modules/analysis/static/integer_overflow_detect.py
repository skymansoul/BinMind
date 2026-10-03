# 整数溢出检测器 (Integer Overflow Detection)
#
# 检测可能导致堆/栈溢出的整数溢出模式:
#   1. 乘法/移位溢出: a * b 或 a << k 的结果超出类型范围.
#   2. 加法溢出: 分配大小计算中的加法溢出.
#   3. 符号混淆: 有符号与无符号比较中的截断/扩展.
#
# 聚焦于安全相关的溢出: 仅当溢出结果被用于内存分配(malloc)
# 或内存复制(memcpy)等危险操作时才报告.
#
# 决策依据:
#   1. 安全相关筛选: 检测所有算术指令, 但仅当溢出结果
#      流向 malloc/realloc/memcpy 等危险函数时才告警.
#      单纯的计算溢出(如循环计数器)不报告.
#   2. 调用实参解析: objdump 的 call 指令只有函数名操作数,
#      实参需从调用点前序 mov/lea 反查 (Win64: rcx/rdx/r8/r9;
#      SysV: rdi/rsi/rdx/rcx/r8/r9). 溢出操作结果寄存器与
#      实参寄存器关联时判定流向危险函数.
#   3. 常见模式: malloc(a * b) 若无溢出检查 → 报告.
#      malloc(a + b) 若 a 和 b 均可控 → 报告.
#

# 实参寄存器解析, 适配 objdump 指令格式

import re
from typing import Dict, List, Optional, Tuple

from .int_overflow_guards import IntOverflowGuardMixin

_WIN64_ARGS = ("rcx", "rdx", "r8", "r9")
_SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


class IntegerOverflowDetector(IntOverflowGuardMixin):
    """整数溢出检测器 - 安全上下文感知.

    只报告可能被用于内存操作的溢出, 忽略纯计算溢出.
    """

    # 危险使用者: 溢出结果流向这些函数时触发告警
    DANGEROUS_CONSUMERS = {"malloc","calloc","realloc","memcpy","memmove",
                            "memset","alloca","_alloca","mmap","brk"}

    # 乘法和移位是最常见的溢出来源
    OVERFLOW_OPS = {"imul","mul","shl","sal","add","sub"}

    def __init__(self, use_win64_abi: bool = False):
        self._findings: List[dict] = []
        self._reg_types: Dict[str, Tuple[int, int]] = {}  # reg → (bit_width, signed)
        self._pending_ops: List[dict] = []  # 最近的算术操作, 待确认是否流向危险函数
        self._args = _WIN64_ARGS if use_win64_abi else _SYSV_ARGS
        self._instructions: List[dict] = []
        self._ins_idx = 0
        self._jno_targets: List[int] = []
        self._user_ranges = []  # jno 目标地址 (安全路径块起点)

    def set_instructions(self, instructions: List[dict]):
        """预置指令序列, 供危险调用实参反查."""
        self._instructions = instructions

    def set_user_func_ranges(self, ranges):
        """限定用户函数范围; 范围外指令 (CRT/库) 不参与分析."""
        self._user_ranges = ranges or []

    def _in_user_code(self, addr: int) -> bool:
        if not self._user_ranges:
            return True
        return any(lo <= addr < hi for lo, hi in self._user_ranges)

    def analyze(self, ins: dict):
        """逐指令分析."""
        mnem = ins.get("mnemonic","").lower()
        ops = ins.get("operands",[])
        addr = ins.get("address",0)
        if not self._in_user_code(addr):
            self._ins_idx += 1
            return

        # 追踪寄存器宽度
        if mnem == "mov" and len(ops) >= 2:
            dst = ops[0].strip().lower().lstrip("%")
            src = ops[1].strip().lower().lstrip("%").replace("$","")
            if "e" in dst and len(dst) >= 3:  # eax, ebx, ...
                self._reg_types[dst.replace("e","r")] = (32, False)
            elif dst.startswith("r"):  # rax, rbx, ...
                self._reg_types[dst] = (64, False)

        # 检测溢出操作
        # mul 单操作数 (隐式 rax), 其余指令需 >=2 操作数
        need_ops = 1 if mnem == "mul" else 2
        if mnem in self.OVERFLOW_OPS and len(ops) >= need_ops:
            op_info = {
                "mnemonic": mnem,
                "operands": ops,
                "address": addr,
                "result_reg": self._normalize(ops[0]) if ops else "",
                "checked": False,
            }
            # 栈指针/帧指针算术 (sub rsp, 0x30) 非用户可控溢出, 不追踪
            is_stack_arith = op_info["result_reg"] in (
                "rsp", "rbp", "esp", "ebp")
            if not is_stack_arith:
                # 单操作数 mul: 隐式 rax × ops[1], 结果在 rdx:rax
                if mnem == "mul" and len(ops) == 1:
                    src1 = "rax"
                    src2 = ops[0].strip().lower().lstrip("%").replace("$","")
                    op_info["result_reg"] = "rax"
                else:
                    # 检查操作数类型以判断是否可能溢出
                    src1 = ops[1].strip().lower().lstrip("%").replace("$","") if len(ops) >= 2 else ""
                    src2 = ops[2].strip().lower().lstrip("%").replace("$","") if len(ops) >= 3 else ""

                if mnem in ("imul","mul") and self._can_overflow(src1, src2):
                    op_info["overflow_type"] = "multiplication"
                    op_info["src1"] = src1
                    op_info["src2"] = src2
                    # 位于 jno 安全路径块内的乘法 (编译器重算) 视为已检查
                    if any(addr >= t for t in self._jno_targets):
                        op_info["checked"] = True
                    self._pending_ops.append(op_info)
                elif mnem == "shl" and self._can_overflow_shift(src1, src2):
                    op_info["overflow_type"] = "shift"
                    op_info["src1"] = src1
                    op_info["src2"] = src2
                    self._pending_ops.append(op_info)
                elif mnem in ("add","sub"):
                    op_info["overflow_type"] = "addition"
                    op_info["src1"] = src1
                    op_info["src2"] = src2
                    self._pending_ops.append(op_info)

        # O2 优化: count*N 编译为 lea reg, [reg*N] (scaled-index 乘法)
        # 非 OVERFLOW_OPS, 需单独识别为乘法溢出源.
        if mnem == "lea" and len(ops) >= 2:
            m = re.search(r"\[([a-z0-9]+)\s*\*\s*([0-9]+)", ops[1].lower())
            if m:
                src1 = m.group(1)
                scale = int(m.group(2))
                if scale > 1:
                    op_info = {
                        "mnemonic": "lea",
                        "operands": ops,
                        "address": addr,
                        "result_reg": self._normalize(ops[0]),
                        "overflow_type": "multiplication",
                        "src1": src1,
                        "src2": str(scale),
                        "checked": False,
                    }
                    self._pending_ops.append(op_info)

        # 溢出守卫识别: shr 回除 / mul-jno / add-carry / cmp 大常量
        self.apply_guard(mnem, ins, ops)

        # 危险调用检测
        if mnem == "call" and ops:
            func = self._extract_func(ops[0])
            if func in self.DANGEROUS_CONSUMERS:
                # 反查调用点实参寄存器
                arg_regs = self._resolve_call_args(self._ins_idx, addr)
                for op_info in self._pending_ops[-8:]:
                    result = op_info["result_reg"]
                    # 溢出已经过回除校验 (cmp sz/sizeof vs count) → 安全
                    if op_info.get("checked"):
                        continue
                    # 溢出结果寄存器与任一实参寄存器同源
                    if result in arg_regs:
                        self._findings.append({
                            "type": "integer_overflow_to_dangerous",
                            "overflow_type": op_info["overflow_type"],
                            "overflow_addr": op_info["address"],
                            "consumer": func,
                            "consumer_addr": addr,
                            "severity": "critical" if func in ("malloc","calloc","realloc")
                                        else "high",
                        })
                        break
                    # 溢出结果经 mov 链传播到实参 (rax→rcx→malloc)
                    if self._reaches_arg(result, arg_regs, self._ins_idx):
                        self._findings.append({
                            "type": "integer_overflow_to_dangerous",
                            "overflow_type": op_info["overflow_type"],
                            "overflow_addr": op_info["address"],
                            "consumer": func,
                            "consumer_addr": addr,
                            "severity": "critical" if func in ("malloc","calloc","realloc")
                                        else "high",
                        })
                        break

        self._ins_idx += 1

        # 定期清理 (保持待定列表在合理大小)
        if len(self._pending_ops) > 20:
            self._pending_ops = self._pending_ops[-10:]

    def _extract_func(self, target: str) -> str:
        """从 call 操作数提取函数名 (含 <__mingw_malloc> 归一化)."""
        import re
        t = target.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        m = re.search(r"<([^>]+)>", t)
        if m:
            t = m.group(1)
        name = t.split("@")[0].split("(")[0].split(".")[-1]
        return _MINGW_NORMALIZE.get(name, name)

    def _resolve_call_args(self, idx: int, call_addr: int) -> set:
        """从调用点前序指令解析实参寄存器 (值来源寄存器集合)."""
        args = set()
        if not self._instructions or idx <= 0:
            return args
        # 定位 call 在指令列表中的下标
        call_i = idx
        for j in range(call_i - 1, max(0, call_i - 25) - 1, -1):
            p = self._instructions[j]
            p_ops = p.get("operands", [])
            if len(p_ops) < 2:
                continue
            dst = self._normalize(p_ops[0])
            if dst in self._args:
                src = p_ops[1].strip().lower().replace("$","")
                args.add(self._normalize(src))
        return args

    def _reaches_arg(self, result_reg: str, arg_regs: set,
                     idx: int) -> bool:
        """检查 result_reg 是否经 mov 链传播到任一实参寄存器."""
        if result_reg in arg_regs:
            return True
        # 前向扫描: result → temp → arg
        if not self._instructions:
            return False
        current = result_reg
        for j in range(idx + 1, min(idx + 15, len(self._instructions))):
            p = self._instructions[j]
            p_ops = p.get("operands", [])
            if len(p_ops) < 2:
                continue
            dst = self._normalize(p_ops[0])
            src = self._normalize(p_ops[1]) if len(p_ops) > 1 else ""
            if src == current:
                if dst in arg_regs:
                    return True
                current = dst
        return False

    def _can_overflow(self, src1: str, src2: str) -> bool:
        """检查乘法操作数是否可能溢出.

        保守策略: 任一操作数为未知寄存器 → 可能溢出.
        因为不追踪寄存器具体值, 无法证明安全.
        """
        # 检查是否全是立即数
        both_immediate = True
        for s in (src1, src2):
            is_imm = False
            try:
                int(s, 16) if s.startswith("0x") else int(s)
                is_imm = True
            except ValueError:
                try: int(s); is_imm = True
                except ValueError: pass
            if not is_imm:
                both_immediate = False; break
        # 全是立即数: 计算实际乘积, 检查是否超过类型范围
        if both_immediate:
            v1 = int(src1, 16) if src1.startswith("0x") else int(src1)
            v2 = int(src2, 16) if src2.startswith("0x") else int(src2)
            return (v1 * v2) > 2**31
        # 否则保守: 任一寄存器未知 → 可能溢出
        return True

    def _can_overflow_shift(self, src1: str, shift: str) -> bool:
        try:
            s = int(shift, 16) if shift.startswith("0x") else int(shift)
            return s >= 32  # 32位以上移位可能溢出
        except ValueError:
            return True  # 未知移位量 → 保守

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def reset(self):
        self._findings.clear(); self._pending_ops.clear()
        self._instructions = []
        self._ins_idx = 0
        self._jno_targets.clear()

    @staticmethod
    def _normalize(op: str) -> str:
        """寄存器宽度归一化: edi→rdi, ax→rax, dil→rdi 等."""
        op = op.strip().lower().lstrip("%").replace("$","")
        # 32-bit → 64-bit mapping
        w32_to_w64 = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
                       "esi":"rsi","edi":"rdi","ebp":"rbp","esp":"rsp",
                       "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11",
                       "r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
        # 16-bit → 64-bit
        w16_to_w64 = {"ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
                       "si":"rsi","di":"rdi","bp":"rbp","sp":"rsp"}
        # 8-bit → 64-bit
        w8_to_w64 = {"al":"rax","bl":"rbx","cl":"rcx","dl":"rdx",
                      "dil":"rdi","sil":"rsi","bpl":"rbp","spl":"rsp"}
        for mapping in (w32_to_w64, w16_to_w64, w8_to_w64):
            if op in mapping: return mapping[op]
        return op


# MinGW 函数名归一化 (与 disasm_util 保持一致)
_MINGW_NORMALIZE = {
    "__mingw_malloc": "malloc", "__mingw_calloc": "calloc",
    "__mingw_realloc": "realloc", "__mingw_memcpy": "memcpy",
    "__mingw_memmove": "memmove", "__mingw_memset": "memset",
}


__all__ = ["IntegerOverflowDetector"]
