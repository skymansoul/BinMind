# 整数溢出检测器 (Integer Overflow Detection)
#
# 检测可能导致堆/栈溢出的整数溢出模式:
#   1. 乘法溢出: a * b 的结果超出类型范围.
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
#   2. 区间推导: 从操作数类型推导可能的值域.
#      32位操作数 → [0, 2^32-1]; 16位 → [0, 65535].
#      若乘法结果超出类型范围 → 标记.
#   3. 常见模式: malloc(a * b) 若无溢出检查 → 报告.
#      malloc(a + b) 若 a 和 b 均可控 → 报告.
#
# 创建: 2026-08-06

from typing import Dict, List, Optional, Tuple


class IntegerOverflowDetector:
    """整数溢出检测器 — 安全上下文感知.

    只报告可能被用于内存操作的溢出, 忽略纯计算溢出.
    """

    # 危险使用者: 溢出结果流向这些函数时触发告警
    DANGEROUS_CONSUMERS = {"malloc","calloc","realloc","memcpy","memmove",
                            "memset","alloca","_alloca","mmap","brk"}

    # 乘法和移位是最常见的溢出来源
    OVERFLOW_OPS = {"imul","mul","shl","sal","add","sub"}

    def __init__(self):
        self._findings: List[dict] = []
        self._reg_types: Dict[str, Tuple[int, int]] = {}  # reg → (bit_width, signed)
        self._pending_ops: List[dict] = []  # 最近的算术操作, 待确认是否流向危险函数

    def analyze(self, ins: dict):
        """逐指令分析."""
        mnem = ins.get("mnemonic","").lower()
        ops = ins.get("operands",[])
        addr = ins.get("address",0)

        # 追踪寄存器宽度
        if mnem == "mov" and len(ops) >= 2:
            dst = ops[0].strip().lower().lstrip("%")
            src = ops[1].strip().lower().lstrip("%").replace("$","")
            if "e" in dst and len(dst) >= 3:  # eax, ebx, ...
                self._reg_types[dst.replace("e","r")] = (32, False)
            elif dst.startswith("r"):  # rax, rbx, ...
                self._reg_types[dst] = (64, False)

        # 检测溢出操作
        if mnem in self.OVERFLOW_OPS and len(ops) >= 2:
            op_info = {
                "mnemonic": mnem,
                "operands": ops,
                "address": addr,
                "result_reg": self._normalize(ops[0]) if ops else "",
            }
            # 检查操作数类型以判断是否可能溢出
            src1 = ops[1].strip().lower().lstrip("%").replace("$","") if len(ops) >= 2 else ""
            src2 = ops[2].strip().lower().lstrip("%").replace("$","") if len(ops) >= 3 else ""

            if mnem in ("imul","mul") and self._can_overflow(src1, src2):
                op_info["overflow_type"] = "multiplication"
                self._pending_ops.append(op_info)
            elif mnem == "shl" and self._can_overflow_shift(src1, src2):
                op_info["overflow_type"] = "shift"
                self._pending_ops.append(op_info)
            elif mnem in ("add","sub"):
                op_info["overflow_type"] = "addition"
                self._pending_ops.append(op_info)

        # 危险调用检测
        if mnem == "call" and ops:
            func = ops[0].strip().lower().split("@")[0].split(".")[-1]
            if func in self.DANGEROUS_CONSUMERS:
                # 检查前几个操作数是否来自待定的溢出操作
                for op_info in self._pending_ops[-5:]:  # 最近5个溢出操作
                    if op_info["result_reg"] == self._normalize(ops[1]) if len(ops) > 1 else False:
                        self._findings.append({
                            "type": "integer_overflow_to_dangerous",
                            "overflow_type": op_info["overflow_type"],
                            "overflow_addr": op_info["address"],
                            "consumer": func,
                            "consumer_addr": addr,
                            "severity": "critical" if func in ("malloc","calloc","realloc")
                                        else "high",
                        })

        # 定期清理 (保持待定列表在合理大小)
        if len(self._pending_ops) > 20:
            self._pending_ops = self._pending_ops[-10:]

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


__all__ = ["IntegerOverflowDetector"]
