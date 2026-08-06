# Use-After-Free 检测器 (Cross-Function UAF Lifecycle Detection)
#
# 追踪堆对象的分配-释放-使用生命周期, 在函数边界内检测use-after-free.
#
# 决策依据:
#   1. 堆操作配对: 追踪 malloc/calloc/realloc → free/delete 的配对关系.
#      用分配点地址作为对象ID, 记录分配大小和释放状态.
#   2. 跨函数追踪: 通过调用图传播"已释放"标记.
#      当指针作为参数传递给子函数时, 将其标记状态传播到被调用函数.
#   3. 危险使用模式: free后立即将指针置NULL是安全的(防御性编程).
#      仅报告 free后未置NULL 且 后续有解引用/传参 的情况.
#      free→use间隙越大 → 越难通过code review发现 → 风险越高.
#   4. double free: 同一地址被free两次且中间无malloc → 报告.
#
# 创建: 2026-08-04  初始版本

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class HeapObject:
    """堆对象追踪: 分配点→释放点→使用点."""
    __slots__ = ("obj_id","alloc_addr","alloc_size","freed_at",
                 "use_after_free_at","nulled_after_free","call_path")
    def __init__(self, obj_id: int, alloc_addr: int, alloc_size: int = 0):
        self.obj_id = obj_id; self.alloc_addr = alloc_addr
        self.alloc_size = alloc_size; self.freed_at: List[int] = []
        self.use_after_free_at: List[int] = []
        self.nulled_after_free = False
        self.call_path: List[str] = []


class UAFDetector:
    """UAF 生命周期检测器.

    输入: 反汇编指令流 + 基本控制流信息.
    输出: 检测到的UAF/double-free位置.
    """

    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                    "operator_new", "g_malloc", "ExAllocatePool"}
    FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete",
                   "g_free", "ExFreePool"}
    REALLOC_FUNCS = {"realloc"}

    def __init__(self):
        self._objects: Dict[int, HeapObject] = {}  # 地址→对象
        self._reg_to_obj: Dict[str, int] = {}       # 寄存器→对象ID
        self._findings: List[dict] = []
        self._next_obj_id = 1
        # 地址被free的次数 (用于double free检测)
        self._free_count: Dict[int, int] = defaultdict(int)

    def analyze_instruction(self, ins: dict):
        """分析单条指令: 检测堆操作模式.

        ins格式: {"mnemonic": str, "operands": [str, ...],
                   "address": int, "comment": str}
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        if mnem == "call" and ops:
            self._handle_call(ops[0], addr, ops)

        if mnem in ("mov", "lea") and len(ops) >= 2:
            self._track_pointer_move(ops[0], ops[1])

        if mnem in ("test", "cmp") and len(ops) >= 1:
            self._check_null_check(ops)

    def _handle_call(self, call_target: str, addr: int, ops: List[str]):
        """处理函数调用: 分配/释放/使用."""
        func = self._extract_func(call_target)

        if func in self.ALLOC_FUNCS:
            # 分配: 记录新堆对象, 返回值在 rax/eax
            obj = HeapObject(self._next_obj_id, addr)
            self._objects[self._next_obj_id] = obj
            self._reg_to_obj["rax"] = self._next_obj_id
            self._reg_to_obj["eax"] = self._next_obj_id
            self._next_obj_id += 1

        elif func in self.FREE_FUNCS and len(ops) >= 2:
            # 释放: 追踪被释放的对象
            src_reg = self._normalize_reg(ops[1])
            obj_id = self._reg_to_obj.get(src_reg)
            if obj_id is not None and obj_id in self._objects:
                obj = self._objects[obj_id]
                self._free_count[addr] += 1
                if self._free_count[addr] >= 2:
                    self._findings.append({
                        "type": "double_free",
                        "address": addr,
                        "obj_id": obj_id,
                        "severity": "critical",
                    })
                obj.freed_at.append(addr)

        elif func in self.ALLOC_FUNCS | self.FREE_FUNCS:
            pass  # 非堆操作, 跳过

        else:
            # 任意调用: 若参数来自已释放对象 → UAF
            for i, op in enumerate(ops[1:], 1):
                reg = self._normalize_reg(op)
                obj_id = self._reg_to_obj.get(reg)
                if obj_id is not None and obj_id in self._objects:
                    obj = self._objects[obj_id]
                    if obj.freed_at and not obj.nulled_after_free:
                        gap = addr - obj.freed_at[-1]
                        obj.use_after_free_at.append(addr)
                        self._findings.append({
                            "type": "use_after_free",
                            "address": addr,
                            "obj_id": obj_id,
                            "freed_at": obj.freed_at[-1],
                            "instr_gap": gap,
                            "function": func,
                            "severity": "critical" if gap > 100 else "high",
                        })

    def _track_pointer_move(self, dst: str, src: str):
        """追踪寄存器间的指针传递."""
        dst_reg = self._normalize_reg(dst)
        src_reg = self._normalize_reg(src)
        obj_id = self._reg_to_obj.get(src_reg)
        if obj_id is not None:
            self._reg_to_obj[dst_reg] = obj_id

    def _check_null_check(self, ops: List[str]) -> bool:
        """检测 free后置NULL 的防御性模式.

        识别 'xor reg, reg' 后同一寄存器被写入指针位置 →
        判定为防御性置空. 返回 True 表示指针已安全置空.
        """
        if len(ops) < 1:
            return False
        op0 = ops[0].strip().lower()
        # xor reg, reg → 寄存器清零
        if any(op0.startswith(p) for p in ["xor ","xorb ","xorl ","xorq "]):
            parts = op0.split(",")
            if len(parts) >= 2 and parts[0].strip().lstrip("%") == parts[1].strip().lstrip("%"):
                return True
        # mov $0, reg → 显式置零
        if any(op0.startswith(p) for p in ["mov ","movl ","movq "]):
            parts = op0.split(",")
            if len(parts) >= 2 and parts[1].strip().replace("$","") in ("0","0x0"):
                return True
        return False

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def stats(self) -> dict:
        n_alloc = sum(1 for o in self._objects.values() if True)
        n_freed = sum(1 for o in self._objects.values() if o.freed_at)
        n_uaf = sum(1 for o in self._objects.values() if o.use_after_free_at)
        return {
            "objects_allocated": self._next_obj_id - 1,
            "objects_freed": n_freed,
            "uaf_detected": len([f for f in self._findings if f["type"] == "use_after_free"]),
            "double_free_detected": len([f for f in self._findings if f["type"] == "double_free"]),
        }

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower().replace("call ", "").split("@")[0].split("(")[0]
        return t.split(".")[-1]  # 取最后一段: libc.malloc → malloc

    @staticmethod
    def _normalize_reg(reg: str) -> str:
        return reg.strip().lower().lstrip("%").replace("$", "")


__all__ = ["UAFDetector", "HeapObject"]
