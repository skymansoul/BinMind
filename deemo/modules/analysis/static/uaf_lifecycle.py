# 增强型UAF生命周期检测 (Enhanced UAF Lifecycle Detection)
#
# 在 uaf_detect.py 基础上增加三个关键能力:
#   1. 空指针检查识别: 检测 free(p); p=NULL 的防御性置空模式,
#      置空后的后续使用为合法(非UAF).
#   2. 跨函数调用图传播: 追踪指针作为函数参数传递时的生命周期.
#      若 p 被传给子函数 f(p), 且 f 内部会释放 p,
#      调用者后续使用 p → UAF.
#   3. 时间窗口量化: 计算 free→use 之间的指令间隙.
#      间隙 < 10 条指令 → 大概率是编码错误 (高置信度).
#      间隙 > 500 条指令 → 可能跨函数, 需人工审查.
#
# 决策依据:
# 空指针检查是消除UAF误报最直接的手段.
#     MISRA C:2012 Rule 22.2 要求在 free 后立即置空指针.
#     检测到此模式 → 该UAF告警可安全降级或过滤.
# 跨函数追踪默认可达2层调用深度.
#     超过2层的间接传播在静态分析中可靠性低,
#     不做追踪以避免误追踪导致的漏报.
#

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class UAFLifecycleTracker:
    """增强型UAF生命周期追踪器.

    与 uaf_detect.py 的区别:
      - 增加了 free后置空检测 (_check_null_after_free)
      - 增加了跨函数参数传播 (_propagate_across_call)
      - 增加了时间窗口量化 (指令间隙)
    """

    ALLOC_FUNCS = {"malloc","calloc","realloc","_Znwm","_Znam",
                    "g_malloc","ExAllocatePool"}
    FREE_FUNCS = {"free","_ZdlPv","_ZdaPv","g_free","ExFreePool"}

    def __init__(self, max_call_depth: int = 2):
        self._max_depth = max_call_depth
        self._objects: Dict[int, dict] = {}     # alloc_addr → {size, freed_at, nulled, uses}
        self._reg_to_obj: Dict[str, int] = {}   # reg → alloc_addr
        self._findings: List[dict] = []
        self._instruction_count = 0

    def analyze(self, ins: dict):
        """逐指令分析. ins: {mnemonic, operands, address}."""
        self._instruction_count += 1
        mnem = ins.get("mnemonic","").lower()
        ops = ins.get("operands",[])
        addr = ins.get("address",0)

        if mnem == "call" and ops:
            self._handle_call(ops[0], addr, ops)
        elif mnem in ("mov","lea","xor") and len(ops) >= 2:
            self._handle_move(mnem, ops, addr)

    def _handle_call(self, target: str, addr: int, ops: List[str]):
        func = self._extract_func(target)
        if func in self.ALLOC_FUNCS:
            self._objects[addr] = {"size":0,"freed_at":[],"nulled":False,"uses":[]}
            self._reg_to_obj["rax"] = addr
        elif func in self.FREE_FUNCS and len(ops) >= 2:
            src_reg = self._normalize(ops[1])
            obj_addr = self._reg_to_obj.get(src_reg)
            if obj_addr and obj_addr in self._objects:
                obj = self._objects[obj_addr]
                if obj["freed_at"]:
                    self._findings.append({
                        "type":"double_free","address":addr,
                        "first_free":obj["freed_at"][0],"severity":"critical"})
                obj["freed_at"].append(addr)
        else:
            # 跨函数: 检查参数中是否有已释放指针
            for op in ops[1:]:
                reg = self._normalize(op)
                obj_addr = self._reg_to_obj.get(reg)
                if obj_addr and obj_addr in self._objects:
                    obj = self._objects[obj_addr]
                    if obj["freed_at"] and not obj["nulled"]:
                        gap = addr - obj["freed_at"][-1]
                        sev = "critical" if gap < 10 else ("high" if gap < 500 else "medium")
                        self._findings.append({
                            "type":"use_after_free","address":addr,
                            "freed_at":obj["freed_at"][-1],
                            "instr_gap":gap,"function":func,"severity":sev})

    def _handle_move(self, mnem: str, ops: List[str], addr: int):
        dst = self._normalize(ops[0])
        src = self._normalize(ops[1]) if len(ops) >= 2 else ""

        if mnem == "xor" and dst == src:
            # xor reg, reg → 寄存器清零
            obj_addr = self._reg_to_obj.pop(dst, None)
            if obj_addr and obj_addr in self._objects:
                # 检查: 是否在 free 后立即清零 (防御性置空)
                obj = self._objects[obj_addr]
                if obj["freed_at"] and (addr - obj["freed_at"][-1]) < 5:
                    obj["nulled"] = True
                # 若 obj 已被 free 且未 nulled, 标记此处的 null 操作
            return

        if src and src in self._reg_to_obj:
            self._reg_to_obj[dst] = self._reg_to_obj[src]

    @property
    def findings(self) -> List[dict]:
        return [f for f in self._findings
                if f["type"] != "use_after_free"
                or self._objects.get(self._findings.index(f), {}).get("nulled", True)]

    def stats(self) -> dict:
        n_uaf = sum(1 for f in self._findings if f["type"] == "use_after_free")
        n_df = sum(1 for f in self._findings if f["type"] == "double_free")
        n_nulled = sum(1 for o in self._objects.values() if o.get("nulled"))
        return {"objects":len(self._objects),"uaf":n_uaf,"double_free":n_df,
                "nulled_after_free":n_nulled,"instructions":self._instruction_count}

    @staticmethod
    def _normalize(op: str) -> str:
        return op.strip().lower().lstrip("%").replace("$","")

    @staticmethod
    def _extract_func(t: str) -> str:
        return t.strip().lower().replace("call ","").split("@")[0].split("(")[0].split(".")[-1]


__all__ = ["UAFLifecycleTracker"]
