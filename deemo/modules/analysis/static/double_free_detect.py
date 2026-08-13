from ._user_scope_mixin import UserScopeMixin
# 双重释放检测器 v1 — 符号指针标签追踪 (Double-Free Detector)
# 追踪malloc/calloc返回的指针标签, 检测同一标签被free()两次的模式.
# v1: 指令级分析, 寄存器+栈槽+别名追踪.
# 创建: 2026-07-25

import re
from typing import Dict, List, Optional, Tuple


class DoubleFreeDetector(UserScopeMixin):
    """指令级双重释放检测器 v1.

    检测模式:
      1. 直线双重释放: free(p); free(p) — 同寄存器/栈槽
      2. 别名双重释放: q=p; free(p); free(q) — 不同寄存器同标签
      3. 栈重载双重释放: 指针存栈→free→从栈再加载→free
      4. 错误路径双重释放: if(err)free(p); free(p) — 条件+无条件

    方法: 每个malloc返回唯一符号标签(tag_id), 追踪标签通过寄存器/栈槽传播,
          在free()调用点检查参数标签是否已FREED.
    """

    ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam", "g_malloc"}
    REALLOC_FUNCS = {"realloc"}
    FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "g_free"}

    # Win64 ABI: arg0=rcx, arg1=rdx, arg2=r8, arg3=r9
    _ARG_REGS = ["rcx", "rdx", "r8", "r9"]
    _caller_saved = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}

    __slots__ = ("_findings", "_tag_state", "_reg_tags", "_stack_tags",
                 "_next_tag", "_user_func_ranges")

    def __init__(self):
        self._findings: List[dict] = []
        self._tag_state: Dict[int, str] = {}       # tag_id → "ALLOCATED"|"FREED"
        self._reg_tags: Dict[str, int] = {}         # 寄存器→tag_id
        self._stack_tags: Dict[int, int] = {}       # 栈偏移(rbp相对)→tag_id
        self._next_tag = 1
        self._user_func_ranges: List[Tuple[int, int]] = []

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = sorted(ranges, key=lambda r: r[0])

    def _is_user_code(self, addr: int) -> bool:
        if not self._user_func_ranges:
            return True
        for lo, hi in self._user_func_ranges:
            if lo <= addr < hi:
                return True
        return False

# 主分析入口

    def analyze_instruction(self, ins: dict):
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

# ret → 重置
        if mnem == "ret":
            self._reg_tags.clear()
            self._stack_tags.clear()
            return

# 1. call: malloc/calloc/realloc/free
        if mnem == "call" and ops:
            func = self._extract_func(ops[0])
            if not self._is_user_code(addr):
                return

            is_alloc = func in self.ALLOC_FUNCS
            is_realloc = func in self.REALLOC_FUNCS
            is_free = func in self.FREE_FUNCS

            # 1a. malloc/calloc → rax = new_tag
            if is_alloc:
                tag = self._next_tag
                self._next_tag += 1
                self._tag_state[tag] = "ALLOCATED"
                self._reg_tags["rax"] = tag
                # 不清除rax — 返回值需要存活

            # 1b. realloc(ptr, size) → old tag FREED, rax = new_tag
            elif is_realloc:
                arg0 = self._ARG_REGS[0]
                if arg0 in self._reg_tags:
                    old_tag = self._reg_tags[arg0]
                    self._tag_state[old_tag] = "FREED"
                tag = self._next_tag
                self._next_tag += 1
                self._tag_state[tag] = "ALLOCATED"
                self._reg_tags["rax"] = tag
                # 清除其他caller-saved (不含rax)
                for reg in self._caller_saved:
                    if reg != "rax":
                        self._reg_tags.pop(reg, None)

            # 1c. free(ptr) → 检查释放状态
            elif is_free:
                arg0 = self._ARG_REGS[0]
                if arg0 in self._reg_tags:
                    tag = self._reg_tags[arg0]
                    if self._tag_state.get(tag) == "FREED":
                        self._findings.append({
                            "type": "double_free",
                            "address": addr,
                            "tag_id": tag,
                            "severity": "critical",
                            "description": f"Double free detected: pointer tag#{tag} freed again"
                        })
                    else:
                        self._tag_state[tag] = "FREED"
                # free不修改指针值 → 保留rax标签
                # 清除arg0(rer通常rcx) — 已被free消费
                self._reg_tags.pop(arg0, None)
                # 清除其他caller-saved (不含rax: 指针值存活)
                for reg in ("rdx", "r8", "r9", "r10", "r11"):
                    self._reg_tags.pop(reg, None)

            else:
                # 其他call → 清除caller-saved (含rax: 返回值覆盖)
                for reg in self._caller_saved:
                    self._reg_tags.pop(reg, None)

# 2. mov: 标签传播
        if mnem == "mov" and len(ops) >= 2:
            dst = self._norm_reg(ops[0])
            src_raw = ops[1]
            dst_raw = ops[0].strip().lower()
            src = self._norm_reg(src_raw)

            # 2a. reg→reg 标签传播
            if src in self._reg_tags:
                self._reg_tags[dst] = self._reg_tags[src]
                # 目标不是栈引用时不传播
            else:
                # 如果不是已知寄存器标签, 清除dst的旧标签
                self._reg_tags.pop(dst, None)

            # 2b. 栈→reg 标签加载: mov reg, [rbp-N]
            soff = self._extract_rbp_offset(src_raw)
            if soff is not None and soff in self._stack_tags:
                self._reg_tags[dst] = self._stack_tags[soff]

            # 2c. reg→栈 标签存储: mov [rbp-N], reg
            dstoff = self._extract_rbp_offset(dst_raw)
            if dstoff is not None:
                if src in self._reg_tags:
                    self._stack_tags[dstoff] = self._reg_tags[src]
                else:
                    self._stack_tags.pop(dstoff, None)

        # 3. lea: 非堆指针→清除标签 (lea rax,[rbp-N] 不是malloc)
        if mnem == "lea" and len(ops) >= 2:
            dst = self._norm_reg(ops[0])
            self._reg_tags.pop(dst, None)

# 4. xor reg,reg / xor reg, reg → 清零→清除标签
        if mnem == "xor" and len(ops) >= 2:
            a, b = self._norm_reg(ops[0]), self._norm_reg(ops[1]) if len(ops) > 1 else ""
            if a == b:  # xor rax, rax → null
                self._reg_tags.pop(a, None)

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

# 工具

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        m = re.search(r"<([^>]+)>", t)
        if m:
            t = m.group(1)
        t = t.split("@")[0].split("(")[0].split(".")[-1]
        for prefix in ("__mingw_", "__imp_", "_"):
            if t.startswith(prefix):
                t = t[len(prefix):]
                break
        return t

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%")
        return {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
                "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
                "si": "rsi", "di": "rdi", "rbp": "rbp", "rsp": "rsp",
                "ebp": "rbp", "esp": "rsp"}.get(r, r)

    @staticmethod
    def _extract_rbp_offset(operand: str) -> Optional[int]:
        """从内存操作数提取[rbp±N]或[rsp±N]中的偏移量."""
        o = operand.strip().lower()
        m = re.search(r'\[(?:rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', o)
        if not m:
            return None
        sign = 1 if m.group(1) == '+' else -1
        vs = m.group(2)
        val = int(vs, 16) if vs.startswith("0x") else int(vs)
        return sign * val


_JMP_MNEMS = {"jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
              "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jcxz"}


__all__ = ["DoubleFreeDetector"]


def detect_double_free(instructions: List[dict], file_format: str = "",
                       user_func_ranges: List[Tuple[int, int]] = None) -> List[dict]:
    detector = DoubleFreeDetector()
    if user_func_ranges:
        detector.set_user_func_ranges(user_func_ranges)

    # 按函数范围分批分析
    if user_func_ranges:
        # 索引: addr→instruction
        ins_by_addr = {i.get("address", 0): i for i in instructions if i.get("address", 0)}
        _analyze_per_function(detector, instructions, user_func_ranges, ins_by_addr)
    else:
        for ins in instructions:
            detector.analyze_instruction(ins)

    return [{"type": "double_free", "verdict": f.get("severity", "unknown"),
             "confidence": 0.85, "address": f.get("address", 0),
             "detail": str(f)[:200]} for f in detector.findings]


def _analyze_per_function(detector, instructions, user_func_ranges, ins_by_addr):
    """按函数范围分批分析, 循环体内联展开一次 (后向跳转时立即重放)."""
    unrolled = set()  # 防止重复展开: (target_addr, from_addr)

    for lo, hi in user_func_ranges:
        func_ins = [i for i in instructions if lo <= i.get("address", 0) < hi]
        if not func_ins:
            continue

        for ins in func_ins:
            mnem = ins.get("mnemonic", "").lower()
            addr = ins.get("address", 0)

            # 先执行当前指令
            detector.analyze_instruction(ins)

            # 如果是后向条件跳转, 立即重放循环体一次
            # 此时_stack_tags保留了指针标签, 重放时reg→stack→free传播有效
            ops = ins.get("operands", [])
            if mnem in _JMP_MNEMS and ops:
                target = _parse_jmp_target(ops[0])
                key = (target, addr)
                if (target is not None and target < addr and lo <= target < hi
                        and key not in unrolled):
                    unrolled.add(key)
                    # 重放目标→当前地址范围内的指令 (循环展开一次)
                    for ri in func_ins:
                        ra = ri.get("address", 0)
                        if target <= ra <= addr:
                            detector.analyze_instruction(ri)


def _parse_jmp_target(operand: str) -> Optional[int]:
    """解析跳转目标地址. 支持 0x1400017a0 和 1400017a0 两种格式."""
    import re
    o = operand.strip().lower()
    # 去掉 <symbol+offset> 后缀, 只保留地址部分
    o = o.split("<")[0].strip()
    if not o:
        return None
    # 尝试 0x 前缀格式
    if o.startswith("0x"):
        try:
            return int(o, 16)
        except ValueError:
            return None
    # 纯十六进制地址 (objdump格式, 无0x前缀)
    if re.match(r'^[0-9a-f]{5,}$', o):
        return int(o, 16)
    return None
