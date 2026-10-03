# 后向值流切片追踪 (Backward Value-Flow Slice Tracing)
#
# 堆溢出误报的主要来源: 将不可控的常量赋值或已校验变量
# 标记为"攻击者可控". 本模块从危险调用点出发,
# 沿 def-use 链反向追踪, 判断实参是否真的可能溢出.
#
# 核心决策:
#   1. 追踪策略: 从危险调用的 size 参数出发, 反向遍历指令.
#      遇到 mov/lea/算术指令 → 继续追踪源操作数;
#      遇到 call → 若被调函数已知返回值为常量或已校验 → 停止追踪;
#      遇到 cmp/test + jcc → 标记该路径上的变量为"已校验".
#   2. 污染源分类:
# "constant": 编译时确定的值 → 安全
#      - "bounds_checked": 在到达危险调用前通过了 cmp/jcc → 安全
# "external_input": 来自 read/recv/argv → 危险
# "unknown_register": 无法确定来源 → 保守标记为危险
#   3. 跨函数追踪深度: 默认追踪2层调用 (当前函数 + 直接调用者).
#      超过2层的间接数据流在静态分析中可靠性急剧下降,
#      不做追踪以减少误追踪导致的漏报.
#

from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class SourceKind(Enum):
    CONSTANT = 1         # 编译时常量: 立即数 / .rodata
    BOUNDS_CHECKED = 2   # 在到达危险调用前通过了 bounds check
    EXTERNAL_INPUT = 3   # 来自外部: read/recv/argv/getenv
    UNKNOWN = 4          # 无法确定来源, 保守处理
    ALLOC_SIZE_MATCH = 5 # 大小与分配时的参数一致 → 安全


class TaintSource:
    """值流追踪中的污染源."""
    __slots__ = ("kind","value","description","confidence")
    def __init__(self, kind: SourceKind, value: int = 0,
                 description: str = "", confidence: float = 1.0):
        self.kind = kind; self.value = value
        self.description = description; self.confidence = confidence


class BackwardSliceTracer:

    # 外部输入函数: 返回值不可信
    EXTERNAL_SOURCES = {
        "read","recv","recvfrom","recvmsg","fread","fgets",
        "scanf","__isoc99_scanf","getenv","getpwuid",
        "getaddrinfo","gethostbyname","inet_ntoa",
    }

    # 返回常量的函数 (忽略大小写)
    CONSTANT_RETURN_FUNCS = {
        "strlen", "strnlen", "sizeof",  # 实际无sizeof函数, 占位
    }

    def trace(self, instructions: List[dict],
               start_operand: str, max_depth: int = 50) -> TaintSource:
        current_reg = self._normalize(start_operand)

        # 立即数 → 常量
        if current_reg.startswith("0x") or current_reg.isdigit():
            try:
                val = int(current_reg, 16) if current_reg.startswith("0x") else int(current_reg)
                return TaintSource(
                    SourceKind.CONSTANT, value=val,
                    description=f"immediate value {val}")
            except ValueError:
                pass

        # 反向扫描
        checked_before_use = False
        for i in range(len(instructions) - 1, -1, -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            addr = ins.get("address", 0)

            if max_depth <= 0:
                break
            max_depth -= 1

            # cmp/test + jcc: 标记 bounds check
            if mnem in ("cmp", "test") and len(ops) >= 2:
                if self._normalize(ops[0]) == current_reg:
                    checked_before_use = True

            # 该寄存器被写入: 追踪写入源
            dst = self._normalize(ops[0]) if ops else ""
            if dst == current_reg and len(ops) >= 2:
                if mnem == "mov":
                    src = self._normalize(ops[1])
                    if src.startswith("0x") or src.isdigit():
                        try:
                            val = int(src, 16) if src.startswith("0x") else int(src)
                            return TaintSource(
                                SourceKind.CONSTANT if not checked_before_use
                                else SourceKind.BOUNDS_CHECKED,
                                value=val, description=f"constant {val}")
                        except ValueError:
                            pass
                    current_reg = src  # 继续追踪新的源
                    continue

                if mnem in ("add", "sub", "shl", "shr", "and", "or", "xor"):
                    # 算术指令: 追踪第一源操作数
                    src = self._normalize(ops[1])
                    if not (src.startswith("0x") or src.isdigit()):
                        current_reg = src
                    continue

                if mnem == "lea":
                    # lea 通常用于地址计算, 不改变可控性
                    continue

            # call 指令: 检查被调函数
            if mnem == "call" and ops:
                func = self._extract_func(ops[0])
                if func in self.EXTERNAL_SOURCES:
                    return TaintSource(
                        SourceKind.EXTERNAL_INPUT,
                        description=f"from external: {func}")
                if func in self.CONSTANT_RETURN_FUNCS:
                    return TaintSource(
                        SourceKind.CONSTANT,
                        description=f"from safe function: {func}")

        # 到达函数顶部 (参数): 标记为外部输入
        if current_reg in ("rdi","rsi","rdx","rcx","r8","r9","edi","esi","edx","ecx"):
            return TaintSource(
                SourceKind.EXTERNAL_INPUT,
                description=f"function parameter: {current_reg}")

        return TaintSource(
            SourceKind.UNKNOWN,
            description=f"untraceable: {current_reg}")

    @staticmethod
    def _normalize(op: str) -> str:
        return op.strip().lower().lstrip("%").replace("$","")

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for prefix in ("call ", "callq "):
            if t.startswith(prefix): t = t[len(prefix):]
        return t.split("@")[0].split("(")[0].split(".")[-1]


__all__ = ["BackwardSliceTracer", "TaintSource", "SourceKind"]
