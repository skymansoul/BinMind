# 分配-写关联 共享基础 - 根来源类型常量与 Root 数据结构
#
# 独立模块避免 co_source_engine 与 co_source_operands 循环导入.

# 根来源类型
ROOT_IMM = "imm"          # 立即数
ROOT_STACK = "stack"      # 栈槽 [rbp-0x20]
ROOT_PARAM = "param"      # 函数入口参数寄存器
ROOT_CALLRET = "callret"  # 被调函数返回值 (read/recv → 外部输入)
ROOT_UNKNOWN = "unknown"

# SysV 与 Win64 参数寄存器
_SYSV_ARGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
_WIN64_ARGS = ("rcx", "rdx", "r8", "r9")

# call 指令 clobber 的 caller-saved 寄存器
_CALLER_SAVED = set(_SYSV_ARGS) | {"r10", "r11", "rax"}


class Root:
    """size 参数的根来源."""
    __slots__ = ("kind", "value", "coeff", "const", "confidence")

    def __init__(self, kind: str, value, coeff: int = 1,
                 const: int = 0, confidence: float = 1.0):
        self.kind = kind
        self.value = value
        self.coeff = coeff      # 相对根的线性系数
        self.const = const      # 相对根的常量偏移
        self.confidence = confidence

    def is_unknown(self) -> bool:
        return self.kind == ROOT_UNKNOWN

    def __repr__(self) -> str:
        if self.kind == ROOT_UNKNOWN:
            return "?"
        base = {"imm": f"#{self.value}", "stack": f"[{self.value}]",
                "param": f"arg({self.value})",
                "callret": f"ret({self.value})"}.get(self.kind, "?")
        if self.coeff != 1 or self.const != 0:
            return f"{self.coeff}*{base}{self.const:+d}"
        return base


__all__ = ["Root", "ROOT_IMM", "ROOT_STACK", "ROOT_PARAM",
           "ROOT_CALLRET", "ROOT_UNKNOWN", "_SYSV_ARGS",
           "_WIN64_ARGS", "_CALLER_SAVED"]
